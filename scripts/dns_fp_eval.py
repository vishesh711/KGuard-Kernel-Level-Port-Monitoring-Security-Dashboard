#!/usr/bin/env python3
"""
False-positive measurement for KGuard's DNS tunnelling detector (roadmap N5.7).

Replays real hostnames through backend/app/services/dns_tunnel.py:

  corpus   the 500 most linked-to sites (npm package "top-sites") and the
           hostnames of third-party trackers, ad servers and CDNs that
           browsers contact (npm package "@ghostery/trackerdb", built from
           real browsing), both fetched with `npm pack` if not given

  browsing a simulated user: a page every 15 s for 8 hours; each page looks
           up its site and 10-40 third-party hosts (popularity-weighted),
           through a 5-minute client DNS cache
  worst    every hostname in the corpus from one client within 10 minutes,
           no cache

The hostnames are real; the browsing pattern is a model, since this
environment has no Internet access to record real browsing.

    backend/python scripts/dns_fp_eval.py [--corpus DIR]
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

from app.services.dns_tunnel import DnsTunnelDetector, query_features, score  # noqa: E402

PACKAGES = {"top-sites": "top-sites/package/top-sites.json",
            "@ghostery/trackerdb": "trackerdb/package/dist/trackerdb.json"}


class Detector(SimpleNamespace):
    """The parts of AnomalyDetectorService the DNS detector uses; no cooldown, every alert counts"""

    def __init__(self):
        super().__init__(stats={"dns_tunnels_detected": 0})

    def is_trusted(self, ip):
        return False

    def _is_in_cooldown(self, key):
        return False

    def _start_cooldown(self, key):
        pass


def fetch(corpus_dir):
    for package, path in PACKAGES.items():
        target = os.path.join(corpus_dir, path)
        if os.path.exists(target):
            continue
        name = path.split("/")[0]
        os.makedirs(os.path.join(corpus_dir, name), exist_ok=True)
        tgz = subprocess.run(["npm", "pack", package, "--silent"], cwd=corpus_dir, check=True,
                             capture_output=True, text=True).stdout.split()[-1]
        subprocess.run(["tar", "xzf", tgz, "-C", name], cwd=corpus_dir, check=True)


def load(corpus_dir):
    sites = [s["rootDomain"].lower() for s in
             json.load(open(os.path.join(corpus_dir, PACKAGES["top-sites"])))]
    db = json.load(open(os.path.join(corpus_dir, PACKAGES["@ghostery/trackerdb"])))
    third = set(db["domains"])
    for rule in db["filters"]:
        m = re.match(r"\|\|([a-z0-9.-]+\.[a-z]{2,})[\^/$]", rule)
        if m:
            third.add(m.group(1))
    return sites, sorted(third)


def zipf_choice(rng, items, s=1.0):
    weights = [1 / (i + 1) ** s for i in range(len(items))]
    return lambda k: rng.choices(items, weights=weights, k=k)


def run(name, queries):
    detector = DnsTunnelDetector(Detector())
    alerts, closest = [], {"score": 0.0}
    for t, host in queries:
        alert = detector.observe(None, "192.168.1.20", host, 1, t)
        if alert:
            alerts.append(alert.alert_metadata)
        group = detector.groups.get((None, "192.168.1.20", query_features(host)[0]))
        if group and len(group) >= detector.min_queries:
            features = score(group)
            if features["score"] > closest["score"]:
                closest = {"domain": query_features(host)[0], **features}
    return {"scenario": name, "queries": len(queries), "alerts": len(alerts),
            "alerted_domains": sorted({a["domain"] for a in alerts}),
            "closest_group": closest,
            "thresholds": {"min_queries": detector.min_queries, "score": detector.threshold}}


def browsing(sites, third, hours=8, seed=1):
    rng = random.Random(seed)
    third = third[:]
    rng.shuffle(third)  # popularity order unknown: a random rank per host
    pick_site, pick_third = zipf_choice(rng, sites), zipf_choice(rng, third, 0.8)
    cache, queries, t = {}, [], 0.0
    while t < hours * 3600:
        site = pick_site(1)[0]
        hosts = [site] + ([] if site.startswith("www.") else ["www." + site]) + pick_third(rng.randint(10, 40))
        for i, host in enumerate(hosts):
            if cache.get(host, -1e9) > t - 300:
                continue
            cache[host] = t
            queries.append((t + i * 0.05, host))
        t += 15
    return queries


def worst_case(sites, third):
    hosts = sites + third
    return [(i * 600 / len(hosts), h) for i, h in enumerate(hosts)]


def per_query(hosts):
    long_random = [h for h in hosts if (lambda f: len(f[1]) >= 30 and f[2] >= 3.5)(query_features(h))]
    return {"hostnames": len(hosts), "long_random_names": len(long_random), "examples": long_random[:5]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", help="directory for the downloaded datasets")
    args = parser.parse_args()
    corpus_dir = args.corpus or os.path.join(tempfile.gettempdir(), "kguard-dns-corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    fetch(corpus_dir)
    sites, third = load(corpus_dir)

    print(json.dumps({"corpus": {"top_sites": len(sites), "third_party_hosts": len(third)},
                      "per_query": per_query(sites + third)}, indent=2))
    hours = 8
    for result in (run(f"browsing, {hours} h", browsing(sites, third, hours)),
                   run("worst case: whole corpus in 10 min, no cache", worst_case(sites, third))):
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
