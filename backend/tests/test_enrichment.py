"""Alert enrichment (S6.3): MITRE ATT&CK, GeoIP, threat lists, list updates"""

import http.server
import ipaddress
import threading
from datetime import datetime
from functools import partial

import pytest
from mmdb_writer import MMDBWriter
from netaddr import IPSet

from app.config import settings
from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.services.enrichment import MITRE, ThreatLists, enricher
from app.threatlists import update

from .conftest import make_event

FIREHOL = """#
# firehol_level1
# Maintainer: FireHOL
#
198.18.0.0/15
5.188.10.0/23
5.188.11.0/24
185.220.101.4
2a0e:fd80::/29
"""
SPAMHAUS = """; Spamhaus DROP List 2026/11/09
; Last-Modified: Mon, 09 Nov 2026 12:00:00 GMT
45.155.204.0/22 ; SBL123456
91.92.240.0/24 ; SBL654321
"""


@pytest.fixture
def lists(tmp_path, monkeypatch):
    directory = tmp_path / "threatlists"
    directory.mkdir()
    (directory / "firehol_level1.netset").write_text(FIREHOL)
    (directory / "spamhaus_drop.txt").write_text(SPAMHAUS)
    (directory / "README.md").write_text("not a list")
    monkeypatch.setattr(settings, "threat_lists_dir", str(directory))
    monkeypatch.setattr(enricher, "lists", ThreatLists())
    return directory


def write_mmdb(path, database_type, records):
    writer = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type=database_type)
    for network, data in records.items():
        writer.insert_network(IPSet([network]), data)
    writer.to_db_file(str(path))


@pytest.fixture
def geoip(tmp_path, monkeypatch):
    country, asn = tmp_path / "country.mmdb", tmp_path / "asn.mmdb"
    write_mmdb(country, "GeoLite2-Country", {
        "5.188.10.0/23": {"country": {"iso_code": "NL", "names": {"en": "Netherlands"}}},
        "2a0e:fd80::/29": {"country": {"iso_code": "DE", "names": {"en": "Germany"}}},
    })
    write_mmdb(asn, "GeoLite2-ASN", {
        "5.188.10.0/23": {"autonomous_system_number": 64500,
                          "autonomous_system_organization": "Example Hosting"},
    })
    monkeypatch.setattr(settings, "geoip_country_db", str(country))
    monkeypatch.setattr(settings, "geoip_asn_db", str(asn))


def test_every_alert_type_has_a_mitre_entry():
    assert set(MITRE) == set(AlertType)
    for techniques in MITRE.values():
        for t in techniques:
            assert t["id"].startswith("T") and t["url"].startswith("https://attack.mitre.org/techniques/T")
    assert MITRE[AlertType.PORT_SCAN][0]["id"] == "T1046"
    assert MITRE[AlertType.SYN_FLOOD][0]["url"].endswith("/T1499/001/")


def test_threat_lists_parse_both_formats(lists):
    tl = ThreatLists(str(lists))
    tl.refresh(force=True)
    assert tl.sizes == {"firehol_level1": 5, "spamhaus_drop": 2}
    def match(ip):
        return tl.match(ipaddress.ip_address(ip))
    assert match("5.188.11.200") == ["firehol_level1"]  # merged 5.188.10.0/23 + .11.0/24
    assert match("185.220.101.4") == ["firehol_level1"]
    assert match("185.220.101.5") == []
    assert match("45.155.207.255") == ["spamhaus_drop"]
    assert match("2a0e:fd87:ffff::1") == ["firehol_level1"]
    assert match("8.8.8.8") == []


def test_threat_lists_reload_when_files_change(lists):
    tl = ThreatLists(str(lists))
    tl.refresh(force=True)
    (lists / "mine.list").write_text("203.0.113.0/24\n")
    tl.refresh()  # checked at most once a minute
    assert "mine" not in tl.sizes
    tl.refresh(force=True)
    assert tl.sizes["mine"] == 1


def test_alert_is_enriched(lists, geoip, db):
    alert = SecurityAlert(alert_type=AlertType.PORT_SCAN, severity=AlertSeverity.HIGH, title="scan",
                          description="d", src_ip="5.188.10.7", dst_ip="10.0.0.1",
                          timestamp=datetime.utcnow(), alert_metadata={"unique_ports": 40})
    db.add(alert)
    db.commit()
    data = alert.alert_metadata["enrichment"]
    assert alert.alert_metadata["unique_ports"] == 40
    assert data["mitre"][0]["id"] == "T1046"
    assert data["src"] == {"ip": "5.188.10.7", "country": "NL", "country_name": "Netherlands", "asn": 64500,
                           "as_org": "Example Hosting", "threat_lists": ["firehol_level1"]}
    assert data["dst"] == {"ip": "10.0.0.1", "scope": "not public"}


def test_ipv6_and_unknown_addresses(lists, geoip):
    assert enricher.address("2a0e:fd80::5")["country"] == "DE"
    unknown = enricher.address("9.9.9.9")
    assert unknown == {"ip": "9.9.9.9", "threat_lists": []}  # nothing known, nothing made up
    assert enricher.address("not an ip") is None


def test_missing_databases_are_fine(lists, monkeypatch):
    monkeypatch.setattr(settings, "geoip_country_db", "/nonexistent.mmdb")
    monkeypatch.setattr(settings, "geoip_asn_db", "/nonexistent.mmdb")
    assert enricher.address("5.188.10.7") == {"ip": "5.188.10.7", "threat_lists": ["firehol_level1"]}


def test_scan_shows_country_list_and_technique_in_the_api(lists, geoip, fake_kernel, collect, client):
    fake_kernel.write([make_event(src_ip="5.188.10.7", dst_port=1000 + p) for p in range(30)])
    collect()
    item = client.get("/api/alerts/").json()["items"][0]
    enrichment = item["metadata"]["enrichment"]
    src = enrichment["src"]
    assert (src["country"], src["threat_lists"]) == ("NL", ["firehol_level1"])
    assert enrichment["mitre"][0]["id"] == "T1046"
    health = client.get("/api/health/detailed").json()["services"]["enrichment"]
    assert health["geoip"] == {"country": True, "asn": True}
    assert health["threat_lists"] == {"firehol_level1": 5, "spamhaus_drop": 2}


def test_enrichment_failure_never_loses_the_alert(db, monkeypatch):
    def broken(alert):
        raise RuntimeError("boom")
    monkeypatch.setattr(enricher, "enrich", broken)
    alert = SecurityAlert(alert_type=AlertType.PORT_SCAN, severity=AlertSeverity.LOW, title="t",
                          description="d", timestamp=datetime.utcnow())
    db.add(alert)
    db.commit()
    assert alert.id is not None


@pytest.fixture
def list_server(tmp_path):
    served = tmp_path / "served"
    served.mkdir()
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(served))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield served, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_update_downloads_and_keeps_old_copies_on_failure(tmp_path, list_server):
    served, base = list_server
    (served / "drop.txt").write_text(SPAMHAUS)
    (served / "empty.txt").write_text("; nothing here\n")
    target = tmp_path / "lists"
    urls = {"spamhaus_drop": f"{base}/drop.txt"}
    assert update(urls=urls, directory=str(target)) == {"spamhaus_drop": "ok: 2 networks"}
    assert (target / "spamhaus_drop.txt").read_text() == SPAMHAUS

    broken = {"spamhaus_drop": f"{base}/empty.txt"}
    assert "no addresses" in update(urls=broken, directory=str(target))["spamhaus_drop"]
    missing = {"spamhaus_drop": f"{base}/gone.txt"}
    assert "404" in update(urls=missing, directory=str(target))["spamhaus_drop"]
    assert (target / "spamhaus_drop.txt").read_text() == SPAMHAUS  # previous copy kept
    assert [p.name for p in target.iterdir()] == ["spamhaus_drop.txt"]  # no temp files left
