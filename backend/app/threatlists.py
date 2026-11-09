"""
Fetch the bad-IP lists in THREAT_LIST_URLS into THREAT_LISTS_DIR (roadmap S6.3):

    python -m app.threatlists update            # every configured list
    python -m app.threatlists update spamhaus_drop
    python -m app.threatlists status            # what is loaded

A download replaces a list only if it parses to at least one address, and
the file is swapped in atomically, so a failed or truncated download keeps
the previous copy. The backend notices new files within a minute. Run it
daily (cron, or THREAT_LIST_UPDATE_HOURS=24 to let the backend do it).
"""

import argparse
import logging
import os
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from .config import settings
from .services.enrichment import ThreatLists

logger = logging.getLogger(__name__)

MAX_BYTES = 50_000_000


def fetch(name: str, url: str, directory: Path, timeout: float = 60) -> int:
    """Download one list; returns how many networks it holds. Raises on failure."""
    request = urllib.request.Request(url, headers={"User-Agent": "kguard-threatlists/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("larger than 50 MB")
    count = len(ThreatLists.parse(data.decode("utf-8", errors="replace")))
    if not count:
        raise ValueError("no addresses in it")
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, directory / f"{name}.txt")
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return count


def update(only: Optional[list] = None, urls: Dict[str, str] = None, directory: str = None) -> Dict[str, str]:
    urls = urls if urls is not None else settings.threat_list_urls
    target = Path(directory or settings.threat_lists_dir)
    results = {}
    for name, url in urls.items():
        if only and name not in only:
            continue
        try:
            results[name] = f"ok: {fetch(name, url, target)} networks"
            logger.info("Threat list updated", extra={"list": name, "result": results[name]})
        except Exception as e:
            results[name] = f"failed: {e}"
            logger.error(f"Threat list {name} not updated (kept the previous copy): {e}")
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.threatlists")
    sub = parser.add_subparsers(dest="command", required=True)
    up = sub.add_parser("update")
    up.add_argument("names", nargs="*")
    sub.add_parser("status")
    args = parser.parse_args(argv)
    if args.command == "status":
        lists = ThreatLists()
        lists.refresh(force=True)
        for name, size in sorted(lists.sizes.items()):
            print(f"{name:24} {size} networks")
        if not lists.sizes:
            print(f"no lists in {settings.threat_lists_dir}")
        return 0
    results = update(args.names or None)
    for name, result in results.items():
        print(f"{name:24} {result}")
    return 0 if results and all(r.startswith("ok") for r in results.values()) else 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    sys.exit(main())
