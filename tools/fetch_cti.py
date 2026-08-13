#!/usr/bin/env python3
r"""Fetch public threat-intel feeds and build the MMDBs the enriched profile reads.

Run this before starting the ``vector-enriched`` pipeline, so the
``sagan_denylist`` and ``sagan_zeek_intel`` enrichment tables have data: it
downloads the feeds and builds them into MMDBs with ``build_denylist_mmdb.py``.

The feeds are the public sources Sagan's own docs point at, plus a CC0
alternative. Their licences differ, and you are fetching them here for your own
use, which is not the same as redistributing them, so all of them are available:

    dshield                 SANS DShield block.txt              denylist  CC BY-NC-SA
    feodotracker            abuse.ch Feodo Tracker (aggressive) denylist  CC0
    criticalpath-threatfox  CriticalPathSecurity ThreatFox IPs  zeek      MIT code
    criticalpath-cobaltstrike  CriticalPathSecurity CobaltStrike zeek     MIT code

Review each feed's terms before relying on it. Building the MMDBs needs
``mmdb-writer`` (``pip install "sagan2sigma[cti]"``); fetching needs only the
library.

Usage::

    pip install "sagan2sigma[cti]"
    # Recommended defaults: DShield -> denylist.mmdb, ThreatFox -> zeek-intel.mmdb
    python tools/fetch_cti.py --output-dir /etc/vector

    # Only a CC0 denylist, no Zeek feed
    python tools/fetch_cti.py --denylist-feed feodotracker --no-zeek --output-dir out

    python tools/fetch_cti.py --list
"""

from __future__ import annotations

import argparse
import importlib.util
import urllib.request
from dataclasses import dataclass
from pathlib import Path

_BUILDER_PATH = Path(__file__).with_name("build_denylist_mmdb.py")


def _load_builder():
    """Load the sibling ``build_denylist_mmdb`` module by path."""
    spec = importlib.util.spec_from_file_location("build_denylist_mmdb", _BUILDER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Feed:
    """A known public feed: where to get it, how to parse it, what it feeds."""

    url: str
    format: str
    role: str  # "denylist" or "zeek"
    licence: str


#: Public feeds this script knows how to fetch and parse.
FEEDS: dict[str, Feed] = {
    "dshield": Feed(
        "https://feeds.dshield.org/block.txt", "dshield", "denylist", "CC BY-NC-SA"
    ),
    "feodotracker": Feed(
        "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        "cidr",
        "denylist",
        "CC0",
    ),
    "criticalpath-threatfox": Feed(
        "https://raw.githubusercontent.com/CriticalPathSecurity/"
        "Zeek-Intelligence-Feeds/master/abuse-ch-threatfox-ip.intel",
        "zeek",
        "zeek",
        "MIT code, mixed data",
    ),
    "criticalpath-cobaltstrike": Feed(
        "https://raw.githubusercontent.com/CriticalPathSecurity/"
        "Zeek-Intelligence-Feeds/master/cobaltstrike_ips.intel",
        "zeek",
        "zeek",
        "MIT code, mixed data",
    ),
}

#: Sensible defaults, the sources Sagan's docs recommend for each role.
DEFAULT_DENYLIST = ("dshield",)
DEFAULT_ZEEK = ("criticalpath-threatfox",)


def fetch(url: str) -> list[str]:
    """Download a feed and return its lines. Overridable in tests."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "sagan2sigma-fetch-cti"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", "replace").splitlines()


def build_table(feed_names: list[str], output: Path, database_type: str) -> int:
    """Fetch and merge feeds into one MMDB, returning the network count."""
    builder = _load_builder()
    entries: list[tuple[str, str]] = []
    for name in feed_names:
        feed = FEEDS[name]
        entries.extend(builder.parse_feed(fetch(feed.url), feed.format, name))
    return builder.build_mmdb(entries, output, database_type)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--denylist-feed",
        action="append",
        choices=sorted(FEEDS),
        metavar="NAME",
        help=f"feed(s) for denylist.mmdb (default: {', '.join(DEFAULT_DENYLIST)})",
    )
    parser.add_argument(
        "--zeek-feed",
        action="append",
        choices=sorted(FEEDS),
        metavar="NAME",
        help=f"feed(s) for zeek-intel.mmdb (default: {', '.join(DEFAULT_ZEEK)})",
    )
    parser.add_argument("--no-denylist", action="store_true", help="skip the denylist")
    parser.add_argument("--no-zeek", action="store_true", help="skip the Zeek feed")
    parser.add_argument(
        "--output-dir", type=Path, default=Path(), help="where to write the MMDBs"
    )
    parser.add_argument(
        "--list", action="store_true", help="list the known feeds and exit"
    )
    args = parser.parse_args(argv)

    if args.list:
        for name, feed in sorted(FEEDS.items()):
            print(f"{name:26} {feed.role:9} {feed.licence:24} {feed.url}")
        return 0

    if not args.no_denylist:
        feeds = args.denylist_feed or list(DEFAULT_DENYLIST)
        output = args.output_dir / "denylist.mmdb"
        count = build_table(feeds, output, "sagan-denylist")
        print(f"denylist: {count} networks from {', '.join(feeds)} -> {output}")

    if not args.no_zeek:
        feeds = args.zeek_feed or list(DEFAULT_ZEEK)
        output = args.output_dir / "zeek-intel.mmdb"
        count = build_table(feeds, output, "sagan-zeek-intel")
        print(f"zeek-intel: {count} networks from {', '.join(feeds)} -> {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
