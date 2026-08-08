#!/usr/bin/env python3
r"""Build a MaxMind-format MMDB from a public IP feed, for Vector enrichment.

The ``blacklist`` and ``zeek-intel`` rules convert to a match on a field the
bundled ``sagan-denylist.vrl`` / ``sagan-zeek-intel.vrl`` transforms set when an
address is on a feed. Those transforms read a Vector ``mmdb`` enrichment table,
which does a longest-prefix network lookup, so the feed has to be an MMDB. This
script turns a feed into one.

It is deliberately format-aware rather than provider-locked, so any of the public
feeds works:

* ``dshield``  SANS DShield ``block.txt``: tab-separated
              ``start_ip  end_ip  netmask  count  as  country  email``. The
              network is ``start_ip/netmask``.
* ``cidr``    a plain list of IP or CIDR, one per line, ``#`` comments allowed.
              A bare address is treated as a ``/32`` (or ``/128``).
* ``zeek``    a Zeek Intelligence Framework file (for example from
              CriticalPathSecurity's Zeek-Intelligence-Feeds): tab-separated with
              an ``indicator`` and ``indicator_type`` column. Only
              ``Intel::ADDR`` rows are taken, since that is all the rule keyword
              tests.

Usage::

    python tools/build_denylist_mmdb.py --format dshield \\
        --feed block.txt --output /etc/vector/denylist.mmdb

    python tools/build_denylist_mmdb.py --format zeek \\
        --feed abuse-ch-threatfox-ip.intel --output /etc/vector/zeek-intel.mmdb

Multiple ``--feed`` files are merged. Building the MMDB needs ``mmdbwriter``
(``pip install mmdbwriter``); the feed parsers do not.
"""

from __future__ import annotations

import argparse
import ipaddress
from collections.abc import Iterable, Iterator
from pathlib import Path

#: A parsed feed entry: a network in CIDR text and the feed it came from.
Entry = tuple[str, str]


def _to_network(token: str) -> str | None:
    """Normalise an address or CIDR to a network string, or ``None`` if invalid."""
    token = token.strip()
    if not token:
        return None
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        return None


def parse_cidr(lines: Iterable[str], source: str) -> Iterator[Entry]:
    """Parse a plain IP/CIDR list, one entry per line, ``#`` comments allowed."""
    for line in lines:
        line = line.split("#", 1)[0].strip()
        network = _to_network(line)
        if network is not None:
            yield network, source


def parse_dshield(lines: Iterable[str], source: str) -> Iterator[Entry]:
    """Parse SANS DShield ``block.txt``: start, end, netmask, then metadata."""
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        network = _to_network(f"{fields[0].strip()}/{fields[2].strip()}")
        if network is not None:
            yield network, source


def parse_zeek(lines: Iterable[str], source: str) -> Iterator[Entry]:
    """Parse a Zeek Intel file, taking the ``Intel::ADDR`` indicators only."""
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 2 or fields[1].strip() != "Intel::ADDR":
            continue
        network = _to_network(fields[0])
        if network is not None:
            yield network, source


_PARSERS = {"dshield": parse_dshield, "cidr": parse_cidr, "zeek": parse_zeek}


def parse_feed(lines: Iterable[str], fmt: str, source: str) -> Iterator[Entry]:
    """Parse a feed in one of the supported formats."""
    return _PARSERS[fmt](lines, source)


def build_mmdb(entries: Iterable[Entry], output: Path, database_type: str) -> int:
    """Write ``entries`` into an MMDB and return the number of networks written.

    Each network maps to ``{"listed": true, "source": <feed>}``; the transform
    only checks that a record exists, so any non-empty value would do, but the
    source is kept for debugging.
    """
    from mmdbwriter import MMDBWriter
    from mmdbwriter.types import Boolean, Map, String

    writer = MMDBWriter(ip_version=6, database_type=database_type, languages=["en"])
    count = 0
    for network, source in entries:
        writer.insert_network(
            ipaddress.ip_network(network),
            Map(listed=Boolean(True), source=String(source)),
        )
        count += 1
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        writer.write(handle)
    return count


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--feed",
        action="append",
        required=True,
        type=Path,
        help="a feed file; repeatable, all merged into one database",
    )
    parser.add_argument(
        "--format", required=True, choices=sorted(_PARSERS), help="feed format"
    )
    parser.add_argument("--output", required=True, type=Path, help="output .mmdb")
    parser.add_argument(
        "--database-type",
        default="sagan-denylist",
        help="MMDB metadata database_type (default: sagan-denylist)",
    )
    args = parser.parse_args(argv)

    entries: list[Entry] = []
    for feed in args.feed:
        lines = feed.read_text(encoding="utf-8", errors="replace").splitlines()
        entries.extend(parse_feed(lines, args.format, feed.stem))

    count = build_mmdb(entries, args.output, args.database_type)
    print(f"wrote {count} networks from {len(args.feed)} feed(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
