#!/usr/bin/env python3
"""Build the lab's tiny country database.

The checks and the corpus differential need a GeoIP database that answers the
same way every time, so the lab uses three networks and nothing else:

    5.5.5.0/24      RU
    8.8.8.0/24      US
    203.0.113.0/24  FR

Everything else is unknown, which is a case that has to be exercised too:
`country_code` compares nothing when the address cannot be placed, and reading
it the other way once made every private address match "connection from
outside $HOME_COUNTRY".

The file is generated rather than committed. A 700-byte binary blob in a
repository is something a reader can neither check nor rebuild, and this script
is both the recipe and the documentation of what the database contains.

The record shape is GeoIP2's, `country.iso_code`, which is what Sagan's
`GeoIP2_Lookup_Country` reads and what `data/vrl/sagan-geoip.vrl` looks up
first.

Needs `mmdb-writer` and `netaddr`, the same two the repository's
`tools/build_denylist_mmdb.py` uses:

    pip install mmdb-writer netaddr
    python lab/config/make-country-mmdb.py
"""

from __future__ import annotations

import argparse
from pathlib import Path

#: Network to ISO country code. Kept here rather than in a data file: three
#: entries are easier to read as code, and every check that depends on them
#: quotes this table in its own docstring.
NETWORKS = {
    "5.5.5.0/24": "RU",
    "8.8.8.0/24": "US",
    "203.0.113.0/24": "FR",
}

DEFAULT_OUTPUT = Path(__file__).resolve().parent / "country.mmdb"


def build(output: Path) -> int:
    """Write the database and return the number of networks in it."""
    from mmdb_writer import MMDBWriter
    from netaddr import IPSet

    # A v6 database with ipv4_compatible, as in tools/build_denylist_mmdb.py:
    # without it insert_network refuses v4 networks.
    writer = MMDBWriter(
        ip_version=6,
        database_type="GeoIP2-Country",
        languages=["en"],
        ipv4_compatible=True,
    )
    for network, iso in NETWORKS.items():
        writer.insert_network(IPSet([network]), {"country": {"iso_code": iso}})
    output.parent.mkdir(parents=True, exist_ok=True)
    writer.to_db_file(str(output))
    return len(NETWORKS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    count = build(args.output)
    print(f"{count} networks written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
