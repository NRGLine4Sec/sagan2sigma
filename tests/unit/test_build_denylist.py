"""Tests for the denylist MMDB builder in tools/build_denylist_mmdb.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).parents[2] / "tools" / "build_denylist_mmdb.py"
_spec = importlib.util.spec_from_file_location("build_denylist_mmdb", _PATH)
assert _spec and _spec.loader
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)


class TestFeedParsers:
    def test_dshield_uses_start_ip_and_netmask(self) -> None:
        line = "64.62.156.0\t64.62.156.255\t24\t348\tHURRICANE\tUS\tabuse@he.net"
        assert list(builder.parse_dshield([line], "dshield")) == [
            ("64.62.156.0/24", "dshield")
        ]

    def test_dshield_skips_comments_and_short_lines(self) -> None:
        lines = ["# header", "", "1.2.3.0\tonly-two-fields"]
        assert list(builder.parse_dshield(lines, "dshield")) == []

    def test_zeek_takes_only_addr_indicators(self) -> None:
        lines = [
            "#fields\tindicator\tindicator_type\tmeta.source",
            "106.12.219.245\tIntel::ADDR\tCobaltStrike",
            "evil.example.com\tIntel::DOMAIN\tsource",
            "deadbeef\tIntel::FILE_HASH\tsource",
        ]
        assert list(builder.parse_zeek(lines, "cobalt")) == [
            ("106.12.219.245/32", "cobalt")
        ]

    def test_cidr_handles_comments_bare_ips_and_ranges(self) -> None:
        lines = ["# c", "1.2.3.0/24", "8.8.8.8", "garbage", "2001:db8::/32"]
        assert list(builder.parse_cidr(lines, "t")) == [
            ("1.2.3.0/24", "t"),
            ("8.8.8.8/32", "t"),
            ("2001:db8::/32", "t"),
        ]


@pytest.mark.skipif(
    importlib.util.find_spec("mmdbwriter") is None,
    reason="pip install mmdbwriter to test the MMDB build",
)
class TestBuildMmdb:
    def test_built_database_answers_lookups(self, tmp_path: Path) -> None:
        import maxminddb

        out = tmp_path / "denylist.mmdb"
        entries = [("64.62.156.0/24", "dshield"), ("203.0.113.7/32", "test")]
        count = builder.build_mmdb(entries, out, "sagan-denylist-test")
        assert count == 2

        reader = maxminddb.open_database(str(out))
        # A host inside a /24 resolves by longest-prefix; an unlisted one does not.
        assert reader.get("64.62.156.42") is not None
        assert reader.get("203.0.113.7") is not None
        assert reader.get("8.8.8.8") is None
