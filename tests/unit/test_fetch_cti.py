"""Tests for the CTI fetch-and-build helper in tools/fetch_cti.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).parents[2] / "tools" / "fetch_cti.py"
_spec = importlib.util.spec_from_file_location("fetch_cti", _PATH)
assert _spec and _spec.loader
fetch_cti = importlib.util.module_from_spec(_spec)
# Register before executing so the module's dataclass can resolve its own module.
sys.modules["fetch_cti"] = fetch_cti
_spec.loader.exec_module(fetch_cti)


class TestFeedRegistry:
    def test_every_feed_has_a_known_role_and_format(self) -> None:
        builder_formats = {"dshield", "cidr", "zeek"}
        for feed in fetch_cti.FEEDS.values():
            assert feed.role in {"denylist", "zeek", "bluedot-tor"}
            assert feed.format in builder_formats

    def test_defaults_point_at_real_feeds(self) -> None:
        for name in (
            *fetch_cti.DEFAULT_DENYLIST,
            *fetch_cti.DEFAULT_ZEEK,
            *fetch_cti.DEFAULT_BLUEDOT_TOR,
        ):
            assert name in fetch_cti.FEEDS

    def test_list_runs_cleanly(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert fetch_cti.main(["--list"]) == 0
        assert "dshield" in capsys.readouterr().out


class TestBuildTable:
    def test_merges_feeds_and_forwards_to_the_builder(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Two denylist feeds, canned instead of downloaded.
        monkeypatch.setattr(
            fetch_cti,
            "fetch",
            lambda url: {
                fetch_cti.FEEDS["dshield"].url: [
                    "64.62.156.0\t64.62.156.255\t24\t1\tAS\tUS\tx"
                ],
                fetch_cti.FEEDS["feodotracker"].url: ["8.8.8.8"],
            }[url],
        )

        captured: dict[str, object] = {}

        class FakeBuilder:
            parse_feed = staticmethod(fetch_cti._load_builder().parse_feed)

            @staticmethod
            def build_mmdb(entries, output, database_type):  # type: ignore[no-untyped-def]
                items = list(entries)
                captured["entries"] = items
                captured["database_type"] = database_type
                return len(items)

        monkeypatch.setattr(fetch_cti, "_load_builder", lambda: FakeBuilder)

        count = fetch_cti.build_table(
            ["dshield", "feodotracker"], tmp_path / "denylist.mmdb", "sagan-denylist"
        )
        assert count == 2
        assert captured["database_type"] == "sagan-denylist"
        assert ("64.62.156.0/24", "dshield") in captured["entries"]  # type: ignore[operator]
        assert ("8.8.8.8/32", "feodotracker") in captured["entries"]  # type: ignore[operator]

    def test_no_flags_skip_each_role(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            fetch_cti,
            "build_table",
            lambda feeds, output, dbtype: calls.append(dbtype) or 0,
        )
        # --no-zeek skips only the Zeek table; denylist and the Bluedot Tor
        # category still build, each of the others suppressible on its own.
        assert fetch_cti.main(["--no-zeek", "--output-dir", "/tmp"]) == 0
        assert calls == ["sagan-denylist", "sagan-bluedot-tor"]

    def test_no_bluedot_tor_skips_only_that_table(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            fetch_cti,
            "build_table",
            lambda feeds, output, dbtype: calls.append(dbtype) or 0,
        )
        assert (
            fetch_cti.main(
                [
                    "--no-denylist",
                    "--no-zeek",
                    "--no-bluedot-tor",
                    "--output-dir",
                    "/tmp",
                ]
            )
            == 0
        )
        assert calls == []
