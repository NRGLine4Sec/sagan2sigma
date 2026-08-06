"""Tests for the synthesised-event cache."""

from __future__ import annotations

from pathlib import Path

from sagan2sigma.overlap import cache as cache_module
from sagan2sigma.overlap.cache import SynthesisCache

from .conftest import make_record

EVENTS = [{"EventID": 4625, "CommandLine": "zqadminzq"}]


def test_disabled_cache_is_a_no_op() -> None:
    cache = SynthesisCache(None)
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"})
    cache.store(record, 4, EVENTS)  # must not raise
    assert cache.load(record, 4) is None
    assert cache.hits == 0
    assert cache.misses == 0


def test_round_trip(tmp_path: Path) -> None:
    cache = SynthesisCache(tmp_path)
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"})
    assert cache.load(record, 4) is None
    cache.store(record, 4, EVENTS)
    assert cache.load(record, 4) == EVENTS
    assert cache.hits == 1
    assert cache.misses == 1


def test_key_depends_on_detection_not_id(tmp_path: Path) -> None:
    cache = SynthesisCache(tmp_path)
    detection = {"sel": {"EventID": 7}, "condition": "sel"}
    first = make_record(detection, rule_id="aaaaaaaa-0000-4000-8000-000000000000")
    second = make_record(detection, rule_id="bbbbbbbb-0000-4000-8000-000000000000")
    cache.store(first, 4, EVENTS)
    # A different id but the same detection block hits the same entry.
    assert cache.load(second, 4) == EVENTS


def test_limit_is_part_of_the_key(tmp_path: Path) -> None:
    cache = SynthesisCache(tmp_path)
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"})
    cache.store(record, 4, EVENTS)
    assert cache.load(record, 8) is None


def test_origin_is_part_of_the_key(tmp_path: Path) -> None:
    cache = SynthesisCache(tmp_path)
    detection = {"sel": {"EventID": 1}, "condition": "sel"}
    sagan = make_record(detection, origin="sagan")
    sigmahq = make_record(detection, origin="sigmahq")
    cache.store(sagan, 4, EVENTS)
    assert cache.load(sigmahq, 4) is None


def test_algorithm_version_invalidates(tmp_path: Path, monkeypatch) -> None:
    cache = SynthesisCache(tmp_path)
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"})
    cache.store(record, 4, EVENTS)
    monkeypatch.setattr(cache_module, "ALGORITHM_VERSION", 999)
    assert cache.load(record, 4) is None


def test_corrupt_entry_is_a_miss(tmp_path: Path) -> None:
    cache = SynthesisCache(tmp_path)
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"})
    path = cache._path(record, 4)
    path.write_text("not json at all", encoding="utf-8")
    assert cache.load(record, 4) is None
    assert cache.misses == 1


def test_entry_without_events_list_is_a_miss(tmp_path: Path) -> None:
    cache = SynthesisCache(tmp_path)
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"})
    path = cache._path(record, 4)
    path.write_text('{"key": "x"}', encoding="utf-8")
    assert cache.load(record, 4) is None


def test_store_handles_date_values(tmp_path: Path) -> None:
    import datetime

    cache = SynthesisCache(tmp_path)
    # SigmaHQ documents carry date objects; the detection hash must survive them.
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"})
    record.document["date"] = datetime.date(2024, 1, 1)
    cache.store(record, 4, EVENTS)
    assert cache.load(record, 4) == EVENTS
