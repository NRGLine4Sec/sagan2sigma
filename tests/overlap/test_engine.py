"""Tests for the engine batch driver.

The sentinel segmentation is pure string handling and is tested directly on
crafted engine output. The end-to-end behaviour, that one invocation returns
aligned per-event match sets and that ``compilable`` isolates a bad rule, is
tested against the real engine and skipped when it is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sagan2sigma.overlap.engine import (
    SENTINEL_FIELD,
    SENTINEL_ID,
    EngineUnavailableError,
    RsigmaBatch,
    compilable,
    find_engine,
)

from .conftest import make_document, needs_engine


def _match(rule_id: str) -> str:
    return json.dumps({"rule_id": rule_id, "rule_title": "x"})


def _sentinel(index: int) -> str:
    return json.dumps(
        {
            "rule_id": SENTINEL_ID,
            "matched_fields": [{"field": SENTINEL_FIELD, "value": index}],
        }
    )


def test_find_engine_missing_raises() -> None:
    with pytest.raises(EngineUnavailableError):
        find_engine("/nonexistent/path/to/rsigma")


def test_segment_aligns_matches_to_events() -> None:
    stdout = "\n".join(
        [
            _match("rule-a"),
            _sentinel(0),
            # event 1 matched nothing
            _sentinel(1),
            _match("rule-a"),
            _match("rule-b"),
            _sentinel(2),
        ]
    )
    segmented = RsigmaBatch._segment(stdout, expected=3)
    assert segmented == [{"rule-a"}, set(), {"rule-a", "rule-b"}]


def test_segment_returns_empty_sets_for_unmatched_tail() -> None:
    # Only the first of three events produced any output line.
    stdout = "\n".join([_match("rule-a"), _sentinel(0)])
    segmented = RsigmaBatch._segment(stdout, expected=3)
    assert segmented == [{"rule-a"}, set(), set()]


def test_segment_ignores_noise_and_bad_json() -> None:
    stdout = "\n".join(
        ["not json", "", "  ", "{bad json", _match("rule-a"), _sentinel(0)]
    )
    segmented = RsigmaBatch._segment(stdout, expected=1)
    assert segmented == [{"rule-a"}]


def test_segment_ignores_out_of_range_sentinel() -> None:
    stdout = "\n".join([_match("rule-a"), _sentinel(99)])
    segmented = RsigmaBatch._segment(stdout, expected=1)
    # The sentinel index is out of range, so nothing is attributed.
    assert segmented == [set()]


# --- engine-backed --------------------------------------------------------


@needs_engine
def test_evaluate_returns_aligned_match_sets(tmp_path: Path) -> None:
    rule = make_document(
        {"sel": {"EventID": 4625}, "condition": "sel"},
        rule_id="dddddddd-0000-4000-8000-000000000001",
    )
    batch = RsigmaBatch([rule], workdir=tmp_path)
    matches = batch.evaluate([{"EventID": 4625}, {"EventID": 1}, {"EventID": 4625}])
    assert matches[0] == {"dddddddd-0000-4000-8000-000000000001"}
    assert matches[1] == set()
    assert matches[2] == {"dddddddd-0000-4000-8000-000000000001"}


@needs_engine
def test_evaluate_empty_events(tmp_path: Path) -> None:
    rule = make_document({"sel": {"EventID": 1}, "condition": "sel"})
    assert RsigmaBatch([rule], workdir=tmp_path).evaluate([]) == []


@needs_engine
def test_compilable_isolates_a_bad_rule(tmp_path: Path) -> None:
    good_one = make_document(
        {"sel": {"EventID": 1}, "condition": "sel"},
        rule_id="cccccccc-0000-4000-8000-000000000001",
    )
    good_two = make_document(
        {"sel": {"EventID": 2}, "condition": "sel"},
        rule_id="cccccccc-0000-4000-8000-000000000002",
    )
    # A lookahead: the Rust regex crate behind RSigma rejects it by design,
    # since it guarantees linear-time matching, while Python's re accepts it.
    bad = make_document(
        {"sel": {"CommandLine|re": "admin(?!istrator)"}, "condition": "sel"},
        rule_id="cccccccc-0000-4000-8000-0000000000bb",
    )
    good, refused = compilable([good_one, bad, good_two], workdir=tmp_path)
    good_ids = {doc["id"] for doc in good}
    refused_ids = {doc["id"] for doc in refused}
    assert refused_ids == {"cccccccc-0000-4000-8000-0000000000bb"}
    assert good_ids == {
        "cccccccc-0000-4000-8000-000000000001",
        "cccccccc-0000-4000-8000-000000000002",
    }
