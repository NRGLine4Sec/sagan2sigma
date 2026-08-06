"""Invariants that validate the trustworthiness of a verdict, not just the code.

These are the tests that let a reader believe the report without re-deriving it.
Each one asserts a property the analysis promises but that the per-construct and
unit tests do not, in isolation, prove:

* every covering verdict's witness event, replayed independently, fires both
  rules, which is the central promise the tool makes;
* the single-pass batch tells the same truth as evaluating each event on its
  own, which is what the sentinel technique claims;
* the four-way classification, including OVERLAP and the "every event" boundary
  between coverage and overlap, lands where it should;
* the analysis is deterministic.

All of them need the real engine and are skipped without it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sagan2sigma.overlap.analysis import Relation, RuleRecord, analyse
from sagan2sigma.overlap.engine import RsigmaBatch

from .conftest import make_document, make_record, needs_engine


def _fires(document: dict[str, Any], event: dict[str, Any], workdir: Path) -> bool:
    """Whether one rule, evaluated alone, fires on one event."""
    matched = RsigmaBatch([document], workdir=workdir).evaluate([event])[0]
    return str(document["id"]) in matched


@needs_engine
def test_every_covering_witness_fires_both_rules(tmp_path: Path) -> None:
    """The core promise: a coverage witness triggers both rules, independently.

    The witness is replayed against each rule on its own, not through the batch,
    so this also guards against a witness chosen by a segmentation bug.
    """
    sagan = [
        # Redundant: EventID plus an extra condition, so SigmaHQ (EventID alone)
        # covers it.
        make_record(
            {
                "sel": {"EventID": 4625, "CommandLine|contains": "whoami"},
                "condition": "sel",
            },
            origin="sagan",
        ),
        # Equivalent: identical to a SigmaHQ rule below.
        make_record({"sel": {"EventID": 4688}, "condition": "sel"}, origin="sagan"),
    ]
    sigmahq = [
        make_record({"sel": {"EventID": 4625}, "condition": "sel"}, origin="sigmahq"),
        make_record({"sel": {"EventID": 4688}, "condition": "sel"}, origin="sigmahq"),
    ]
    result = analyse(sagan, sigmahq, workdir=tmp_path)

    documents = {r.key: r.document for r in sagan + sigmahq}
    covering = [
        v
        for v in result.verdicts
        if v.relation in (Relation.EQUIVALENT, Relation.SAGAN_REDUNDANT)
    ]
    assert covering, "expected at least one covering verdict to check"
    for index, verdict in enumerate(covering):
        work = tmp_path / f"witness-{index}"
        assert _fires(documents[verdict.sagan_key], verdict.witness, work / "a"), (
            f"witness does not fire the converted rule for {verdict.sagan_sid}"
        )
        assert _fires(documents[verdict.sigmahq_key], verdict.witness, work / "b"), (
            f"witness does not fire the SigmaHQ rule for {verdict.sagan_sid}"
        )


@needs_engine
def test_partial_firing_is_overlap_not_coverage(tmp_path: Path) -> None:
    """Two rules that fire together on some events but neither contains the other.

    Converted matches EventID 1 or 2, SigmaHQ matches EventID 2 or 3. They share
    the EventID 2 event, but each fires on an event the other misses, so the
    relation must be OVERLAP, never a coverage verdict.
    """
    sagan = make_record(
        {"a": {"EventID": 1}, "b": {"EventID": 2}, "condition": "a or b"},
        origin="sagan",
    )
    sigmahq = make_record(
        {"c": {"EventID": 2}, "d": {"EventID": 3}, "condition": "c or d"},
        origin="sigmahq",
    )
    result = analyse([sagan], [sigmahq], workdir=tmp_path)
    relations = {v.relation for v in result.verdicts}
    assert relations == {Relation.OVERLAP}
    # And nothing is reported as covered.
    assert result.redundant_sagan_keys == set()


@needs_engine
def test_partial_firing_is_never_reported_as_coverage(tmp_path: Path) -> None:
    """The "every event" boundary: coverage requires all of a rule's events.

    The converted rule fires on two distinct events (EventID 10 or 11); only one
    of them fires the SigmaHQ rule (EventID 10). Coverage requires all of them,
    so the converted rule must not be reported as covered, whatever else the
    pair is classified as. Here the SigmaHQ rule is in fact contained by the
    converted one, so the relation is SAGAN_BROADER, which is the opposite of
    coverage.
    """
    sagan = make_record(
        {"a": {"EventID": 10}, "b": {"EventID": 11}, "condition": "a or b"},
        origin="sagan",
    )
    sigmahq = make_record(
        {"sel": {"EventID": 10}, "condition": "sel"}, origin="sigmahq"
    )
    result = analyse([sagan], [sigmahq], workdir=tmp_path)
    verdicts = [v for v in result.verdicts if v.sigmahq_key == sigmahq.key]
    assert verdicts
    assert verdicts[0].relation not in (Relation.EQUIVALENT, Relation.SAGAN_REDUNDANT)
    assert sagan.key not in result.redundant_sagan_keys


@needs_engine
def test_batch_agrees_with_independent_single_event_eval(tmp_path: Path) -> None:
    """The sentinel technique tells the same truth as one event at a time.

    A single batch pass over several events is cross-checked against evaluating
    each event on its own against the same rule set. Any misattribution from the
    interleaved sentinels, or any contamination from a rule firing on the marker
    events, would show up as a disagreement here.
    """
    documents = [
        make_document(
            {"sel": {"EventID": 4625}, "condition": "sel"},
            rule_id="aaaaaaaa-0000-4000-8000-000000000001",
        ),
        make_document(
            {"sel": {"CommandLine|contains": "whoami"}, "condition": "sel"},
            rule_id="aaaaaaaa-0000-4000-8000-000000000002",
        ),
        make_document(
            {"a": {"EventID": 1}, "b": {"EventID": 2}, "condition": "a or b"},
            rule_id="aaaaaaaa-0000-4000-8000-000000000003",
        ),
    ]
    events: list[dict[str, Any]] = [
        {"EventID": 4625},
        {"CommandLine": "ran whoami now"},
        {"EventID": 1},
        {"unrelated": "nothing matches this"},
        {"EventID": 4625, "CommandLine": "whoami"},  # fires two rules at once
    ]
    batch = RsigmaBatch(documents, workdir=tmp_path / "batch")
    combined = batch.evaluate(events)

    for index, event in enumerate(events):
        alone = RsigmaBatch(documents, workdir=tmp_path / f"alone-{index}").evaluate(
            [event]
        )[0]
        assert combined[index] == alone, (
            f"batch and single-event eval disagree on event {index}: "
            f"{combined[index]} vs {alone}"
        )


@needs_engine
def test_analysis_is_deterministic(tmp_path: Path) -> None:
    """Two runs over the same corpora produce the same verdicts in the same order."""

    def corpora() -> tuple[list[RuleRecord], list[RuleRecord]]:
        sagan = [
            make_record(
                {
                    "sel": {"EventID": 4625, "CommandLine|contains": "whoami"},
                    "condition": "sel",
                },
                origin="sagan",
                rule_id="bbbbbbbb-0000-4000-8000-000000000001",
            ),
            make_record(
                {"a": {"EventID": 1}, "b": {"EventID": 2}, "condition": "a or b"},
                origin="sagan",
                rule_id="bbbbbbbb-0000-4000-8000-000000000002",
            ),
        ]
        sigmahq = [
            make_record(
                {"sel": {"EventID": 4625}, "condition": "sel"},
                origin="sigmahq",
                rule_id="bbbbbbbb-0000-4000-8000-0000000000f1",
            ),
            make_record(
                {"c": {"EventID": 2}, "d": {"EventID": 3}, "condition": "c or d"},
                origin="sigmahq",
                rule_id="bbbbbbbb-0000-4000-8000-0000000000f2",
            ),
        ]
        return sagan, sigmahq

    def signature(workdir: Path) -> list[tuple[str, str, str]]:
        sagan, sigmahq = corpora()
        result = analyse(sagan, sigmahq, workdir=workdir)
        return [(v.sagan_key, v.sigmahq_key, v.relation.value) for v in result.verdicts]

    assert signature(tmp_path / "run-a") == signature(tmp_path / "run-b")
