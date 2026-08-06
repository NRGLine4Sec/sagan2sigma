"""Tests for conceptual report rendering."""

from __future__ import annotations

import json

from sagan2sigma.conceptual.analysis import Candidate, ConceptualResult
from sagan2sigma.conceptual.report import render_json, render_markdown


def _candidate(sid: str = "5000001") -> Candidate:
    return Candidate(
        sagan_key=f"sagan:{sid}",
        sagan_sid=sid,
        sagan_title="[WINDOWS] Sticky Key Backdoor | note",
        sagan_source_file="windows-security.rules",
        sigmahq_key="sigmahq:abc",
        sigmahq_title="Sticky Key Like Backdoor Execution",
        sigmahq_path="rules/windows/x.yml",
        lexical=0.62,
        technique_score=5.4,
        composite=1.16,
        shared_terms=("sethc.exe", "utilman.exe"),
        shared_techniques=("t1546.008",),
    )


def _result() -> ConceptualResult:
    return ConceptualResult(
        candidates=[_candidate("5000001"), _candidate("5000002")],
        sagan_total=7911,
        sigmahq_total=4013,
        sagan_with_candidate=798,
    )


def test_markdown_leads_with_the_disclaimer() -> None:
    text = render_markdown(_result())
    assert "not the behavioural analysis" in text
    assert "grounds for retiring any rule" in text
    assert "review candidates" in text.lower()
    # The evidence column is present.
    assert "Shared terms" in text
    assert "sethc.exe" in text
    # A pipe in a title does not break the table.
    assert "Backdoor \\| note" in text


def test_markdown_empty() -> None:
    text = render_markdown(ConceptualResult(sagan_total=1, sigmahq_total=1))
    assert "No candidates cleared the lexical floor." in text


def test_json_valid_and_complete() -> None:
    payload = json.loads(render_json(_result()))
    assert payload["kind"] == "conceptual"
    assert payload["summary"]["candidates"] == 2
    assert payload["candidates"][0]["shared_terms"] == ["sethc.exe", "utilman.exe"]
