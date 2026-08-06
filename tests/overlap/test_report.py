"""Tests for report rendering, driven by a hand-built analysis result."""

from __future__ import annotations

import json

from sagan2sigma.overlap.analysis import AnalysisResult, Relation, Verdict
from sagan2sigma.overlap.report import build_json, render_json, render_markdown


def _verdict(
    relation: Relation,
    sid: str = "5000001",
    events: int = 4,
    logsource_compatible: bool = True,
) -> Verdict:
    return Verdict(
        sagan_key=f"sagan:{sid}",
        sagan_sid=sid,
        sagan_title="Converted rule about pipes | and newlines\n",
        sagan_source_file="web-attack.rules",
        sigmahq_key="sigmahq:abc",
        sigmahq_title="SigmaHQ rule",
        sigmahq_path="rules/windows/web.yml",
        relation=relation,
        sagan_events=events,
        sagan_events_firing_sigmahq=events,
        sigmahq_events=4,
        sigmahq_events_firing_sagan=1,
        witness={"EventID": 4625, "CommandLine": "zqwhoamizq"},
        logsource_compatible=logsource_compatible,
        sigmahq_coverage_breadth=2,
    )


def _result() -> AnalysisResult:
    return AnalysisResult(
        verdicts=[
            _verdict(Relation.SAGAN_REDUNDANT, "5000001"),
            _verdict(Relation.EQUIVALENT, "5000002"),
            _verdict(Relation.SAGAN_BROADER, "5000003"),
            _verdict(Relation.OVERLAP, "5000004"),
            # A covering co-firing across incompatible log sources: recorded,
            # but not counted as actionable coverage.
            _verdict(Relation.SAGAN_REDUNDANT, "5000005", logsource_compatible=False),
        ],
        sagan_total=100,
        sigmahq_total=200,
        sagan_usable=90,
        sigmahq_usable=180,
        sagan_unsynthesisable=["sagan:x"],
        sigmahq_unsynthesisable=["sigmahq:y"],
        sagan_uncompilable=["sagan:z"],
        sigmahq_blanket=["sigmahq:blanket"],
        events_evaluated=720,
    )


def test_markdown_has_all_sections() -> None:
    text = render_markdown(_result())
    assert "# Overlap with SigmaHQ" in text
    assert "## Converted rules SigmaHQ already covers" in text
    assert "## Where the overlap sits" in text
    assert "## Evidence" in text
    assert "## What this analysis cannot say" in text
    # The headline counts only log-source-compatible covered verdicts.
    assert "2 converted rules are fully covered" in text
    # The cross-log-source co-firing is reported but not counted.
    assert "1 covering co-firings were found across incompatible log sources" in text
    # The blanket-matcher exclusion is surfaced in the limits.
    assert "Absence matchers excluded" in text


def test_markdown_escapes_pipes_and_newlines() -> None:
    text = render_markdown(_result())
    # A title carrying a pipe must not break the table.
    assert "pipes \\| and newlines" in text
    assert "and newlines\n |" not in text


def test_markdown_handles_empty_result() -> None:
    text = render_markdown(AnalysisResult(sagan_total=1, sigmahq_total=1))
    assert "# Overlap with SigmaHQ" in text
    # No verdicts, so the coverage table is omitted entirely.
    assert "## Converted rules SigmaHQ already covers" not in text


def test_json_round_trips_and_carries_witness() -> None:
    payload = build_json(_result())
    assert payload["summary"]["sagan_rules_covered"] == 2
    assert payload["summary"]["cross_logsource_covered"] == 1
    assert payload["verdicts"][0]["logsource_compatible"] in (True, False)
    assert payload["excluded"]["sagan_uncompilable"] == ["sagan:z"]
    first = payload["verdicts"][0]
    assert first["witness_event"] == {"EventID": 4625, "CommandLine": "zqwhoamizq"}
    # render_json must produce valid JSON.
    assert json.loads(render_json(_result()))["schema_version"] == 1


def test_coverage_table_truncates(monkeypatch) -> None:
    from sagan2sigma.overlap import report as report_module

    monkeypatch.setattr(report_module, "MAX_ROWS", 2)
    verdicts = [
        _verdict(Relation.SAGAN_REDUNDANT, f"500000{i}", events=4 - (i % 3))
        for i in range(5)
    ]
    result = AnalysisResult(verdicts=verdicts, sagan_total=5, sigmahq_total=5)
    text = render_markdown(result)
    assert "more, see the JSON report" in text
