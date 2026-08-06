"""Tests for inventory rendering and its commit pinning."""

from __future__ import annotations

import json

from sagan2sigma.inventory.classify import classify
from sagan2sigma.inventory.render import (
    Corpus,
    Provenance,
    render_json,
    render_markdown,
)

from .conftest import candidate, conceptual_report, overlap_report, verdict

PROVENANCE = Provenance(
    generated="2026-08-06",
    sagan=Corpus(
        name="sagan-rules",
        url="https://github.com/quadrantsec/sagan-rules.git",
        commit="142303c749801b4882b73a36e94e8d76f79e7500",
        committed="2026-08-05T14:53:40-04:00",
    ),
    sigmahq=Corpus(
        name="SigmaHQ",
        url="https://github.com/SigmaHQ/sigma.git",
        commit="8eaafff1f2845a696050e05e72ba1140ee190698",
        committed="2026-08-05T10:52:16+02:00",
    ),
    engine_version="0.21.0",
    profile="rsigma-syslog",
)


def _entries():
    return classify(
        overlap_report(
            verdict("a", "x", "SAGAN_REDUNDANT"),
            verdict("b", "y", "SAGAN_REDUNDANT", compatible=False),
        ),
        conceptual_report(candidate("a", "x", 0.6), candidate("c", "z", 0.4)),
    )


def test_markdown_pins_both_commits_and_warns_of_staleness() -> None:
    text = render_markdown(_entries(), PROVENANCE)
    assert "142303c749801b4882b73a36e94e8d76f79e7500" in text
    assert "8eaafff1f2845a696050e05e72ba1140ee190698" in text
    assert "point-in-time snapshot" in text
    # No stray blockquote marker mid-sentence.
    assert "The > pairs" not in text
    # The confidence legend is present with tier names.
    assert "Confirmed by both analyses" in text
    assert "grounds to retire a rule" in text


def test_markdown_is_deterministic() -> None:
    assert render_markdown(_entries(), PROVENANCE) == render_markdown(
        _entries(), PROVENANCE
    )


def test_json_carries_corpora_commits_and_entries() -> None:
    payload = json.loads(render_json(_entries(), PROVENANCE))
    assert payload["corpora"]["sagan_rules"]["commit"].startswith("142303c7")
    assert payload["corpora"]["sigmahq"]["commit"].startswith("8eaafff1")
    assert len(payload["entries"]) == len(_entries())
    # A tested entry keeps its witness for replay.
    tested = [e for e in payload["entries"] if e["relation"]]
    assert tested and tested[0]["witness_event"] == {"EventID": 4625}
