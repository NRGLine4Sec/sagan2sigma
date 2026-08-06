"""Reporting for the conceptual analysis.

The report leads, and keeps leading, with what this is not. Its whole risk is
being mistaken for the behavioural analysis, so the framing is repeated rather
than stated once: these are candidates for a human to review, ranked by a
lexical score, and no rule should be retired on the strength of them. Each row
shows the shared distinctive terms and techniques that put the pair together, so
the reader judges the evidence, not the tool's confidence.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .analysis import build_json

if TYPE_CHECKING:  # pragma: no cover
    from .analysis import ConceptualResult

#: Rows listed in the Markdown before the rest are summarised. The JSON carries
#: everything.
MAX_ROWS = 400


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(result: ConceptualResult) -> str:
    """Render the human-facing candidate list, framing included."""
    lines = [
        "# Conceptual overlap with SigmaHQ (review candidates)",
        "",
        "**This is not the behavioural analysis, and its rows are not verdicts.** "
        "It pairs a converted rule with a SigmaHQ rule when they share distinctive "
        "search terms, and optionally ATT&CK techniques, which suggests they may "
        "be written to catch the same thing. It does **not** establish that they "
        "fire on the same event, and it is **not** grounds for retiring any rule. "
        "For that, see the behavioural analysis in `OVERLAP-REPORT.md`; a pair "
        "that appears in both is far stronger evidence than one that appears only "
        "here.",
        "",
        "Use this to triage: a reviewer reads a row, looks at the shared terms, "
        "and decides in seconds whether the two rules really are about the same "
        "detection.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Converted rules | {result.sagan_total} |",
        f"| SigmaHQ rules | {result.sigmahq_total} |",
        f"| Converted rules with at least one candidate | "
        f"{result.sagan_with_candidate} |",
        f"| Candidate pairs | {len(result.candidates)} |",
        f"| Lexical similarity floor | {result.min_lexical} |",
        f"| Candidates kept per converted rule | {result.top_k} |",
        "",
        "`Lexical` is the IDF-weighted cosine over the terms each rule searches "
        "for and its wording, from 0 to 1. `Tech` is the summed rarity of shared "
        "ATT&CK techniques, which reorders but never creates a candidate. "
        "`Shared terms` are the distinctive tokens behind the match, rarest "
        "first, and are the evidence to read.",
        "",
    ]
    lines += _table(result)
    return "\n".join(lines).rstrip() + "\n"


def _table(result: ConceptualResult) -> list[str]:
    if not result.candidates:
        return ["No candidates cleared the lexical floor.", ""]
    lines = [
        "## Candidate pairs, strongest first",
        "",
        "| Sagan SID | Converted rule | Candidate SigmaHQ rule | SigmaHQ path | "
        "Lexical | Tech | Shared terms |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for candidate in result.candidates[:MAX_ROWS]:
        techniques = (
            " ".join(candidate.shared_techniques) if candidate.shared_techniques else ""
        )
        terms = ", ".join(candidate.shared_terms)
        tech_cell = f"{candidate.technique_score:.1f}"
        if techniques:
            tech_cell += f" ({techniques})"
        lines.append(
            f"| `{candidate.sagan_sid}` | {_escape(candidate.sagan_title[:60])} | "
            f"{_escape(candidate.sigmahq_title[:60])} | "
            f"`{candidate.sigmahq_path}` | {candidate.lexical:.2f} | "
            f"{tech_cell} | {_escape(terms[:80])} |"
        )
    if len(result.candidates) > MAX_ROWS:
        lines.append(
            f"| ... | *{len(result.candidates) - MAX_ROWS} more, see the JSON "
            f"report* | | | | | |"
        )
    lines.append("")
    return lines


def render_json(result: ConceptualResult) -> str:
    """Serialise the machine-readable report."""
    payload: dict[str, Any] = build_json(result)
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"
