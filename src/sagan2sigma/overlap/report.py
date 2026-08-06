"""Reporting for the overlap analysis.

Two audiences, two artefacts. The Markdown report is for deciding what to
deploy: it leads with the converted rules SigmaHQ already covers, because that
is the actionable list. The JSON report is untruncated and carries the witness
event behind every verdict, so a claim can be re-checked rather than trusted.

Every table states how many events a verdict rests on. A containment backed by
one event is weaker evidence than one backed by four, and hiding that
difference would be the easiest way to make this analysis look more certain
than it is.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any

from .analysis import RELATION_HELP, Relation

if TYPE_CHECKING:  # pragma: no cover
    from .analysis import AnalysisResult, Verdict

#: Rows past this point are summarised rather than listed, keeping the Markdown
#: readable. The JSON report is never truncated.
MAX_ROWS = 300


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _pct(part: int, total: int) -> str:
    return f"{100.0 * part / total:.1f}%" if total else "n/a"


def _summary(result: AnalysisResult) -> list[str]:
    counts = Counter(verdict.relation for verdict in result.verdicts)
    redundant = result.redundant_sagan_keys
    lines = [
        "# Overlap with SigmaHQ",
        "",
        "Which converted Sagan rules already have an equivalent in SigmaHQ, "
        "established by running both rule sets against events synthesised from "
        "each rule and evaluated by the RSigma engine.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Converted rules analysed | {result.sagan_total} |",
        f"| SigmaHQ rules analysed | {result.sigmahq_total} |",
        f"| Converted rules with a confirmed test event | {result.sagan_usable} "
        f"({_pct(result.sagan_usable, result.sagan_total)}) |",
        f"| SigmaHQ rules with a confirmed test event | {result.sigmahq_usable} "
        f"({_pct(result.sigmahq_usable, result.sigmahq_total)}) |",
        f"| Events evaluated | {result.events_evaluated} |",
        f"| Verdicts recorded | {len(result.verdicts)} |",
        "",
        "**Headline:** "
        f"{len(redundant)} converted rules are fully covered by a "
        "log-source-compatible SigmaHQ rule "
        f"({_pct(len(redundant), max(result.sagan_usable, 1))} of those testable). "
        "Deploying SigmaHQ makes them redundant.",
        "",
        f"A further {result.cross_logsource_covered} covering co-firings were "
        "found across incompatible log sources, typically a SigmaHQ keyword rule "
        "matching a common word in the raw body of a rule from another product. "
        "Those are recorded in the JSON report but are not counted here, because "
        "the SigmaHQ rule would not run on that product's logs in production.",
        "",
        "| Relation | Pairs | Meaning |",
        "| --- | ---: | --- |",
    ]
    for relation in Relation:
        lines.append(
            f"| `{relation.value}` | {counts.get(relation, 0)} | "
            f"{_escape(RELATION_HELP[relation])} |"
        )
    lines.append("")
    return lines


def _coverage_table(result: AnalysisResult) -> list[str]:
    covering = [
        verdict
        for verdict in result.verdicts
        if verdict.relation in (Relation.EQUIVALENT, Relation.SAGAN_REDUNDANT)
        and verdict.logsource_compatible
    ]
    if not covering:
        return []

    best: dict[str, Verdict] = {}
    for verdict in covering:
        current = best.get(verdict.sagan_key)
        if current is None or verdict.sagan_events > current.sagan_events:
            best[verdict.sagan_key] = verdict

    lines = [
        "## Converted rules SigmaHQ already covers",
        "",
        "Every event built from the converted rule also fires the SigmaHQ rule.",
        "These are the rules to drop if you deploy SigmaHQ.",
        "",
        "`Events` is how many distinct events back the verdict; `Breadth` is how "
        "many converted rules the same SigmaHQ rule covers, which flags a rule "
        "broad enough that the match may be less meaningful than it looks.",
        "",
        "| Sagan SID | Converted rule | Source file | Covered by | SigmaHQ path | "
        "Events | Breadth | Relation |",
        "| --- | --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    ordered = sorted(
        best.values(), key=lambda v: (-v.sagan_events, v.sagan_source_file, v.sagan_sid)
    )
    for verdict in ordered[:MAX_ROWS]:
        lines.append(
            f"| `{verdict.sagan_sid}` | {_escape(verdict.sagan_title[:70])} | "
            f"`{verdict.sagan_source_file}` | {_escape(verdict.sigmahq_title[:70])} | "
            f"`{verdict.sigmahq_path}` | {verdict.sagan_events} | "
            f"{verdict.sigmahq_coverage_breadth} | `{verdict.relation.value}` |"
        )
    if len(ordered) > MAX_ROWS:
        lines.append(
            f"| ... | *{len(ordered) - MAX_ROWS} more, see the JSON report* | | | "
            f"| | | |"
        )
    lines.append("")
    return lines


def _by_family(result: AnalysisResult) -> list[str]:
    families: dict[str, Counter[str]] = defaultdict(Counter)
    seen: set[tuple[str, str]] = set()
    covers = (Relation.EQUIVALENT.value, Relation.SAGAN_REDUNDANT.value)
    for verdict in result.verdicts:
        # A covering verdict only counts here when the log sources are
        # compatible, matching the actionable list above.
        if verdict.relation.value in covers and not verdict.logsource_compatible:
            continue
        key = (verdict.sagan_key, verdict.relation.value)
        if key in seen:
            continue
        seen.add(key)
        families[verdict.sagan_source_file][verdict.relation.value] += 1

    if not families:
        return []
    lines = [
        "## Where the overlap sits",
        "",
        "Grouped by the Sagan source file, which is the product the rules cover.",
        "",
        "| Source file | Covered | Broader | Overlapping |",
        "| --- | ---: | ---: | ---: |",
    ]
    for source in sorted(
        families,
        key=lambda name: (
            -(
                families[name][Relation.EQUIVALENT.value]
                + families[name][Relation.SAGAN_REDUNDANT.value]
            )
        ),
    )[:60]:
        counts = families[source]
        covered = (
            counts[Relation.EQUIVALENT.value] + counts[Relation.SAGAN_REDUNDANT.value]
        )
        lines.append(
            f"| `{source}` | {covered} | {counts[Relation.SAGAN_BROADER.value]} | "
            f"{counts[Relation.OVERLAP.value]} |"
        )
    lines.append("")
    return lines


def _witnesses(result: AnalysisResult) -> list[str]:
    covering = [
        verdict
        for verdict in result.verdicts
        if verdict.relation in (Relation.EQUIVALENT, Relation.SAGAN_REDUNDANT)
        and verdict.logsource_compatible
    ]
    if not covering:
        return []
    lines = [
        "## Evidence",
        "",
        "The event that fired both rules, for the twenty best-supported "
        "verdicts. Each one can be replayed:",
        "",
        "```sh",
        "rsigma engine eval --rules <ruleset> --event '<event>'",
        "```",
        "",
    ]
    ordered = sorted(covering, key=lambda v: -v.sagan_events)[:20]
    for verdict in ordered:
        lines.extend(
            [
                f"### SID {verdict.sagan_sid} covered by "
                f"{_escape(verdict.sigmahq_title[:80])}",
                "",
                f"- converted rule: {_escape(verdict.sagan_title[:110])}",
                f"- SigmaHQ rule: `{verdict.sigmahq_path}`",
                f"- verified on {verdict.sagan_events} event(s), "
                f"{verdict.sagan_events_firing_sigmahq} of which fire both",
                "",
                "```json",
                json.dumps(verdict.witness, ensure_ascii=False, indent=2)[:900],
                "```",
                "",
            ]
        )
    return lines


def _limits(result: AnalysisResult) -> list[str]:
    lines = [
        "## What this analysis cannot say",
        "",
        "A verdict is a statement about the events this tool could build, not a "
        "proof over every possible event. Three limits are worth stating plainly.",
        "",
        "**Coverage of the corpora.** "
        f"{len(result.sagan_unsynthesisable)} converted and "
        f"{len(result.sigmahq_unsynthesisable)} SigmaHQ rules yielded no event "
        "the engine would confirm, so they took no part in the comparison. A "
        "further "
        f"{len(result.sagan_uncompilable)} converted and "
        f"{len(result.sigmahq_uncompilable)} SigmaHQ rules were refused by the "
        "engine itself and removed before the run.",
        "",
        "**Absence matchers excluded.** "
        f"{len(result.sagan_blanket)} converted and "
        f"{len(result.sigmahq_blanket)} SigmaHQ rules fire on the empty event: "
        "they match on the absence of a field (a `not selection` filter, or "
        "`field|exists: false`) rather than on anything an event carries, so "
        "they co-fire with almost any event. Counting that co-firing as shared "
        "detection would be meaningless, so these rules are excluded from the "
        "comparison rather than allowed to manufacture coverage.",
        "",
        "**Field vocabulary.** Two rules can only fire on one event if they "
        "agree on field names. A converted rule matching the raw message body "
        "and a SigmaHQ rule matching a structured Windows field describe "
        "related detections but cannot share an event, and are correctly "
        "reported as unrelated here. That is a statement about the event shape "
        "your pipeline produces, not about detection intent.",
        "",
        "**Correlations are out of scope.** Rules that need a sequence of "
        "events, which is every converted `after` and `xbits` rule, cannot be "
        "judged by single-event evaluation and are excluded.",
        "",
    ]
    return lines


def render_markdown(result: AnalysisResult) -> str:
    """Render the human-facing report."""
    sections: list[str] = []
    sections += _summary(result)
    sections += _coverage_table(result)
    sections += _by_family(result)
    sections += _witnesses(result)
    sections += _limits(result)
    return "\n".join(sections).rstrip() + "\n"


def build_json(result: AnalysisResult) -> dict[str, Any]:
    """Build the machine-readable payload."""
    return {
        "schema_version": 1,
        "summary": {
            "sagan_rules": result.sagan_total,
            "sigmahq_rules": result.sigmahq_total,
            "sagan_testable": result.sagan_usable,
            "sigmahq_testable": result.sigmahq_usable,
            "events_evaluated": result.events_evaluated,
            "verdicts": len(result.verdicts),
            "sagan_rules_covered": len(result.redundant_sagan_keys),
            "cross_logsource_covered": result.cross_logsource_covered,
        },
        "excluded": {
            "sagan_uncompilable": result.sagan_uncompilable,
            "sigmahq_uncompilable": result.sigmahq_uncompilable,
            "sagan_no_test_event": result.sagan_unsynthesisable,
            "sigmahq_no_test_event": result.sigmahq_unsynthesisable,
            "sagan_absence_matcher": result.sagan_blanket,
            "sigmahq_absence_matcher": result.sigmahq_blanket,
        },
        "verdicts": [
            {
                "relation": verdict.relation.value,
                "logsource_compatible": verdict.logsource_compatible,
                "sagan": {
                    "sid": verdict.sagan_sid,
                    "id": verdict.sagan_key.split(":", 1)[1],
                    "title": verdict.sagan_title,
                    "source_file": verdict.sagan_source_file,
                    "events": verdict.sagan_events,
                    "events_firing_sigmahq": verdict.sagan_events_firing_sigmahq,
                },
                "sigmahq": {
                    "id": verdict.sigmahq_key.split(":", 1)[1],
                    "title": verdict.sigmahq_title,
                    "path": verdict.sigmahq_path,
                    "events": verdict.sigmahq_events,
                    "events_firing_sagan": verdict.sigmahq_events_firing_sagan,
                    "coverage_breadth": verdict.sigmahq_coverage_breadth,
                },
                "witness_event": verdict.witness,
            }
            for verdict in result.verdicts
        ],
    }


def render_json(result: AnalysisResult) -> str:
    """Serialise the machine-readable report."""
    return (
        json.dumps(build_json(result), indent=2, ensure_ascii=False, default=str) + "\n"
    )
