"""Markdown conversion report.

The report answers three questions a rule engineer actually has after a run:

1. what did not convert, and why, precisely enough to act on it;
2. which product families are affected, so effort can be prioritised;
3. what converted but lost something along the way.

That third section matters as much as the first. A rule whose ``threshold`` was
demoted to metadata, or whose ``by_src`` grouping silently became a per-host
grouping, is not a failure but it is not a faithful conversion either, and
nothing else in the pipeline would surface it.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import TYPE_CHECKING

from ..errors import DEGRADATION_HELP, REFUSAL_HELP, DegradationCode, RefusalCode

if TYPE_CHECKING:  # pragma: no cover
    from ..converter import ConversionResult, RefusedRule

#: Rows beyond this count are collapsed into a summary line, keeping the
#: report readable on a corpus of ten thousand rules.
MAX_ROWS_PER_TABLE = 400


def _escape(text: str) -> str:
    """Escape the characters that would break a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _pct(part: int, total: int) -> str:
    return f"{100.0 * part / total:.1f}%" if total else "n/a"


def _summary(result: ConversionResult, profile: str, case_policy: str) -> list[str]:
    total = result.total_rules
    lines = [
        "# Conversion report",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Rule files processed | {result.files_processed} |",
        f"| Active rules parsed | {total} |",
        f"| Commented-out rules skipped | {result.disabled_rules} |",
        f"| Rules converted | {len(result.converted_rules)} "
        f"({_pct(len(result.converted_rules), total)}) |",
        f"| Rules refused | {len(result.refused)} "
        f"({_pct(len(result.refused), total)}) |",
        f"| Lines that failed to parse | {len(result.parse_failures)} |",
        f"| Synthetic rules added | {len(result.synthetic_rules)} |",
        f"| Sigma documents emitted | {len(result.documents)} |",
        f"| pySigma validation issues | {len(result.validation_issues)} |",
        f"| Output profile | `{profile}` |",
        f"| Case policy | `{case_policy}` |",
        "",
    ]
    return lines


def _by_category(result: ConversionResult) -> list[str]:
    categories: dict[str, Counter[str]] = defaultdict(Counter)
    for converted in result.converted:
        categories[converted.category]["converted"] += 1
        if converted.degradations:
            categories[converted.category]["degraded"] += 1
    for refused in result.refused:
        categories[refused.category]["refused"] += 1

    lines = [
        "## Outcome by product family",
        "",
        "Grouping comes from the rule file name, resolved through the bundled",
        "logsource catalog. It answers which kinds of device caused trouble.",
        "",
        "| Product family | Converted | Refused | Rate | Converted with loss |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for category in sorted(categories):
        counts = categories[category]
        converted_count = counts["converted"]
        refused_count = counts["refused"]
        total = converted_count + refused_count
        lines.append(
            f"| {_escape(category)} | {converted_count} | {refused_count} | "
            f"{_pct(converted_count, total)} | {counts['degraded']} |"
        )
    lines.append("")
    return lines


def _by_refusal_code(result: ConversionResult) -> list[str]:
    counts = Counter(refused.code for refused in result.refused)
    lines = [
        "## Refusals by code",
        "",
        "| Code | Rules | Share | Meaning |",
        "| --- | ---: | ---: | --- |",
    ]
    total = len(result.refused)
    for code, count in counts.most_common():
        lines.append(
            f"| `{code.value}` | {count} | {_pct(count, total)} | "
            f"{_escape(REFUSAL_HELP.get(code, ''))} |"
        )
    lines.append("")
    return lines


def _refusal_detail(result: ConversionResult) -> list[str]:
    lines = ["## Refused rules", ""]
    by_code: dict[RefusalCode, list[RefusedRule]] = defaultdict(list)
    for refused in result.refused:
        by_code[refused.code].append(refused)

    for code in sorted(by_code, key=lambda item: -len(by_code[item])):
        rules = sorted(by_code[code], key=lambda item: (item.source_file, item.sid))
        lines.extend(
            [
                f"### `{code.value}` ({len(rules)} rules)",
                "",
                REFUSAL_HELP.get(code, ""),
                "",
                "| SID | Source file | Family | Title | Keywords | Detail |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for refused in rules[:MAX_ROWS_PER_TABLE]:
            keywords = ", ".join(refused.keywords) or "-"
            lines.append(
                f"| `{refused.sid}` | `{refused.source_file}` | "
                f"{_escape(refused.category)} | {_escape(refused.title[:90])} | "
                f"`{_escape(keywords)}` | {_escape(refused.detail[:180])} |"
            )
        if len(rules) > MAX_ROWS_PER_TABLE:
            lines.append(
                f"| ... | ... | ... | *{len(rules) - MAX_ROWS_PER_TABLE} more rows "
                f"omitted, see the JSON report* | | |"
            )
        lines.append("")
    return lines


def _degradations(result: ConversionResult) -> list[str]:
    counts: Counter[DegradationCode] = Counter()
    examples: dict[DegradationCode, list[str]] = defaultdict(list)
    for converted in result.converted:
        for degradation in converted.degradations:
            counts[degradation.code] += 1
            if len(examples[degradation.code]) < 5:
                examples[degradation.code].append(converted.sid)

    lines = [
        "## Converted with semantic loss",
        "",
        "These rules were converted, but something the Sagan engine does is not",
        "reproduced. They are worth reviewing before the ruleset goes live.",
        "",
        "| Code | Rules | Meaning | Example SIDs |",
        "| --- | ---: | --- | --- |",
    ]
    for code, count in counts.most_common():
        sample = ", ".join(f"`{sid}`" for sid in examples[code])
        lines.append(
            f"| `{code.value}` | {count} | {_escape(DEGRADATION_HELP.get(code, ''))} "
            f"| {sample} |"
        )
    lines.append("")
    return lines


def _unknown_keywords(result: ConversionResult) -> list[str]:
    if not result.unknown_keywords:
        return []
    lines = [
        "## Unknown keywords",
        "",
        "Keywords encountered in the corpus that no handler covers. Each one is",
        "a candidate for a new handler, and a good first contribution.",
        "",
        "| Keyword | Rules affected |",
        "| --- | ---: |",
    ]
    for keyword, count in sorted(
        result.unknown_keywords.items(), key=lambda item: (-item[1], item[0])
    ):
        lines.append(f"| `{_escape(keyword)}` | {count} |")
    lines.append("")
    return lines


def _parse_failures(result: ConversionResult) -> list[str]:
    if not result.parse_failures:
        return []
    lines = [
        "## Lines that failed to parse",
        "",
        "| Source file | Line | Reason |",
        "| --- | ---: | --- |",
    ]
    for failure in result.parse_failures[:MAX_ROWS_PER_TABLE]:
        lines.append(
            f"| `{failure.source_file}` | {failure.line_number} | "
            f"{_escape(failure.reason)} |"
        )
    lines.append("")
    return lines


def _validation(result: ConversionResult) -> list[str]:
    if not result.validation_issues:
        return [
            "## pySigma validation",
            "",
            "Every emitted document was accepted by pySigma, and every",
            "correlation resolved the rules it references.",
            "",
        ]
    lines = [
        "## pySigma validation",
        "",
        "Documents rejected by the reference implementation, or correlations",
        "pointing at a rule absent from the batch. Any entry here is a",
        "converter defect worth reporting.",
        "",
        "| Document id | Error | Message |",
        "| --- | --- | --- |",
    ]
    for issue in result.validation_issues[:MAX_ROWS_PER_TABLE]:
        lines.append(
            f"| `{issue.document_id}` | `{issue.error_type}` | "
            f"{_escape(issue.message[:200])} |"
        )
    lines.append("")
    return lines


def render(result: ConversionResult, profile: str = "?", case_policy: str = "?") -> str:
    """Render the full Markdown report."""
    sections: list[str] = []
    sections += _summary(result, profile, case_policy)
    sections += _by_category(result)
    if result.refused:
        sections += _by_refusal_code(result)
    sections += _degradations(result)
    sections += _unknown_keywords(result)
    sections += _validation(result)
    if result.refused:
        sections += _refusal_detail(result)
    sections += _parse_failures(result)
    return "\n".join(sections).rstrip() + "\n"
