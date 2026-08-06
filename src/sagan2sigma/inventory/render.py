"""Rendering the tiered inventory as a commit-pinned Markdown document."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass

from .classify import (
    TIER_BACKING,
    TIER_MEANING,
    TIER_TITLE,
    Entry,
    Tier,
)


@dataclass(frozen=True, slots=True)
class Corpus:
    """A rule corpus pinned to the commit an inventory was built from."""

    name: str
    url: str
    commit: str
    committed: str


@dataclass(frozen=True, slots=True)
class Provenance:
    """Everything needed to reproduce and to date the inventory."""

    generated: str
    sagan: Corpus
    sigmahq: Corpus
    engine_version: str
    profile: str


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _corpus_row(corpus: Corpus) -> str:
    return f"| {corpus.name} | `{corpus.commit}` | {corpus.committed} | {corpus.url} |"


def _header(provenance: Provenance, total: int) -> list[str]:
    return [
        "# Overlapping rules: Sagan-converted and SigmaHQ",
        "",
        "A precise, confidence-tiered list of the rule pairs that overlap between "
        "the converted Sagan corpus and SigmaHQ. Each pair sits in the single "
        "strongest tier its evidence earns.",
        "",
        "> **This is a point-in-time snapshot.** Both corpora change daily, so "
        "the pairs below are valid only for the exact commits pinned here. "
        "Against a later state of either repository the list may be wrong; "
        "regenerate it with `sagan2sigma-inventory` after updating the corpora.",
        "",
        "## Provenance",
        "",
        f"- Generated: {provenance.generated}",
        f"- Engine: rsigma {provenance.engine_version}",
        f"- Conversion profile: `{provenance.profile}`",
        "",
        "| Corpus | Commit | Committed | Source |",
        "| --- | --- | --- | --- |",
        _corpus_row(provenance.sagan),
        _corpus_row(provenance.sigmahq),
        "",
        f"Total overlapping pairs listed: **{total}**.",
        "",
    ]


def _legend(counts: Counter[Tier]) -> list[str]:
    lines = [
        "## Confidence tiers",
        "",
        "Read top to bottom: the first tiers are established by running the "
        "engine, the last two are lexical leads for a human to review and are "
        "**not** grounds to retire a rule.",
        "",
        "| Tier | Pairs | Backed by | What it means |",
        "| --- | ---: | --- | --- |",
    ]
    for tier in sorted(Tier, reverse=True):
        lines.append(
            f"| **{TIER_TITLE[tier]}** | {counts.get(tier, 0)} | "
            f"{TIER_BACKING[tier]} | {_escape(TIER_MEANING[tier])} |"
        )
    lines.append("")
    return lines


def _tested_table(entries: list[Entry]) -> list[str]:
    lines = [
        "| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Relation | "
        "Events | Shared terms |",
        "| --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for entry in entries:
        terms = ", ".join(entry.shared_terms)
        lines.append(
            f"| `{entry.sagan_sid}` | {_escape(entry.sagan_title[:55])} | "
            f"{_escape(entry.sigmahq_title[:55])} | `{entry.sigmahq_path}` | "
            f"`{entry.relation}` | {entry.events} | {_escape(terms[:60])} |"
        )
    lines.append("")
    return lines


def _conceptual_table(entries: list[Entry]) -> list[str]:
    lines = [
        "| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Lexical | "
        "Shared terms |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for entry in entries:
        terms = ", ".join(entry.shared_terms)
        lines.append(
            f"| `{entry.sagan_sid}` | {_escape(entry.sagan_title[:55])} | "
            f"{_escape(entry.sigmahq_title[:55])} | `{entry.sigmahq_path}` | "
            f"{entry.lexical:.2f} | {_escape(terms[:70])} |"
        )
    lines.append("")
    return lines


def render_markdown(entries: list[Entry], provenance: Provenance) -> str:
    """Render the full inventory document."""
    counts = Counter(entry.tier for entry in entries)
    lines = _header(provenance, len(entries))
    lines += _legend(counts)

    conceptual_tiers = (Tier.CONCEPTUAL_STRONG, Tier.CONCEPTUAL_WEAK)
    for tier in sorted(Tier, reverse=True):
        in_tier = [entry for entry in entries if entry.tier is tier]
        if not in_tier:
            continue
        lines.append(f"## {TIER_TITLE[tier]} ({len(in_tier)})")
        lines.append("")
        lines.append(_escape(TIER_MEANING[tier]))
        lines.append("")
        if tier in conceptual_tiers:
            lines += _conceptual_table(in_tier)
        else:
            lines += _tested_table(in_tier)

    return "\n".join(lines).rstrip() + "\n"


def render_json(entries: list[Entry], provenance: Provenance) -> str:
    """The same inventory, machine-readable, with a witness per tested pair."""
    payload = {
        "schema_version": 1,
        "generated": provenance.generated,
        "engine_version": provenance.engine_version,
        "profile": provenance.profile,
        "corpora": {
            "sagan_rules": {
                "url": provenance.sagan.url,
                "commit": provenance.sagan.commit,
                "committed": provenance.sagan.committed,
            },
            "sigmahq": {
                "url": provenance.sigmahq.url,
                "commit": provenance.sigmahq.commit,
                "committed": provenance.sigmahq.committed,
            },
        },
        "entries": [
            {
                "tier": entry.tier.name,
                "sagan": {
                    "sid": entry.sagan_sid,
                    "id": entry.sagan_id,
                    "title": entry.sagan_title,
                    "source_file": entry.sagan_source_file,
                },
                "sigmahq": {
                    "id": entry.sigmahq_id,
                    "title": entry.sigmahq_title,
                    "path": entry.sigmahq_path,
                },
                "relation": entry.relation,
                "events": entry.events,
                "lexical_similarity": entry.lexical,
                "shared_terms": list(entry.shared_terms),
                "witness_event": entry.witness,
            }
            for entry in entries
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"
