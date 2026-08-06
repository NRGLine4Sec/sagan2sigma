"""Merging the two analyses into confidence-tiered rule pairs.

A pair of rules can be reported by the behavioural analysis, the conceptual
analysis, or both, and each carries different evidential weight. The tiers order
that weight, and every pair is assigned to the single strongest tier it earns,
so it appears once rather than being scattered across the report.

The ordering reflects what the test modules actually establish:

* a pair confirmed by **both** analyses is the strongest thing the project can
  say, since an engine confirmed the two fire on one event and, independently,
  they were found to search for the same distinctive terms;
* behavioural coverage, confirmed by the engine and re-checked by the
  witness-fires-both invariant, is next;
* behavioural co-firing that is not coverage is tested but weaker;
* a covering co-firing across incompatible log sources is tested but not
  deployable, since the SigmaHQ rule would not run on that product's logs;
* a conceptual candidate rests on lexical similarity alone and is a lead for a
  human, not a tested fact, strong or weak by its similarity score.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

#: Lexical similarity at or above which a conceptual-only pair is "strong".
STRONG_LEXICAL = 0.50


class Tier(IntEnum):
    """Confidence tiers, highest value first when sorted in reverse."""

    CONFIRMED_BY_BOTH = 6
    TESTED_COVERAGE = 5
    TESTED_RELATED = 4
    CROSS_LOGSOURCE = 3
    CONCEPTUAL_STRONG = 2
    CONCEPTUAL_WEAK = 1


TIER_TITLE: dict[Tier, str] = {
    Tier.CONFIRMED_BY_BOTH: "Confirmed by both analyses",
    Tier.TESTED_COVERAGE: "Behaviourally confirmed coverage (tested)",
    Tier.TESTED_RELATED: "Behaviourally related, not coverage (tested)",
    Tier.CROSS_LOGSOURCE: "Cross-log-source co-firing (tested, not deployable)",
    Tier.CONCEPTUAL_STRONG: "Conceptual candidate, strong lexical match (review)",
    Tier.CONCEPTUAL_WEAK: "Conceptual candidate, weaker lexical match (review)",
}

TIER_MEANING: dict[Tier, str] = {
    Tier.CONFIRMED_BY_BOTH: (
        "The engine confirmed both rules fire on one synthesised event, they are "
        "log-source compatible, and independently the conceptual analysis found "
        "them searching for the same distinctive terms. Strongest evidence "
        "available; review these first."
    ),
    Tier.TESTED_COVERAGE: (
        "Every event synthesised from the converted rule also fired the SigmaHQ "
        "rule (or each fired all of the other's), log sources are compatible, and "
        "the witness event is attached and replayable. Deploying SigmaHQ makes "
        "the converted rule redundant on the evidence."
    ),
    Tier.TESTED_RELATED: (
        "The two fired together on at least one event, log sources are "
        "compatible, but neither contains the other (an overlap), or the "
        "converted rule is the broader of the two. Related, not interchangeable."
    ),
    Tier.CROSS_LOGSOURCE: (
        "The engine confirmed the two fire on one event, but their log sources "
        "differ, so in production the SigmaHQ rule would not see that event. "
        "Usually a SigmaHQ keyword rule matching a common word in another "
        "product's raw text. Not deployable coverage; recorded for completeness."
    ),
    Tier.CONCEPTUAL_STRONG: (
        "No behavioural co-firing was found, but the two rules share distinctive "
        "search terms strongly enough to suggest they detect the same thing. A "
        "lead for human review, not a tested fact."
    ),
    Tier.CONCEPTUAL_WEAK: (
        "A weaker lexical similarity, near the floor. A candidate to skim, most "
        "useful read alongside its shared terms."
    ),
}

#: Which test module backs each tier, shown in the report so a reader knows what
#: kind of evidence a tier rests on.
TIER_BACKING: dict[Tier, str] = {
    Tier.CONFIRMED_BY_BOTH: "overlap engine + witness invariant, and conceptual",
    Tier.TESTED_COVERAGE: "overlap engine + witness-fires-both invariant",
    Tier.TESTED_RELATED: "overlap engine (co-firing tested)",
    Tier.CROSS_LOGSOURCE: "overlap engine (co-firing tested); log-source gate",
    Tier.CONCEPTUAL_STRONG: "conceptual lexical similarity only",
    Tier.CONCEPTUAL_WEAK: "conceptual lexical similarity only",
}


@dataclass(frozen=True, slots=True)
class Entry:
    """One overlapping rule pair, placed in its strongest tier."""

    tier: Tier
    sagan_sid: str
    sagan_id: str
    sagan_title: str
    sagan_source_file: str
    sigmahq_id: str
    sigmahq_title: str
    sigmahq_path: str
    #: The behavioural relation, empty for a conceptual-only pair.
    relation: str
    #: Events behind the behavioural verdict, zero for a conceptual-only pair.
    events: int
    lexical: float
    shared_terms: tuple[str, ...]
    #: A JSON-encodable witness event, empty for a conceptual-only pair.
    witness: dict[str, Any]


def _pair(sagan_id: str, sigmahq_id: str) -> tuple[str, str]:
    return (sagan_id, sigmahq_id)


def classify(
    overlap_report: dict[str, Any],
    conceptual_report: dict[str, Any],
    strong_lexical: float = STRONG_LEXICAL,
) -> list[Entry]:
    """Merge the two reports into tiered entries, one per rule pair.

    A pair reported by both analyses is merged and lifted to the highest tier its
    combined evidence earns.
    """
    conceptual_by_pair: dict[tuple[str, str], dict[str, Any]] = {
        _pair(c["sagan"]["id"], c["sigmahq"]["id"]): c
        for c in conceptual_report.get("candidates", [])
    }

    entries: dict[tuple[str, str], Entry] = {}

    # Behavioural verdicts first: they carry the stronger evidence.
    for verdict in overlap_report.get("verdicts", []):
        key = _pair(verdict["sagan"]["id"], verdict["sigmahq"]["id"])
        relation = verdict["relation"]
        compatible = verdict.get("logsource_compatible", True)
        also_conceptual = key in conceptual_by_pair
        covering = relation in ("EQUIVALENT", "SAGAN_REDUNDANT")

        if covering and compatible and also_conceptual:
            tier = Tier.CONFIRMED_BY_BOTH
        elif covering and compatible:
            tier = Tier.TESTED_COVERAGE
        elif covering and not compatible:
            tier = Tier.CROSS_LOGSOURCE
        elif compatible:
            tier = Tier.TESTED_RELATED
        else:
            # A non-covering co-firing across incompatible log sources is the
            # weakest behavioural signal; group it with the cross-log-source
            # tier rather than inventing another.
            tier = Tier.CROSS_LOGSOURCE

        conceptual = conceptual_by_pair.get(key)
        entries[key] = Entry(
            tier=tier,
            sagan_sid=verdict["sagan"]["sid"],
            sagan_id=verdict["sagan"]["id"],
            sagan_title=verdict["sagan"]["title"],
            sagan_source_file=verdict["sagan"]["source_file"],
            sigmahq_id=verdict["sigmahq"]["id"],
            sigmahq_title=verdict["sigmahq"]["title"],
            sigmahq_path=verdict["sigmahq"]["path"],
            relation=relation,
            events=verdict["sagan"].get("events", 0),
            lexical=conceptual["lexical_similarity"] if conceptual else 0.0,
            shared_terms=tuple(conceptual["shared_terms"]) if conceptual else (),
            witness=verdict.get("witness_event", {}),
        )

    # Conceptual-only pairs: those not already carried by a behavioural verdict.
    for key, candidate in conceptual_by_pair.items():
        if key in entries:
            continue
        lexical = candidate["lexical_similarity"]
        tier = (
            Tier.CONCEPTUAL_STRONG
            if lexical >= strong_lexical
            else Tier.CONCEPTUAL_WEAK
        )
        entries[key] = Entry(
            tier=tier,
            sagan_sid=candidate["sagan"]["sid"],
            sagan_id=candidate["sagan"]["id"],
            sagan_title=candidate["sagan"]["title"],
            sagan_source_file=candidate["sagan"]["source_file"],
            sigmahq_id=candidate["sigmahq"]["id"],
            sigmahq_title=candidate["sigmahq"]["title"],
            sigmahq_path=candidate["sigmahq"]["path"],
            relation="",
            events=0,
            lexical=lexical,
            shared_terms=tuple(candidate["shared_terms"]),
            witness={},
        )

    # Deterministic order: strongest tier first, then by evidence within a tier.
    return sorted(
        entries.values(),
        key=lambda e: (
            -int(e.tier),
            -e.events,
            -e.lexical,
            e.sagan_sid,
            e.sagan_id,
            e.sigmahq_path,
        ),
    )
