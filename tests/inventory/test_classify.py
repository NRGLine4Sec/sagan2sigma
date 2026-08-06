"""Tests for the confidence tiering."""

from __future__ import annotations

from sagan2sigma.inventory.classify import Tier, classify

from .conftest import candidate, conceptual_report, overlap_report, verdict


def _tier_of(entries, sagan_id, sigmahq_id):
    for entry in entries:
        if entry.sagan_id == sagan_id and entry.sigmahq_id == sigmahq_id:
            return entry.tier
    return None


def test_covering_and_conceptual_is_confirmed_by_both() -> None:
    entries = classify(
        overlap_report(verdict("a", "x", "SAGAN_REDUNDANT")),
        conceptual_report(candidate("a", "x", 0.6)),
    )
    assert len(entries) == 1
    assert entries[0].tier is Tier.CONFIRMED_BY_BOTH
    # The conceptual evidence is merged in.
    assert entries[0].shared_terms == ("mimikatz",)


def test_covering_compatible_alone_is_tested_coverage() -> None:
    entries = classify(
        overlap_report(verdict("a", "x", "SAGAN_REDUNDANT")), conceptual_report()
    )
    assert _tier_of(entries, "a", "x") is Tier.TESTED_COVERAGE


def test_covering_incompatible_is_cross_logsource() -> None:
    entries = classify(
        overlap_report(verdict("a", "x", "SAGAN_REDUNDANT", compatible=False)),
        conceptual_report(),
    )
    assert _tier_of(entries, "a", "x") is Tier.CROSS_LOGSOURCE


def test_overlap_compatible_is_tested_related() -> None:
    entries = classify(
        overlap_report(verdict("a", "x", "OVERLAP")), conceptual_report()
    )
    assert _tier_of(entries, "a", "x") is Tier.TESTED_RELATED


def test_broader_compatible_is_tested_related() -> None:
    entries = classify(
        overlap_report(verdict("a", "x", "SAGAN_BROADER")), conceptual_report()
    )
    assert _tier_of(entries, "a", "x") is Tier.TESTED_RELATED


def test_conceptual_only_strong_and_weak() -> None:
    entries = classify(
        overlap_report(),
        conceptual_report(candidate("a", "x", 0.7), candidate("b", "y", 0.36)),
    )
    assert _tier_of(entries, "a", "x") is Tier.CONCEPTUAL_STRONG
    assert _tier_of(entries, "b", "y") is Tier.CONCEPTUAL_WEAK


def test_a_pair_is_not_double_counted() -> None:
    # Present in both reports: exactly one entry, in the merged tier.
    entries = classify(
        overlap_report(verdict("a", "x", "SAGAN_REDUNDANT")),
        conceptual_report(candidate("a", "x", 0.6)),
    )
    pairs = [(e.sagan_id, e.sigmahq_id) for e in entries]
    assert pairs == [("a", "x")]


def test_ordering_is_by_tier_then_evidence() -> None:
    entries = classify(
        overlap_report(
            verdict("a", "x", "SAGAN_REDUNDANT"),  # tested coverage
            verdict("b", "y", "OVERLAP"),  # tested related
        ),
        conceptual_report(candidate("c", "z", 0.9)),  # conceptual strong
    )
    tiers = [e.tier for e in entries]
    # Strongest tier first, non-increasing.
    assert tiers == sorted(tiers, reverse=True)
    assert tiers[0] is Tier.TESTED_COVERAGE
