"""Tests for term weighting and pair scoring."""

from __future__ import annotations

from collections import Counter

from sagan2sigma.conceptual.features import Fingerprint
from sagan2sigma.conceptual.similarity import (
    build_weights,
    cosine,
    norm,
    technique_score,
    vector,
)


def _fp(tokens: dict[str, int], techniques: set[str] | None = None) -> Fingerprint:
    return Fingerprint(
        key="k",
        origin="sagan",
        title="t",
        source="s",
        sagan_sid="",
        techniques=frozenset(techniques or set()),
        tokens=Counter(tokens),
    )


def test_idf_discounts_common_terms() -> None:
    # "common" appears in all four, "rare" in one.
    prints = [
        _fp({"common": 1, "rare": 1}),
        _fp({"common": 1}),
        _fp({"common": 1}),
        _fp({"common": 1}),
    ]
    weights = build_weights(prints)
    assert weights.token("rare") > weights.token("common")
    # A term in every document carries no weight.
    assert weights.token("common") == 0.0
    # An unseen term is weightless, not an error.
    assert weights.token("absent") == 0.0


def test_vector_drops_zero_weight_terms() -> None:
    prints = [_fp({"common": 1, "rare": 1}), _fp({"common": 1})]
    weights = build_weights(prints)
    v = vector(prints[0], weights)
    assert "rare" in v
    assert "common" not in v  # zero idf


def test_cosine_of_shared_rare_terms() -> None:
    prints = [
        _fp({"rare": 1, "x": 1}),
        _fp({"rare": 1, "y": 1}),
        _fp({"z": 1}),
        _fp({"w": 1}),
    ]
    weights = build_weights(prints)
    a, b = vector(prints[0], weights), vector(prints[1], weights)
    score = cosine(a, b, norm(a), norm(b))
    assert 0.0 < score <= 1.0


def test_cosine_disjoint_is_zero() -> None:
    prints = [_fp({"a": 1}), _fp({"b": 1}), _fp({"c": 1})]
    weights = build_weights(prints)
    a, b = vector(prints[0], weights), vector(prints[1], weights)
    assert cosine(a, b, norm(a), norm(b)) == 0.0


def test_technique_score_rewards_rarity() -> None:
    # t_broad in three of four, t_rare in one.
    prints = [
        _fp({"a": 1}, {"t_broad", "t_rare"}),
        _fp({"b": 1}, {"t_broad"}),
        _fp({"c": 1}, {"t_broad"}),
        _fp({"d": 1}),
    ]
    weights = build_weights(prints)
    rare = technique_score(frozenset({"t_rare"}), frozenset({"t_rare"}), weights)
    broad = technique_score(frozenset({"t_broad"}), frozenset({"t_broad"}), weights)
    assert rare > broad
    assert technique_score(frozenset({"t_rare"}), frozenset(), weights) == 0.0
