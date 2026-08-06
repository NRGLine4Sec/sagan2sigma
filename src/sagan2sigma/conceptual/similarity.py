"""Weighting terms by how much they distinguish a rule, and scoring a pair.

A shared token is only interesting in proportion to how rare it is. Two rules
both mentioning "powershell" say little; two both mentioning
``set-psreadlineoption`` say a great deal. Inverse document frequency captures
exactly that, computed over both corpora together so a term common in one and
rare in the other is judged on the whole population.

The lexical score is a cosine over IDF-weighted token vectors, so it rewards
sharing rare terms and is unmoved by sharing common ones. ATT&CK techniques are
scored the same way, by their own inverse frequency, so a shared broad technique
like "Valid Accounts" counts for almost nothing while a shared narrow one counts
for a lot. The two are kept separate rather than folded into a single number, so
a reader can see whether a candidate rests on shared wording, shared taxonomy, or
both.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from .features import Fingerprint


@dataclass(frozen=True, slots=True)
class Weights:
    """Inverse document frequency for tokens and for techniques."""

    token_idf: dict[str, float]
    technique_idf: dict[str, float]
    document_count: int

    def token(self, term: str) -> float:
        """The weight of a token, zero if it never appeared in the corpus."""
        return self.token_idf.get(term, 0.0)

    def technique(self, identifier: str) -> float:
        """The weight of a technique, by its rarity across both corpora."""
        return self.technique_idf.get(identifier, 0.0)


def build_weights(fingerprints: Iterable[Fingerprint]) -> Weights:
    """Compute IDF for every token and technique over the whole population."""
    fingerprints = list(fingerprints)
    total = len(fingerprints)
    token_df: Counter[str] = Counter()
    technique_df: Counter[str] = Counter()
    for print_ in fingerprints:
        token_df.update(print_.tokens.keys())
        technique_df.update(print_.techniques)
    # ``log(total / df)`` is the standard idf. A term appearing in every rule
    # scores zero and drops out; a term appearing once scores highest.
    token_idf = {term: math.log(total / df) for term, df in token_df.items()}
    technique_idf = {
        identifier: math.log(total / df) for identifier, df in technique_df.items()
    }
    return Weights(
        token_idf=token_idf, technique_idf=technique_idf, document_count=total
    )


def vector(fingerprint: Fingerprint, weights: Weights) -> dict[str, float]:
    """The IDF-weighted token vector, dropping tokens of zero weight."""
    result: dict[str, float] = {}
    for term, count in fingerprint.tokens.items():
        weight = weights.token(term)
        if weight > 0.0:
            result[term] = count * weight
    return result


def norm(vector: dict[str, float]) -> float:
    """Euclidean norm, floored at one so an empty vector cannot divide by zero."""
    total = math.sqrt(sum(value * value for value in vector.values()))
    return total or 1.0


def cosine(
    a: dict[str, float], b: dict[str, float], norm_a: float, norm_b: float
) -> float:
    """Cosine similarity of two precomputed vectors and their norms."""
    if len(a) > len(b):
        a, b = b, a
    dot = sum(weight * b.get(term, 0.0) for term, weight in a.items())
    return dot / (norm_a * norm_b)


def technique_score(a: frozenset[str], b: frozenset[str], weights: Weights) -> float:
    """Summed inverse frequency of the techniques two rules share.

    A shared sub-technique and its parent are both counted when both are
    present; that is intended, since declaring the specific and the general form
    together is a stronger signal than either alone.
    """
    return sum(weights.technique(identifier) for identifier in a & b)
