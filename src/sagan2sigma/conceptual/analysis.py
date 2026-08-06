"""Proposing conceptual-overlap candidates between the two corpora.

The shape of the computation is a blocked nearest-neighbour search. Comparing
every converted rule against every SigmaHQ rule would be tens of millions of
pairs, almost all of them unrelated, so a converted rule is only compared
against SigmaHQ rules with which it shares a *distinctive* token, found through
an inverted index. Two rules that share no rare term are not conceptually close
by this method's lights, so skipping them costs nothing and saves everything.

A candidate is emitted only when the lexical similarity clears a floor. This is
deliberate and is what keeps ATT&CK out of the driver's seat: technique
agreement can raise a candidate that already has lexical support, but it can
never manufacture one on its own. That rules out the failure the prototype
showed, where an Apache authentication rule and a Huawei BGP rule were paired on
nothing but two broad shared techniques and the word "authentication".

Every candidate carries its evidence: the shared distinctive tokens and the
shared techniques. A reviewer should be able to see, in one line, why the tool
thinks two rules are about the same thing, and decide in seconds whether it is
right. Nothing here is a verdict.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..overlap.analysis import RuleRecord, load_converted, load_sigmahq
from .features import Fingerprint, fingerprint
from .similarity import Weights, build_weights, cosine, norm, technique_score, vector

#: A token must be at least this distinctive (in IDF) to block on, so a shared
#: common word never drags two rules into comparison.
DEFAULT_BLOCK_IDF = 2.5

#: Minimum lexical cosine for a pair to be proposed at all.
DEFAULT_MIN_LEXICAL = 0.35

#: How much a shared technique's inverse frequency adds to the composite score.
#: Small on purpose: it reorders lexically-plausible candidates, it does not
#: create them.
TECHNIQUE_WEIGHT = 0.10

#: Candidates kept per converted rule, best first.
DEFAULT_TOP_K = 3


@dataclass(frozen=True, slots=True)
class Candidate:
    """One converted rule paired with a conceptually similar SigmaHQ rule."""

    sagan_key: str
    sagan_sid: str
    sagan_title: str
    sagan_source_file: str
    sigmahq_key: str
    sigmahq_title: str
    sigmahq_path: str
    lexical: float
    technique_score: float
    composite: float
    shared_terms: tuple[str, ...]
    shared_techniques: tuple[str, ...]


@dataclass(slots=True)
class ConceptualResult:
    """Everything the conceptual pass proposed, and over what population."""

    candidates: list[Candidate] = field(default_factory=list)
    sagan_total: int = 0
    sigmahq_total: int = 0
    sagan_with_candidate: int = 0
    min_lexical: float = DEFAULT_MIN_LEXICAL
    top_k: int = DEFAULT_TOP_K


def _fingerprints(records: list[RuleRecord]) -> list[Fingerprint]:
    return [
        fingerprint(
            key=record.key,
            origin=record.origin,
            title=record.title,
            source=record.source_file,
            sagan_sid=record.sagan_sid,
            document=record.document,
        )
        for record in records
    ]


def analyse(
    converted: list[RuleRecord],
    sigmahq: list[RuleRecord],
    min_lexical: float = DEFAULT_MIN_LEXICAL,
    block_idf: float = DEFAULT_BLOCK_IDF,
    top_k: int = DEFAULT_TOP_K,
) -> ConceptualResult:
    """Propose conceptual-overlap candidates for every converted rule."""
    result = ConceptualResult(
        sagan_total=len(converted),
        sigmahq_total=len(sigmahq),
        min_lexical=min_lexical,
        top_k=top_k,
    )

    converted_prints = _fingerprints(converted)
    sigmahq_prints = _fingerprints(sigmahq)
    weights = build_weights(converted_prints + sigmahq_prints)

    # Precompute the SigmaHQ side once: vectors, norms and an inverted index from
    # each distinctive token to the rules carrying it.
    sig_vectors = [vector(print_, weights) for print_ in sigmahq_prints]
    sig_norms = [norm(v) for v in sig_vectors]
    index: dict[str, list[int]] = defaultdict(list)
    for position, print_ in enumerate(sigmahq_prints):
        for term in print_.tokens:
            if weights.token(term) >= block_idf:
                index[term].append(position)

    candidates: list[Candidate] = []
    for sagan_print, sagan_vec in _with_vectors(converted_prints, weights):
        sagan_norm = norm(sagan_vec)
        block = _candidate_positions(sagan_print, weights, block_idf, index)
        scored = _score_block(
            sagan_print,
            sagan_vec,
            sagan_norm,
            block,
            sigmahq_prints,
            sig_vectors,
            sig_norms,
            weights,
            min_lexical,
        )
        if scored:
            result.sagan_with_candidate += 1
            candidates.extend(scored[:top_k])

    # Deterministic ordering: strongest first, ties broken by stable rule ids.
    candidates.sort(
        key=lambda c: (-c.composite, c.sagan_sid, c.sagan_key, c.sigmahq_path)
    )
    result.candidates = candidates
    return result


def _with_vectors(
    prints: list[Fingerprint], weights: Weights
) -> list[tuple[Fingerprint, dict[str, float]]]:
    return [(print_, vector(print_, weights)) for print_ in prints]


def _candidate_positions(
    sagan_print: Fingerprint,
    weights: Weights,
    block_idf: float,
    index: dict[str, list[int]],
) -> set[int]:
    positions: set[int] = set()
    for term in sagan_print.tokens:
        if weights.token(term) >= block_idf:
            positions.update(index.get(term, ()))
    return positions


def _score_block(
    sagan_print: Fingerprint,
    sagan_vec: dict[str, float],
    sagan_norm: float,
    block: set[int],
    sigmahq_prints: list[Fingerprint],
    sig_vectors: list[dict[str, float]],
    sig_norms: list[float],
    weights: Weights,
    min_lexical: float,
) -> list[Candidate]:
    scored: list[Candidate] = []
    for position in block:
        lexical = cosine(
            sagan_vec, sig_vectors[position], sagan_norm, sig_norms[position]
        )
        if lexical < min_lexical:
            continue
        other = sigmahq_prints[position]
        shared_techniques = sagan_print.techniques & other.techniques
        techniques = technique_score(sagan_print.techniques, other.techniques, weights)
        composite = lexical + TECHNIQUE_WEIGHT * techniques
        shared_terms = _shared_terms(sagan_print, other, weights)
        scored.append(
            Candidate(
                sagan_key=sagan_print.key,
                sagan_sid=sagan_print.sagan_sid,
                sagan_title=sagan_print.title,
                sagan_source_file=sagan_print.source,
                sigmahq_key=other.key,
                sigmahq_title=other.title,
                sigmahq_path=other.source,
                lexical=round(lexical, 4),
                technique_score=round(techniques, 4),
                composite=round(composite, 4),
                shared_terms=shared_terms,
                shared_techniques=tuple(sorted(shared_techniques)),
            )
        )
    scored.sort(key=lambda c: (-c.composite, c.sigmahq_path))
    return scored


def _shared_terms(
    a: Fingerprint, b: Fingerprint, weights: Weights, limit: int = 6
) -> tuple[str, ...]:
    """The most distinctive tokens the two rules share, rarest first."""
    common = set(a.tokens) & set(b.tokens)
    ranked = sorted(common, key=lambda term: (-weights.token(term), term))
    return tuple(ranked[:limit])


def load(
    converted_dir: Path, sigmahq_dir: Path
) -> tuple[list[RuleRecord], list[RuleRecord]]:
    """Load both corpora, reusing the behavioural analysis's loaders."""
    return (
        load_converted(converted_dir),
        load_sigmahq(sigmahq_dir, skip_dirs=frozenset({"rules-placeholder"})),
    )


def build_json(result: ConceptualResult) -> dict[str, Any]:
    """The machine-readable report: every candidate with its evidence."""
    return {
        "schema_version": 1,
        "kind": "conceptual",
        "summary": {
            "sagan_rules": result.sagan_total,
            "sigmahq_rules": result.sigmahq_total,
            "sagan_with_candidate": result.sagan_with_candidate,
            "candidates": len(result.candidates),
            "min_lexical": result.min_lexical,
            "top_k": result.top_k,
        },
        "candidates": [
            {
                "sagan": {
                    "sid": candidate.sagan_sid,
                    "id": candidate.sagan_key.split(":", 1)[1],
                    "title": candidate.sagan_title,
                    "source_file": candidate.sagan_source_file,
                },
                "sigmahq": {
                    "id": candidate.sigmahq_key.split(":", 1)[1],
                    "title": candidate.sigmahq_title,
                    "path": candidate.sigmahq_path,
                },
                "lexical_similarity": candidate.lexical,
                "technique_score": candidate.technique_score,
                "composite": candidate.composite,
                "shared_terms": list(candidate.shared_terms),
                "shared_techniques": list(candidate.shared_techniques),
            }
            for candidate in result.candidates
        ],
    }
