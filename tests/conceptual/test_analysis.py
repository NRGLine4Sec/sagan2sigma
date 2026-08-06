"""Tests for the conceptual candidate generation."""

from __future__ import annotations

from sagan2sigma.conceptual.analysis import analyse, build_json

from .conftest import make_record

# Small corpora need a low blocking threshold, since IDF depends on corpus size.
LOOSE = {"min_lexical": 0.3, "block_idf": 0.1}

# Filler rules give the distinctive tokens something to be rare against.
FILLERS_SAGAN = [
    make_record(f"filler {n}", {"sel": {"k|contains": f"zzz{n}"}, "condition": "sel"})
    for n in range(6)
]
FILLERS_SIGMA = [
    make_record(
        f"noise {n}",
        {"sel": {"k|contains": f"yyy{n}"}, "condition": "sel"},
        origin="sigmahq",
    )
    for n in range(6)
]


def test_shared_rare_term_makes_a_candidate() -> None:
    sagan = make_record(
        "Sticky Key Backdoor",
        {"sel": {"CommandLine|contains": "sethc.exe"}, "condition": "sel"},
        tags=["attack.t1546.008"],
        sagan_sid="5000001",
    )
    sigmahq = make_record(
        "Sticky Key Like Backdoor Execution",
        {"sel": {"CommandLine|contains": "sethc.exe"}, "condition": "sel"},
        origin="sigmahq",
        tags=["attack.t1546.008"],
    )
    result = analyse([sagan, *FILLERS_SAGAN], [sigmahq, *FILLERS_SIGMA], **LOOSE)
    pair = [c for c in result.candidates if c.sagan_key == sagan.key]
    assert pair, "expected a candidate for the sticky-key rule"
    candidate = pair[0]
    assert candidate.sigmahq_key == sigmahq.key
    assert "sethc.exe" in candidate.shared_terms
    assert "t1546.008" in candidate.shared_techniques
    assert candidate.lexical >= 0.3


def test_only_common_terms_yields_no_candidate() -> None:
    # Both mention "backdoor" but it is in every rule here, so it carries no
    # weight and there is nothing distinctive to pair them on.
    common = [
        make_record(
            f"backdoor thing {n}",
            {"sel": {"k|contains": "backdoor"}, "condition": "sel"},
        )
        for n in range(5)
    ]
    sagan = make_record(
        "Some backdoor", {"sel": {"k|contains": "backdoor"}, "condition": "sel"}
    )
    sigmahq = make_record(
        "Another backdoor",
        {"sel": {"k|contains": "backdoor"}, "condition": "sel"},
        origin="sigmahq",
    )
    result = analyse([sagan, *common], [sigmahq], **LOOSE)
    assert result.candidates == []


def test_shared_technique_alone_does_not_make_a_candidate() -> None:
    # The two share a technique but no distinctive token, so blocking never even
    # compares them: ATT&CK cannot manufacture a candidate.
    sagan = make_record(
        "Linux daemon oddity",
        {"sel": {"k|contains": "wibble"}, "condition": "sel"},
        tags=["attack.t1078"],
    )
    sigmahq = make_record(
        "Windows account thing",
        {"sel": {"k|contains": "flumph"}, "condition": "sel"},
        origin="sigmahq",
        tags=["attack.t1078"],
    )
    result = analyse([sagan, *FILLERS_SAGAN], [sigmahq, *FILLERS_SIGMA], **LOOSE)
    assert all(c.sagan_key != sagan.key for c in result.candidates)


def test_top_k_limits_candidates_per_rule() -> None:
    sagan = make_record(
        "mimikatz dumper",
        {"sel": {"k|contains": "mimikatz"}, "condition": "sel"},
    )
    sigma = [
        make_record(
            f"mimikatz variant {n}",
            {"sel": {"k|contains": "mimikatz"}, "condition": "sel"},
            origin="sigmahq",
        )
        for n in range(4)
    ]
    result = analyse(
        [sagan, *FILLERS_SAGAN],
        [*sigma, *FILLERS_SIGMA],
        min_lexical=0.3,
        block_idf=0.1,
        top_k=2,
    )
    mine = [c for c in result.candidates if c.sagan_key == sagan.key]
    assert len(mine) == 2


def test_is_deterministic() -> None:
    sagan = make_record(
        "whoami recon", {"sel": {"k|contains": "whoami"}, "condition": "sel"}
    )
    sigmahq = make_record(
        "Renamed Whoami Execution",
        {"sel": {"k|contains": "whoami"}, "condition": "sel"},
        origin="sigmahq",
    )
    corpora = ([sagan, *FILLERS_SAGAN], [sigmahq, *FILLERS_SIGMA])
    first = analyse(*corpora, **LOOSE).candidates
    second = analyse(*corpora, **LOOSE).candidates
    assert [(c.sagan_key, c.sigmahq_key, c.composite) for c in first] == [
        (c.sagan_key, c.sigmahq_key, c.composite) for c in second
    ]


def test_build_json_shape() -> None:
    sagan = make_record(
        "whoami recon",
        {"sel": {"k|contains": "whoami"}, "condition": "sel"},
        sagan_sid="5000009",
    )
    sigmahq = make_record(
        "Renamed Whoami Execution",
        {"sel": {"k|contains": "whoami"}, "condition": "sel"},
        origin="sigmahq",
    )
    payload = build_json(analyse([sagan, *FILLERS_SAGAN], [sigmahq], **LOOSE))
    assert payload["kind"] == "conceptual"
    assert payload["summary"]["candidates"] == len(payload["candidates"])
    first = payload["candidates"][0]
    assert first["sagan"]["sid"] == "5000009"
    assert "whoami" in first["shared_terms"]
    assert 0.0 <= first["lexical_similarity"] <= 1.0
