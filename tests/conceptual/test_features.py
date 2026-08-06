"""Tests for concept-fingerprint extraction."""

from __future__ import annotations

from sagan2sigma.conceptual.features import (
    STOPWORDS,
    extract_techniques,
    fingerprint,
    tokenise,
)


def test_extract_techniques_keeps_subtechniques() -> None:
    doc = {"tags": ["attack.t1059.001", "attack.T1055", "attack.execution", "misc"]}
    assert extract_techniques(doc) == frozenset({"t1059.001", "t1055"})


def test_extract_techniques_none() -> None:
    assert extract_techniques({}) == frozenset()
    assert extract_techniques({"tags": ["attack.execution"]}) == frozenset()


def test_tokenise_keeps_filenames_and_paths() -> None:
    tokens = tokenise("Runs sethc.exe and reads /etc/passwd via cmd.exe")
    assert "sethc.exe" in tokens
    # The leading slash is stripped, but the distinctive path body survives.
    assert "etc/passwd" in tokens
    assert "cmd.exe" in tokens


def test_tokenise_drops_stopwords_digits_and_short() -> None:
    tokens = tokenise("the windows process 4625 ab created")
    assert "the" not in tokens  # stopword
    assert "windows" not in tokens  # stopword
    assert "4625" not in tokens  # pure digit
    assert "ab" not in tokens  # too short
    assert "created" in tokens
    # Sanity: the stoplist is the reason, not an accident.
    assert "windows" in STOPWORDS


def test_fingerprint_pulls_literals_from_detection() -> None:
    fp = fingerprint(
        key="sagan:x",
        origin="sagan",
        title="Sticky Key Backdoor",
        source="win.rules",
        sagan_sid="5000001",
        document={
            "description": "Detects sethc.exe debugger",
            "tags": ["attack.t1546.008"],
            "detection": {
                "sel": {"CommandLine|contains": "sethc.exe"},
                "condition": "sel",
            },
        },
    )
    assert "sethc.exe" in fp.tokens
    assert fp.techniques == frozenset({"t1546.008"})
    # The condition keyword is not a token.
    assert "sel" not in fp.tokens
