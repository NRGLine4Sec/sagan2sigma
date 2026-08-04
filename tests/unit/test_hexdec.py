"""Tests for the Sagan hexadecimal escape decoder."""

from __future__ import annotations

import pytest

from sagan2sigma.sagan.hexdec import decode_hex, has_hex


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("User Agent|3a| Testing", "User Agent: Testing"),
        ("no escapes", "no escapes"),
        ("", ""),
        ("|22|key|22 3a 20 22|value|22|", '"key": "value"'),
        ("This |3a| is a test with |3b| in it", "This : is a test with ; in it"),
        ("|3a 3b 3c|", ":;<"),
        ("Azure|20|AD|20|joined", "Azure AD joined"),
        ("|3A|", ":"),
        ("|3a\t3b|", ":;"),
    ],
)
def test_decodes_known_sequences(raw: str, expected: str) -> None:
    assert decode_hex(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "a|not hex|b",
        "pipe | alone",
        "|zz|",
        "|3|",
        "|333|",
        "100|200",
    ],
)
def test_leaves_non_sequences_untouched(raw: str) -> None:
    """An unpaired or malformed pipe must survive: the corpus contains both."""
    assert decode_hex(raw) == raw


def test_decoding_is_idempotent_on_plain_text() -> None:
    assert decode_hex(decode_hex("plain text")) == "plain text"


def test_has_hex() -> None:
    assert has_hex("a|3a|b")
    assert not has_hex("a|b|c")
    assert not has_hex("")
