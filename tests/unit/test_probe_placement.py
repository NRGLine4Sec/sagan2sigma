"""Putting a rule's literals where the serialised document will contain them.

A rule that searches raw text on a JSON-bodied event searches the *serialised*
document, so a literal carrying quotes cannot sit in a string value: the
serialiser escapes it and both evaluators then look for text the document does
not hold. They agree on silence, which reads as success and measures nothing.

The literals here are corpus ones. Each shape below came from a rule the
differential could not decide, and the rules that remain undecidable are listed
at the end with the reason, so the boundary is written down rather than
rediscovered.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_rule
from tests.differential.events import (
    build_base,
    positive_literals,
    unplaceable,
    wire_body,
)


def stuck(raw: str) -> list[str]:
    rule = make_rule(raw)
    return unplaceable(rule, positive_literals(rule))


JSON_RULE = 'msg:"t"; program: p; json_content:".Operation","New-InboxRule"; '


class TestFragmentsOfTheDocumentItself:
    """A literal that is a slice of a serialised document is put back as one."""

    @pytest.mark.parametrize(
        ("literal", "shape"),
        [
            (
                "|22|Name|22 3a 20 22|Name|22|,|20 22|Value|22 3a 20 22|.",
                "stops mid-value",
            ),
            ("Name|22 3a 22|MoveToFolder", "starts mid-key"),
            ("|22|mfaAuthenticated|22 3a 20 22|true|22|", "a whole member"),
            ("eventName|22 3a 20 22|CreateFunction", "no outer quotes"),
            (
                "risk_score|22 3a 22|76|22|",
                "a member missing only its opening quote, the `\\x22` shape",
            ),
            (
                "FromAddressContainsWords|22|,|22|Value|22 3a 22|@",
                "a run crossing from one value into the next member",
            ),
        ],
    )
    def test_placed(self, literal: str, shape: str) -> None:
        assert not stuck(f'{JSON_RULE} content:"{literal}"; sid:1;'), shape

    def test_two_literals_wanting_the_same_key(self) -> None:
        """One object cannot hold a key twice, so the second key is renamed.

        sid 5017920 searches for `Name":"MoveToFolder` and `Name":"RedirectTo`.
        Both start inside the key, so a key ending in `Name` carries either, and
        the second placement takes a prefixed one rather than overwriting the
        first. Before this, the second literal was dropped and the rule stayed
        undecided.
        """
        raw = (
            f"{JSON_RULE} "
            'content:"Name|22 3a 22|MoveToFolder"; '
            'content:"Name|22 3a 22|RedirectTo"; sid:1;'
        )
        assert not stuck(raw)

    def test_the_rename_does_not_overwrite_the_first_literal(self) -> None:
        """The event has to carry both, which is the point of renaming."""
        rule = make_rule(
            f"{JSON_RULE} "
            'content:"Name|22 3a 22|MoveToFolder"; '
            'content:"Name|22 3a 22|RedirectTo"; sid:1;'
        )
        body = wire_body(build_base(rule))
        assert 'Name":"MoveToFolder' in body
        assert 'Name":"RedirectTo' in body


class TestWhatCannotBePlaced:
    """Named rather than silently retried, because each is a different limit."""

    def test_quotes_inside_a_sentence(self) -> None:
        """No JSON string can hold them unescaped, so no document carries it.

        sid 5013740: `Supported Encryption Type changed to "23"`.
        """
        raw = f'{JSON_RULE} content:"changed to |22|23|22|"; sid:1;'
        assert stuck(raw)

    def test_two_fragments_wanting_different_spacing(self) -> None:
        """One document has one serialisation, and these ask for two.

        sid 99557 searches for `", "Value": "False"` and `","Value":"16"`. The
        first is a spaced serialiser's output and the second a compact one's.
        """
        raw = (
            f"{JSON_RULE} "
            'content:"A|22|,|20 22|Value|22 3a 20 22|False|22|"; '
            'content:"B|22|,|22|Value|22 3a 22|16|22|"; sid:1;'
        )
        assert stuck(raw)
