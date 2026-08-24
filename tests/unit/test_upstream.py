"""Tests for the upstream-defect detectors.

Each case mirrors a behaviour measured against a locally built Sagan, and the
docstrings say which. They are unit tests of the detector, not of the engine:
what the engine does is pinned in the engine lab, outside this repository.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_rule

from sagan2sigma.upstream import DefectCode, inspect


def codes(raw: str) -> set[DefectCode]:
    return {defect.code for defect in inspect(make_rule(raw))}


class TestWillNotLoad:
    """Rules the engine refuses, taking the whole ruleset with them."""

    def test_after_with_only_an_unrecognised_key(self) -> None:
        """The parser needs a recognised key to reach its validity count.

        sid 5008760 does this with by_tag, and Sagan exits 1 rather than start.
        """
        raw = 'msg:"t"; content:"x"; after: track by_tag, count 5, seconds 300; sid:1;'
        assert DefectCode.WILL_NOT_LOAD in codes(raw)

    def test_a_recognised_key_beside_it_is_enough(self) -> None:
        raw = (
            'msg:"t"; content:"x"; '
            "after: track by_src&by_tag, count 5, seconds 300; sid:1;"
        )
        assert DefectCode.WILL_NOT_LOAD not in codes(raw)

    def test_xbits_toggle(self) -> None:
        """The branch honouring it is commented out, so xbit_type stays 0."""
        raw = 'msg:"t"; content:"x"; xbits: toggle,b,track ip_src; sid:1;'
        assert DefectCode.WILL_NOT_LOAD in codes(raw)

    def test_by_string_alone_is_not_flagged(self) -> None:
        """by_string is inert under after but counts toward validity.

        Flagging it would be wrong: the rule loads. The distinction is only
        visible by running the engine, which is why it is asserted here.
        """
        raw = (
            'msg:"t"; content:"x"; after: track by_string, count 5, seconds 300; sid:1;'
        )
        assert DefectCode.WILL_NOT_LOAD not in codes(raw)


class TestCannotMatch:
    """Rules that load and can never fire."""

    def test_negated_meta_content_with_a_colon(self) -> None:
        r"""The value is cut at the colon, so the search is the text before it.

        `c:\\program files\\...` searches for `c`, and almost every message
        holds one, so the negation is almost never satisfied.
        """
        raw = (
            'msg:"t"; content:"x"; '
            'meta_content:!"%sagan%",c:\\program files\\AVAST\\; sid:1;'
        )
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_a_positive_one_is_not_flagged(self) -> None:
        """Truncation makes it broader, not dead, so it is a different problem."""
        raw = (
            'msg:"t"; content:"x"; '
            'meta_content:"%sagan%",c:\\program files\\AVAST\\; sid:1;'
        )
        assert DefectCode.CANNOT_MATCH not in codes(raw)

    def test_an_escaped_colon_is_fine(self) -> None:
        raw = (
            'msg:"t"; content:"x"; '
            'meta_content:!"%sagan%",c|3a|\\program files\\AVAST\\; sid:1;'
        )
        assert codes(raw) == set()

    @pytest.mark.parametrize(
        ("key", "flagged"),
        [
            ("a" * 30, False),
            ("a" * 31, True),
            ("data.authorizationInfo.granted", False),
            ("data.authorizationInfo.operation", True),
        ],
    )
    def test_json_key_length(self, key: str, flagged: bool) -> None:
        """Measured to the character: 30 matches, 31 does not.

        The two realistic keys differ by one character and sit either side of
        the limit, which is what makes the boundary worth asserting.
        """
        raw = f'msg:"t"; json_content:".{key}","v"; sid:1;'
        assert (DefectCode.CANNOT_MATCH in codes(raw)) is flagged


class TestWrongGrouping:
    """Rules that fire but count the wrong thing."""

    def test_mistyped_username_key(self) -> None:
        """by_user is not by_username; after compares with an exact strcmp."""
        raw = (
            'msg:"t"; content:"x"; '
            "after: track by_src&by_user, count 5, seconds 300; sid:1;"
        )
        assert DefectCode.WRONG_GROUPING in codes(raw)

    def test_correct_spelling_is_clean(self) -> None:
        raw = (
            'msg:"t"; content:"x"; '
            "after: track by_src&by_username, count 5, seconds 300; sid:1;"
        )
        assert codes(raw) == set()

    def test_a_lone_typo_is_a_load_failure_not_a_grouping_one(self) -> None:
        """With no recognised key beside it the rule does not load at all."""
        found = codes(
            'msg:"t"; content:"x"; after: track by_user, count 5, seconds 300; sid:1;'
        )
        assert DefectCode.WILL_NOT_LOAD in found
        assert DefectCode.WRONG_GROUPING not in found


class TestQuietRules:
    def test_an_ordinary_rule_reports_nothing(self) -> None:
        raw = 'msg:"t"; program: sshd; content:"failed"; sid:1;'
        assert codes(raw) == set()
