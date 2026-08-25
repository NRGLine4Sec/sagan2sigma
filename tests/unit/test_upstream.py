"""Tests for the upstream-defect detectors.

Each case mirrors a behaviour measured against a locally built Sagan, and the
docstrings say which. They are unit tests of the detector, not of the engine:
what the engine does is pinned in the engine lab, outside this repository.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_rule

from sagan2sigma.sagan.parser import parse_rule
from sagan2sigma.upstream import DefectCode, inspect


def codes(
    raw: str,
    header: str = "alert any",
    destination_port: str = "any",
) -> set[DefectCode]:
    """Defect codes for one rule, built from its options and header.

    ``header`` carries the action and the protocol together, since the two
    sit side by side in the rule and some detectors read the protocol.
    """
    if header == "alert any" and destination_port == "any":
        return {defect.code for defect in inspect(make_rule(raw))}
    line = f"{header} $EXTERNAL_NET any -> $HOME_NET {destination_port} ({raw})"
    return {defect.code for defect in inspect(parse_rule(line, "test.rules", 1))}


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

    def test_non_hex_after_an_unterminated_pipe(self) -> None:
        """Validate_HEX rejects the pair and aborts the load.

        Measured: `content:"al|pha"` makes the engine exit 1 with
        `Invalid 'ph' Hex detected`.
        """
        raw = 'msg:"t"; content:"al|pha"; sid:1;'
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


class TestUnterminatedHex:
    """A `|` that opens a hex sequence and never closes it.

    Every row here was measured on a reduced rule against a locally built
    Sagan, because the outcome is not guessable from the syntax: two of the
    shapes are harmless and the rest are not.
    """

    @pytest.mark.parametrize(
        ("value", "flagged"),
        [
            ("|7c|DetectionSummaryEvent|4", True),  # sid 5004756, as it ships
            ("|7c|DetectionSummaryEvent|7c|4", False),  # the fix
            ("alpha|", False),  # a trailing pipe adds nothing
            ("alpha|41", False),  # two digits land on the end and convert
            ("alpha|412", True),
            ("alpha|4142", True),
            ("|7c|plain|7c|", False),
        ],
    )
    def test_content(self, value: str, flagged: bool) -> None:
        raw = f'msg:"t"; content:"{value}"; sid:1;'
        assert (DefectCode.CANNOT_MATCH in codes(raw)) is flagged

    def test_the_negated_form_is_flagged_too(self) -> None:
        """A dead negation is worse: the rule matches everything instead."""
        raw = 'msg:"t"; content:"x"; content:!"|7c|Event|4"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_a_pcre_value_on_the_same_line_is_not_examined(self) -> None:
        """The pcre option does not go through Content_Pipe.

        This is the mistake worth guarding: reading every quoted string after a
        keyword instead of that keyword's own argument turns every `(a|b)` in a
        neighbouring pcre into a false positive.
        """
        raw = 'msg:"t"; content:"ok"; pcre:"/dstport=(80|443)[^\\d]/"; sid:1;'
        assert codes(raw) == set()

    def test_meta_content_list_is_examined_whole(self) -> None:
        """The whole comma-separated list is expanded before it is split.

        Both rows were measured. The comma matters: mid-list the pair is `4,`,
        which Validate_HEX rejects and the load aborts, while at the end of the
        list the pair is `4` alone and the rule loads and matches nothing.
        """
        mid = 'msg:"t"; content:"x"; meta_content:"%sagan%",aaa,bb|4,ccc; sid:1;'
        assert DefectCode.WILL_NOT_LOAD in codes(mid)

        end = 'msg:"t"; content:"x"; meta_content:"%sagan%",aaa,bbb|4; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(end)


class TestPunctuation:
    """A forgotten `;` swallows the next option into a quoted argument."""

    def test_content_missing_its_semicolon(self) -> None:
        """Measured on the twelve web-attack rules: they match nothing at all."""
        raw = 'msg:"t"; content:"index.php?system=" default_proto:tcp; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_program_missing_its_semicolon(self) -> None:
        raw = (
            'msg:"t"; content:"x"; '
            "program: DigitalPersona* after: track by_src, count 5, seconds 300; sid:1;"
        )
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_a_doubled_opening_quote_is_harmless(self) -> None:
        """`content:""text` looks broken and is not.

        Between_Quotes lowers its flag on the second quote and raises it again
        on the same character, so the value captured is the text that follows.
        Measured: the rule alerts. Three corpus rules of this shape were first
        reported as unloadable, which was Bluedot and dynamic_load in the same
        files rather than the quotes; the prediction and the observation were
        wrong together, which is why this case is pinned.
        """
        raw = 'msg:"t"; content:""established successfully; sid:1;'
        assert codes(raw) == set()

    def test_a_stray_quote_alone_is_harmless(self) -> None:
        """A trailing bare quote is harmless, as sid 5007405 shows.

        The distinction matters: flagging any trailing character reported it as
        dead, and the engine disagreed.
        """
        raw = 'msg:"t"; content:"\xa0""; sid:1;'
        assert codes(raw) == set()

    def test_a_normal_content_is_clean(self) -> None:
        raw = 'msg:"t"; content:"index.php?system="; default_proto:tcp; sid:1;'
        assert codes(raw) == set()


class TestHeaderConditions:
    """Header fields the engine holds an event to, and those it does not."""

    def test_tcp_header_without_default_proto(self) -> None:
        """A syslog event defaults to udp, so tcp never matches."""
        raw = 'msg:"t"; content:"x"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw, header="alert tcp")

    def test_tcp_header_with_default_proto_is_fine(self) -> None:
        raw = 'msg:"t"; content:"x"; default_proto:tcp; sid:1;'
        assert codes(raw, header="alert tcp") == set()

    @pytest.mark.parametrize("protocol", ["any", "udp", "syslog"])
    def test_protocols_a_syslog_event_satisfies(self, protocol: str) -> None:
        raw = 'msg:"t"; content:"x"; sid:1;'
        assert codes(raw, header=f"alert {protocol}") == set()

    def test_destination_port_without_default(self) -> None:
        raw = 'msg:"t"; content:"x"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(
            raw, header="alert any", destination_port="$FTP_PORT"
        )

    def test_an_address_variable_in_the_port_slot_is_not_a_port(self) -> None:
        """`-> any $HOME_NET` puts an address where the port goes and matches.

        Treating every non-`any` port slot as a filter reported 22 rules, 14 of
        them healthy, which is how this case was found.
        """
        raw = 'msg:"t"; content:"x"; sid:1;'
        assert codes(raw, header="alert any", destination_port="$HOME_NET") == set()


class TestInvertedCondition:
    def test_negated_pcre(self) -> None:
        """Sagan has no negation for pcre, so the `!` is silently dropped.

        Measured both ways on a reduced rule: with the pattern absent the rule
        stays silent, and with it present the rule alerts. That is the opposite
        of what it says.
        """
        raw = 'msg:"t"; content:"x"; pcre:!"/ZZZ/"; sid:1;'
        assert DefectCode.INVERTED_CONDITION in codes(raw)

    def test_a_positive_pcre_is_clean(self) -> None:
        raw = 'msg:"t"; content:"x"; pcre:"/ZZZ/"; sid:1;'
        assert codes(raw) == set()


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
