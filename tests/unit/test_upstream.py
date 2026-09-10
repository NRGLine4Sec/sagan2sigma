"""Tests for the upstream-defect detectors.

Each case mirrors a behaviour measured against a locally built Sagan, and the
docstrings say which. They are unit tests of the detector, not of the engine:
what the engine does is pinned in the engine lab, outside this repository.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_rule

from sagan2sigma.sagan.parser import parse_lines, parse_rule
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


class TestArrayMarkedJsonKey:
    """A `[]` in a JSON key is two characters of the name, not a marker.

    Measured one condition at a time on the engine: `.data.items[]` fires only
    on a document whose key is literally `items[]`, never on `items` holding an
    array, with or without json_contains, while `.data.items` fires on the
    scalar and, under json_contains, on the serialised array. `json.c` builds
    each stored path with `snprintf("%s.%s")` and compares it with strcmp, so
    there is nowhere for a marker to be understood. sid 5004770 is the only
    corpus rule of this shape and its condition is negated, which cannot save
    it: the engine needs the key present to satisfy a negation.
    """

    @pytest.mark.parametrize(
        "keyword", ["json_content", "json_meta_content", "json_pcre"]
    )
    def test_the_marker_kills_the_rule(self, keyword: str) -> None:
        raw = f'msg:"t"; {keyword}:".data.items[]","alpha"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_the_negated_form_too(self) -> None:
        raw = 'msg:"t"; json_meta_content:!".data.items[]",alpha; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_the_plain_key_is_fine(self) -> None:
        raw = 'msg:"t"; json_content:".data.items","alpha"; sid:1;'
        assert codes(raw) == set()


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


class TestQuotedListItems:
    """A value list is compared verbatim, quotes included.

    Measured on the engine, both keywords: `json_meta_content:".k","v"` matches
    an event whose value is the quoted `"v"` and not the bare `v`, while the
    same option without the quotes does the reverse. `json_content`, which
    takes one quoted argument rather than a list, is unaffected: its quotes
    delimit the value.
    """

    def test_every_item_quoted_cannot_match(self) -> None:
        raw = 'msg:"t"; json_meta_content:".eventtype","analytics"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_negated_list_never_excludes(self) -> None:
        """The reduced form of sid 5014486, fortinet-json.rules.

        The rule fires, which is why this is not CANNOT_MATCH: an exclusion
        that matches nothing excludes nothing, so the rule alerts on the very
        events it names as exceptions.
        """
        raw = (
            'msg:"t"; json_content:".type","utm"; '
            'json_meta_content:!".eventtype","analytics"; sid:1;'
        )
        assert DefectCode.INERT_CONDITION in codes(raw)

    def test_meta_content_too(self) -> None:
        raw = 'msg:"t"; meta_content:"USER=%sagan%","root"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_one_bare_item_keeps_the_list_alive(self) -> None:
        """The list is an OR, so a single unquoted item can still match."""
        raw = 'msg:"t"; json_meta_content:".eventtype",analytics,"utm"; sid:1;'
        assert codes(raw) == set()

    def test_a_bare_list_is_clean(self) -> None:
        raw = 'msg:"t"; json_meta_content:".eventtype",analytics,utm; sid:1;'
        assert codes(raw) == set()

    def test_json_content_quotes_are_the_delimiters(self) -> None:
        raw = 'msg:"t"; json_content:".eventtype","analytics"; sid:1;'
        assert codes(raw) == set()


class TestQuoteInsideAPcrePattern:
    r"""The engine compiles a different pattern, which is not the same as none.

    An earlier version of this detector called such a rule dead. Six of the
    twelve corpus rules that carry a quote fire on the text they target, which
    the engine said when it was asked one rule at a time, so what is reported
    now is the alteration and not a consequence. `tests/unit/test_pcre_option`
    holds the measured rows for the pattern itself.
    """

    def test_a_quote_alters_the_pattern(self) -> None:
        raw = 'msg:"t"; content:"x"; pcre:"/id=\\"[0-9]{3}/"; sid:1;'
        assert DefectCode.ALTERED_PATTERN in codes(raw)

    def test_the_detail_names_the_pattern_the_engine_runs(self) -> None:
        raw = 'msg:"t"; content:"x"; pcre:"/id=\\"[0-9]{3}/"; sid:1;'
        defect = next(
            d for d in inspect(make_rule(raw)) if d.code is DefectCode.ALTERED_PATTERN
        )
        assert r"/id=\[0-9]{3}/" in defect.detail

    def test_an_escaped_closing_delimiter_stops_the_load(self) -> None:
        raw = 'msg:"t"; content:"x"; pcre:"/a\\"/i"; sid:1;'
        assert DefectCode.WILL_NOT_LOAD in codes(raw)

    def test_an_apostrophe_is_fine(self) -> None:
        raw = 'msg:"t"; content:"x"; pcre:"/id=\'[0-9]{3}/"; sid:1;'
        assert codes(raw) == set()

    def test_a_pattern_without_quotes_is_fine(self) -> None:
        raw = 'msg:"t"; content:"x"; pcre:"/id=[0-9]{3}/"; sid:1;'
        assert codes(raw) == set()

    def test_the_x22_spelling_is_not_flagged(self) -> None:
        """The fix proposed upstream must not be reported as a defect."""
        raw = 'msg:"t"; content:"x"; pcre:"/id=\\x22[0-9]{3}/"; sid:1;'
        assert codes(raw) == set()


class TestNegatedContentInsideAPositiveOne:
    """`content` ANDs, and its negation is a plain substring test.

    So a message holding the required text holds the excluded text with it,
    and the rule cannot fire on the very event it describes. Measured on sid
    5015819 of barracuda-waf.rules: an event carrying `DENY_ACL_MATCHED`, its
    own literal, does not alert.
    """

    def test_the_negation_swallows_its_own_rule(self) -> None:
        raw = 'msg:"t"; content:"DENY_ACL_MATCHED"; content:!"DENY"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_an_unrelated_negation_is_clean(self) -> None:
        raw = 'msg:"t"; content:"DENY_ACL_MATCHED"; content:!"ALLOW"; sid:1;'
        assert codes(raw) == set()

    def test_the_hex_form_is_decoded_first(self) -> None:
        """`|20|` is a space, so the containment has to be judged after it."""
        raw = 'msg:"t"; content:"user|20|denied"; content:!"user denied"; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)


class TestCommaInsideTheMetaTemplate:
    """`rules.c` cuts the option on the first comma, then unquotes the piece.

    So a comma inside the quoted template ends it, and everything after it,
    closing quote included, is pushed into the value list. Measured on the
    engine in all three of its consequences.
    """

    def test_a_variable_in_the_values_makes_it_dead(self) -> None:
        raw = 'msg:"t"; meta_content:"MD5=%sagan%,",$PSEXEC_MD5; sid:1;'
        assert DefectCode.CANNOT_MATCH in codes(raw)

    def test_literal_values_lose_the_first_alternative(self) -> None:
        """The stray quote lands on it, and no message carries that."""
        raw = 'msg:"t"; meta_content:"%sagan%,"|5c|powershell,|5c|pwsh.exe; sid:1;'
        assert DefectCode.PARTIAL_MATCH in codes(raw)

    def test_a_template_without_a_comma_is_clean(self) -> None:
        raw = 'msg:"t"; meta_content:"MD5=%sagan% ",$PSEXEC_MD5; sid:1;'
        assert codes(raw) == set()

    def test_an_unclosed_template_is_not_this_defect(self) -> None:
        """The whole option is quoted here, template and values together.

        The engine still cuts at the first comma and Between_Quotes takes the
        text after the lone quote, so the template is what the author meant and
        only the last value carries the closing quote, which is the character a
        CloudTrail document has there anyway.
        """
        raw = (
            'msg:"t"; meta_content:"eventName|22 3a 20 22|%sagan%,'
            'AttachRolePolicy,PutBucketPolicy"; sid:1;'
        )
        assert DefectCode.CANNOT_MATCH not in codes(raw)
        assert DefectCode.PARTIAL_MATCH not in codes(raw)


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


class TestClippedKeyPath:
    """Upstream's clipped-key workaround does not always reach the value.

    The engine stores a dotted key path clipped to 31 characters, counting the
    leading dot, and upstream names the clipped path so the exact strcmp
    succeeds. That holds only when the clip lands on the last segment.
    """

    MARK = (
        "# [truncated for JSON_MAX_KEY_SIZE=32 engine limit -- legacy engine "
        "stores keys clipped to 31 chars, full path never matches] "
    )

    def defects(self, full: str, short: str) -> set[DefectCode]:
        lines = [
            self.MARK + f".{full} -> .{short}",
            f'alert any any any -> any any (msg:"t"; '
            f'json_content:".{short}","v"; sid:1;)',
        ]
        rules, _, _ = parse_lines(lines, "f.rules")
        return {defect.code for defect in inspect(rules[0])}

    def test_a_clip_landing_on_the_last_segment_is_fine(self) -> None:
        """A clip landing on the last segment is fine, as sid 5005921 shows.

        Measured: the rule alerts on an event carrying the full path.
        """
        assert (
            self.defects(
                "data.authorizationInfo.operation", "data.authorizationInfo.operati"
            )
            == set()
        )

    def test_a_clip_above_a_further_level_is_dead(self) -> None:
        """In sid 5005923 the clip lands inside `metadata`, `mechanism` below it.

        Measured: neither the clipped nor the full key matches, and nesting
        depth alone is not the cause, five short levels matching fine.
        """
        assert DefectCode.CANNOT_MATCH in self.defects(
            "data.authenticationInfo.metadata.mechanism",
            "data.authenticationInfo.metada",
        )


class TestThresholdKeys:
    """threshold recognises its keys differently from after.

    It tests the whole track value with Sagan_strstr rather than comparing each
    token with strcmp, and by_string is a real synonym for by_username there.
    Measured on sid 5014022's shape, three events with different usernames from
    one source under `type suppress, count 1`: by_src&by_username alerts three
    times, by_src&byusername once, and by_src alone once.
    """

    def test_a_mistyped_key_is_never_found(self) -> None:
        """`by_username` is not a substring of `by_src&byusername`."""
        raw = (
            'msg:"t"; content:"x"; '
            "threshold: type suppress, track by_src&byusername, count 1, "
            "seconds 3600; sid:1;"
        )
        assert DefectCode.WRONG_GROUPING in codes(raw)

    def test_the_correct_spelling_is_clean(self) -> None:
        raw = (
            'msg:"t"; content:"x"; '
            "threshold: type suppress, track by_src&by_username, count 1, "
            "seconds 3600; sid:1;"
        )
        assert codes(raw) == set()

    def test_by_string_is_a_synonym_here(self) -> None:
        """Unlike under after, where the token is truncated before the test."""
        raw = (
            'msg:"t"; content:"x"; '
            "threshold: type suppress, track by_string, count 1, seconds 3600; sid:1;"
        )
        assert codes(raw) == set()

    def test_no_recognised_key_stops_the_load(self) -> None:
        """Sid 5008760 does this, and rules.c:3370 rejects the option."""
        raw = (
            'msg:"t"; content:"x"; '
            "threshold: type suppress, track by_tag, count 1, seconds 3600; sid:1;"
        )
        assert DefectCode.WILL_NOT_LOAD in codes(raw)
