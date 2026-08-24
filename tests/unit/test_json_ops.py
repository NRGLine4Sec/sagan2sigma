"""Tests for the Sagan JSON operators."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.json_ops import (
    handle_json_content,
    handle_json_meta_content,
    handle_json_pcre,
    parse_json_args,
)


class TestParseJsonArgs:
    def test_splits_key_and_value(self) -> None:
        assert parse_json_args('".eventName","CreateTrail"', "json_content") == (
            False,
            "eventName",
            '"CreateTrail"',
        )

    def test_detects_negation(self) -> None:
        assert parse_json_args('!".a","b"', "json_content")[0] is True

    def test_accepts_nested_keys(self) -> None:
        assert parse_json_args('".a.b.c","x"', "json_content")[1] == "a.b.c"

    def test_accepts_array_keys(self) -> None:
        assert parse_json_args('".a[].b","x"', "json_content")[1] == "a[].b"

    def test_rejects_a_malformed_argument(self) -> None:
        with pytest.raises(Refusal, match="unparsable"):
            parse_json_args("garbage", "json_content")


class TestJsonContent:
    def test_literal_match_is_exact(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_content:".eventName","CreateTrail"; sid:1;')
        run(handle_json_content, rule, draft, context)
        predicate = draft.predicates[0]
        assert predicate.field == "eventName"
        assert predicate.modifiers == ("cased",)
        assert predicate.values == ("CreateTrail",)

    def test_json_contains_switches_to_substring(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; json_content:".name","example"; json_contains; sid:1;'
        )
        run(handle_json_content, rule, draft, context)
        assert draft.predicates[0].modifiers == ("contains", "cased")

    def test_json_nocase_drops_cased(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_content:".a","b"; json_nocase; sid:1;')
        run(handle_json_content, rule, draft, context)
        assert draft.predicates[0].modifiers == ()

    def test_numeric_value_becomes_an_integer(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_content:".EventID","4624"; sid:1;')
        run(handle_json_content, rule, draft, context)
        assert draft.predicates[0].values == (4624,)

    def test_numeric_value_never_carries_cased(self, draft: RuleDraft, context) -> None:
        """PySigma rejects `field|cased: 4624`: case is undefined on a number.

        157 corpus rules hit this before the guard existed.
        """
        rule = make_rule('msg:"t"; json_content:".resultType","0"; sid:1;')
        run(handle_json_content, rule, draft, context)
        assert draft.predicates[0].modifiers == ()

    def test_numeric_under_contains_stays_a_string(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule('msg:"t"; json_content:".a","404"; json_contains; sid:1;')
        run(handle_json_content, rule, draft, context)
        assert draft.predicates[0].values == ("404",)

    def test_negation_also_requires_the_key(self, draft: RuleDraft, context) -> None:
        """Sagan can only satisfy a negated condition on a key it finds.

        The engine walks the event's keys, so a missing key fails the rule,
        while Sigma reads `not field: value` as satisfied when the field is
        absent. Measured against a running engine, and the exists guard beside
        the negation reproduces all three cases. 200 upstream rules carry one.
        """
        rule = make_rule('msg:"t"; json_content:!".sni","www.example.com"; sid:1;')
        run(handle_json_content, rule, draft, context)
        guard, negated = draft.predicates
        assert guard.field == "sni"
        assert guard.modifiers == ("exists",)
        assert guard.rendered_value is True
        assert negated.negated

    def test_decodes_hex_escapes(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_content:".a","x|3a|y"; sid:1;')
        run(handle_json_content, rule, draft, context)
        assert draft.predicates[0].values == ("x:y",)

    # Only this spelling exists. json_base64_decode is not in Sagan's
    # VALID_RULE_OPTIONS and the engine aborts the ruleset on it, so it is no
    # longer recognised here either and falls through to E_UNKNOWN_KEYWORD.
    @pytest.mark.parametrize("flag", ["json_decode_base64"])
    def test_refuses_base64_field_decoding(
        self, draft: RuleDraft, context, flag: str
    ) -> None:
        """Sagan decodes the field, Sigma encodes the pattern; not equivalent."""
        rule = make_rule(f'msg:"t"; json_content:".payload","BOB"; {flag}; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_json_content, rule, draft, context)
        assert excinfo.value.code is RefusalCode.BASE64_FIELD_DECODE


class TestJsonMetaContent:
    def test_value_list_is_an_or(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_meta_content:".threat",medium,low; sid:1;')
        run(handle_json_meta_content, rule, draft, context)
        assert draft.predicates[0].values == ("medium", "low")

    def test_negation_also_requires_the_key(self, draft: RuleDraft, context) -> None:
        """As for json_content: the key has to exist for Sagan to be satisfied."""
        rule = make_rule('msg:"t"; json_meta_content:!".threat",low; sid:1;')
        run(handle_json_meta_content, rule, draft, context)
        guard, negated = draft.predicates
        assert guard.modifiers == ("exists",)
        assert negated.negated

    def test_json_meta_contains(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; json_meta_content:".a",x,y; json_meta_contains; sid:1;'
        )
        run(handle_json_meta_content, rule, draft, context)
        assert draft.predicates[0].modifiers == ("contains", "cased")

    def test_refuses_an_empty_value_list(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_meta_content:".a",  ; sid:1;')
        with pytest.raises(Refusal):
            run(handle_json_meta_content, rule, draft, context)


class TestJsonPcre:
    def test_emits_a_re_predicate_on_the_key(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_pcre:".sni","/example\\.com/i"; sid:1;')
        run(handle_json_pcre, rule, draft, context)
        predicate = draft.predicates[0]
        assert predicate.field == "sni"
        assert predicate.modifiers == ("re", "i")

    def test_rejects_a_non_portable_pattern(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_pcre:".a","/(x)(?R)/"; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_json_pcre, rule, draft, context)
        assert excinfo.value.code is RefusalCode.PCRE_UNSUPPORTED

    def test_reports_the_absent_key_divergence(self, draft: RuleDraft, context) -> None:
        """Sagan counts a missing key as a match here; the Sigma rule does not.

        JSON_Pcre() tests only keys the event carries and returns false only on
        a failed match, so an absent key falls through to true. Measured
        against a running engine, including with a pattern that can match
        nothing. json_content and json_meta_content do not share this.
        """
        rule = make_rule('msg:"t"; json_pcre:".sni","/x/"; sid:1;')
        run(handle_json_pcre, rule, draft, context)
        assert any(
            d.code is DegradationCode.JSON_PCRE_ABSENT_KEY for d in draft.degradations
        )

    @pytest.mark.parametrize("flag", ["A", "x"])
    def test_uses_the_shared_flag_handling(
        self, flag: str, draft: RuleDraft, context
    ) -> None:
        """json_pcre filtered flags itself, so the pcre refusals never reached it.

        Its own `flag in ("i", "m", "s")` test dropped everything else in
        silence, including the two letters that change what the pattern
        matches.
        """
        rule = make_rule(f'msg:"t"; json_pcre:".a","/abc/{flag}"; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_json_pcre, rule, draft, context)
        assert excinfo.value.code is RefusalCode.PCRE_UNSUPPORTED
        assert "changes what the pattern matches" in excinfo.value.detail
