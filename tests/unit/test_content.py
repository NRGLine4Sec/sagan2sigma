"""Tests for content and meta_content, the two highest-volume keywords."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.content import (
    between_quotes,
    handle_content,
    handle_meta_content,
    split_meta_content,
)
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.values import CasePolicy


class TestContentCaseInversion:
    """The single most expensive defect available in this converter.

    Sagan is case-sensitive unless nocase is present; Sigma is the opposite.
    Copying the flag across without inverting would flip the semantics of
    thousands of rules, and nothing downstream would notice.
    """

    def test_without_nocase_emits_cased(self, draft: RuleDraft, context) -> None:
        run(
            handle_content,
            make_rule('msg:"t"; content:"failure"; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].modifiers == ("contains", "cased")

    def test_with_nocase_omits_cased(self, draft: RuleDraft, context) -> None:
        run(
            handle_content,
            make_rule('msg:"t"; content:"failure"; nocase; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].modifiers == ("contains",)

    def test_nocase_binds_to_the_preceding_content_only(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule('msg:"t"; content:"a"; nocase; content:"b"; sid:1;')
        run(handle_content, rule, draft, context)
        assert draft.predicates[0].modifiers == ("contains",)
        assert draft.predicates[1].modifiers == ("contains", "cased")

    def test_relaxed_policy_drops_cased_everywhere(
        self, draft: RuleDraft, context
    ) -> None:
        run(
            handle_content,
            make_rule('msg:"t"; content:"a"; sid:1;'),
            draft,
            context,
            CasePolicy.RELAXED,
        )
        assert draft.predicates[0].modifiers == ("contains",)


class TestContent:
    def test_targets_the_profile_message_field(self, draft: RuleDraft, context) -> None:
        run(handle_content, make_rule('msg:"t"; content:"a"; sid:1;'), draft, context)
        assert draft.predicates[0].field == "_raw"

    def test_targets_the_mapped_key(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_map:"message",".Desc"; content:"a"; sid:1;')
        run(handle_content, rule, draft, context)
        assert draft.predicates[0].field == "Desc"

    def test_decodes_hex_escapes(self, draft: RuleDraft, context) -> None:
        run(
            handle_content,
            make_rule('msg:"t"; content:"User Agent|3a| Testing"; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].values == ("User Agent: Testing",)

    def test_negation(self, draft: RuleDraft, context) -> None:
        run(
            handle_content,
            make_rule('msg:"t"; content:!"frank"; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].negated

    def test_escapes_literal_wildcards(self, draft: RuleDraft, context) -> None:
        """Escape the asterisk: it is literal in Sagan but a wildcard in Sigma."""
        run(
            handle_content, make_rule('msg:"t"; content:"100*"; sid:1;'), draft, context
        )
        assert draft.predicates[0].values == ("100\\*",)

    def test_flags_portability_on_raw_text(self, draft: RuleDraft, context) -> None:
        run(handle_content, make_rule('msg:"t"; content:"a"; sid:1;'), draft, context)
        assert any(d.code is DegradationCode.RAW_TEXT_MATCH for d in draft.degradations)

    def test_no_portability_warning_when_json_mapped(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule('msg:"t"; json_map:"message",".D"; content:"a"; sid:1;')
        run(handle_content, rule, draft, context)
        assert not draft.degradations


class TestMetaContent:
    def test_expands_inline_values(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; meta_content:"User|3a| %sagan%",bob,mary; sid:1;')
        run(handle_meta_content, rule, draft, context)
        assert draft.predicates[0].values == ("User: bob", "User: mary")

    def test_expands_a_sagan_yaml_variable(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; meta_content:"User|3a| %sagan%",$USERS; sid:1;')
        run(handle_meta_content, rule, draft, context)
        assert draft.predicates[0].values == ("User: bob", "User: frank", "User: mary")

    def test_refuses_an_unknown_variable(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; meta_content:"%sagan%",$NOPE; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_meta_content, rule, draft, context)
        assert excinfo.value.code is RefusalCode.VAR_UNRESOLVED

    def test_refuses_a_missing_placeholder(self, draft: RuleDraft, context) -> None:
        """Refuse what Sagan itself aborts on at load time."""
        rule = make_rule('msg:"t"; meta_content:"no helper",bob; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_meta_content, rule, draft, context)
        assert excinfo.value.code is RefusalCode.PARSE

    def test_meta_nocase_inverts_like_nocase(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; meta_content:"%sagan%",bob; meta_nocase; sid:1;')
        run(handle_meta_content, rule, draft, context)
        assert draft.predicates[0].modifiers == ("contains",)

    def test_negation(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; meta_content:!"User|3a| %sagan%",$USERS; sid:1;')
        run(handle_meta_content, rule, draft, context)
        assert draft.predicates[0].negated

    def test_placeholder_may_sit_mid_pattern(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; meta_content:"a %sagan% b",x,y; sid:1;')
        run(handle_meta_content, rule, draft, context)
        assert draft.predicates[0].values == ("a x b", "a y b")

    def test_refuses_an_unparsable_form(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; meta_content:garbage; sid:1;')
        with pytest.raises(Refusal):
            run(handle_meta_content, rule, draft, context)


class TestMetaContentEngineSplit:
    """The helper/values split must match Sagan's rules.c, not a tidy regex.

    Sagan grabs the first comma-delimited token as the helper and strips its
    quotes with Between_Quotes, then takes everything after that first comma as
    the values. Matching the engine, rather than a regex that assumes the comma
    sits outside the quotes, is what fixes the double-quote and values-in-quotes
    forms below.
    """

    def test_between_quotes_matches_the_engine(self) -> None:
        # Everything after the first quote, with quotes removed.
        assert between_quotes('"Username %sagan%"') == "Username %sagan%"
        assert between_quotes('"%sagan%') == "%sagan%"
        # A doubled opening quote: the engine keeps the inner content, dropping
        # every quote. This is the Cisco ASA case.
        assert between_quotes('""%sagan%"') == "%sagan%"

    def test_split_on_first_comma_even_inside_quotes(self) -> None:
        negated, helper, values = split_meta_content('"a %sagan%,b,c"')
        assert not negated
        assert helper == "a %sagan%"
        assert values == 'b,c"'

    def test_no_comma_is_refused(self) -> None:
        with pytest.raises(Refusal) as excinfo:
            split_meta_content('"%sagan% only"')
        assert excinfo.value.code is RefusalCode.PARSE

    def test_double_quote_helper_drops_the_leading_quote(
        self, draft: RuleDraft, context
    ) -> None:
        # `meta_content: ""%sagan%", %ASA,%FWSM` (Cisco ASA). The old regex
        # emitted `"%ASA` with a spurious leading quote that no real ASA log
        # carries; the engine-faithful split emits `%ASA`.
        rule = make_rule('msg:"t"; meta_content:""%sagan%", %ASA,%FWSM; sid:1;')
        run(handle_meta_content, rule, draft, context)
        assert draft.predicates[0].values == ("%ASA", "%FWSM")

    def test_values_written_inside_the_closing_quote(
        self, draft: RuleDraft, context
    ) -> None:
        # `meta_content:"eventName|22 3a 20 22|%sagan%,A,B"` (AWS IAM). The values
        # sit inside the quote; the last one keeps the trailing quote, exactly as
        # the engine reads it. This form was refused with E_PARSE before.
        rule = make_rule(
            'msg:"t"; meta_content:"eventName|22 3a 20 22|%sagan%,A,B"; sid:1;'
        )
        run(handle_meta_content, rule, draft, context)
        assert draft.predicates[0].values == ('eventName": "A', 'eventName": "B"')
