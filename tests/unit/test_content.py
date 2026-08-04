"""Tests for content and meta_content, the two highest-volume keywords."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.content import handle_content, handle_meta_content
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
