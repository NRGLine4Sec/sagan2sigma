"""Tests for the metadata handlers."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import Refusal
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.metadata import (
    TITLE_MAX,
    handle_classtype,
    handle_metadata,
    handle_msg,
    handle_reference,
)


class TestMsg:
    def test_becomes_the_title(self, draft: RuleDraft, context) -> None:
        run(handle_msg, make_rule('msg:"Invalid Password"; sid:1;'), draft, context)
        assert draft.title == "Invalid Password"

    def test_collapses_whitespace(self, draft: RuleDraft, context) -> None:
        run(handle_msg, make_rule('msg:"a    b"; sid:1;'), draft, context)
        assert draft.title == "a b"

    def test_truncates_to_the_sigma_limit(self, draft: RuleDraft, context) -> None:
        run(handle_msg, make_rule(f'msg:"{"x" * 400}"; sid:1;'), draft, context)
        assert len(draft.title) == TITLE_MAX

    def test_refuses_a_missing_msg(self, draft: RuleDraft, context) -> None:
        with pytest.raises(Refusal, match="msg"):
            run(handle_msg, make_rule("sid:1;"), draft, context)

    def test_refuses_an_empty_msg(self, draft: RuleDraft, context) -> None:
        with pytest.raises(Refusal, match="empty"):
            run(handle_msg, make_rule('msg:"  "; sid:1;'), draft, context)


class TestClasstype:
    def test_sets_the_level(self, draft: RuleDraft, context) -> None:
        run(
            handle_classtype,
            make_rule('msg:"t"; classtype: exploit-attempt; sid:1;'),
            draft,
            context,
        )
        assert draft.level == "high"

    def test_keeps_the_classtype_as_a_tag(self, draft: RuleDraft, context) -> None:
        run(
            handle_classtype,
            make_rule('msg:"t"; classtype: user-activity; sid:1;'),
            draft,
            context,
        )
        assert "sagan.classtype.user-activity" in draft.tags

    def test_unknown_classtype_uses_the_default_level(
        self, draft: RuleDraft, context
    ) -> None:
        run(
            handle_classtype,
            make_rule('msg:"t"; classtype: made-up; sid:1;'),
            draft,
            context,
        )
        assert draft.level == "medium"

    def test_does_not_override_a_locked_level(self, draft: RuleDraft, context) -> None:
        draft.set_level("high", locked=True)
        run(
            handle_classtype,
            make_rule('msg:"t"; classtype: hardware-event; sid:1;'),
            draft,
            context,
        )
        assert draft.level == "high"


class TestReference:
    def test_bare_url_gets_a_scheme(self, draft: RuleDraft, context) -> None:
        run(
            handle_reference,
            make_rule('msg:"t"; reference:url,example.org/a; sid:1;'),
            draft,
            context,
        )
        assert draft.references == ["https://example.org/a"]

    def test_cve_uses_the_configured_prefix(self, draft: RuleDraft, context) -> None:
        run(
            handle_reference,
            make_rule('msg:"t"; reference:cve,1999-0531; sid:1;'),
            draft,
            context,
        )
        assert draft.references[0].endswith("name=1999-0531")

    def test_deduplicates(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; reference:url,a.org; reference:url,a.org; sid:1;')
        run(handle_reference, rule, draft, context)
        assert len(draft.references) == 1

    def test_ignores_a_malformed_reference(self, draft: RuleDraft, context) -> None:
        run(
            handle_reference,
            make_rule('msg:"t"; reference:justone; sid:1;'),
            draft,
            context,
        )
        assert draft.references == []


class TestMetadata:
    def test_promotes_attack_techniques(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; metadata: mitre_technique_id T1059; sid:1;')
        run(handle_metadata, rule, draft, context)
        assert "attack.t1059" in draft.tags

    def test_promotes_subtechniques(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; metadata: mitre_technique_id T1059.001; sid:1;')
        run(handle_metadata, rule, draft, context)
        assert "attack.t1059.001" in draft.tags

    def test_promotes_tactics(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; metadata: mitre_tactic_id TA0002; sid:1;')
        run(handle_metadata, rule, draft, context)
        assert "attack.ta0002" in draft.tags

    def test_keeps_other_metadata_verbatim(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; metadata: created_at 2024_01_01, affected_product Windows; sid:1;'
        )
        run(handle_metadata, rule, draft, context)
        assert "created_at=2024_01_01" in draft.custom_attributes["sagan.metadata"]

    def test_skips_none_values(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; metadata: mitre_tactic_id NONE, mitre_technique_id T1078; sid:1;'
        )
        run(handle_metadata, rule, draft, context)
        assert "attack.t1078" in draft.tags
        assert "sagan.metadata" not in draft.custom_attributes
