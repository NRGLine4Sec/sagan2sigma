"""Tests for the ``blacklist`` (IP denylist) handler."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.mapping.intel import handle_blacklist, handle_zeek_intel
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.sagan.config import SaganConfig


@pytest.fixture
def enriched_context() -> Context:
    """Context on the vector-enriched profile, which supplies the intel flags."""
    return Context(
        profile=load_profile("vector-enriched"),
        config=SaganConfig(),
        catalog=load_catalog(),
    )


class TestInertUsernameDenylist:
    """blacklist by_username sets no flag in the engine, so it is dropped."""

    def test_by_username_converts_with_a_degradation(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; blacklist: by_username; sid:1;'
        )
        run(handle_blacklist, rule, draft, context)
        assert any(
            d.code is DegradationCode.DENYLIST_USERNAME_INERT
            for d in draft.degradations
        )

    def test_by_username_adds_no_predicate(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; blacklist: by_username; sid:1;'
        )
        run(handle_blacklist, rule, draft, context)
        assert draft.predicates == []


class TestAddressDenylistRefused:
    @pytest.mark.parametrize("track", ["by_src", "by_dst", "both", "all"])
    def test_address_tracking_is_refused_pending_enrichment(
        self, draft: RuleDraft, context, track: str
    ) -> None:
        rule = make_rule(
            f'msg:"t"; program: sshd; content:"x"; blacklist: {track}; sid:1;'
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_blacklist, rule, draft, context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT

    def test_username_combined_with_address_is_refused(
        self, draft: RuleDraft, context
    ) -> None:
        """If any address form is present the denylist really is consulted."""
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "blacklist: by_src, by_username; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_blacklist, rule, draft, context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT

    def test_address_without_parsed_ip_is_refused(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """by_src needs the address parse_src_ip would have positioned."""
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; blacklist: by_src; sid:1;'
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_blacklist, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT


class TestConvertsUnderEnriched:
    def test_blacklist_by_src_matches_the_denylist_flag(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "blacklist: by_src; sid:1;"
        )
        run(handle_blacklist, rule, draft, enriched_context)
        predicate = draft.predicates[0]
        assert predicate.key == "sagan_denylist_1"
        assert predicate.rendered_value is True
        assert any(
            d.code is DegradationCode.DENYLIST_ENRICHMENT for d in draft.degradations
        )

    def test_zeek_intel_by_src_matches_the_zeek_flag(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "zeek-intel: by_src; sid:1;"
        )
        run(handle_zeek_intel, rule, draft, enriched_context)
        assert draft.predicates[0].key == "sagan_zeek_intel_1"
        assert any(
            d.code is DegradationCode.ZEEK_INTEL_ENRICHMENT for d in draft.degradations
        )

    def test_all_is_a_disjunction_over_every_position(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "blacklist: all; sid:1;"
        )
        run(handle_blacklist, rule, draft, enriched_context)
        assert draft.predicates == []
        group = draft.condition_groups[0]
        assert group.condition == (
            "denylist_hit_1 or denylist_hit_2 or denylist_hit_3 "
            "or denylist_hit_4 or denylist_hit_5"
        )
        assert group.blocks["denylist_hit_1"] == {"sagan_denylist_1": True}
