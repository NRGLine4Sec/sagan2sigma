"""Tests for the ``blacklist`` (IP denylist) handler."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.mapping.intel import (
    handle_blacklist,
    handle_bluedot,
    handle_zeek_intel,
)
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


class TestBluedotSubstitution:
    """bluedot is substituted by open-source per-category feeds under enriched.

    The engine reference is src/processors/bluedot.c (the five lookup types and
    the category-list compare) and src/rules.c (the option grammar). Only the
    ip_reputation lookup is reproduced, over the four categories the corpus uses;
    every case that cannot be substituted faithfully is refused.
    """

    def _bluedot(self, option: str) -> object:
        return make_rule(
            f'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            f"bluedot: {option}; sid:1;"
        )

    def test_single_category_matches_one_flag(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        run(
            handle_bluedot,
            self._bluedot("type ip_reputation, track by_src, none, Tor"),
            draft,
            enriched_context,
        )
        assert draft.predicates[0].key == "sagan_bluedot_tor_1"
        assert draft.predicates[0].rendered_value is True
        assert any(
            d.code is DegradationCode.BLUEDOT_SUBSTITUTION for d in draft.degradations
        )

    def test_several_categories_are_a_disjunction(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        run(
            handle_bluedot,
            self._bluedot("type ip_reputation, track by_src, none, Malicious,Tor"),
            draft,
            enriched_context,
        )
        assert draft.predicates == []
        group = draft.condition_groups[0]
        assert group.condition == "bluedot_hit_1 or bluedot_hit_2"
        assert group.blocks["bluedot_hit_1"] == {"sagan_bluedot_malicious_1": True}
        assert group.blocks["bluedot_hit_2"] == {"sagan_bluedot_tor_1": True}

    def test_track_all_crosses_positions_and_categories(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        run(
            handle_bluedot,
            self._bluedot("type ip_reputation, track all, none, Tor,Proxy"),
            draft,
            enriched_context,
        )
        group = draft.condition_groups[0]
        # 5 positions x 2 categories = 10 disjuncts.
        assert len(group.blocks) == 10
        assert {"sagan_bluedot_tor_1": True} in group.blocks.values()
        assert {"sagan_bluedot_proxy_5": True} in group.blocks.values()

    def test_freshness_and_none_tokens_are_ignored(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        run(
            handle_bluedot,
            self._bluedot(
                "type ip_reputation, track by_src, mdate_effective_period 3 months, Tor"
            ),
            draft,
            enriched_context,
        )
        assert draft.predicates[0].key == "sagan_bluedot_tor_1"

    def test_hash_lookup_is_refused(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; bluedot: type file_hash,Malicious; '
            "sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_bluedot, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT
        assert "hash" in str(excinfo.value).lower()

    def test_url_lookup_is_refused(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; bluedot: type url, Malicious; sid:1;'
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_bluedot, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT

    def test_unknown_category_is_refused(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        with pytest.raises(Refusal) as excinfo:
            run(
                handle_bluedot,
                self._bluedot("type ip_reputation, track by_src, none, Cryptomining"),
                draft,
                enriched_context,
            )
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT
        assert "cryptomining" in str(excinfo.value).lower()

    def test_missing_parsed_address_is_refused(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """by_src without parse_src_ip has no position to enrich (like blacklist)."""
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "bluedot: type ip_reputation, track by_src, none, Tor; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_bluedot, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT

    def test_refused_under_the_default_profile(
        self, draft: RuleDraft, context: Context
    ) -> None:
        """The syslog profile has no bluedot flags, so it cannot substitute."""
        with pytest.raises(Refusal) as excinfo:
            run(
                handle_bluedot,
                self._bluedot("type ip_reputation, track by_src, none, Tor"),
                draft,
                context,
            )
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT
