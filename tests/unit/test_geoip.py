"""Tests for the ``country_code`` handler."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.mapping.geoip import handle_country_code
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.sagan.config import SaganConfig


@pytest.fixture
def enriched_context() -> Context:
    """Context on the vector-enriched profile, with HOME_COUNTRY resolved."""
    return Context(
        profile=load_profile("vector-enriched"),
        config=SaganConfig(variables={"HOME_COUNTRY": ["US", "CA"]}),
        catalog=load_catalog(),
    )


def _predicates(draft: RuleDraft) -> dict[str, tuple]:
    """Map each predicate's key to ``(values, negated)`` for concise asserts."""
    return {p.key: (p.rendered_value, p.negated) for p in draft.predicates}


class TestConvertsUnderEnriched:
    def test_isnot_keys_presence_on_the_address_not_the_country(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """Isnot fires on a present address whose country is not in the list.

        Sagan fires on a private or unresolved address too, so the presence test
        keys on the address field, not the country field.
        """
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src, isnot US,CA; sid:1;"
        )
        run(handle_country_code, rule, draft, enriched_context)
        preds = _predicates(draft)
        assert preds["sagan_ip_1|exists"] == (True, False)
        assert preds["sagan_geoip_country_1"] == (["US", "CA"], True)

    def test_is_matches_country_in_list(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_dst_ip: 2; '
            "country_code: track by_dst, is RU,CN; sid:1;"
        )
        run(handle_country_code, rule, draft, enriched_context)
        preds = _predicates(draft)
        assert preds["sagan_geoip_country_2"] == (["RU", "CN"], False)
        # `is` needs no separate presence test: membership implies presence.
        assert "sagan_ip_2|exists" not in preds

    def test_position_follows_parse_src_ip(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 3; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        run(handle_country_code, rule, draft, enriched_context)
        preds = _predicates(draft)
        assert "sagan_ip_3|exists" in preds
        assert "sagan_geoip_country_3" in preds

    def test_variable_home_country_is_expanded(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src, isnot $HOME_COUNTRY; sid:1;"
        )
        run(handle_country_code, rule, draft, enriched_context)
        assert _predicates(draft)["sagan_geoip_country_1"] == (["US", "CA"], True)

    def test_records_the_enrichment_degradation(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        run(handle_country_code, rule, draft, enriched_context)
        assert any(
            d.code is DegradationCode.GEOIP_COUNTRY_ENRICHMENT
            for d in draft.degradations
        )


class TestRefusals:
    def test_default_profile_has_no_country_field(
        self, draft: RuleDraft, context: Context
    ) -> None:
        """Under a non-enriched profile there is no country field to match."""
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT

    def test_json_map_address_is_alive_but_needs_a_position(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """json_map binds src_ip, so the address can resolve on JSON input.

        The rule is not dead, but with no parse_src_ip there is still no
        positional country field to match, so it is refused for the enrichment,
        not as a rule that never fires.
        """
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".ClientIP"; content:"x"; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT

    def test_normalize_address_is_alive_but_needs_a_position(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """Normalize can bind the address through liblognorm, so not dead."""
        rule = make_rule(
            'msg:"t"; normalize; content:"x"; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.EXTERNAL_ENRICHMENT

    def test_unresolved_variable_is_refused(self, draft: RuleDraft) -> None:
        context = Context(
            profile=load_profile("vector-enriched"),
            config=SaganConfig(variables={}),
            catalog=load_catalog(),
        )
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src, isnot $HOME_COUNTRY; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, context)
        assert excinfo.value.code is RefusalCode.VAR_UNRESOLVED

    def test_malformed_option_is_a_parse_error(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src US; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.PARSE


class TestDeadCountryCodeRulesNeverFire:
    """A country_code rule can only fire when the engine marks its tracked.

    address valid, which happens solely through parse_src_ip / parse_dst_ip, a
    json_map binding, or normalize (see src/processors/engine.c and
    src/routing.c). A rule that gives the tracked direction none of these can
    never fire in Sagan, so emitting anything that does would be unfaithful; it
    is refused as E_NO_DETECTION, not as recoverable enrichment. These tests pin
    the exact liveness boundary.
    """

    def test_by_src_with_no_source_is_dead(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.NO_DETECTION

    def test_by_dst_with_no_source_is_dead(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "country_code: track by_dst, isnot US; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.NO_DETECTION

    def test_by_dst_with_only_parse_src_ip_is_dead(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """Tracking by_dst while only parsing the source never validates dst."""
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_dst, isnot US; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_country_code, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.NO_DETECTION

    def test_parse_src_ip_keeps_a_by_src_rule_alive(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """The liveness check must not swallow a rule the engine can fire: with.

        parse_src_ip the address resolves and the rule converts normally.
        """
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        run(handle_country_code, rule, draft, enriched_context)
        assert draft.predicates  # converted, no refusal
