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

    def test_missing_parsed_address_is_refused(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        """by_src without parse_src_ip has no position to enrich."""
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
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
