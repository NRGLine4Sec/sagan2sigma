"""Tests for positional IP resolution, the basis of the enriched profile."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.mapping.correlation import handle_after
from sagan2sigma.mapping.fields import FieldResolver, parse_positions
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.sagan.config import SaganConfig


@pytest.fixture
def enriched(config: SaganConfig) -> Context:
    return Context(
        profile=load_profile("vector-enriched"),
        config=config,
        catalog=load_catalog(),
    )


class TestParsePositions:
    def test_reads_both_keywords(self) -> None:
        rule = make_rule('msg:"t"; parse_src_ip: 2; parse_dst_ip: 3; sid:1;')
        assert parse_positions(rule) == {"src_ip": 2, "dest_ip": 3}

    def test_absent_keyword_yields_no_position(self) -> None:
        assert parse_positions(make_rule('msg:"t"; sid:1;')) == {}

    def test_flag_without_a_value_defaults_to_one(self) -> None:
        assert parse_positions(make_rule('msg:"t"; parse_src_ip; sid:1;')) == {
            "src_ip": 1
        }

    def test_trailing_junk_is_ignored_like_atoi(self) -> None:
        """The engine runs the value through atoi(); one corpus rule needs it."""
        rule = make_rule('msg:"t"; parse_src_ip: 1/"; sid:1;')
        assert parse_positions(rule) == {"src_ip": 1}


class TestProfilePositionalSupport:
    def test_enriched_profile_supplies_templates(self) -> None:
        profile = load_profile("vector-enriched")
        assert profile.positional_field("src_ip", 1) == "sagan_ip_1"
        assert profile.positional_field("dest_ip", 3) == "sagan_ip_3"

    @pytest.mark.parametrize("name", ["rsigma-syslog", "vector-json"])
    def test_plain_profiles_supply_none(self, name: str) -> None:
        """Absence is load-bearing: it is what makes the converter refuse."""
        assert load_profile(name).positional_field("src_ip", 1) is None

    def test_resolver_reports_the_declared_position(self, enriched: Context) -> None:
        rule = make_rule('msg:"t"; parse_src_ip: 2; sid:1;')
        assert (
            FieldResolver.for_rule(rule, enriched).positional("src_ip") == "sagan_ip_2"
        )

    def test_resolver_returns_none_without_a_position(self, enriched: Context) -> None:
        rule = make_rule('msg:"t"; sid:1;')
        assert FieldResolver.for_rule(rule, enriched).positional("src_ip") is None


class TestEnrichedGroupBy:
    def test_correlation_groups_on_the_declared_position(
        self, draft: RuleDraft, enriched: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; parse_src_ip: 2; '
            "after: track by_src, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, enriched)
        assert draft.correlations[0].group_by == ("sagan_ip_2",)

    def test_dependency_on_the_transform_is_reported(
        self, draft: RuleDraft, enriched: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; parse_src_ip: 1; '
            "after: track by_src, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, enriched)
        assert any(
            d.code is DegradationCode.POSITIONAL_IP_FIELD for d in draft.degradations
        )

    def test_normalize_precedence_is_reported(
        self, draft: RuleDraft, enriched: Context
    ) -> None:
        """Sagan lets liblognorm win; only the positional fallback is ported."""
        rule = make_rule(
            'msg:"t"; normalize; parse_src_ip: 1; '
            "after: track by_src, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, enriched)
        assert any(
            d.code is DegradationCode.NORMALIZE_PRECEDENCE for d in draft.degradations
        )

    def test_username_resolves_against_the_enriched_field(
        self, draft: RuleDraft, enriched: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; normalize; after: track by_username, count 5, seconds 300; sid:1;'
        )
        run(handle_after, rule, draft, enriched)
        assert draft.correlations[0].group_by == ("sagan_username",)

    def test_normalize_only_still_refuses_without_enrichment(
        self, draft: RuleDraft, context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; normalize; after: track by_username, count 5, seconds 300; sid:1;'
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_after, rule, draft, context)
        assert excinfo.value.code is RefusalCode.GROUPBY_UNRESOLVED

    def test_refusal_points_at_the_enriched_profile(
        self, draft: RuleDraft, context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; parse_src_ip: 1; '
            "after: track by_src, count 5, seconds 300; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_after, rule, draft, context)
        assert "vector-enriched" in excinfo.value.detail
