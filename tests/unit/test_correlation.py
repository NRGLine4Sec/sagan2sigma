"""Tests for correlation handlers and group-by resolution."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.correlation import (
    bit_name,
    format_timespan,
    handle_after,
    handle_bits,
    handle_threshold,
)
from sagan2sigma.mapping.ir import RuleDraft


class TestFormatTimespan:
    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (90, "90s"),
            (300, "5m"),
            (3600, "1h"),
            (21600, "6h"),
            (86400, "1d"),
            (0, "0s"),
        ],
    )
    def test_picks_the_most_readable_unit(self, seconds: int, expected: str) -> None:
        assert format_timespan(seconds) == expected


class TestAfterGroupByResolution:
    """The three-branch resolution is the least obvious part of the tool."""

    def test_json_map_binding_wins(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".sourceIPAddress"; '
            "after: track by_src, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == ("sourceIPAddress",)

    def test_falls_back_to_the_syslog_sender(self, draft: RuleDraft, context) -> None:
        """Without extraction, Sagan copies syslog_host into src_ip, so the.

        grouping is per emitting host, not per attacker.
        """
        rule = make_rule('msg:"t"; after: track by_src, count 5, seconds 300; sid:1;')
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == ("hostname",)
        assert any(
            d.code is DegradationCode.GROUPBY_SYSLOG_HOST for d in draft.degradations
        )

    def test_refuses_when_the_key_is_regex_extracted(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; parse_src_ip: 1; '
            "after: track by_src, count 5, seconds 300; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_after, rule, draft, context)
        assert excinfo.value.code is RefusalCode.GROUPBY_UNRESOLVED

    def test_refuses_when_the_key_comes_from_liblognorm(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; normalize; after: track by_username, count 5, seconds 300; sid:1;'
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_after, rule, draft, context)
        assert excinfo.value.code is RefusalCode.GROUPBY_UNRESOLVED

    def test_refuses_by_string(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; after: track by_string, count 5, seconds 300; sid:1;'
        )
        with pytest.raises(Refusal, match="by_string"):
            run(handle_after, rule, draft, context)

    def test_composite_tracking(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".ip"; json_map:"username",".user"; '
            "after: track by_src&by_username, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == ("ip", "user")


class TestAfter:
    def test_builds_an_event_count_correlation(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; after: track by_src, count 10, seconds 300; sid:1;')
        run(handle_after, rule, draft, context)
        spec = draft.correlations[0]
        assert spec.correlation_type == "event_count"
        assert spec.condition == {"gte": 10}
        assert spec.timespan == "5m"

    def test_refuses_an_incomplete_after(self, draft: RuleDraft, context) -> None:
        with pytest.raises(Refusal, match="incomplete"):
            run(
                handle_after,
                make_rule('msg:"t"; after: track by_src; sid:1;'),
                draft,
                context,
            )


class TestThreshold:
    """threshold controls alert volume, never detection. Turning it into an.

    event_count correlation would change what the rule means.
    """

    def test_suppress_becomes_a_custom_attribute(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; '
            "threshold: type suppress, track by_src, count 5, seconds 900; sid:1;"
        )
        run(handle_threshold, rule, draft, context)
        assert draft.custom_attributes["rsigma.suppress"] == "15m"
        assert draft.correlations == []

    def test_limit_is_dropped_and_reported(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; '
            "threshold: type limit, track by_src, count 10, seconds 3600; sid:1;"
        )
        run(handle_threshold, rule, draft, context)
        assert "rsigma.suppress" not in draft.custom_attributes
        assert draft.degradations[0].code is DegradationCode.THRESHOLD_LIMIT

    def test_refuses_a_threshold_without_type(self, draft: RuleDraft, context) -> None:
        with pytest.raises(Refusal, match="type"):
            run(
                handle_threshold,
                make_rule('msg:"t"; threshold: track by_src; sid:1;'),
                draft,
                context,
            )


class TestBitName:
    def test_xbits_puts_the_name_second(self) -> None:
        assert bit_name(["set", "brute_force", "track ip_src"], "set") == "brute_force"

    def test_flexbits_inserts_a_tracking_key(self) -> None:
        assert (
            bit_name(["isset", "by_src", "windows_reboot"], "isset") == "windows_reboot"
        )

    def test_xbits_isset_keeps_the_second_position(self) -> None:
        assert (
            bit_name(["isset", "brute_force", "track ip_src"], "isset") == "brute_force"
        )


class TestBits:
    def test_set_records_the_bit_and_its_expiry(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; xbits: set,brute_force,track ip_src, expire 21600; sid:1;'
        )
        run(handle_bits, rule, draft, context)
        assert draft.sets_bits == {"brute_force": 21600}

    def test_set_without_expire_uses_the_fallback(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule('msg:"t"; xbits: set,b,track ip_src; sid:1;')
        run(handle_bits, rule, draft, context)
        assert draft.sets_bits["b"] == 86400

    def test_isset_records_the_bit_and_group_by(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".ip"; '
            "xbits: isset,brute_force,track ip_src; sid:1;"
        )
        run(handle_bits, rule, draft, context)
        assert draft.tests_bits == {"brute_force"}
        assert draft.bit_group_by == ("ip",)

    def test_ip_pair_groups_on_both_ends(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".s"; json_map:"dest_ip",".d"; '
            "xbits: isset,b,track ip_pair; sid:1;"
        )
        run(handle_bits, rule, draft, context)
        assert draft.bit_group_by == ("s", "d")

    def test_isnotset_is_refused(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; xbits: isnotset,b,track ip_src; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_bits, rule, draft, context)
        assert excinfo.value.code is RefusalCode.STATE_ABSENCE

    def test_unset_is_reported(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; xbits: unset,b,track ip_src; sid:1;')
        run(handle_bits, rule, draft, context)
        assert draft.degradations[0].code is DegradationCode.SIDE_EFFECT_DROPPED

    def test_noalert_is_a_no_op(self, draft: RuleDraft, context) -> None:
        run(handle_bits, make_rule('msg:"t"; xbits: noalert; sid:1;'), draft, context)
        assert draft.sets_bits == {} and draft.tests_bits == set()
