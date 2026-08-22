"""Tests for correlation handlers and group-by resolution."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.correlation import (
    KNOWN_INERT_TRACK_KEYS,
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

    def test_after_drops_by_string_and_keeps_the_rest(
        self, draft: RuleDraft, context
    ) -> None:
        """Sagan groups on the source alone here.

        Grouping on the username too would invent a distinction it does not make.
        """
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".ip"; json_map:"username",".user"; '
            "after: track by_src&by_string, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == ("ip",)
        assert any(
            d.code is DegradationCode.AFTER_BY_STRING_INERT for d in draft.degradations
        )

    def test_after_with_only_by_string_is_refused(
        self, draft: RuleDraft, context
    ) -> None:
        """Sagan rejects such a rule at load, so there is nothing to emit."""
        rule = make_rule(
            'msg:"t"; json_map:"username",".user"; '
            "after: track by_string, count 5, seconds 300; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_after, rule, draft, context)
        assert excinfo.value.code is RefusalCode.PARSE

    @pytest.mark.parametrize("inert", sorted(KNOWN_INERT_TRACK_KEYS))
    def test_keys_the_engine_ignores_are_dropped(
        self, inert: str, draft: RuleDraft, context
    ) -> None:
        """The after parser compares tokens with strcmp, so these set nothing.

        by_user is not by_username, byusername is an upstream typo, and neither
        by_tag nor by_hostname has a branch at all. Honouring one would group
        the converted rule more finely than Sagan groups it, so it would fire
        less often than the original. Checked against a running engine: two
        events differing only in the inert key still share a counter.
        """
        rule = make_rule(
            f'msg:"t"; json_map:"src_ip",".ip"; json_map:"username",".user"; '
            f"after: track by_src&{inert}, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == ("ip",)
        assert any(
            d.code is DegradationCode.TRACK_KEY_INERT for d in draft.degradations
        )

    def test_an_arbitrary_unknown_key_is_inert_too(
        self, draft: RuleDraft, context
    ) -> None:
        """Inertness is decided by the engine's rule, not by a list of typos.

        The parser recognises five tokens and ignores everything else, so the
        converter treats anything outside TRACK_TO_INTERNAL as inert rather
        than keeping a second list of known-bad tokens in step with the first.
        Refusing here would make the converter stricter than what it targets:
        Sagan loads and runs this rule, grouping on the source alone.
        """
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".ip"; '
            "after: track by_src&by_notarealkey, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == ("ip",)
        assert any(
            d.code is DegradationCode.TRACK_KEY_INERT for d in draft.degradations
        )

    def test_a_lone_inert_key_is_refused(self, draft: RuleDraft, context) -> None:
        """Sagan needs a validity count of four and an inert key scores three.

        Two upstream rules track by_tag alone and two by_hostname alone, so the
        engine refuses to load them and there is nothing faithful to emit.
        """
        rule = make_rule('msg:"t"; after: track by_tag, count 5, seconds 300; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_after, rule, draft, context)
        assert excinfo.value.code is RefusalCode.PARSE

    @pytest.mark.parametrize(
        ("token", "field"), [("by_srcport", "sp"), ("by_dstport", "dp")]
    )
    def test_the_port_keys_resolve(
        self, token: str, field: str, draft: RuleDraft, context
    ) -> None:
        """by_srcport and by_dstport are real branches the converter lacked."""
        rule = make_rule(
            f'msg:"t"; json_map:"src_port",".sp"; json_map:"dest_port",".dp"; '
            f"after: track {token}, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == (field,)

    def test_composite_tracking(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".ip"; json_map:"username",".user"; '
            "after: track by_src&by_username, count 5, seconds 300; sid:1;"
        )
        run(handle_after, rule, draft, context)
        assert draft.correlations[0].group_by == ("ip", "user")


class TestAfter:
    def test_builds_an_event_count_correlation(self, draft: RuleDraft, context) -> None:
        """`count N` becomes `gte: N+1`, because Sagan alerts from the N+1th.

        The engine seeds its counter at 1 on the first match and alerts only
        while `after2_count < count` (src/after.c), so N events pass in silence
        and the next one alerts. A Sigma event_count of `gte: N` fires as soon
        as the window holds N, one event early. Both engines were run on the
        same six events to settle it: Sagan alerts on the 4th, 5th and 6th for
        `count 3`, and rsigma reproduces that exactly with `gte: 4`.
        """
        rule = make_rule('msg:"t"; after: track by_src, count 10, seconds 300; sid:1;')
        run(handle_after, rule, draft, context)
        spec = draft.correlations[0]
        assert spec.correlation_type == "event_count"
        assert spec.condition == {"gte": 11}
        assert spec.timespan == "5m"
        # The title keeps the rule's own number, which is what an analyst reads.
        assert "threshold 10" in spec.title_suffix

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

    def test_every_direction_the_engine_accepts_is_skipped(self) -> None:
        # Flexbit_Type() in src/flexbit.c accepts these fourteen and rejects
        # everything else, checked against a running engine. A direction missing
        # from the converter's list is silently taken for the bit name, so the
        # correlation is rebuilt around a bit no rule sets.
        for direction in (
            "none",
            "both",
            "by_src",
            "by_dst",
            "reverse",
            "src_xbitdst",
            "dst_xbitsrc",
            "both_p",
            "by_src_p",
            "by_dst_p",
            "reverse_p",
            "src_xbitdst_p",
            "dst_xbitsrc_p",
            "username",
        ):
            assert bit_name(["isset", direction, "the_bit"], "isset") == "the_bit"


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

    def test_flexbits_groups_on_the_direction_it_names(
        self, draft: RuleDraft, context
    ) -> None:
        # flexbits states its direction as a bare token, so the xbits pattern
        # ("track ip_src") never matches and the group-by used to fall through
        # to the source address whatever the rule asked for. On the upstream
        # corpus that put nine correlations on an address where Sagan keys on
        # the user.
        rule = make_rule(
            'msg:"t"; json_map:"username",".user"; '
            "flexbits: isset, username, vpn_login; sid:1;"
        )
        run(handle_bits, rule, draft, context)
        assert draft.tests_bits == {"vpn_login"}
        assert draft.bit_group_by == ("user",)

    def test_flexbits_by_dst_groups_on_the_destination(
        self, draft: RuleDraft, context
    ) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"dest_ip",".d"; flexbits: isset, by_dst, b; sid:1;'
        )
        run(handle_bits, rule, draft, context)
        assert draft.bit_group_by == ("d",)

    def test_flexbits_both_groups_on_the_pair(self, draft: RuleDraft, context) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".s"; json_map:"dest_ip",".d"; '
            "flexbits: isset, both, b; sid:1;"
        )
        run(handle_bits, rule, draft, context)
        assert draft.bit_group_by == ("s", "d")

    @pytest.mark.parametrize("direction", ["none", "reverse", "by_src_p"])
    def test_flexbits_directions_sigma_cannot_state_are_refused(
        self, direction: str, draft: RuleDraft, context
    ) -> None:
        # none is a global bit with no key, reverse compares one event's source
        # against another's destination, and the _p forms add the port. None is
        # a group-by over a single field, so they refuse rather than approximate.
        rule = make_rule(f'msg:"t"; flexbits: isset, {direction}, b; sid:1;')
        with pytest.raises(Refusal) as excinfo:
            run(handle_bits, rule, draft, context)
        assert excinfo.value.code is RefusalCode.GROUPBY_UNRESOLVED

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
