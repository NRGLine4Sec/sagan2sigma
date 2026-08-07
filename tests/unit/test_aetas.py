"""Tests for the ``alert_time`` handler and its condition groups."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.converter import Converter
from sagan2sigma.emit.sigma import build_rule_document
from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.aetas import _rollover, _weekdays, handle_alert_time
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.sagan.config import SaganConfig


@pytest.fixture
def enriched_context() -> Context:
    """vector-enriched context with the aetas variables resolved."""
    return Context(
        profile=load_profile("vector-enriched"),
        config=SaganConfig(
            variables={"SAGAN_DAYS": ["12345"], "SAGAN_HOURS": ["1800-0800"]}
        ),
        catalog=load_catalog(),
    )


class TestHelpers:
    def test_weekdays_are_deduplicated_and_sorted(self) -> None:
        assert _weekdays("6120") == [0, 1, 2, 6]

    def test_rollover_adds_the_following_day(self) -> None:
        assert _rollover([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5, 6]
        assert _rollover([6]) == [0, 6]


class TestSameDayWindow:
    def test_emits_a_closed_hhmm_interval(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "alert_time: days 12345, hours 0900-1700; sid:1;"
        )
        run(handle_alert_time, rule, draft, enriched_context)
        group = draft.condition_groups[0]
        assert group.blocks["at_days"] == {"sagan_event_weekday": [1, 2, 3, 4, 5]}
        assert group.blocks["at_from"] == {"sagan_event_hhmm|gte": 900}
        assert group.blocks["at_to"] == {"sagan_event_hhmm|lte": 1700}
        assert group.condition == "at_days and at_from and at_to"


class TestOvernightWindow:
    def test_disjunction_with_rollover(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "alert_time: days 12345, hours 1800-0800; sid:1;"
        )
        run(handle_alert_time, rule, draft, enriched_context)
        group = draft.condition_groups[0]
        assert group.blocks["at_days"] == {"sagan_event_weekday": [1, 2, 3, 4, 5]}
        assert group.blocks["at_days_rollover"] == {
            "sagan_event_weekday": [1, 2, 3, 4, 5, 6]
        }
        assert group.blocks["at_evening"] == {"sagan_event_hhmm|gte": 1800}
        assert group.blocks["at_morning"] == {"sagan_event_hhmm|lte": 800}
        assert group.condition == (
            "(at_days and at_evening) or (at_days_rollover and at_morning)"
        )

    def test_variables_resolve_from_the_config(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "alert_time: days $SAGAN_DAYS, hours $SAGAN_HOURS; sid:1;"
        )
        run(handle_alert_time, rule, draft, enriched_context)
        group = draft.condition_groups[0]
        assert group.blocks["at_evening"] == {"sagan_event_hhmm|gte": 1800}
        assert group.blocks["at_morning"] == {"sagan_event_hhmm|lte": 800}

    def test_records_the_event_clock_degradation(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "alert_time: days 12345, hours 1800-0800; sid:1;"
        )
        run(handle_alert_time, rule, draft, enriched_context)
        assert any(
            d.code is DegradationCode.ALERT_TIME_EVENT_CLOCK for d in draft.degradations
        )


class TestFoldsIntoTheCondition:
    def test_group_is_anded_into_the_document_condition(
        self, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "alert_time: days 12345, hours 1800-0800; sid:1;"
        )
        converter = Converter(context=enriched_context)
        draft = converter.convert_rule(rule)
        entry = enriched_context.catalog.resolve(rule.source_file)
        document = build_rule_document(
            draft=draft,
            sid=rule.sid,
            rev=rule.rev,
            source_file=rule.source_file,
            logsource=entry,
            needs_name=False,
        )
        condition = document["detection"]["condition"]
        assert condition.endswith(
            " and ((at_days and at_evening) or (at_days_rollover and at_morning))"
        )
        # The predicate blocks and the group blocks coexist.
        assert "at_evening" in document["detection"]
        assert any(key.startswith("selection_") for key in document["detection"])


class TestRefusals:
    def test_default_profile_is_refused(
        self, draft: RuleDraft, context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "alert_time: days 12345, hours 0900-1700; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_alert_time, rule, draft, context)
        assert excinfo.value.code is RefusalCode.TIME_WINDOW

    def test_unresolved_variable_is_refused(self, draft: RuleDraft) -> None:
        context = Context(
            profile=load_profile("vector-enriched"),
            config=SaganConfig(variables={}),
            catalog=load_catalog(),
        )
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; '
            "alert_time: days $SAGAN_DAYS, hours $SAGAN_HOURS; sid:1;"
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_alert_time, rule, draft, context)
        assert excinfo.value.code is RefusalCode.VAR_UNRESOLVED

    def test_malformed_window_is_a_parse_error(
        self, draft: RuleDraft, enriched_context: Context
    ) -> None:
        rule = make_rule(
            'msg:"t"; program: sshd; content:"x"; alert_time: days 12345; sid:1;'
        )
        with pytest.raises(Refusal) as excinfo:
            run(handle_alert_time, rule, draft, enriched_context)
        assert excinfo.value.code is RefusalCode.PARSE
