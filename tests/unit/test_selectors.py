"""Tests for the envelope selector handlers."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import DegradationCode, Refusal
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.selectors import (
    handle_append_program,
    handle_event_id,
    handle_facility,
    handle_level,
    handle_priority,
    handle_program,
    handle_tag,
)
from sagan2sigma.mapping.values import CasePolicy


class TestProgram:
    def test_single_value(self, draft: RuleDraft, context) -> None:
        run(handle_program, make_rule('msg:"t"; program: sshd; sid:1;'), draft, context)
        predicate = draft.predicates[0]
        assert predicate.field == "appname"
        assert predicate.values == ("sshd",)
        assert predicate.modifiers == ("cased",)

    def test_pipe_becomes_a_list(self, draft: RuleDraft, context) -> None:
        run(
            handle_program,
            make_rule('msg:"t"; program: sshd|openssh; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].values == ("sshd", "openssh")

    def test_wildcards_are_preserved(self, draft: RuleDraft, context) -> None:
        """Sagan's Wildcard() has the same semantics as a Sigma plain value."""
        run(
            handle_program,
            make_rule('msg:"t"; program: *Security*; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].values == ("*Security*",)

    def test_relaxed_policy_drops_cased(self, draft: RuleDraft, context) -> None:
        run(
            handle_program,
            make_rule('msg:"t"; program: sshd; sid:1;'),
            draft,
            context,
            CasePolicy.RELAXED,
        )
        assert draft.predicates[0].modifiers == ()

    def test_event_type_is_an_alias(self, draft: RuleDraft, context) -> None:
        run(
            handle_program,
            make_rule('msg:"t"; event_type: crowdstrike; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].field == "appname"

    def test_follows_json_map(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_map:"program",".Src"; program: x; sid:1;')
        run(handle_program, rule, draft, context)
        assert draft.predicates[0].field == "Src"


class TestEventId:
    def test_single_id_is_an_integer(self, draft: RuleDraft, context) -> None:
        run(
            handle_event_id,
            make_rule('msg:"t"; event_id: 4624; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].values == (4624,)
        assert draft.predicates[0].field == "EventID"

    def test_several_ids(self, draft: RuleDraft, context) -> None:
        run(
            handle_event_id,
            make_rule('msg:"t"; event_id: 4624,4625; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].values == (4624, 4625)

    def test_uses_the_mapped_key(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_map:"event_id",".Id"; event_id: 1; sid:1;')
        run(handle_event_id, rule, draft, context)
        assert draft.predicates[0].field == "Id"
        assert not any(
            d.code is DegradationCode.EVENT_ID_HEURISTIC for d in draft.degradations
        )

    def test_reports_the_positional_heuristic(self, draft: RuleDraft, context) -> None:
        run(
            handle_event_id,
            make_rule('msg:"t"; event_id: 4624; sid:1;'),
            draft,
            context,
        )
        assert any(
            d.code is DegradationCode.EVENT_ID_HEURISTIC for d in draft.degradations
        )


class TestFacilityAndLevel:
    def test_facility(self, draft: RuleDraft, context) -> None:
        run(
            handle_facility,
            make_rule('msg:"t"; syslog_facility: daemon|auth; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].field == "facility"
        assert draft.predicates[0].values == ("daemon", "auth")

    def test_facility_is_case_insensitive(self, draft: RuleDraft, context) -> None:
        run(
            handle_facility,
            make_rule('msg:"t"; syslog_facility: daemon; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].modifiers == ()

    def test_level(self, draft: RuleDraft, context) -> None:
        run(
            handle_level,
            make_rule('msg:"t"; syslog_level: notice; sid:1;'),
            draft,
            context,
        )
        assert draft.predicates[0].field == "severity"


class TestTag:
    def test_emits_and_reports(self, draft: RuleDraft, context) -> None:
        run(handle_tag, make_rule('msg:"t"; syslog_tag: 2d; sid:1;'), draft, context)
        assert draft.predicates[0].field == "syslog_tag"
        assert draft.degradations

    def test_no_op_when_absent(self, draft: RuleDraft, context) -> None:
        run(handle_tag, make_rule('msg:"t"; sid:1;'), draft, context)
        assert draft.predicates == []
        assert draft.degradations == []


class TestPriority:
    def test_sets_and_locks_the_level(self, draft: RuleDraft, context) -> None:
        run(handle_priority, make_rule('msg:"t"; priority: 1; sid:1;'), draft, context)
        assert draft.level == "high"
        assert draft.level_locked

    def test_pri_is_an_alias_of_priority(self, draft: RuleDraft, context) -> None:
        """`pri` and `priority` both set s_pri in the engine (src/rules.c)."""
        run(handle_priority, make_rule('msg:"t"; pri: 1; sid:1;'), draft, context)
        assert draft.level == "high"
        assert draft.level_locked

    def test_locked_level_survives_a_later_classtype(
        self, draft: RuleDraft, context
    ) -> None:
        """The documentation states priority overrides classtype; option order.

        inside a rule is arbitrary, so the override has to be sticky.
        """
        run(handle_priority, make_rule('msg:"t"; priority: 1; sid:1;'), draft, context)
        draft.set_level("informational")
        assert draft.level == "high"

    def test_rejects_a_non_numeric_priority(self, draft: RuleDraft, context) -> None:
        with pytest.raises(Refusal, match="priority"):
            run(
                handle_priority,
                make_rule('msg:"t"; priority: high; sid:1;'),
                draft,
                context,
            )

    def test_ignores_an_out_of_range_priority(self, draft: RuleDraft, context) -> None:
        run(handle_priority, make_rule('msg:"t"; priority: 9; sid:1;'), draft, context)
        assert draft.level == "medium"


class TestAppendProgram:
    def test_reports_the_widened_search_surface(
        self, draft: RuleDraft, context
    ) -> None:
        run(
            handle_append_program,
            make_rule('msg:"t"; append_program; sid:1;'),
            draft,
            context,
        )
        assert draft.degradations[0].code is DegradationCode.APPEND_PROGRAM
