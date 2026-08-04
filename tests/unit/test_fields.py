"""Tests for field resolution, including the json_map redirection."""

from __future__ import annotations

from tests.conftest import make_rule

from sagan2sigma.mapping.context import Context
from sagan2sigma.mapping.fields import INTERNAL_VALUES, FieldResolver, json_map


class TestJsonMap:
    def test_extracts_bindings(self) -> None:
        rule = make_rule('msg:"t"; json_map: "message", ".RenderedDescription"; sid:1;')
        assert json_map(rule) == {"message": "RenderedDescription"}

    def test_strips_the_leading_dot(self) -> None:
        rule = make_rule('msg:"t"; json_map:"src_ip",".ClientIP"; sid:1;')
        assert json_map(rule) == {"src_ip": "ClientIP"}

    def test_collects_several_bindings(self) -> None:
        rule = make_rule(
            'msg:"t"; json_map:"src_ip",".a"; json_map:"username",".b"; sid:1;'
        )
        assert json_map(rule) == {"src_ip": "a", "username": "b"}

    def test_ignores_unknown_internal_values(self) -> None:
        """Guarding on the engine's list keeps typos from silently binding."""
        rule = make_rule('msg:"t"; json_map:"not_an_internal",".x"; sid:1;')
        assert json_map(rule) == {}

    def test_username_is_accepted_although_undocumented(self) -> None:
        """The docs omit username; the engine accepts it and the corpus uses it.

        in more than a thousand rules.
        """
        assert "username" in INTERNAL_VALUES
        assert "flow_id" in INTERNAL_VALUES
        assert "ja3" in INTERNAL_VALUES


class TestFieldResolver:
    def test_message_defaults_to_the_profile(self, context: Context) -> None:
        rule = make_rule('msg:"t"; content:"x"; sid:1;')
        assert FieldResolver.for_rule(rule, context).message == "_raw"

    def test_message_follows_json_map(self, context: Context) -> None:
        """This is the correctness fix that matters most: about a thousand.

        corpus rules redirect content searches to a JSON key.
        """
        rule = make_rule('msg:"t"; json_map:"message",".Msg"; content:"x"; sid:1;')
        assert FieldResolver.for_rule(rule, context).message == "Msg"

    def test_program_follows_json_map(self, context: Context) -> None:
        rule = make_rule('msg:"t"; json_map:"program",".Source"; program:x; sid:1;')
        assert FieldResolver.for_rule(rule, context).program == "Source"

    def test_profile_changes_the_message_field(self, vector_context: Context) -> None:
        rule = make_rule('msg:"t"; content:"x"; sid:1;')
        assert FieldResolver.for_rule(rule, vector_context).message == "message"

    def test_targets_json_flag(self, context: Context) -> None:
        plain = FieldResolver.for_rule(make_rule('msg:"t"; sid:1;'), context)
        mapped = FieldResolver.for_rule(
            make_rule('msg:"t"; json_map:"message",".M"; sid:1;'), context
        )
        assert not plain.targets_json
        assert mapped.targets_json

    def test_unmapped_internal_value_is_none(self, context: Context) -> None:
        """src_ip has no syslog equivalent, which is what makes the converter.

        refuse correlations grouped on a field that does not exist.
        """
        resolver = FieldResolver.for_rule(make_rule('msg:"t"; sid:1;'), context)
        assert resolver.resolve("src_ip") is None
        assert resolver.resolve("event_id") is None
