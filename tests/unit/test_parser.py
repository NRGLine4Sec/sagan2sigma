"""Tests for the Sagan rule parser."""

from __future__ import annotations

import pytest

from sagan2sigma.sagan.parser import (
    LexError,
    find_options_block,
    parse_lines,
    parse_option,
    parse_rule,
    split_options,
)

HEADER = "alert any $EXTERNAL_NET any -> $HOME_NET any"


class TestSplitOptions:
    def test_splits_on_semicolons(self) -> None:
        assert split_options('msg:"a"; sid:1;') == ['msg:"a"', "sid:1"]

    def test_keeps_flags(self) -> None:
        assert split_options('content:"x"; nocase; sid:1') == [
            'content:"x"',
            "nocase",
            "sid:1",
        ]

    def test_ignores_empty_segments(self) -> None:
        assert split_options(";;  ;;") == []

    def test_tolerates_unbalanced_quotes(self) -> None:
        """175 corpus rules carry an odd quote count; Sagan parses them fine."""
        parts = split_options(
            'json_meta_content:!".properties".deviceDetail",A; sid:1;'
        )
        assert parts[-1] == "sid:1"
        assert len(parts) == 2


class TestFindOptionsBlock:
    def test_extracts_body(self) -> None:
        line = f'{HEADER} (msg:"a"; sid:1;)'
        body, close = find_options_block(line, line.index("("))
        assert body == 'msg:"a"; sid:1;'
        assert line[close] == ")"

    def test_tolerates_nested_parentheses_in_values(self) -> None:
        line = f'{HEADER} (msg:"a (b) c"; sid:1;)'
        body, _ = find_options_block(line, line.index("("))
        assert body == 'msg:"a (b) c"; sid:1;'

    def test_raises_without_closing_parenthesis(self) -> None:
        with pytest.raises(LexError, match="closing parenthesis"):
            find_options_block("alert any (msg", 10)


class TestParseOption:
    def test_named_option(self) -> None:
        option = parse_option('content:"x"', 0)
        assert (option.name, option.value, option.index) == ("content", '"x"', 0)

    def test_flag_option(self) -> None:
        option = parse_option("nocase", 7)
        assert (option.name, option.value, option.index) == ("nocase", None, 7)

    def test_lowercases_the_name(self) -> None:
        assert parse_option("NoCase", 0).name == "nocase"

    def test_keeps_colons_inside_the_value(self) -> None:
        assert parse_option("reference:url,http://x/y", 0).value == "url,http://x/y"


class TestParseRule:
    def test_parses_header_fields(self) -> None:
        rule = parse_rule(f'{HEADER} (msg:"a"; sid:1;)', "f.rules", 3)
        assert rule.header.action == "alert"
        assert rule.header.direction == "->"
        assert rule.header.source == "$EXTERNAL_NET"
        assert rule.source_file == "f.rules"
        assert rule.line_number == 3

    @pytest.mark.parametrize("action", ["alert", "drop", "pass"])
    def test_accepts_every_documented_action(self, action: str) -> None:
        line = f'{action} any any any -> any any (msg:"a"; sid:1;)'
        assert parse_rule(line, "f.rules", 1).header.action == action

    def test_rejects_unknown_header(self) -> None:
        with pytest.raises(LexError, match="header"):
            parse_rule('notanaction any (msg:"a";)', "f.rules", 1)

    def test_rejects_empty_option_block(self) -> None:
        with pytest.raises(LexError, match="empty option block"):
            parse_rule(f"{HEADER} ()", "f.rules", 1)

    def test_exposes_sid_and_rev(self) -> None:
        rule = parse_rule(f'{HEADER} (msg:"a"; sid:5000116; rev:2;)', "f.rules", 1)
        assert (rule.sid, rule.rev) == ("5000116", "2")

    def test_defaults_rev_to_one(self) -> None:
        assert parse_rule(f'{HEADER} (msg:"a"; sid:1;)', "f.rules", 1).rev == "1"


class TestRuleAccessors:
    @pytest.fixture
    def rule(self):
        return parse_rule(
            f'{HEADER} (msg:"a"; content:"x"; nocase; content:"y"; sid:1;)',
            "f.rules",
            1,
        )

    def test_values_returns_every_occurrence(self, rule) -> None:
        assert rule.values("content") == ['"x"', '"y"']

    def test_first_returns_the_first(self, rule) -> None:
        assert rule.first("content") == '"x"'

    def test_first_is_none_when_absent(self, rule) -> None:
        assert rule.first("pcre") is None

    def test_has_detects_flags(self, rule) -> None:
        assert rule.has("nocase")
        assert not rule.has("meta_nocase")

    def test_keywords(self, rule) -> None:
        assert rule.keywords == {"msg", "content", "nocase", "sid"}

    def test_modifiers_after_is_positional(self, rule) -> None:
        """Nocase must attach to the content it follows, not to the other one."""
        contents = list(rule.iter_options("content"))
        assert rule.modifiers_after(contents[0].index, frozenset({"nocase"})) == {
            "nocase"
        }
        assert (
            rule.modifiers_after(contents[1].index, frozenset({"nocase"}))
            == frozenset()
        )


class TestParseLines:
    def test_counts_disabled_rules(self) -> None:
        lines = [
            f'{HEADER} (msg:"live"; sid:1;)',
            f'# {HEADER} (msg:"disabled"; sid:2;)',
            '#alert any any any -> any any (msg:"also disabled"; sid:3;)',
            "# a plain comment",
            "",
        ]
        rules, failures, disabled = parse_lines(lines, "f.rules")
        assert len(rules) == 1
        assert disabled == 2
        assert failures == []

    def test_records_failures_without_raising(self) -> None:
        rules, failures, _ = parse_lines([f"{HEADER} (", "alert x"], "f.rules")
        assert rules == []
        assert len(failures) == 1
        assert failures[0].line_number == 1
