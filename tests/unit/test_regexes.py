"""Tests for the pcre handler and its PCRE subset guard."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import Refusal, RefusalCode
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.regexes import (
    handle_pcre,
    has_unsupported_brace,
    parse_pcre,
    validate_regex,
)


class TestParsePcre:
    def test_plain_pattern(self) -> None:
        assert parse_pcre('"/broken system/"') == (False, "broken system", ("re",))

    def test_case_insensitive_flag(self) -> None:
        negated, body, modifiers = parse_pcre('"/abc/i"')
        assert (negated, body, modifiers) == (False, "abc", ("re", "i"))

    def test_combined_flags(self) -> None:
        assert parse_pcre('"/a/ims"')[2] == ("re", "i", "m", "s")

    def test_negation(self) -> None:
        assert parse_pcre('!"/abc/"')[0] is True

    def test_unquoted_form(self) -> None:
        assert parse_pcre("/abc/i")[1] == "abc"

    def test_rejects_missing_delimiters(self) -> None:
        with pytest.raises(Refusal) as excinfo:
            parse_pcre('"abc"')
        assert excinfo.value.code is RefusalCode.PCRE_UNSUPPORTED

    def test_rejects_an_unsupported_flag(self) -> None:
        with pytest.raises(Refusal, match="flag"):
            parse_pcre('"/abc/Q"')

    def test_tolerates_no_op_flags(self) -> None:
        assert parse_pcre('"/abc/g"')[2] == ("re",)


class TestValidateRegex:
    @pytest.mark.parametrize(
        "pattern",
        [
            r"srcip=(10(\.(1?\d\d?|2([0-4]\d?|5[0-5])))(?2))",
            r"(a)(?R)",
            r"(?&name)",
            r"(*SKIP)abc",
            r"(?(1)a|b)",
            r"abc\K def",
            # A '{' that is not a counted repetition: Python reads a literal
            # brace, the Rust regex engine rejects it. This is the real corpus
            # pattern that the positional un-blocking exposed.
            r'{\d}{\d}{\d}\\*"\s*-f',
            r"a{def}b",
        ],
    )
    def test_rejects_non_portable_constructs(self, pattern: str) -> None:
        with pytest.raises(Refusal) as excinfo:
            validate_regex(pattern)
        assert excinfo.value.code is RefusalCode.PCRE_UNSUPPORTED

    def test_rejects_an_uncompilable_pattern(self) -> None:
        with pytest.raises(Refusal, match="compile"):
            validate_regex("([a-z")

    @pytest.mark.parametrize(
        "pattern",
        [
            r"broken system|breaking system",
            r"^\d{1,3}\.\d{1,3}$",
            r"(?i)abc",
            r"a(?:b|c)+",
            # A well-formed counted repetition is fine, as is an escaped or
            # in-class brace, which is a literal to both engines.
            r"x{3}y{2,}z{1,4}",
            r"a\{3\}b",
            r"[a{]b",
        ],
    )
    def test_accepts_portable_patterns(self, pattern: str) -> None:
        validate_regex(pattern)

    @pytest.mark.parametrize(
        ("pattern", "unsupported"),
        [
            (r"{\d}", True),
            (r"a{def}", True),
            (r"{3}abc", False),  # a valid quantifier body, left to the engine
            (r"\d{3}", False),
            (r"a\{3\}b", False),  # escaped braces are literals
            (r"[a{]b", False),  # a brace inside a character class is a literal
        ],
    )
    def test_has_unsupported_brace(self, pattern: str, unsupported: bool) -> None:
        assert has_unsupported_brace(pattern) is unsupported


class TestHandlePcre:
    def test_emits_a_re_predicate(self, draft: RuleDraft, context) -> None:
        run(handle_pcre, make_rule('msg:"t"; pcre:"/failed/i"; sid:1;'), draft, context)
        predicate = draft.predicates[0]
        assert predicate.field == "_raw"
        assert predicate.modifiers == ("re", "i")
        assert predicate.values == ("failed",)

    def test_follows_json_map(self, draft: RuleDraft, context) -> None:
        rule = make_rule('msg:"t"; json_map:"message",".D"; pcre:"/x/"; sid:1;')
        run(handle_pcre, rule, draft, context)
        assert draft.predicates[0].field == "D"
