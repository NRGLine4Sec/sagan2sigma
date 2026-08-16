"""Tests for the pcre handler and its PCRE subset guard."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.errors import Refusal, RefusalCode
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.regexes import (
    escape_literal_braces,
    expand_subroutines,
    handle_pcre,
    has_unsupported_brace,
    normalise_regex,
    parse_pcre,
    strip_tempered_negation,
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

    def test_tolerates_the_inert_h_flag(self) -> None:
        """Sagan's flag switch has no default case, so it drops H silently.

        Refusing a rule Sagan runs, over a no-op buffer modifier it never
        implemented, would make the converter stricter than its target engine.
        """
        assert parse_pcre('"/abc/iH"')[2] == ("re", "i")


class TestValidateRegex:
    @pytest.mark.parametrize(
        "pattern",
        [
            r"(a)(?R)",
            r"(?&name)",
            r"(*SKIP)abc",
            r"(?(1)a|b)",
            r"abc\K def",
            # validate_regex is the low-level guard and runs on the raw pattern,
            # so a numbered subroutine and a literal brace are refused here. The
            # converter recovers them upstream in parse_pcre, which normalises
            # the pattern first; see TestRegexRewrites.
            r"srcip=(10(\.(1?\d\d?|2([0-4]\d?|5[0-5])))(?2))",
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


class TestRegexRewrites:
    """The meaning-preserving rewrites that recover E_PCRE_UNSUPPORTED rules.

    Each rewrite was fuzzed against a PCRE oracle and its output confirmed to
    load in the RSigma engine before being committed; these tests pin the
    behaviour and the corpus patterns that motivated it.
    """

    def test_escape_literal_brace_only_touches_the_open_brace(self) -> None:
        # {\d} is a literal '{', a digit and a literal '}'. Only the '{' breaks
        # the Rust engine, so only it is escaped; the '}' is left as-is.
        assert escape_literal_braces(r"{\d}") == r"\{\d}"

    def test_escape_literal_brace_keeps_quantifiers_and_classes(self) -> None:
        # A valid repetition, an escaped brace and an in-class brace are all
        # left byte-for-byte, so a well-formed pattern is unchanged.
        for pattern in (r"\d{1,3}", r"a\{3\}b", r"[a{]b", r"x{3}y{2,}z{1,4}"):
            assert escape_literal_braces(pattern) == pattern

    def test_escape_literal_brace_on_the_corpus_pattern(self) -> None:
        original = r"\${[\!\-\%\(\)]{1,3}}"
        assert escape_literal_braces(original) == r"\$\{[\!\-\%\(\)]{1,3}}"

    def test_expand_subroutine_inlines_the_group_pattern(self) -> None:
        assert expand_subroutines(r"(\d+)-(?1)") == r"(\d+)-(?:\d+)"

    def test_expand_subroutine_is_identity_without_calls(self) -> None:
        for pattern in (r"a(?:b|c)+", r"(\d+)\.(\d+)", r"^\w+$"):
            assert expand_subroutines(pattern) == pattern

    def test_expand_subroutine_leaves_recursion_for_the_guard(self) -> None:
        # A self-referential group cannot be flattened; the call is left in
        # place so validate_regex refuses it rather than looping.
        result = expand_subroutines(r"(a(?1)?b)")
        with pytest.raises(Refusal):
            validate_regex(result)

    def test_strip_tempered_negation_extracts_the_inner_pattern(self) -> None:
        assert strip_tempered_negation(r"^((?!Account Name: (.*)\$ ).)*$") == (
            r"Account Name: (.*)\$ "
        )

    @pytest.mark.parametrize(
        "pattern",
        [
            r"abc",
            r"^((?!A)B.)*$",  # a stray ')' inside: not the tempered shape
            r"^(?!x).*$",  # a plain look-ahead, not the whole-string idiom
            r"((?!x).)*$",  # missing the leading anchor
        ],
    )
    def test_strip_tempered_negation_rejects_other_shapes(self, pattern: str) -> None:
        assert strip_tempered_negation(pattern) is None

    def test_normalise_is_identity_on_well_formed_patterns(self) -> None:
        for pattern in (r"broken|breaking", r"^\d{1,3}\.\d{1,3}$", r"a(?:b|c)+"):
            assert normalise_regex(pattern) == pattern

    def test_parse_pcre_recovers_a_brace_pattern(self) -> None:
        negated, body, _ = parse_pcre(r'"/{\d}{\d}/"')
        assert negated is False
        assert body == r"\{\d}\{\d}"

    def test_parse_pcre_recovers_a_subroutine_pattern(self) -> None:
        _, body, _ = parse_pcre(r'"/(10|172)(?1)/"')
        assert "(?1)" not in body
        assert body == r"(10|172)(?:10|172)"

    def test_parse_pcre_recovers_tempered_negation_as_a_negated_search(self) -> None:
        # ^((?!X).)*$ matches when X is absent, so it becomes a negated search.
        negated, body, _ = parse_pcre(r'"/^((?!secret).)*$/"')
        assert negated is True
        assert body == "secret"

    def test_parse_pcre_negated_tempered_negation_double_negates(self) -> None:
        # !"...^((?!X).)*$..." is "not (X absent)" = "X present": a plain search.
        negated, body, _ = parse_pcre(r'!"/^((?!secret).)*$/"')
        assert negated is False
        assert body == "secret"


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
