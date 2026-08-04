"""Tests for value normalisation between Sagan and Sigma semantics."""

from __future__ import annotations

import pytest

from sagan2sigma.mapping.values import (
    CasePolicy,
    case_modifiers,
    coerce_scalar,
    escape_literal,
    split_alternatives,
    split_csv,
    strip_quotes,
)


class TestEscapeLiteral:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("plain", "plain"),
            ("50%*", "50%\\*"),
            ("who?", "who\\?"),
            ("a\\b", "a\\\\b"),
            ("", ""),
        ],
    )
    def test_escapes_sigma_specials(self, raw: str, expected: str) -> None:
        assert escape_literal(raw) == expected

    def test_escapes_backslash_before_wildcards(self) -> None:
        """Order matters: escaping * first would double-escape its backslash."""
        assert escape_literal("*") == "\\*"
        assert escape_literal("\\*") == "\\\\\\*"


class TestCaseModifiers:
    def test_faithful_inverts_sagan_semantics(self) -> None:
        """Sagan is case-sensitive by default, Sigma is not: cased must appear.

        when nocase is ABSENT.
        """
        assert case_modifiers(nocase=False, policy=CasePolicy.FAITHFUL) == ("cased",)
        assert case_modifiers(nocase=True, policy=CasePolicy.FAITHFUL) == ()

    def test_relaxed_never_emits_cased(self) -> None:
        assert case_modifiers(nocase=False, policy=CasePolicy.RELAXED) == ()
        assert case_modifiers(nocase=True, policy=CasePolicy.RELAXED) == ()


class TestStripQuotes:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ('"authentication failure"', (False, "authentication failure")),
            ('!"frank"', (True, "frank")),
            ('  ! "x"  ', (True, "x")),
            ("sshd", (False, "sshd")),
            ('""', (False, "")),
            ('"a"b"', (False, 'a"b')),
        ],
    )
    def test_splits_negation_and_quotes(self, raw: str, expected) -> None:
        assert strip_quotes(raw) == expected


class TestSplitCsv:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("bob, frank ,mary", ["bob", "frank", "mary"]),
            ("[CN,RU]", ["CN", "RU"]),
            ('"a","b"', ["a", "b"]),
            ("single", ["single"]),
            (" , , ", []),
        ],
    )
    def test_splits(self, raw: str, expected: list[str]) -> None:
        assert split_csv(raw) == expected


class TestSplitAlternatives:
    def test_pipe_is_an_or(self) -> None:
        assert split_alternatives("sshd|openssh") == ["sshd", "openssh"]

    def test_preserves_wildcards(self) -> None:
        assert split_alternatives("*Security*|*Sysmon*") == ["*Security*", "*Sysmon*"]

    def test_drops_empty_segments(self) -> None:
        assert split_alternatives("a||b|") == ["a", "b"]


class TestCoerceScalar:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("4624", 4624),
            ("-1", -1),
            ("0", 0),
            ("0x1f", "0x1f"),
            ("4624a", "4624a"),
            ("", ""),
        ],
    )
    def test_coerces_only_pure_integers(self, raw: str, expected) -> None:
        assert coerce_scalar(raw) == expected

    def test_preserves_type(self) -> None:
        assert isinstance(coerce_scalar("4624"), int)
        assert isinstance(coerce_scalar("04624"), int)
        assert isinstance(coerce_scalar("1.5"), str)
