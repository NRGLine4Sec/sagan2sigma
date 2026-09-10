r"""What the engine compiles for a `pcre` option, row by measured row.

Every row was run against a locally built Sagan: one rule carrying the option,
one event carrying the text, and the alert or its absence read back. The model
in `sagan.pcre` is written from `util.c` and `rules.c`; these rows are what say
it describes the engine rather than the C as somebody read it.
"""

from __future__ import annotations

import pytest

from sagan2sigma.sagan.pcre import between_quotes, engine_pattern, written_pattern


class TestBetweenQuotes:
    """The copy loop does not stop at the second quote."""

    def test_an_ordinary_value_loses_only_its_delimiters(self) -> None:
        assert between_quotes('"/abc/"') == "/abc/"

    def test_an_inner_quote_is_dropped_and_copying_continues(self) -> None:
        assert between_quotes('"/a"b/"') == "/ab/"

    def test_text_before_the_first_quote_is_lost(self) -> None:
        assert between_quotes(' /"abc"/i"') == "abc/i"


class TestEnginePattern:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # Plain values are untouched, which is most of the corpus.
            ('"/plain[0-9]{2}/"', ("plain[0-9]{2}", "")),
            ('"/abc/i"', ("abc", "i")),
            # A quote inside the pattern is deleted and the backslash before it
            # attaches to whatever follows. Measured: this fires on the literal
            # text `id=[0-9]]]` and not on `id="123`.
            (r'"/id=\"[0-9]{3}/"', (r"id=\[0-9]{3}", "")),
            # A character class loses one of its members. Measured: fires on
            # `-Value 0` and on `-Value '0'`, not on `-Value "0"`.
            ('"/[\\"\']?0[\\"\']?/"', ("[\\']?0[\\']?", "")),
            # No opening quote, so the slash goes with the text before it and
            # the pattern loses its first character. Measured on sid 5014601:
            # fires on `procdump.exe`, the `p` no longer required.
            (' /"procdump(64)*\\.exe"/i"', ("rocdump(64)*\\.exe", "i")),
            # The fix: \x22 is a quote to PCRE and not a quote to the parser.
            # Measured: fires on `id="123`.
            (r'"/id=\x22[0-9]{3}/"', (r"id=\x22[0-9]{3}", "")),
        ],
    )
    def test_rows(self, value: str, expected: tuple[str, str]) -> None:
        assert engine_pattern(value) == expected

    def test_an_escaped_delimiter_stops_the_ruleset_loading(self) -> None:
        r"""`\\"/` leaves `\\/`, so the parser never finds its closing slash.

        Measured: the engine says `Missing last '/' in pcre` and exits 1, which
        takes the whole ruleset with it.
        """
        assert engine_pattern(r'"/\"procdump\.exe\"/i"') is None

    def test_a_value_with_no_quote_at_all_yields_nothing(self) -> None:
        assert engine_pattern("/abc/") is None


class TestWrittenPattern:
    """The reading a person gives the same line."""

    def test_the_quotes_are_delimiters_and_the_pattern_is_kept_whole(self) -> None:
        assert written_pattern(r'"/id=\"[0-9]{3}/"') == (r"id=\"[0-9]{3}", "")

    def test_a_negation_is_stripped_like_the_engine_strips_it(self) -> None:
        assert written_pattern('!"/abc/i"') == ("abc", "i")

    def test_the_two_readings_agree_on_a_pattern_holding_no_quote(self) -> None:
        value = '"/a[0-9]b/im"'
        assert written_pattern(value) == engine_pattern(value)
