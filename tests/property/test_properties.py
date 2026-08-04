"""Property-based tests.

Example-based tests confirm the cases we thought of. These confirm the invariants
that must hold for inputs nobody thought of, which is where a rule corpus of ten
thousand hand-written signatures actually lives.
"""

from __future__ import annotations

from hypothesis import assume, given
from hypothesis import strategies as st

from sagan2sigma.mapping.values import (
    CasePolicy,
    case_modifiers,
    coerce_scalar,
    escape_literal,
    split_alternatives,
    split_csv,
    strip_quotes,
)
from sagan2sigma.sagan.hexdec import decode_hex
from sagan2sigma.sagan.parser import parse_option, parse_rule, split_options

# Printable text without the characters that carry structural meaning in the
# Sagan grammar, so that generated values stay inside one option.
SAFE_TEXT = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=126, blacklist_characters=';:"()|'
    ),
    max_size=60,
)
KEYWORD = st.from_regex(r"\A[a-z][a-z0-9_]{0,20}\Z", fullmatch=True)


class TestHexDecoder:
    @given(SAFE_TEXT)
    def test_is_total(self, text: str) -> None:
        """The decoder must never raise, whatever it is fed."""
        assert isinstance(decode_hex(text), str)

    @given(SAFE_TEXT)
    def test_text_without_pipes_is_unchanged(self, text: str) -> None:
        assert decode_hex(text) == text

    @given(st.lists(st.integers(min_value=32, max_value=126), min_size=1, max_size=12))
    def test_round_trips_encoded_bytes(self, codes: list[int]) -> None:
        encoded = "|" + " ".join(f"{code:02x}" for code in codes) + "|"
        assert decode_hex(encoded) == "".join(chr(code) for code in codes)

    @given(SAFE_TEXT, st.integers(min_value=32, max_value=126), SAFE_TEXT)
    def test_decodes_sequences_in_context(
        self, before: str, code: int, after: str
    ) -> None:
        assert (
            decode_hex(f"{before}|{code:02x}|{after}") == f"{before}{chr(code)}{after}"
        )


class TestOptionSplitter:
    @given(st.lists(SAFE_TEXT.filter(lambda s: s.strip()), min_size=1, max_size=8))
    def test_never_loses_a_segment(self, segments: list[str]) -> None:
        """Joining on ';' and splitting again must preserve every segment."""
        assert split_options(";".join(segments)) == [s.strip() for s in segments]

    @given(SAFE_TEXT)
    def test_is_total(self, block: str) -> None:
        assert isinstance(split_options(block), list)

    @given(st.lists(SAFE_TEXT, max_size=10))
    def test_output_is_never_blank(self, segments: list[str]) -> None:
        assert all(part for part in split_options(";".join(segments)))


class TestOptionParser:
    @given(KEYWORD, SAFE_TEXT)
    def test_name_and_value_round_trip(self, name: str, value: str) -> None:
        assume(value.strip())
        option = parse_option(f"{name}:{value}", 0)
        assert option.name == name
        assert option.value == value.strip()

    @given(KEYWORD)
    def test_flags_have_no_value(self, name: str) -> None:
        assert parse_option(name, 0).value is None

    @given(KEYWORD, SAFE_TEXT)
    def test_name_is_always_lowercase(self, name: str, value: str) -> None:
        assert parse_option(f"{name.upper()}:{value}", 0).name == name


class TestRuleParser:
    @given(SAFE_TEXT, st.integers(min_value=1, max_value=9_999_999))
    def test_msg_and_sid_survive_a_round_trip(self, msg: str, sid: int) -> None:
        assume(msg.strip())
        line = f'alert any any any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'
        rule = parse_rule(line, "f.rules", 1)
        assert rule.sid == str(sid)
        assert rule.first("msg") == f'"{msg}"'

    @given(st.lists(KEYWORD, min_size=1, max_size=6, unique=True))
    def test_every_flag_is_kept(self, flags: list[str]) -> None:
        options = "; ".join(flags)
        line = f"alert any any any -> any any ({options};)"
        assert parse_rule(line, "f.rules", 1).keywords == set(flags)

    @given(st.lists(SAFE_TEXT.filter(lambda s: s.strip()), min_size=1, max_size=5))
    def test_option_indices_are_contiguous(self, values: list[str]) -> None:
        options = "; ".join(f"content:{value}" for value in values)
        rule = parse_rule(f"alert any any any -> any any ({options};)", "f.rules", 1)
        assert [option.index for option in rule.options] == list(
            range(len(rule.options))
        )


class TestValueHelpers:
    @given(SAFE_TEXT)
    def test_escaping_neutralises_every_wildcard(self, text: str) -> None:
        escaped = escape_literal(text)
        assert escaped.count("*") == text.count("*")
        for index, char in enumerate(escaped):
            if char in "*?":
                assert index > 0 and escaped[index - 1] == "\\"

    @given(SAFE_TEXT)
    def test_escaping_is_injective_on_specials(self, text: str) -> None:
        """Two different inputs must not collapse onto the same escaped form."""
        assume("\\" not in text)
        assert escape_literal(text).replace("\\", "") == text

    @given(st.booleans(), st.sampled_from(list(CasePolicy)))
    def test_case_modifiers_are_at_most_one(
        self, nocase: bool, policy: CasePolicy
    ) -> None:
        assert len(case_modifiers(nocase, policy)) <= 1

    @given(st.booleans())
    def test_relaxed_never_emits_cased(self, nocase: bool) -> None:
        assert case_modifiers(nocase, CasePolicy.RELAXED) == ()

    @given(SAFE_TEXT)
    def test_strip_quotes_is_total(self, text: str) -> None:
        negated, stripped = strip_quotes(text)
        assert isinstance(negated, bool)
        assert isinstance(stripped, str)

    @given(st.lists(SAFE_TEXT.filter(lambda s: s.strip() and "," not in s), max_size=6))
    def test_split_csv_preserves_the_item_count(self, items: list[str]) -> None:
        assert len(split_csv(",".join(items))) == len(items)

    @given(st.lists(SAFE_TEXT.filter(lambda s: s.strip()), min_size=1, max_size=6))
    def test_split_alternatives_preserves_the_item_count(
        self, items: list[str]
    ) -> None:
        assert len(split_alternatives("|".join(items))) == len(items)

    @given(st.integers())
    def test_integers_round_trip(self, value: int) -> None:
        assert coerce_scalar(str(value)) == value

    @given(SAFE_TEXT)
    def test_coerce_scalar_never_raises(self, text: str) -> None:
        assert isinstance(coerce_scalar(text), (str, int))
