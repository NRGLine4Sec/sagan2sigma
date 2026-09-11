"""Text that satisfies a pattern, and the constructs that used to defeat it.

Every case here came from a corpus rule the sampler refused, found by asking it
why rather than by imagining what might be hard. A pattern it cannot sample
leaves its rule undecided on both sides of the differential, which reads as
agreement and measures nothing, so each refusal is a rule nobody is checking.

`sample_for` verifies its own output against the pattern before returning it,
so a test asserting that it returns something is also asserting the text
matches.
"""

from __future__ import annotations

import re

import pytest
from tests.differential.pcre_sample import sample_for


class TestConstructsThatUsedToRefuse:
    @pytest.mark.parametrize(
        ("pattern", "why"),
        [
            (r"{\d}{\d}{\d}\\*\s*-f", "literal braces, not a repeat count"),
            (r"\${[\!\-\%\(\)\[\]\-\+\/\#\'\`]{1,3}}", "a class inside braces"),
            (r"risk_score\x22:\x22(?:7[6-9]|[8-9]\d)\x22", "a hex escape"),
            (r"\.(bat|cmd)\x22.{1,10}ParentUser", "a hex escape after a group"),
            (r"to=<[A-Za-z0-9|&'*+-.=?^_{}~]+@", "a pipe inside a class"),
            (r"[\!\-\%\(\)\[\]]x", "an escaped bracket inside a class"),
        ],
    )
    def test_a_sample_comes_back(self, pattern: str, why: str) -> None:
        assert sample_for(pattern, "") is not None, why


class TestSubroutineCalls:
    """`(?2)` re-runs the second group, which the sampler writes out."""

    RFC1918 = (
        r"srcip=(10(\.(1?\d\d?|2([0-4]\d?|5[0-5])))(?2)(?2)"
        r"|172\.(1[6-9]|2\d|3[0-2])(?2)(?2))"
    )

    def test_the_call_is_inlined_and_the_sample_matches(self) -> None:
        got = sample_for(self.RFC1918, "")
        assert got is not None
        # Verified against the pattern written out, since `re` has no (?2).
        from tests.differential.pcre_sample import _inline_subroutines

        assert re.search(_inline_subroutines(self.RFC1918), got)

    def test_a_call_to_a_group_that_does_not_exist_is_refused(self) -> None:
        assert sample_for(r"srcip=(10)(?7)", "") is None

    def test_a_group_calling_itself_is_refused(self) -> None:
        """One pass cannot settle a recursion, so it is not attempted."""
        assert sample_for(r"(a(?1)?b)", "") is None


class TestWhatItStillRefuses:
    """Refusing is the safe answer: a wrong sample decides a rule wrongly."""

    @pytest.mark.parametrize(
        "pattern",
        [r"(?=ahead)x", r"(?!ahead)x", r"(?<=behind)x", r"(a)\1"],
    )
    def test_lookaround_and_backreferences(self, pattern: str) -> None:
        assert sample_for(pattern, "") is None


class TestOrdinaryPatternsStillWork:
    @pytest.mark.parametrize(
        "pattern",
        [
            r"plain[0-9]{2}",
            r"a+b*c?",
            r"(?:alpha|beta)-\d{3}",
            r"CommandLine\: C:\\Users\\[a-zA-Z0-9]+\\Temp",
        ],
    )
    def test_sampled(self, pattern: str) -> None:
        assert sample_for(pattern, "") is not None
