"""Tests for positional content modifiers.

Sagan's ``Content()`` and ``MetaContent()`` guard every positional adjustment
with ``if (value != 0)``, so a zero-valued ``offset``/``depth``/``distance``/
``within`` is a no-op and a rule carrying only inert ones converts exactly as if
they were absent. A non-zero ``offset``, ``depth`` or ``distance`` is a real byte
position and is refused. These tests pin both halves, and the nocase-through-
positional scan that the un-blocking exposed.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, run

from sagan2sigma.converter import Converter
from sagan2sigma.errors import Refusal, RefusalCode
from sagan2sigma.mapping.content import handle_content, handle_meta_content
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.positional import effective_positional


class TestEffectivePositional:
    def test_zero_valued_positionals_are_inert(self) -> None:
        rule = make_rule(
            'msg:"t"; content:"a"; content:"b"; distance:0; offset:0; '
            "depth:0; within:0; sid:1;"
        )
        assert effective_positional(rule) == []

    def test_within_without_distance_is_inert(self) -> None:
        # within only bites inside a non-zero distance block, so a lone within
        # changes nothing.
        rule = make_rule('msg:"t"; content:"a"; within:20; sid:1;')
        assert effective_positional(rule) == []

    @pytest.mark.parametrize(
        ("options", "expected"),
        [
            ('content:"a"; content:"b"; distance:1;', ("distance", "1")),
            ('content:"a"; depth:5;', ("depth", "5")),
            ('content:"a"; offset:3;', ("offset", "3")),
            ('meta_content:"%sagan%",v; meta_distance:2;', ("meta_distance", "2")),
        ],
    )
    def test_nonzero_positionals_are_effective(
        self, options: str, expected: tuple[str, str]
    ) -> None:
        rule = make_rule(f'msg:"t"; {options} sid:1;')
        assert expected in effective_positional(rule)


class TestConversion:
    def test_distance_zero_converts_as_independent_contains(self, context) -> None:
        # distance:0 is a no-op: the two contents are unordered substring
        # searches, exactly what the plain content handler emits.
        rule = make_rule(
            'msg:"t"; program:sshd; content:"alpha"; content:"beta"; distance:0; sid:1;'
        )
        draft = Converter(context=context).convert_rule(rule)
        values = {p.values[0] for p in draft.predicates if "contains" in p.modifiers}
        assert {"alpha", "beta"} <= values

    def test_inert_positional_rule_is_not_refused(self, context) -> None:
        rule = make_rule(
            'msg:"t"; program:sshd; content:"x"; within:20; offset:0; sid:1;'
        )
        # Must not raise.
        Converter(context=context).convert_rule(rule)

    @pytest.mark.parametrize("positional", ["distance:1", "depth:5", "offset:3"])
    def test_effective_positional_is_refused(self, context, positional: str) -> None:
        rule = make_rule(
            f'msg:"t"; program:sshd; content:"x"; content:"y"; {positional} sid:1;'
        )
        with pytest.raises(Refusal) as excinfo:
            Converter(context=context).convert_rule(rule)
        assert excinfo.value.code is RefusalCode.POSITIONAL
        assert positional.replace(";", "") in excinfo.value.detail


class TestNocaseThroughPositional:
    """A nocase can sit after a content's positional modifiers.

    Un-blocking positional keywords exposed 14 corpus rules shaped like
    ``content:"x"; distance:0; nocase``. Reading nocase must look through the
    inert positional, or the converted rule would be case-sensitive where the
    original is not.
    """

    def test_nocase_after_positional_is_honoured(
        self, draft: RuleDraft, context
    ) -> None:
        run(
            handle_content,
            make_rule('msg:"t"; content:"x"; distance:0; nocase; sid:1;'),
            draft,
            context,
        )
        # nocase honoured means no |cased modifier is added.
        assert draft.predicates[0].modifiers == ("contains",)

    def test_positional_between_content_and_nocase(
        self, draft: RuleDraft, context
    ) -> None:
        run(
            handle_content,
            make_rule('msg:"t"; content:"x"; distance:0; nocase; content:"y"; sid:1;'),
            draft,
            context,
        )
        # x carries nocase (case-insensitive), y does not (case-sensitive).
        assert draft.predicates[0].modifiers == ("contains",)
        assert draft.predicates[1].modifiers == ("contains", "cased")

    def test_meta_nocase_after_positional_is_honoured(
        self, draft: RuleDraft, context
    ) -> None:
        run(
            handle_meta_content,
            make_rule(
                'msg:"t"; meta_content:"%sagan%",root; meta_distance:0; '
                "meta_nocase; sid:1;"
            ),
            draft,
            context,
        )
        assert draft.predicates[0].modifiers == ("contains",)
