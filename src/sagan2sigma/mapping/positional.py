"""Positional content modifiers, and why the zero-valued ones are inert.

This is a case where the Sagan engine and the Snort documentation it inherits
its syntax from disagree, and the engine wins. The rule-syntax docs describe
``offset``, ``depth``, ``distance`` and ``within`` as byte constraints on where
a ``content`` match may sit. The engine's implementation, in ``src/content.c``
and ``src/meta-content.c``, guards every one of them with ``if (value != 0)``::

    if ( rulestruct[rule_position].s_offset[z] != 0 )   { ... }
    if ( rulestruct[rule_position].s_depth[z]  != 0 )   { ... }
    if ( rulestruct[rule_position].s_distance[z] != 0 ) { ... within ... }

So ``offset:0``, ``depth:0``, ``distance:0`` and ``within:0`` change nothing:
the search runs over the whole message, exactly as a bare ``content`` does. And
``within`` is applied only inside the ``distance != 0`` block, so a ``within`` is
inert unless the same content also carries a non-zero ``distance``.

The practical consequence is large. A rule such as
``content:"A"; content:"B"; distance:0`` does **not** require B to follow A: with
``distance`` at zero the positional block is skipped and both are independent
substring searches over the whole message. Reading ``distance:0`` as "B after A",
which the Snort documentation would suggest, would emit a rule that misses events
the original matches. So a rule whose positional keywords are all inert is
converted faithfully as plain ``|contains`` predicates, and only a non-zero
``offset``, ``depth`` or ``distance`` is refused, since that is a real byte
constraint Sigma's string modifiers cannot express.
"""

from __future__ import annotations

from ..sagan.model import SaganRule

#: Every positional modifier keyword, content and meta_content forms.
POSITIONAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "offset",
        "depth",
        "distance",
        "within",
        "meta_offset",
        "meta_depth",
        "meta_distance",
        "meta_within",
    }
)

#: Positional keywords whose non-zero value actually changes what the engine
#: matches. ``within``/``meta_within`` are excluded on purpose: the engine
#: applies them only inside the ``distance != 0`` block, so a non-zero
#: ``distance`` is what makes a ``within`` bite, and that ``distance`` is already
#: caught here.
_EFFECTIVE: frozenset[str] = frozenset(
    {
        "offset",
        "depth",
        "distance",
        "meta_offset",
        "meta_depth",
        "meta_distance",
    }
)


def effective_positional(rule: SaganRule) -> list[tuple[str, str]]:
    """Positional constraints that actually alter matching, in order.

    Returns ``(keyword, value)`` pairs; an empty list means every positional
    keyword the rule carries is inert, so the rule converts as if they were
    absent. A value that is not an integer is treated as effective, since the
    tool cannot prove it inert; the upstream corpus carries only integer values,
    so that is a defensive path rather than one the corpus exercises.
    """
    effective: list[tuple[str, str]] = []
    for option in rule.options:
        if option.name not in _EFFECTIVE:
            continue
        value = (option.value or "").strip()
        try:
            inert = int(value) == 0
        except ValueError:
            inert = False
        if not inert:
            effective.append((option.name, value))
    return effective
