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

from dataclasses import dataclass

from ..sagan.model import Option, SaganRule

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


@dataclass(frozen=True, slots=True)
class Window:
    """The slice of the message one ``content`` is searched in.

    ``start`` is a byte offset from the beginning of the message and ``length``
    the number of bytes the search may read, ``None`` meaning to the end. The
    literal has to fit **entirely** inside the slice, which is what the engine's
    truncation of ``alter_content`` amounts to.
    """

    start: int
    length: int | None

    @property
    def constrains(self) -> bool:
        """Whether this window is narrower than the whole message."""
        return self.start > 0 or self.length is not None


def _value(option: Option | None) -> int:
    """A positional option's integer value, 0 when absent or not a number."""
    if option is None or option.value is None:
        return 0
    try:
        return int(option.value.strip())
    except ValueError:
        return 0


def _qualifiers(rule: SaganRule, index: int) -> dict[str, Option]:
    """The positional options qualifying the option at ``index``.

    Sagan applies them to the option that precedes them, and the scan stops at
    the first keyword that is neither positional nor a flag modifier, mirroring
    :meth:`SaganRule.modifiers_after`. ``nocase`` is allowed to sit among them,
    as the corpus writes `content:"x"; distance:0; nocase`.
    """
    found: dict[str, Option] = {}
    for option in rule.options[index + 1 :]:
        if option.name in POSITIONAL_KEYWORDS:
            found.setdefault(option.name, option)
            continue
        if option.name == "nocase":
            continue
        break
    return found


def content_windows(rule: SaganRule) -> dict[int, Window]:
    """Option index of each ``content`` mapped to the window it is searched in.

    Only the contents whose window is narrower than the message appear. The
    arithmetic follows ``src/content.c`` in its own order, which is not the
    Snort semantics the syntax suggests and was measured against the engine
    before being written here:

    * ``offset`` starts the window that many bytes in;
    * ``depth`` truncates it to ``depth + 1`` bytes;
    * ``distance`` **discards** the window built so far and starts a new one at
      ``depth-of-the-previous-content + distance + 1`` bytes from the start of
      the message, so the position is absolute rather than relative to where
      the previous content matched;
    * ``within`` truncates that to ``within`` bytes, and is inert without a
      non-zero ``distance``.

    Measured, needle six bytes long in a message of dots:

        content:"NEEDLE"; depth:10                 fires at 0..4
        content:"a"; content:"NEEDLE"; distance:5  fires from 6
        the same with depth:8 on the first content fires from 14
        distance:5; within:10                      fires at 6..10
        distance:5; within:6                       fires at 6 only
        distance:5; within:5                       never fires
    """
    windows: dict[int, Window] = {}
    previous_depth = 0
    for index, option in enumerate(rule.options):
        if option.name != "content":
            continue
        qualifiers = _qualifiers(rule, index)
        offset = _value(qualifiers.get("offset"))
        depth = _value(qualifiers.get("depth"))
        distance = _value(qualifiers.get("distance"))
        within = _value(qualifiers.get("within"))

        start, length = offset, None
        if depth:
            length = depth + 1
        if distance:
            start = previous_depth + distance + 1
            length = within or None
        window = Window(start=start, length=length)
        if window.constrains:
            windows[index] = window
        previous_depth = depth
    return windows
