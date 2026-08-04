"""Value normalisation between Sagan and Sigma semantics.

Two mismatches justify this module.

**Wildcards.** Sigma treats ``*`` and ``?`` as wildcards inside a plain value.
Sagan does the same in ``program`` (the ``Wildcard()`` function in
``src/util.c``: same semantics, same full-string anchoring), but **not** in
``content`` or ``json_content``, where those characters are literal. They must
therefore be escaped for the latter and preserved for the former.

**Case sensitivity.** Sagan compares ``content`` case-sensitively and
``nocase`` turns that off. Sigma does the exact opposite: case-insensitive by
default, ``|cased`` to force sensitivity. A conversion that copied ``nocase``
across without inverting would silently flip the semantics of roughly 7,600
rules in the upstream corpus, and the defect would be invisible in any test
that only checks that the rule parses.
"""

from __future__ import annotations

from enum import Enum

#: Characters Sigma gives special meaning to inside a plain value.
_SIGMA_SPECIAL = ("\\", "*", "?")


class CasePolicy(str, Enum):
    """How to treat case sensitivity."""

    #: Reproduce Sagan exactly: emit ``|cased`` unless ``nocase`` is present.
    FAITHFUL = "faithful"
    #: Drop ``|cased`` everywhere, trading fidelity for recall.
    RELAXED = "relaxed"


def escape_literal(value: str) -> str:
    r"""Escape the Sigma-special characters of a literal value.

    >>> escape_literal('plain')
    'plain'
    >>> escape_literal('50%*')
    '50%\\*'
    >>> escape_literal('who?')
    'who\\?'
    """
    for char in _SIGMA_SPECIAL:
        value = value.replace(char, "\\" + char)
    return value


def case_modifiers(nocase: bool, policy: CasePolicy) -> tuple[str, ...]:
    """Case modifiers to apply to a predicate.

    >>> case_modifiers(nocase=False, policy=CasePolicy.FAITHFUL)
    ('cased',)
    >>> case_modifiers(nocase=True, policy=CasePolicy.FAITHFUL)
    ()
    >>> case_modifiers(nocase=False, policy=CasePolicy.RELAXED)
    ()
    """
    if policy is CasePolicy.RELAXED:
        return ()
    return () if nocase else ("cased",)


def strip_quotes(value: str) -> tuple[bool, str]:
    """Split off the negation operator and remove enclosing quotes.

    >>> strip_quotes('!"frank"')
    (True, 'frank')
    >>> strip_quotes('  "authentication failure" ')
    (False, 'authentication failure')
    >>> strip_quotes('sshd')
    (False, 'sshd')
    """
    text = value.strip()
    negated = False
    if text.startswith("!"):
        negated = True
        text = text[1:].strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return negated, text


def split_csv(value: str) -> list[str]:
    """Split a Sagan ``a,b,c`` list, stripping quotes and brackets.

    >>> split_csv('bob, frank ,mary')
    ['bob', 'frank', 'mary']
    >>> split_csv('[CN,RU]')
    ['CN', 'RU']
    """
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return [part.strip().strip('"') for part in text.split(",") if part.strip()]


def split_alternatives(value: str) -> list[str]:
    """Split Sagan ``|``-separated alternatives.

    Sagan runs ``strtok_r(buffer, "|", ...)`` over ``program``,
    ``syslog_facility``, ``syslog_level`` and ``syslog_tag``, so the pipe is
    always an OR in those keywords, never a literal character.

    >>> split_alternatives('sshd|openssh')
    ['sshd', 'openssh']
    >>> split_alternatives('*Security*')
    ['*Security*']
    """
    return [part.strip() for part in value.split("|") if part.strip()]


def coerce_scalar(value: str) -> str | int:
    """Turn a purely numeric value into an integer.

    Sigma distinguishes ``EventID: 4624`` from ``EventID: "4624"``. Windows
    logs expose an integer, so the conversion must produce one.

    >>> coerce_scalar('4624')
    4624
    >>> coerce_scalar('0x1f')
    '0x1f'
    >>> coerce_scalar('-1')
    -1
    """
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value)
    return value
