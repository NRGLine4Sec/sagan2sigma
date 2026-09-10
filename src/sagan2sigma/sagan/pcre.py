r"""The pattern a ``pcre`` option really compiles to, which is not the one written.

Two steps of the engine decide it, and both are mechanical:

``Between_Quotes`` (``src/util.c``)
    copies the option value from its first ``"`` onward, leaving out every
    ``"`` it meets. It does not stop at the second quote: the loop clears its
    copy flag on a quote and sets it again on the same character, so what comes
    back is the whole value minus its quote characters, minus whatever preceded
    the first one.

``rules.c`` line 3032
    reads the pattern from index **1** to the first ``/`` whose predecessor is
    not a backslash, and the letters after that ``/`` are the flags. Index 0 is
    assumed to be the opening slash and is dropped without being looked at, so
    a value whose slash was consumed by the step above loses a real character
    of its pattern instead.

Measured against a locally built Sagan, one rule and one event per row:

===================================  =========================  =============
option value                         pattern the engine runs    fires on
===================================  =========================  =============
``"/id=\\"[0-9]{3}/"``                ``id=\\[0-9]{3}``           ``id=[0-9]]]``
``"/[\\"']?0[\\"']?/"``                ``[\\']?0[\\']?``            ``-Value 0``
``"/[\\"\\']x[0-9]/"``                 ``[\\\\']x[0-9]``            ``'x1``
``/"procdump(64)*\\.exe"/i"``         ``rocdump(64)*\\.exe``      ``procdump.exe``
``"/id=\\x22[0-9]{3}/"``              ``id=\\x22[0-9]{3}``        ``id="123``
===================================  =========================  =============

The fourth row is the one worth reading twice: the value opens with ``/`` and
not with a quote, so ``Between_Quotes`` drops the slash, and the pattern then
loses its own first character. The fifth is the way out, and the fix this
project proposes upstream: ``\\x22`` is the quote written as PCRE reads it,
which survives both steps.
"""

from __future__ import annotations


def between_quotes(value: str) -> str:
    """``Between_Quotes``: everything after the first quote, quotes apart."""
    out: list[str] = []
    inside = False
    for char in value:
        # The three tests are the C's, in its order: a quote clears the flag,
        # the copy happens only while it is set, and the same quote sets it
        # again. That last line is why a quote does not end the argument.
        if inside and char == '"':
            inside = False
        elif inside:
            out.append(char)
        if char == '"':
            inside = True
    return "".join(out)


def engine_pattern(value: str) -> tuple[str, str] | None:
    r"""The pattern and flags the engine compiles, or None when it will not load.

    None means ``Missing last '/' in pcre``, which aborts the whole ruleset:
    it happens when removing the quotes leaves the closing delimiter escaped,
    as ``\\"/`` does.
    """
    kept = between_quotes(value)
    if not kept:
        return None
    body: list[str] = []
    flags: list[str] = []
    closed = False
    for index in range(1, len(kept)):
        if not closed and kept[index] == "/" and kept[index - 1] != "\\":
            closed = True
            continue
        (flags if closed else body).append(kept[index])
    if not closed:
        return None
    return "".join(body), "".join(flags)


def written_pattern(value: str) -> tuple[str, str] | None:
    """The pattern and flags as the rule's author spelled them.

    The reading a person gives the line: strip an outer pair of quotes, then
    take what lies between the first and last slash. Comparing it with
    :func:`engine_pattern` is what says whether the rule tests the condition it
    appears to.
    """
    text = value.strip()
    if text.startswith("!"):
        text = text[1:].strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    if not text.startswith("/"):
        return None
    closing = text.rfind("/")
    if closing <= 0:
        return None
    return text[1:closing], text[closing + 1 :]
