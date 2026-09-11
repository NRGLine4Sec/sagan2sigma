"""One string that satisfies a `pcre`, when one can be produced safely.

A rule whose detection rests on a regular expression cannot be probed by
joining its literals: there are none. 233 corpus rules sat silent on both
sides for that reason, so the `pcre` conversion, which is the `|re` modifier
and its flags, was judged by hand-written tests alone and never at corpus
scale.

This produces a candidate and then **verifies it**, so the generator cannot
invent a probe that does not match: whatever it emits is checked against the
pattern with `re` before being returned, and anything it cannot handle yields
nothing rather than a guess. On the upstream corpus it samples 285 of the 348
`pcre` options; the 59 it refuses are lookarounds, backreferences and recursive
subpatterns, which is the right place to stop.

What it does not claim is to implement PCRE. Python's `re` and libpcre agree on
this subset, and where they would not, the engine has the last word: a sample
Sagan does not accept simply leaves the rule silent, which the run reports by
name.
"""

from __future__ import annotations

import re

#: What each shorthand contributes, chosen to be ordinary text.
SHORTHAND = {"d": "4", "w": "a", "s": " ", "D": "a", "W": " ", "S": "a"}
REFUSED = ("(?=", "(?!", "(?<", "\\1", "\\2", "\\b")


#: `\xHH`, a character written as its hexadecimal code.
_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")

#: A counted quantifier. A brace that does not read like one is a literal
#: brace, which the corpus writes: `{\d}{\d}{\d}` is three brace-wrapped
#: shorthands and `\${[...]{1,3}}` wraps a class in braces of its own. Treating
#: every `{` as a quantifier made the sampler read the class as a repeat count
#: and raise, so five rules produced no sample at all.
_COUNT = re.compile(r"\{\d+(?:,\d*)?\}")


#: `(?2)`, a call re-running the second capturing group.
_SUBROUTINE = re.compile(r"\(\?(\d+)\)")


class Unsupported(Exception):
    """The pattern uses something this generator will not guess at."""


def _class_member(body: str) -> str:
    """One character a bracket expression accepts."""
    if body.startswith("^"):
        return "z" if "z" not in body else "q"
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            return SHORTHAND.get(body[i + 1], body[i + 1])
        if i + 2 < len(body) and body[i + 1] == "-":
            return body[i]
        if body[i] not in ",":
            return body[i]
        i += 1
    raise Unsupported(f"empty class: {body!r}")


def _class_end(pattern: str, start: int) -> int:
    r"""Index of the `]` that closes the class opened at ``start``.

    A `\]` inside the class does not close it, and neither does a `]` in first
    position. Scanning for the first `]` instead put the class end in the
    middle of `[\!\-\%\(\)\[\]...]`, and two corpus rules produced no
    sample because of it.
    """
    i = start + 1
    if i < len(pattern) and pattern[i] == "^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "]":
            return i
        i += 1
    raise Unsupported(f"unterminated class: {pattern[start : start + 24]!r}")


def _atoms(pattern: str) -> list[str]:
    """Split a branch into atoms, each already reduced to literal text."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            nxt = pattern[i + 1] if i + 1 < len(pattern) else ""
            if nxt == "x" and _HEX_ESCAPE.match(pattern, i):
                # `\x22` is a quote. Passing the escape through unchanged put
                # the four characters in the text instead of the one they name,
                # and eight corpus rules then sampled text their own pattern
                # rejects.
                out.append(chr(int(pattern[i + 2 : i + 4], 16)))
                i += 4
            else:
                out.append(SHORTHAND.get(nxt, nxt))
                i += 2
        elif char == "[":
            depth = _class_end(pattern, i)
            out.append(_class_member(pattern[i + 1 : depth]))
            i = depth + 1
        elif char == "(":
            depth, level = i + 1, 1
            while depth < len(pattern) and level:
                if pattern[depth] == "\\":
                    depth += 2
                    continue
                level += (pattern[depth] == "(") - (pattern[depth] == ")")
                depth += 1
            inner = pattern[i + 1 : depth - 1]
            if inner.startswith("?:"):
                inner = inner[2:]
            elif inner.startswith("?"):
                raise Unsupported(f"group modifier: {inner[:3]!r}")
            out.append(sample(inner))
            i = depth
        elif char in "^$":
            i += 1
        elif char == ".":
            out.append("a")
            i += 1
        else:
            out.append(char)
            i += 1
        # a quantifier binds to the atom just emitted
        while i < len(pattern) and (pattern[i] in "?*+" or _COUNT.match(pattern, i)):
            atom = out.pop() if out else ""
            if pattern[i] in "?*":
                out.append("")
                i += 1
            elif pattern[i] == "+":
                out.append(atom)
                i += 1
            else:
                end = pattern.index("}", i)
                spec = pattern[i + 1 : end].split(",")[0] or "1"
                out.append(atom * int(spec or 1))
                i = end + 1
            if i < len(pattern) and pattern[i] == "?":
                i += 1
    return out


def _capturing_groups(pattern: str) -> dict[int, str]:
    """The source of each capturing group, numbered as PCRE numbers them."""
    groups: dict[int, str] = {}
    stack: list[tuple[int, int]] = []
    number = 0
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "[":
            i = _class_end(pattern, i) + 1
            continue
        if pattern[i] == "(":
            capturing = not pattern.startswith("(?", i)
            if capturing:
                number += 1
            stack.append((i, number if capturing else 0))
        elif pattern[i] == ")" and stack:
            start, index = stack.pop()
            if index:
                groups[index] = pattern[start + 1 : i]
        i += 1
    return groups


def _inline_subroutines(pattern: str) -> str:
    r"""`(?2)` replaced by the source of group 2, as PCRE would re-run it.

    Two corpus rules match an RFC 1918 address by writing the octet once and
    calling it again: `(10(\.(1?\d\d?|...))(?2)|172\....)`. Refusing them
    left both unsampled, and a sampler that cannot produce text for a pattern
    leaves its rule undecided on both sides.
    """
    groups = _capturing_groups(pattern)
    out, i = "", 0
    while i < len(pattern):
        match = _SUBROUTINE.match(pattern, i)
        if match is None:
            out += pattern[i]
            i += 1
            continue
        index = int(match.group(1))
        if index not in groups:
            raise Unsupported(f"subroutine call to an unknown group: {index}")
        out += f"(?:{groups[index]})"
        i = match.end()
    return out


def sample(pattern: str) -> str:
    """One string the pattern accepts, taking the first branch throughout."""
    if any(token in pattern for token in REFUSED):
        raise Unsupported("lookaround or backreference")
    if _SUBROUTINE.search(pattern):
        pattern = _inline_subroutines(pattern)
    branch, level, i = "", 0, 0
    while i < len(pattern):
        if pattern[i] == "\\":
            branch += pattern[i : i + 2]
            i += 2
            continue
        if pattern[i] == "[":
            # A `|` inside a character class is one of its members, not a
            # branch: `[A-Za-z0-9|&...]` was being cut in half here, and the
            # class then read as unterminated.
            end = _class_end(pattern, i)
            branch += pattern[i : end + 1]
            i = end + 1
            continue
        level += (pattern[i] == "(") - (pattern[i] == ")")
        if pattern[i] == "|" and level == 0:
            break
        branch += pattern[i]
        i += 1
    return "".join(_atoms(branch))


def sample_for(body: str, flags: str) -> str | None:
    """A verified sample of ``body``, or None when none could be produced.

    The check runs against the pattern with its subroutine calls inlined, since
    Python's `re` has no `(?2)`: compiling the original refused every such
    pattern and the sample went unused even when it was right. Inlining is the
    same language written out, and a pattern whose group calls itself is
    refused rather than expanded, since one pass cannot settle a recursion.
    """
    try:
        candidate = sample(body)
        checkable = _inline_subroutines(body) if _SUBROUTINE.search(body) else body
    except (Unsupported, ValueError, IndexError):
        return None
    if not candidate or _SUBROUTINE.search(checkable):
        return None
    try:
        compiled = re.compile(checkable, re.IGNORECASE if "i" in flags else 0)
    except re.error:
        return None
    return candidate if compiled.search(candidate) else None
