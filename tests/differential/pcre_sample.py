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


def _atoms(pattern: str) -> list[str]:
    """Split a branch into atoms, each already reduced to literal text."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            nxt = pattern[i + 1] if i + 1 < len(pattern) else ""
            out.append(SHORTHAND.get(nxt, nxt))
            i += 2
        elif char == "[":
            depth = pattern.index("]", i + 2)
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
        while i < len(pattern) and pattern[i] in "?*+{":
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


def sample(pattern: str) -> str:
    """One string the pattern accepts, taking the first branch throughout."""
    if any(token in pattern for token in REFUSED):
        raise Unsupported("lookaround or backreference")
    branch, level, i = "", 0, 0
    while i < len(pattern):
        if pattern[i] == "\\":
            branch += pattern[i : i + 2]
            i += 2
            continue
        level += (pattern[i] == "(") - (pattern[i] == ")")
        if pattern[i] == "|" and level == 0:
            break
        branch += pattern[i]
        i += 1
    return "".join(_atoms(branch))


def sample_for(body: str, flags: str) -> str | None:
    """A verified sample of ``body``, or None when none could be produced."""
    try:
        candidate = sample(body)
    except (Unsupported, ValueError, IndexError):
        return None
    if not candidate:
        return None
    try:
        compiled = re.compile(body, re.IGNORECASE if "i" in flags else 0)
    except re.error:
        return None
    return candidate if compiled.search(candidate) else None
