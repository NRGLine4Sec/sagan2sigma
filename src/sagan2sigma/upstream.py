"""Upstream rules that do not do what they say, in Sagan.

Every other part of this tool asks whether the *conversion* is faithful. This
one asks something the conversion cannot: whether the rule it started from
works at all in the engine it was written for.

The question is not academic. 752 corpus rules fall into the silent category
below, and a migration that converts them faithfully inherits rules that never
fired. Someone comparing the converted output against a running Sagan would find
them agreeing perfectly, both silent, and conclude the conversion was sound.

Each detector below corresponds to an engine behaviour established by running a
locally built Sagan, not by reading it. The comments name what was measured, so
that a reader can disagree with the conclusion rather than with an assertion.
That matters most where the syntax looks decisive and is not: an unbalanced `|`
is harmless in two of its shapes and fatal in the rest, and only the engine
says which is which.

Four of the six have a fix upstream, proposed as pull requests against
`quadrantsec/sagan-rules`. The JSON key length does not: the key names come from
the log formats, so only the engine can fix it.

What this deliberately does **not** do is judge intent. A rule can load, fire,
and still be useless because its pattern matches nothing any real appliance
emits. Nothing here can see that, and nothing in this repository can.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .sagan.model import SaganRule


class DefectCode(str, Enum):
    """Why an upstream rule does not behave as written."""

    #: The engine refuses the ruleset, so Sagan does not start.
    WILL_NOT_LOAD = "U_WILL_NOT_LOAD"
    #: The rule loads and can never match.
    CANNOT_MATCH = "U_CANNOT_MATCH"
    #: The rule loads and matches, but groups on fewer keys than it names.
    WRONG_GROUPING = "U_WRONG_GROUPING"


@dataclass(frozen=True, slots=True)
class UpstreamDefect:
    """One rule that does not do what it says, and why."""

    sid: str
    source_file: str
    code: DefectCode
    detail: str


#: Tracking keys the `after` parser recognises. Each is compared with an exact
#: strcmp, so a near miss contributes nothing. Measured: two events differing
#: only in an unrecognised key share a counter.
AFTER_KEYS = frozenset({"by_src", "by_dst", "by_username", "by_srcport", "by_dstport"})

#: `by_string` is a special case: inert under `after` but honoured by
#: `threshold`, so a rule tracking it alone is not necessarily dead.
AFTER_INERT_BUT_COUNTED = frozenset({"by_string"})

#: The longest JSON key path the parser can store. `JSON_MAX_KEY_SIZE` is 32 in
#: `src/sagan-defs.h` and the path is terminated early, so anything longer is
#: kept truncated and a rule naming the full path compares against a name that
#: was never stored. Measured to the character: 30 matches, 31 does not.
MAX_JSON_KEY = 30

#: The options whose values Sagan expands with `Content_Pipe`, turning `|3a|`
#: into a byte. `src/rules.c` calls it from lines 1942 and 1962 for
#: `meta_content`, 2202 for `json_content`, 2500 for `json_meta_content` and
#: 2828 for `content`.
PIPE_EXPANDED = frozenset(
    {"content", "meta_content", "json_content", "json_meta_content"}
)

_HEX = frozenset("0123456789abcdefABCDEF")
_TRACK = re.compile(r"track\s+([a-z_&]+)", re.I)
_JSON_KEY = re.compile(r'json_(?:meta_)?content\s*:\s*!?\s*"\.([A-Za-z0-9_.\[\]@-]+)"')
_QUOTED = re.compile(r'"([^"]*)"')


def _piped_values(rule: SaganRule) -> list[tuple[str, str]]:
    """Every string handed to `Content_Pipe`, with the option carrying it."""
    values: list[tuple[str, str]] = []
    for option in rule.options:
        if option.name not in PIPE_EXPANDED or not option.value:
            continue
        if option.name == "meta_content":
            # The quoted helper is expanded on its own, and the whole
            # comma-separated remainder is expanded as one string *before* it
            # is split, so an unterminated pipe anywhere in the list counts.
            helper, comma, rest = option.value.partition(",")
            quoted = _QUOTED.search(helper)
            if quoted:
                values.append((option.name, quoted.group(1)))
            if comma:
                values.append((option.name, rest))
        else:
            values.extend((option.name, v) for v in _QUOTED.findall(option.value))
    return values


def _unterminated_hex(value: str) -> tuple[DefectCode, str] | None:
    """How the engine ends up reading a value whose hex section never closes.

    `Content_Pipe` sets a flag on the first `|` and clears it only on finding a
    closing `|` three characters later. Until then it takes the next two
    characters as a hex pair on every pass, with nothing checking that the
    sequence was closed before the value ran out. What that produces depends on
    what is left, and only one of the outcomes is loud:

    ==================  ==========================================
    ``alpha|``          matches; the trailing pipe adds nothing
    ``|alpha``          ruleset refused, "Invalid 'al' Hex detected"
    ``alpha|4``         loads, matches nothing, 0x04 appended
    ``alpha|41``        matches ``alphaA``; the pair lands on the end
    ``alpha|412``       loads, matches nothing
    ``alpha|4142``      loads, matches nothing
    ==================  ==========================================

    Measured on a locally built Sagan, one reduced rule per row. The two benign
    rows are why this cannot simply flag an odd number of pipes.
    """
    if value.count("|") % 2 == 0:
        return None
    tail = value.rsplit("|", 1)[1]
    if tail == "":
        return None
    if not all(c in _HEX for c in tail[:2]):
        return (
            DefectCode.WILL_NOT_LOAD,
            f"the hex sequence opened in {value!r} is never closed, and "
            f"{tail[:2]!r} is not hex; Validate_HEX aborts the load",
        )
    if len(tail) == 2:
        return None
    return (
        DefectCode.CANNOT_MATCH,
        f"the hex sequence opened in {value!r} is never closed, so the parser "
        f"converts {tail!r} and appends a control byte no message carries",
    )


def _after_keys(rule: SaganRule) -> list[set[str]]:
    """The tracking keys each `after` option names."""
    keys: list[set[str]] = []
    for option in rule.iter_options("after"):
        if option.value is None:
            continue
        match = _TRACK.search(option.value)
        if match:
            keys.append(
                {k.strip().lower() for k in match.group(1).split("&") if k.strip()}
            )
    return keys


def inspect(rule: SaganRule) -> list[UpstreamDefect]:
    """Every way this rule fails to do what it says, in Sagan."""
    found: list[UpstreamDefect] = []

    # --- the ruleset will not load -------------------------------------------
    for keys in _after_keys(rule):
        if keys and not (keys & AFTER_KEYS) and not (keys & AFTER_INERT_BUT_COUNTED):
            # The parser needs a validity count of four, made of "track", a
            # recognised key, "count" and "seconds". An unrecognised key scores
            # three and Load_Rules() aborts, so Sagan will not start at all.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WILL_NOT_LOAD,
                    f"after tracks {'&'.join(sorted(keys))}, which the parser does "
                    f"not recognise; the engine refuses the whole ruleset",
                )
            )

    for option in rule.iter_options("xbits"):
        if option.value and option.value.split(",")[0].strip().lower() == "toggle":
            # The branch that would handle it is commented out in src/rules.c,
            # so xbit_type stays 0 and the load aborts. The engine's own error
            # message lists the action as valid, which is why it looks fine.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WILL_NOT_LOAD,
                    "xbits: toggle is parsed by no branch in the engine; the "
                    "ruleset is refused at load",
                )
            )

    # --- the rule loads and can never match ----------------------------------
    for option in rule.iter_options("meta_content"):
        if option.value is None or ":" not in option.value:
            continue
        negated = option.value.lstrip().startswith("!")
        if negated:
            # The value is taken with strtok on ":", so `c:\program files\...`
            # searches for `c`. Negated, that is true of almost no message, so
            # the rule cannot alert. Measured on sid 5009802: the event it is
            # written to catch does not fire it.
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.CANNOT_MATCH,
                    "a negated meta_content value is cut at its first colon, so "
                    "the search is the text before it and the negation is "
                    "almost never satisfied",
                )
            )
            break

    for match in _JSON_KEY.finditer(rule.raw):
        key = match.group(1)
        if len(key) > MAX_JSON_KEY:
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.CANNOT_MATCH,
                    f"the JSON key path {key!r} is {len(key)} characters; the "
                    f"parser stores only the first {MAX_JSON_KEY}, so this "
                    f"condition can never match",
                )
            )
            break

    # An unterminated hex sequence lands in either category above depending on
    # what follows the pipe, so it is judged once and filed by its own verdict.
    for keyword, value in _piped_values(rule):
        verdict = _unterminated_hex(value)
        if verdict is None:
            continue
        code, detail = verdict
        found.append(
            UpstreamDefect(rule.sid, rule.source_file, code, f"{keyword}: {detail}")
        )
        break

    # --- the rule loads, matches, and groups on the wrong thing --------------
    for keys in _after_keys(rule):
        mistyped = sorted(
            k for k in keys if k not in AFTER_KEYS | AFTER_INERT_BUT_COUNTED
        )
        if mistyped and (keys & AFTER_KEYS):
            found.append(
                UpstreamDefect(
                    rule.sid,
                    rule.source_file,
                    DefectCode.WRONG_GROUPING,
                    f"after tracks {', '.join(mistyped)}, which the parser "
                    f"ignores; the correlation groups on the remaining keys only",
                )
            )

    return found
