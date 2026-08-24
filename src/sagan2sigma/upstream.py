"""Upstream rules that do not do what they say, in Sagan.

Every other part of this tool asks whether the *conversion* is faithful. This
one asks something the conversion cannot: whether the rule it started from
works at all in the engine it was written for.

The question is not academic. 749 corpus rules fall into the two silent
categories below, and a migration that converts them faithfully inherits rules
that never fired. Someone comparing the converted output against a running
Sagan would find them agreeing perfectly, both silent, and conclude the
conversion was sound.

Each detector below corresponds to an engine behaviour established by running a
locally built Sagan, not by reading it. The comments name what was measured, so
that a reader can disagree with the conclusion rather than with an assertion.

Three of the five have a fix upstream, proposed as pull requests against
`quadrantsec/sagan-rules`. `JSON_KEY_TOO_LONG` does not: the key names come from
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

_TRACK = re.compile(r"track\s+([a-z_&]+)", re.I)
_JSON_KEY = re.compile(r'json_(?:meta_)?content\s*:\s*!?\s*"\.([A-Za-z0-9_.\[\]@-]+)"')


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
