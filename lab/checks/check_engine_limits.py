#!/usr/bin/env python3
"""Two fixed limits that silently change what a rule searches for.

Both were found by the engine-backed differential rather than by reading, and
both have the same shape: the rule as written is not the rule the engine runs,
and nothing says so. A converted rule that reproduces the *written* intent then
disagrees with Sagan, and the disagreement is the engine's, not the converter's.

They are recorded here rather than reproduced in the converter, because
reproducing either would emit a detection nobody wants: a search for the single
letter `c`, or a match on a truncated key name. What to do about them is a
product decision, and `docs/DESIGN-DECISIONS.md` carries it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import (  # noqa: E402
    SANE,
    Report,
    event,
    rule,
    sagan,
    skip_unless_available,
)

report = Report("engine limits: colon truncation and JSON key length")

if not skip_unless_available(report, SANE):
    raise SystemExit(0 if report.done() else 1)


def fires(sid: int, options: str, message: str) -> bool:
    fired = sagan(
        [rule(sid, f"program: cisco; {options}")],
        [event(message, program="cisco")],
        binary=SANE,
    )
    return str(sid) in fired.get(message, set())


# --- a colon truncates a meta_content value ----------------------------------
# The option's value is extracted with strtok on ":", so everything from the
# first colon onward is lost. 734 corpus rules carry a Windows path in a
# meta_content value, and every one of them searches for the letter before the
# colon instead.
HAS_C = "anchor and a lone c letter"
NO_C = "anhor without that letter"
report.check(
    "a value with a colon matches on the part before it",
    fires(9800, 'content:"anchor"; meta_content:"%sagan%",c:\\program files\\', HAS_C),
    True,
)
report.check(
    "and does not match when even that is absent",
    fires(9801, 'content:"anchor"; meta_content:"%sagan%",c:\\program files\\', NO_C),
    False,
)
report.check(
    "without a colon the whole value is searched",
    fires(9802, 'content:"anchor"; meta_content:"%sagan%",czzz', HAS_C),
    False,
)

# `content` is not affected: it extracts its value differently, which is why
# the two keywords had to be checked apart rather than assumed alike.
FULL = "alert Backdoor:EC2/C&CActivity.B seen"
PREFIX = "alert Backdoor only"
report.check(
    "content keeps the whole value, colon included",
    fires(9803, 'content:"Backdoor:EC2/C&CActivity.B"', FULL),
    True,
)
report.check(
    "so a message holding only the prefix does not match",
    fires(9804, 'content:"Backdoor:EC2/C&CActivity.B"', PREFIX),
    False,
)
report.check(
    "the |3a| escape is the way to write a literal colon",
    fires(9805, 'content:"Backdoor|3a|EC2/C&CActivity.B"', FULL),
    True,
)


# --- a JSON key path longer than 30 characters is truncated -------------------
# `JSON_MAX_KEY_SIZE` is 32 and the parser terminates the stored path early, so
# a rule naming a longer key never matches. 14 corpus rules do, one of them on
# a 50-character CloudTrail path.
def json_key_matches(sid: int, path: str) -> bool:
    parts = path.split(".")
    body: dict = {}
    cursor = body
    for part in parts[:-1]:
        cursor = cursor.setdefault(part, {})
    cursor[parts[-1]] = "V"
    payload = json.dumps(body)
    fired = sagan(
        [rule(sid, f'program: cisco; json_content:".{path}","V"')],
        [event(payload, program="cisco")],
        binary=SANE,
    )
    return str(sid) in fired.get(payload, set())


report.check("a 29 character key path matches", json_key_matches(9810, "a" * 29), True)
report.check("30 still matches", json_key_matches(9811, "a" * 30), True)
report.check("31 does not", json_key_matches(9812, "a" * 31), False)
report.check(
    "nesting does not change the limit, the whole path counts",
    json_key_matches(9813, "data.authorizationInfo.operation"),
    False,
)
report.check(
    "one character shorter, the same shape matches",
    json_key_matches(9814, "data.authorizationInfo.granted"),
    True,
)

raise SystemExit(0 if report.done() else 1)
