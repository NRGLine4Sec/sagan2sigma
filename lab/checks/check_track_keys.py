#!/usr/bin/env python3
"""Which `after: track` keys the engine actually honours.

`TRACK_TO_INTERNAL` in mapping/correlation.py is a hand-copy of the branches in
Sagan's rule parser, and the upstream corpus contains tokens that are not in
either list: `by_user`, `by_tag`, `by_hostname`, and one `byusername` typo.
A key the converter honours but the engine ignores makes the converted rule
group *more finely* than the original, so it fires less often than the rule it
came from. That is the same class of defect as the flexbits direction, in
mirror image, and it is invisible without running the engine.

The parser for `after` splits on `&` and compares each token with `strcmp`, so
an inexact token matches nothing and sets no method. `After2()` then builds its
key as `src|srcport|dst|dstport|username`, filling only the components whose
method is set, which means a rule with no recognised key hashes to one constant
string: a single global counter.

`count 1` throughout, so the second event in a bucket alerts and the question
"do these two events share a bucket?" becomes observable.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import (  # noqa: E402
    PATCHED,
    Report,
    config_with_rulebase,
    event,
    loads,
    rule,
    sagan,
    skip_unless_available,
)

LAB = Path(__file__).resolve().parent.parent
CONFIG = config_with_rulebase(LAB / "config" / "rules" / "lab-normalize.rulebase")

AFTER = "after: track {keys}, count 1, seconds 300"

report = Report("after: which track keys the engine honours")

if not skip_unless_available(report, PATCHED):
    raise SystemExit(0 if report.done() else 1)


def shares_a_bucket(keys: str, first: str, second: str, **event_kwargs: str) -> bool:
    """Do two events land in the same `after` counter?

    With ``count 1`` the first event is silent and the second alerts, but only
    if both hash to the same key.
    """
    probe = rule(5100, 'content:"LOGIN"; normalize; ' + AFTER.format(keys=keys))
    events = [
        event(first, program="cisco"),
        event(second, program="cisco", **event_kwargs),
    ]
    fired = sagan([probe], events, binary=PATCHED, config=CONFIG)
    return "5100" in fired.get(second, set())


ALICE = "LOGIN alice from 10.0.0.1 x"
BOB = "LOGIN bob from 10.0.0.1 y"
ALICE_ELSEWHERE = "LOGIN alice from 10.0.0.2 z"

# --- baselines, which also prove the probe measures something ----------------
# If normalization did not populate the username, every by_username check below
# would pass for the wrong reason, so the two controls come first.
report.check("same source shares a bucket", shares_a_bucket("by_src", ALICE, BOB), True)
report.check(
    "a different source does not",
    shares_a_bucket("by_src", ALICE, ALICE_ELSEWHERE),
    False,
)
report.check(
    "by_username splits two users on one address",
    shares_a_bucket("by_src&by_username", ALICE, BOB),
    False,
)

# --- the tokens the corpus uses and the parser does not recognise ------------
# by_user is not by_username: the parser compares with strcmp, so it sets no
# method and the key is the source alone. The converter mapped it to the
# username and grouped on both.
report.check(
    "by_user is inert, so the key is the source alone",
    shares_a_bucket("by_src&by_user", ALICE, BOB),
    True,
)
report.check(
    "byusername is inert too",
    shares_a_bucket("by_src&byusername", ALICE, BOB),
    True,
)
report.check(
    "by_hostname is inert",
    shares_a_bucket("by_src&by_hostname", ALICE, BOB),
    True,
)

# by_tag has no branch at all either, so it groups on nothing. Paired with a
# recognised key the rule loads and the tag is simply not part of the key.
# The converter grouped on the syslog tag.
report.check(
    "by_tag does not group on the tag",
    shares_a_bucket("by_src&by_tag", ALICE, BOB, tag="othertag"),
    True,
)

# --- a lone unrecognised key is rejected outright ----------------------------
# The parser requires a validity count of four: "track", a *recognised* key,
# "count" and "seconds". An unrecognised key scores three, so the rule is
# refused and Sagan aborts the whole ruleset. Two upstream rules track by_tag
# alone and two track by_hostname alone, so the engine cannot load them.
for lone in ("by_tag", "by_hostname", "by_user", "by_zzznotakey"):
    report.check(
        f"a lone {lone} is rejected at load",
        loads([rule(5200, 'content:"x"; ' + AFTER.format(keys=lone))]),
        False,
    )

# --- the two real keys the converter does not know ---------------------------
for real in ("by_srcport", "by_dstport"):
    report.check(
        f"{real} is a recognised key",
        loads([rule(5201, 'content:"x"; ' + AFTER.format(keys=real))]),
        True,
    )

raise SystemExit(0 if report.done() else 1)
