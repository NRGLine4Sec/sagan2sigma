#!/usr/bin/env python3
"""Which envelope selectors exist, and what each one matches against.

The converter's handler table is a hand-copy of the engine's keyword branches,
and this file checks the copy in both directions:

* keywords the converter accepts that Sagan rejects. A rule using one converts
  into working Sigma while the Sagan file it came from fails to load, so an
  operator would deploy a detection that never existed upstream. `facility`,
  `level` and `tag` were accepted as bare aliases; only the `syslog_` forms are
  real.
* keywords Sagan accepts that the converter does not know. `syslog_priority` is
  a genuine detection selector and was refused as an unknown keyword.

`priority` and `level` are also shown to be *distinct* envelope fields, which is
what stops `syslog_priority` from being quietly mapped onto the severity: they
carry different values and each keyword matches only its own.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, event, loads, rule, sagan  # noqa: E402

report = Report("envelope selectors: which keywords exist and what they match")

# --- which keywords load -----------------------------------------------------
for keyword in ("syslog_facility", "syslog_level", "syslog_tag", "syslog_priority"):
    report.check(
        f"{keyword} is a real keyword",
        loads([rule(6200, f'content:"x"; {keyword}: auth')]),
        True,
    )

# The bare forms are not aliases, they are not keywords at all. Sagan aborts the
# whole ruleset on one, so a rule using them cannot run anywhere.
for keyword in ("facility", "level", "tag"):
    report.check(
        f"{keyword} alone is not a keyword",
        loads([rule(6201, f'content:"x"; {keyword}: auth')]),
        False,
    )

# `pri` and `priority` do exist, but they set the alert's severity (s_pri, via
# atoi) rather than selecting on the envelope. Numeric, and not a detection.
for keyword in ("pri", "priority"):
    report.check(
        f"{keyword} takes a number",
        loads([rule(6202, f'content:"x"; {keyword}: 3')]),
        True,
    )

# --- priority and level are different fields ---------------------------------
# One event, two different values, so each keyword can only match its own field.
cross = event("cross probe", priority="warning", level="notice")
for keyword, matches_warning, matches_notice in (
    ("syslog_priority", True, False),
    ("syslog_level", False, True),
):
    for value, expected in (("warning", matches_warning), ("notice", matches_notice)):
        fired = sagan([rule(6300, f'content:"cross"; {keyword}: {value}')], [cross])
        report.check(
            f"{keyword}: {value}",
            "6300" in fired.get("cross probe", set()),
            expected,
        )

# --- syslog_priority matches exactly, with | alternation ---------------------
probe = event("alt probe", priority="warning")
fired = sagan([rule(6400, 'content:"alt"; syslog_priority: notice|warning')], [probe])
report.check(
    "a | alternation matches any listed value",
    "6400" in fired.get("alt probe", set()),
    True,
)
fired = sagan([rule(6401, 'content:"alt"; syslog_priority: warn')], [probe])
report.check(
    "matching is exact, not a prefix",
    "6401" in fired.get("alt probe", set()),
    False,
)

raise SystemExit(0 if report.done() else 1)
