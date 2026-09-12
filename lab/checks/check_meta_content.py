#!/usr/bin/env python3
"""How `meta_content` is split, and what the helper ends up being.

`meta_content:"HELPER", v1, v2` searches for HELPER once per value, with
`%sagan%` in HELPER replaced by each. The obvious parse is a regex reading a
quoted helper, a comma, then the values. `docs/DESIGN-DECISIONS.md` claims the
engine does something less tidy and that copying it fixed 75 corpus rules, which
makes three falsifiable statements:

* the **first comma** separates helper from values wherever it sits, including
  inside the quotes;
* `Between_Quotes` is not a balanced-quote parser: it starts copying after the
  first quote and drops every quote it meets, so a doubled opening quote in
  `""%sagan%"` yields the helper `%sagan%`, not `"%sagan%`;
* values are kept **verbatim**, so a stray closing quote left on the last value
  is part of what the engine searches for.

Each is observable through whether a rule matches a message, because a helper
carrying a stray quote searches for a string no real log contains. That was the
symptom: 72 Cisco rules searched for `"%ASA` and silently matched nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, event, loads, rule, sagan  # noqa: E402

report = Report("meta_content: splitting, quote handling and verbatim values")


def fires(sid: int, options: str, message: str) -> bool:
    fired = sagan(
        [rule(sid, f"program: cisco; {options}")], [event(message, program="cisco")]
    )
    return str(sid) in fired.get(message, set())


# --- the ordinary shape, so the rest is measured against something -----------
PLAIN = 'meta_content:"user %sagan% denied",alice,bob'
report.check(
    "the first value is substituted", fires(9600, PLAIN, "user alice denied"), True
)
report.check("the second value too", fires(9601, PLAIN, "user bob denied"), True)
report.check(
    "an unlisted value does not", fires(9602, PLAIN, "user carol denied"), False
)
report.check(
    "the helper text around %sagan% is required",
    fires(9603, PLAIN, "alice denied"),
    False,
)

# --- whitespace after the separating comma ------------------------------------
# 156 corpus options write their values as `, value` rather than `,value`, so
# whether that space reaches the search decides what those rules look for. On
# the shape the corpus actually uses, it does not: the rule below matches a
# message with no space in front of %ASA.
#
# Only this case is asserted. Several spaces, or spaces on a later value,
# behave in ways this file could not characterise cleanly, and stating a rule
# for them would be guessing. No corpus rule writes either shape.
SPACED = 'meta_content:""%sagan%", %ASA,%FWSM'
report.check(
    "a single space before the first value does not reach the search",
    fires(9615, SPACED, "fw:%ASA-2-106001 denied"),
    True,
)

# --- the doubled opening quote ------------------------------------------------
# The Cisco case. With Between_Quotes dropping every quote, the helper is
# `%sagan%` and the rule searches for `%ASA`. Had the stray quote survived it
# would search for `"%ASA`, which no ASA log carries.
CISCO = 'meta_content:""%sagan%", %ASA,%FWSM'
report.check(
    "a doubled opening quote does not reach the search",
    fires(9604, CISCO, "Jan 1 fw : %ASA-2-106001 denied"),
    True,
)
report.check(
    "the second value works the same way",
    fires(9605, CISCO, "Jan 1 fw : %FWSM-2-106001 denied"),
    True,
)
# The discriminator: a message that *does* carry the stray quote must not be
# what makes the rule match, or the check above would prove nothing.
report.check(
    "and a literal quote is not what it looks for",
    fires(9606, CISCO, 'Jan 1 fw : "%ASA-2-106001 denied'),
    True,
)
report.check(
    "an unrelated line still does not match",
    fires(9607, CISCO, "Jan 1 fw : %PIX-2-106001 denied"),
    False,
)

# --- the first comma separates, even inside the quotes -----------------------
# |22 3a 20 22| decodes to `": "`. The engine takes `"eventName": "%sagan%` as
# the helper and everything after the first comma as values, so the last value
# keeps the trailing quote the rule writer meant as a delimiter.
AWS = 'meta_content:"eventName|22 3a 20 22|%sagan%,AttachRolePolicy,PutBucketPolicy"'
report.check(
    "the helper is everything before the first comma",
    fires(9608, AWS, '{"eventName": "AttachRolePolicy", "x": 1}'),
    True,
)
report.check(
    "the last value keeps its trailing quote",
    fires(9609, AWS, '{"eventName": "PutBucketPolicy"}'),
    True,
)
report.check(
    "so a longer name does not match it",
    fires(9610, AWS, '{"eventName": "PutBucketPolicyExtra"}'),
    False,
)

# --- %sagan% is mandatory -----------------------------------------------------
report.check(
    "a helper without %sagan% is rejected at load",
    loads([rule(9611, 'content:"x"; meta_content:"plain helper", a, b')]),
    False,
)
report.check(
    "and with it, it loads",
    loads([rule(9612, 'content:"x"; meta_content:"%sagan% helper", a, b')]),
    True,
)

# --- case sensitivity ---------------------------------------------------------
report.check(
    "matching is case sensitive by default",
    fires(9613, 'meta_content:"user %sagan% denied", ALICE', "user alice denied"),
    False,
)
report.check(
    "meta_nocase turns it off",
    fires(
        9614,
        'meta_content:"user %sagan% denied", ALICE; meta_nocase',
        "user alice denied",
    ),
    True,
)

# --- a comma inside the quoted template ---------------------------------------
#
# `rules.c` line 1933 cuts the option with strtok_r(arg, ",") and only then
# calls Between_Quotes on the first piece, so the template ends at the comma
# and everything after it, closing quote included, is pushed into the value
# list. Two corpus rules die of this and two lose their first alternative.
report.check(
    "the template loses everything after its comma",
    fires(9620, 'meta_content:"MD5=%sagan%,",AAA', "x MD5=AAA y"),
    True,
)
report.check(
    "so the comma the author wrote is not required",
    fires(9621, 'meta_content:"MD5=%sagan%,",AAA', "x MD5=AAA, y"),
    True,
)
report.check(
    "the closing quote lands on the first value, which then never matches",
    fires(9622, 'meta_content:"%sagan%,"AAA,BBB', "x AAA y"),
    False,
)
report.check(
    "an event carrying that stray quote does match",
    fires(9623, 'meta_content:"%sagan%,"AAA,BBB', 'x "AAA y'),
    True,
)
report.check(
    "while the second value is untouched",
    fires(9624, 'meta_content:"%sagan%,"AAA,BBB', "x BBB y"),
    True,
)
# With a variable among the values nothing matches at all: neither the values
# the variable holds nor its own name appear in anything the rule fires on.
report.check(
    "a variable in the values makes the rule dead",
    fires(
        9625, 'meta_content:"MD5=%sagan%,",$WINDOWS_DOMAINS', "x MD5=EXAMPLEDOMAIN, y"
    ),
    False,
)
report.check(
    "not even the variable's own name matches",
    fires(
        9626, 'meta_content:"MD5=%sagan%,",$WINDOWS_DOMAINS', "x MD5=$WINDOWS_DOMAINS y"
    ),
    False,
)
report.check(
    "the same variable without the comma works",
    fires(
        9627, 'meta_content:"MD5=%sagan% ",$WINDOWS_DOMAINS', "x MD5=EXAMPLEDOMAIN y"
    ),
    True,
)

raise SystemExit(0 if report.done() else 1)
