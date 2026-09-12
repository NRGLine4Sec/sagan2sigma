#!/usr/bin/env python3
"""`json_meta_content` and `json_pcre`, the two JSON operators not yet pinned.

`json_content` is already covered by check_enrichment.py, which established it
is an exact whole-value match. Its sibling `json_meta_content` takes a *list* of
values, and the module docstring in mapping/json_ops.py claims that list is an
OR, that case is significant by default, and that `json_meta_strstr` switches
to a substring search.

The C says the same thing: `json-meta-content.c` calls
`Search_Case(json_string, value, json_meta_strstr[i])`, and `Search_Case` runs
`strcmp` when that flag is false and `Sagan_strstr` when it is true. Saying it
and doing it are different claims, so both are measured here.

`json_pcre` applies a regular expression to the key's value. A regex is
unanchored by nature, so it matches a substring of the value where
`json_content` would not, and that difference decides whether the converter may
emit `|re` for one and an equality for the other.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, event, rule, sagan  # noqa: E402

report = Report("json_meta_content and json_pcre")

#: One JSON body, reused so every probe asks about the same event.
BODY = '{"Msg":"alpha beta gamma","Act":"Delete","Num":"4624"}'


def fires(sid: int, options: str, body: str = BODY) -> bool:
    fired = sagan([rule(sid, f"program: sshd; {options}")], [event(body)])
    return str(sid) in fired.get(body, set())


# --- json_meta_content: the list is an OR ------------------------------------
report.check(
    "the first listed value matches",
    fires(9001, 'json_meta_content:".Act",Delete,Create'),
    True,
)
report.check(
    "a later listed value matches too",
    fires(9002, 'json_meta_content:".Act",Create,Delete'),
    True,
)
report.check(
    "no listed value means no match",
    fires(9003, 'json_meta_content:".Act",Create,Update'),
    False,
)

# --- and each value is compared whole ----------------------------------------
# Search_Case runs strcmp unless the strstr flag is set, so a substring of the
# value must not match. This is what lets the converter emit an equality rather
# than |contains.
report.check(
    "a substring of the value does not match",
    fires(9004, 'json_meta_content:".Msg",alpha'),
    False,
)
report.check(
    "the whole value does",
    fires(9005, 'json_meta_content:".Msg",alpha|20|beta|20|gamma'),
    True,
)

# --- json_meta_contains switches to a substring search -----------------------
report.check(
    "json_meta_contains makes a substring match",
    fires(9006, 'json_meta_content:".Msg",alpha; json_meta_contains'),
    True,
)

# --- but json_meta_strstr does not, despite loading --------------------------
# VALID_RULE_OPTIONS in src/rules.h whitelists json_strstr and
# json_meta_strstr, so a rule carrying one loads. Neither has a parsing branch:
# only json_contains and json_meta_contains set the strstr flag. So these two
# spellings are accepted and inert, and a converter that treats them as
# synonyms of the working ones emits |contains where Sagan compares whole
# values, which is broader than the rule it came from.
report.check(
    "json_meta_strstr loads but changes nothing",
    fires(9018, 'json_meta_content:".Msg",alpha; json_meta_strstr'),
    False,
)
report.check(
    "json_strstr is inert too",
    fires(9019, 'json_content:".Msg","alpha"; json_strstr'),
    False,
)
report.check(
    "while json_contains works",
    fires(9020, 'json_content:".Msg","alpha"; json_contains'),
    True,
)

# --- case is significant by default ------------------------------------------
report.check(
    "a case variant does not match",
    fires(9007, 'json_meta_content:".Act",DELETE'),
    False,
)
report.check(
    "json_meta_nocase turns case off",
    fires(9008, 'json_meta_content:".Act",DELETE; json_meta_nocase'),
    True,
)

# --- negation ----------------------------------------------------------------
report.check(
    "negating a value that is present suppresses the match",
    fires(9009, 'json_meta_content:!".Act",Delete'),
    False,
)
report.check(
    "negating an absent value matches",
    fires(9010, 'json_meta_content:!".Act",Create'),
    True,
)

# --- json_pcre is a regex, so it is unanchored -------------------------------
# The contrast with json_content is the point: a bare substring pattern matches
# here and would not there.
report.check(
    "a substring pattern matches the value",
    fires(9011, 'json_pcre:".Msg","/beta/"'),
    True,
)
report.check(
    "an anchored pattern respects the value boundary",
    fires(9012, 'json_pcre:".Msg","/^beta/"'),
    False,
)
report.check(
    "anchored at the real start it matches",
    fires(9013, 'json_pcre:".Msg","/^alpha/"'),
    True,
)
report.check(
    "the i flag applies to the value",
    fires(9014, 'json_pcre:".Msg","/BETA/i"'),
    True,
)
report.check(
    "without it the case must agree",
    fires(9015, 'json_pcre:".Msg","/BETA/"'),
    False,
)

# --- a missing key matches nothing -------------------------------------------
report.check(
    "an absent key does not match",
    fires(9016, 'json_meta_content:".Nope",anything'),
    False,
)
# json_pcre on an absent key matches unconditionally, whatever the pattern.
# `JSON_Pcre()` walks the event's keys, runs pcre_exec only on a key that
# exists, and returns false only when a match *fails*; a key that is not there
# is never tested, so the function falls through to `return(true)`.
#
# This is the opposite of json_meta_content above, which returns false for a
# missing key, and the opposite of Sigma, where a `|re` on a field the event
# does not carry never matches. So the converted rule is narrower than the
# original: it stays silent on events that lack the key, where Sagan treats the
# condition as satisfied.
report.check(
    "an absent key matches whatever the pattern",
    fires(9017, 'json_pcre:".Nope","/zzzz/"'),
    True,
)
report.check(
    "even one that cannot match anything",
    fires(9021, 'json_pcre:".Nope","/^$x/"'),
    True,
)
report.check(
    "while a present key is really tested",
    fires(9022, 'json_pcre:".Act","/zzzz/"'),
    False,
)

# --- a list item is compared with its quotes ---------------------------------
#
# `json_content` takes one quoted argument and the quotes delimit it, so the
# value searched for is what they enclose. `json_meta_content` takes a
# comma-separated list, and each item is compared as it stands: quotes around
# an item are part of the text. One corpus rule writes them, sid 5014486 of
# fortinet-json.rules, and its negated `"analytics"` therefore excludes a value
# no producer emits, so the exclusion never fires and the rule alerts on the
# events it names as exceptions (U_INERT_CONDITION).
QUOTED_BODY = '{"Act":"\\"Delete\\"","Msg":"alpha beta gamma"}'

report.check(
    "a quoted item does not match the bare value",
    fires(9023, 'json_meta_content:".Act","Delete"'),
    False,
)
report.check(
    "it matches a value that carries the quotes",
    fires(9024, 'json_meta_content:".Act","Delete"', QUOTED_BODY),
    True,
)
report.check(
    "a bare item matches the bare value",
    fires(9025, 'json_meta_content:".Act",Delete'),
    True,
)
report.check(
    "and not the quoted one",
    fires(9026, 'json_meta_content:".Act",Delete', QUOTED_BODY),
    False,
)
report.check(
    "one quoted item in a list is simply an item that cannot match",
    fires(9027, 'json_meta_content:".Act","Create",Delete'),
    True,
)
report.check(
    "json_content is unaffected: its quotes are the delimiters",
    fires(9028, 'json_content:".Act","Delete"'),
    True,
)

raise SystemExit(0 if report.done() else 1)
