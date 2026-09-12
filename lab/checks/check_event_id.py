#!/usr/bin/env python3
"""What `event_id` matches when the event carries no decoded ID.

`D_EVENT_ID_HEURISTIC` tells the operator what the converted rule gives up:

    Without a json_map for event_id, Sagan looks for ' <id>: ' in the first 10
    bytes of the message.

`Event_ID()` in `src/event-id.c` does this:

    strlcpy(alter_message, SaganProcSyslog_LOCAL->syslog_message, 10);
    snprintf(tmp_content, sizeof(tmp_content), " %s: ", event_id[i]);
    if ( Sagan_strstr( alter_message, tmp_content ))

`strlcpy`'s third argument is the size of the destination *including* the NUL,
so the window is **nine** characters, not ten. The searched string is
``" <id>: "``, seven characters for a four-digit ID, with a leading space that
the message must actually contain.

Both details are testable, and the second one matters more than the off-by-one:
a message beginning with the ID at offset 0 never matches, however plausible
that shape looks. Sagan's own comment above the code says ``depth: 8``, which
agrees with neither the code nor the degradation text.

The window size is measured by padding: with a four-digit ID, ``xx 4624: `` ends
exactly at the ninth character and ``xxx 4624: `` needs a tenth.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, event, rule, sagan  # noqa: E402

report = Report("event_id: the fallback window and the shape it looks for")


def matches(sid: int, message: str, options: str = "event_id: 4624") -> bool:
    """Does an event_id rule fire on this message?"""
    fired = sagan([rule(sid, options)], [event(message)])
    return str(sid) in fired.get(message, set())


# --- the shape: a leading space is required ---------------------------------
report.check(
    "the ID at offset 0 does not match",
    matches(8001, "4624: logon reported"),
    False,
)
report.check(
    "a leading space makes it match",
    matches(8002, " 4624: logon reported"),
    True,
)
report.check(
    "a colon and a space are both required",
    matches(8003, " 4624 logon reported"),
    False,
)
report.check(
    "a trailing space is required too",
    matches(8004, " 4624:logon reported"),
    False,
)

# --- the window: nine characters, not ten ------------------------------------
# " 4624: " is seven characters. Padded by two it ends on the ninth character
# and is found; padded by three it would need a tenth and is not.
report.check(
    "two characters of padding still fits",
    matches(8005, "xx 4624: logon"),
    True,
)
report.check(
    "three characters of padding does not",
    matches(8006, "xxx 4624: logon"),
    False,
)

# A shorter ID shifts the boundary, which confirms the limit is on the window
# rather than on the padding.
report.check(
    "a two-digit ID tolerates four characters of padding",
    matches(8007, "xxxx 42: logon", options="event_id: 42"),
    True,
)
report.check(
    "and not five",
    matches(8008, "xxxxx 42: logon", options="event_id: 42"),
    False,
)

# --- several IDs are an OR ---------------------------------------------------
report.check(
    "any listed ID matches",
    matches(8009, " 4625: failed logon", options="event_id: 4624,4625"),
    True,
)
report.check(
    "an unlisted one does not",
    matches(8010, " 4634: logoff", options="event_id: 4624,4625"),
    False,
)

# --- the structured path is an exact comparison ------------------------------
# With json_map binding event_id, Event_ID() takes the other branch and uses
# strcmp against the decoded value, so the window and the surrounding spaces
# stop mattering entirely. This is the branch the converter reproduces.
STRUCTURED = 'json_map: "event_id", ".eid"; event_id: 4624'
body = '{"eid":"4624","msg":"logon"}'
fired = sagan([rule(8011, STRUCTURED)], [event(body)])
report.check("a decoded ID matches exactly", "8011" in fired.get(body, set()), True)

other = '{"eid":"4625","msg":"logon"}'
fired = sagan([rule(8012, STRUCTURED)], [event(other)])
report.check(
    "a different decoded ID does not", "8012" in fired.get(other, set()), False
)

# The decoded value is compared whole: a longer ID containing the wanted one
# must not match, which a substring search would get wrong.
longer = '{"eid":"46240","msg":"logon"}'
fired = sagan([rule(8013, STRUCTURED)], [event(longer)])
report.check(
    "the decoded comparison is not a substring match",
    "8013" in fired.get(longer, set()),
    False,
)

raise SystemExit(0 if report.done() else 1)
