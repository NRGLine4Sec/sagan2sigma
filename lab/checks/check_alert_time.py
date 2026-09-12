#!/usr/bin/env python3
"""Which clock `alert_time` reads, and how its window behaves.

`D_ALERT_TIME_EVENT_CLOCK` warns the operator that the converted rule matches
on weekday and hour fields derived from the *event's* timestamp, while Sagan
evaluates its window against the wall clock at processing time. The whole
degradation rests on that being true, and until now it rested on reading
`Aetas()` in `src/aetas.c`, which calls `time(NULL)` and `localtime()`.

That is testable with `faketime`, which intercepts `time()` through
`LD_PRELOAD`: the run can pretend to be Tuesday afternoon while the events it
reads are stamped Sunday at 03:00. If the alert follows the fake clock and
ignores the stamp, the claim holds.

Weekday numbering is `tm_wday`, so 0 is Sunday. 2026-08-18 is a Tuesday and
2026-08-16 a Sunday; both are used below.

The timezone matters too, because `localtime()` reads it, which is the second
half of the degradation text.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, event, loads, rule, sagan  # noqa: E402

report = Report("alert_time: the wall clock, the window and the timezone")

#: Stamped Sunday 03:00, which is outside every window used below. If a probe
#: fires, it is because of the faked clock and not because of this.
PROBE = "aetas probe"
EVENT = [event(PROBE, date="08/16/2026", time="03:00:00")]

TUESDAY_AFTERNOON = "2026-08-18 14:30:00"
TUESDAY_NIGHT = "2026-08-18 23:30:00"
SUNDAY_AFTERNOON = "2026-08-16 14:30:00"


def fires(sid: int, window: str, at: str, tz: str = "UTC") -> bool:
    fired = sagan(
        [rule(sid, f'content:"aetas"; alert_time: {window}')],
        EVENT,
        at_time=at,
        timezone=tz,
    )
    return str(sid) in fired.get(PROBE, set())


# --- the clock that decides ---------------------------------------------------
# The event says Sunday 03:00 in every case. Only the faked wall clock moves.
report.check(
    "inside the window on the wall clock, it fires",
    fires(9300, "days 2, hours 1400-1500", TUESDAY_AFTERNOON),
    True,
)
report.check(
    "outside it on the same event, it does not",
    fires(9301, "days 2, hours 0900-1000", TUESDAY_AFTERNOON),
    False,
)
# The decisive pair: a window matching the *event's* Sunday 03:00 stays silent
# on a Tuesday afternoon run, so the event timestamp is not what is read.
report.check(
    "a window matching the event's own stamp does not fire",
    fires(9302, "days 0, hours 0200-0400", TUESDAY_AFTERNOON),
    False,
)
report.check(
    "and it does once the clock is moved to that time",
    fires(9303, "days 0, hours 0200-0400", "2026-08-16 03:00:00"),
    True,
)

# --- the day filter -----------------------------------------------------------
report.check(
    "a day the rule does not list suppresses it",
    fires(9304, "days 3, hours 1400-1500", TUESDAY_AFTERNOON),
    False,
)
report.check(
    "several listed days include the current one",
    fires(9305, "days 12345, hours 1400-1500", TUESDAY_AFTERNOON),
    True,
)
report.check(
    "0 is Sunday, not Monday",
    fires(9306, "days 0, hours 1400-1500", SUNDAY_AFTERNOON),
    True,
)
report.check(
    "so a weekday list excludes Sunday",
    fires(9307, "days 12345, hours 1400-1500", SUNDAY_AFTERNOON),
    False,
)

# --- boundaries are inclusive -------------------------------------------------
# The comparison is `current >= start && current <= end` on an HHMM integer.
report.check(
    "the start minute is inside",
    fires(9308, "days 2, hours 1430-1500", TUESDAY_AFTERNOON),
    True,
)
report.check(
    "the end minute is inside",
    fires(9309, "days 2, hours 1400-1430", TUESDAY_AFTERNOON),
    True,
)
report.check(
    "one minute past the end is outside",
    fires(9310, "days 2, hours 1400-1429", TUESDAY_AFTERNOON),
    False,
)

# --- a window crossing midnight -----------------------------------------------
# start > end flips the engine into its next_day branch, which also accepts the
# hours after midnight that belong to the *previous* listed day.
report.check(
    "late evening is inside an 1800-0800 window",
    fires(9311, "days 2, hours 1800-0800", TUESDAY_NIGHT),
    True,
)
report.check(
    "the afternoon is not",
    fires(9312, "days 2, hours 1800-0800", TUESDAY_AFTERNOON),
    False,
)
report.check(
    "the small hours of the next day still count",
    fires(9313, "days 2, hours 1800-0800", "2026-08-19 02:00:00"),
    True,
)

# --- localtime, so the timezone shifts the window -----------------------------
# The instant has to be pinned as an epoch, not as "2026-08-18 14:30:00":
# faketime reads a wall-clock string in the *current* zone, so that form is
# 14:30 everywhere and tests nothing. The first attempt here did exactly that
# and reported the timezone as having no effect.
#: 2026-08-18 14:30:00 UTC, which is 23:30 the same day in Tokyo.
INSTANT = "@1787063400"
report.check(
    "the instant falls inside a 1400-1500 window in UTC",
    fires(9314, "days 2, hours 1400-1500", INSTANT, tz="UTC"),
    True,
)
report.check(
    "the same instant is outside it in Tokyo",
    fires(9315, "days 2, hours 1400-1500", INSTANT, tz="Asia/Tokyo"),
    False,
)
report.check(
    "and inside the window that matches Tokyo's local hour",
    fires(9316, "days 2, hours 2300-2359", INSTANT, tz="Asia/Tokyo"),
    True,
)

# --- hours without days ------------------------------------------------------
# Sagan accepts the rule. The parser only ever ORs day bits in, so with no days
# listed the mask stays empty, Check_Day is false for every weekday, and the
# rule can never fire. It loads and is inert, which is worth knowing because a
# converter that reproduced the hours alone would emit a rule that does fire.
report.check(
    "hours without days still loads",
    loads([rule(9317, 'content:"x"; alert_time: hours 1400-1500')]),
    True,
)
report.check(
    "but never fires, whatever the hour",
    fires(9318, "hours 1400-1500", TUESDAY_AFTERNOON),
    False,
)

raise SystemExit(0 if report.done() else 1)
