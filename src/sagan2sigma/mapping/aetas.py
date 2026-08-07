"""The ``alert_time`` handler: a recurring day-and-hour window through Vector.

Sagan's ``alert_time`` restricts a rule to a set of weekdays and an hour range
(``src/aetas.c``, ``Check_Time``; parsed in ``src/rules.c``). Sigma has no
recurring-time operator, so the window is matched against two fields the bundled
``sagan-time.vrl`` transform derives from the event timestamp: the weekday and
the time as an HHMM integer, exactly the two values ``Check_Time`` compares.

The engine reads the time as ``atoi("HHMM")`` and compares it as an integer, so
an integer ``gte`` / ``lte`` on the HHMM field reproduces the window exactly,
minute boundaries included. What cannot follow is that Sagan evaluates the clock
at processing time and in the host's local timezone, recorded as the
``D_ALERT_TIME_EVENT_CLOCK`` degradation.

A window whose start is after its end crosses midnight. ``Check_Time`` then also
fires in the morning of the day after an alert day (``next_day`` with an off
day), so the morning half of the window matches on the alert days shifted one day
forward as well. This disjunction of conjunctions is what a flat predicate list
cannot express, so the handler emits a :class:`ConditionGroup`.

The fields only exist under a profile that supplies them, so the rule converts
under ``vector-enriched`` and is refused, recoverably, under any other.
"""

from __future__ import annotations

import re

from ..errors import Degradation, DegradationCode, Refusal, RefusalCode
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import ConditionGroup, RuleDraft
from .registry import handler
from .values import CasePolicy

#: ``$NAME`` variable reference inside an ``alert_time`` value.
_VARIABLE = re.compile(r"\$(\w+)")

#: ``days 12345`` and ``hours 0900-1700`` tokens, order-independent.
_DAYS = re.compile(r"days\s+([0-6]+)")
_HOURS = re.compile(r"hours\s+(\d{4})-(\d{4})")


def _expand_variables(value: str, context: Context) -> str:
    """Resolve every ``$NAME`` in an ``alert_time`` value against the config.

    Sagan runs ``Var_To_Value`` over the whole option before tokenising, so a
    rule written ``days $SAGAN_DAYS, hours $SAGAN_HOURS`` needs the variables
    supplied with ``--sagan-yaml``.
    """

    def replace(match: re.Match[str]) -> str:
        token = f"${match.group(1)}"
        expanded = context.config.expand(token)
        if expanded is None:
            raise Refusal(
                code=RefusalCode.VAR_UNRESOLVED,
                detail=(
                    f"variable {token} in alert_time is undefined; supply the "
                    f"sagan.yaml with --sagan-yaml"
                ),
                keywords=("alert_time",),
            )
        return ",".join(expanded)

    return _VARIABLE.sub(replace, value)


def _weekdays(digits: str) -> list[int]:
    """Weekday integers from a Sagan day string, 0=Sunday, deduplicated."""
    return sorted({int(character) for character in digits})


def _rollover(days: list[int]) -> list[int]:
    """Days plus each day shifted one forward, for the morning of a night window.

    >>> _rollover([1, 2, 3, 4, 5])
    [1, 2, 3, 4, 5, 6]
    """
    return sorted(set(days) | {(day + 1) % 7 for day in days})


@handler("alert_time")
def handle_alert_time(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``alert_time: days 12345, hours 0900-1700;`` onto derived time fields."""
    weekday_field = context.profile.fields.get("event_weekday")
    hhmm_field = context.profile.fields.get("event_hhmm")
    if weekday_field is None or hhmm_field is None:
        raise Refusal(
            code=RefusalCode.TIME_WINDOW,
            detail=(
                "alert_time needs weekday and hour fields, which only the "
                "vector-enriched profile supplies. Convert with --profile "
                "vector-enriched and deploy the bundled time transform"
            ),
            keywords=("alert_time",),
        )

    for option in rule.iter_options("alert_time"):
        if option.value is None:
            continue
        value = _expand_variables(option.value, context)
        days_match = _DAYS.search(value)
        hours_match = _HOURS.search(value)
        if days_match is None or hours_match is None:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=f"unrecognised alert_time: {option.value!r}",
                keywords=("alert_time",),
            )

        days = _weekdays(days_match.group(1))
        start = int(hours_match.group(1))
        end = int(hours_match.group(2))
        if start > 2359 or end > 2359 or start % 100 > 59 or end % 100 > 59:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=f"alert_time hour out of range: {option.value!r}",
                keywords=("alert_time",),
            )

        if start <= end:
            # Same-day window: one weekday set and one closed HHMM interval.
            blocks = {
                "at_days": {weekday_field: days},
                "at_from": {f"{hhmm_field}|gte": start},
                "at_to": {f"{hhmm_field}|lte": end},
            }
            condition = "at_days and at_from and at_to"
        else:
            # Window crossing midnight: evening half on the alert days, morning
            # half on those days and the day after each (Sagan's next_day roll).
            blocks = {
                "at_days": {weekday_field: days},
                "at_days_rollover": {weekday_field: _rollover(days)},
                "at_evening": {f"{hhmm_field}|gte": start},
                "at_morning": {f"{hhmm_field}|lte": end},
            }
            condition = "(at_days and at_evening) or (at_days_rollover and at_morning)"

        draft.condition_groups.append(
            ConditionGroup(blocks=blocks, condition=condition)
        )
        draft.degrade(
            Degradation(
                code=DegradationCode.ALERT_TIME_EVENT_CLOCK,
                detail=(
                    "alert_time is matched on the event timestamp's weekday and "
                    "hour, derived by the bundled time transform; Sagan uses the "
                    "wall clock at processing time, in the host's local timezone"
                ),
            )
        )
