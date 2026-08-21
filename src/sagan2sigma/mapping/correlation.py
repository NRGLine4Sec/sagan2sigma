"""Correlation handlers: ``after``, ``threshold``, ``xbits`` and ``flexbits``.

Three different Sagan mechanisms hide behind a similar surface, and conflating
them is the single most expensive design mistake available in this converter.

``after``
    a genuine correlation: only alert once N events occurred within T seconds.
    Maps exactly onto a Sigma ``event_count`` correlation.

``threshold``
    **alert volume** control, not detection. The documentation is explicit for
    both variants: ``suppress`` caps how many alerts are emitted and resets its
    timer on every event, ``limit`` caps them per fixed window. Neither changes
    whether the underlying event is a detection. ``suppress`` is carried over
    as ``custom_attributes['rsigma.suppress']``; ``limit`` is dropped.
    Translating either into ``event_count`` would change the rule.

``xbits`` / ``flexbits``
    a cross-event state machine. ``isset`` is rebuilt as a ``temporal_ordered``
    correlation; ``isnotset`` is inexpressible in Sigma.

The subtle part is resolving the group-by key. Sagan reasons over internal
values (``src_ip``, ``username``) that need not exist as fields in the event.
Three cases arise, in this order:

1. a ``json_map`` binds the internal value to a JSON key, so use that key;
2. ``parse_src_ip`` or ``normalize`` is present, meaning Sagan extracts the
   address by regular expression from the raw text: no field exists, so refuse;
3. neither applies, in which case ``src_ip`` falls back to the syslog sender
   (``src/processors/engine.c``, where ``src_ip`` is copied from
   ``syslog_host`` when empty, and the rule-syntax documentation, "if the
   signature lacks parse_src_ip or normalize, then the syslog source is
   adopted"). Group on the profile's hostname field and report the shift.
"""

from __future__ import annotations

import re

from ..errors import Degradation, DegradationCode, Refusal, RefusalCode
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import CorrelationSpec, RuleDraft
from .registry import handler
from .values import CasePolicy

_COUNT = re.compile(r"count\s+(\d+)")
_SECONDS = re.compile(r"seconds\s+(\d+)")
_TRACK = re.compile(r"track\s+(?P<keys>[A-Za-z_&]+)")
_TYPE = re.compile(r"type\s+(?P<kind>limit|suppress)")
_XBIT_TRACK = re.compile(r"track\s+(?P<key>ip_src|ip_dst|ip_pair)")
_EXPIRE = re.compile(r"expire\s+(\d+)")

#: ``after`` and ``threshold`` tracking keys onto Sagan internal values.
#:
#: ``by_string`` is where the two keywords part company, and the difference is
#: an accident of the C rather than a design. Under ``threshold`` it really is a
#: synonym for ``by_username``: that parser tests the intact option token, so
#: ``by_string`` sets the same ``method_username`` flag. Under ``after`` the
#: parser first calls ``strtok_r(tmptoken, " ", ...)``, truncating the token to
#: ``"track"``, and then tests *that* for ``by_string`` (``src/rules.c``), so the
#: branch can never fire. ``_group_by`` therefore drops it: that function serves
#: ``after`` alone, since ``threshold`` never reaches a group-by at all (it is
#: alert-volume control, carried over as an attribute). The ``threshold`` half is
#: recorded here because it is easy to rediscover and get backwards.
#:
#: Both halves were confirmed against a locally built engine rather than read
#: alone: ``after: track by_string`` is rejected at load, which is only possible
#: if the key contributes nothing, while the same expression under ``threshold``
#: loads cleanly.
TRACK_TO_INTERNAL = {
    "by_src": "src_ip",
    "by_dst": "dest_ip",
    "by_username": "username",
    "by_user": "username",
}

#: ``xbits`` tracking keys onto Sagan internal values.
XBIT_TO_INTERNAL: dict[str, tuple[str, ...]] = {
    "ip_src": ("src_ip",),
    "ip_dst": ("dest_ip",),
    "ip_pair": ("src_ip", "dest_ip"),
}

#: ``flexbits`` tracking keys, which sit before the bit name in the argument
#: list, unlike ``xbits``.
FLEXBIT_TRACK_KEYS = frozenset(
    {"by_src", "by_dst", "both", "reverse", "username", "none"}
)

#: Default window for a rebuilt state correlation when the setter rules declare
#: no ``expire``. Sagan attaches the expiry to the setter, not to the tester.
DEFAULT_STATE_TIMESPAN_SECONDS = 86400


def format_timespan(seconds: int) -> str:
    """Format a duration in Sigma notation, using the most readable unit.

    >>> format_timespan(300), format_timespan(21600), format_timespan(90)
    ('5m', '6h', '90s')
    >>> format_timespan(86400)
    '1d'
    """
    if seconds and seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds and seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds and seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def resolve_group_key(
    internal: str,
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    keyword: str,
) -> str:
    """Translate a Sagan internal value into a field that actually exists.

    See the module docstring for the three branches and their justification.
    """
    mapped = resolver.resolve(internal)
    if internal in resolver.mapping:
        return mapped  # type: ignore[return-value]

    if internal in ("src_ip", "dest_ip"):
        # Branch 2a: the profile supplies the enrichment and the rule declared a
        # position. Sagan's own precedence applies (engine.c:797): liblognorm
        # wins when it resolves the address, and positional parsing is only the
        # fallback, so a rule carrying both is converted against the fallback
        # and flagged.
        enriched = resolver.positional(internal)
        if enriched is not None:
            if rule.has("normalize"):
                draft.degrade(
                    Degradation(
                        code=DegradationCode.NORMALIZE_PRECEDENCE,
                        detail=(
                            f"{internal} is resolved by liblognorm first and by "
                            f"positional parsing only as a fallback; only the "
                            f"fallback is reproduced"
                        ),
                    )
                )
            draft.degrade(
                Degradation(
                    code=DegradationCode.POSITIONAL_IP_FIELD,
                    detail=(
                        f"{internal} comes from the bundled VRL transform as "
                        f"{enriched}; the correlation requires that transform to "
                        f"run in the ingestion pipeline"
                    ),
                )
            )
            return enriched

        if (
            rule.has("parse_src_ip")
            or rule.has("parse_dst_ip")
            or rule.has("normalize")
        ):
            raise Refusal(
                code=RefusalCode.GROUPBY_UNRESOLVED,
                detail=(
                    f"{internal} is extracted from raw text by Sagan "
                    f"(parse_src_ip / normalize); supply it upstream, or convert "
                    f"with --profile vector-enriched and deploy the bundled VRL "
                    f"transforms"
                ),
                keywords=(keyword,),
            )
        draft.degrade(
            Degradation(
                code=DegradationCode.GROUPBY_SYSLOG_HOST,
                detail=(
                    f"{internal} has no extraction, so Sagan falls back to the "
                    f"syslog sender; grouping is per emitting host, not per "
                    f"attacker address"
                ),
            )
        )
        return context.syslog_host_field

    # Any other internal value, chiefly username. A profile that declares the
    # field takes it; otherwise liblognorm is the only source and there is
    # nothing to reproduce.
    resolved = resolver.resolve(internal)
    if resolved is not None:
        return resolved

    if rule.has("normalize"):
        raise Refusal(
            code=RefusalCode.GROUPBY_UNRESOLVED,
            detail=(
                f"{internal} comes from liblognorm rulebases, which are "
                f"per-format data files with no algorithm to reproduce; supply "
                f"the field upstream in the ingestion pipeline"
            ),
            keywords=(keyword,),
        )

    raise Refusal(
        code=RefusalCode.GROUPBY_UNRESOLVED,
        detail=f"group-by key {internal!r} cannot be resolved to a field",
        keywords=(keyword,),
    )


def _group_by(
    tracks: str,
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    keyword: str,
) -> tuple[str, ...]:
    """Resolve a ``track by_a&by_b`` expression into Sigma group-by fields."""
    keys: list[str] = []
    for token in tracks.split("&"):
        token = token.strip().lower()
        if token == "by_tag":
            keys.append("syslog_tag")
            continue
        if token == "by_string":
            # by_string groups on the username under `threshold`, and on nothing
            # at all under `after`. The two parsers differ by an accident that is
            # only visible in the C: `threshold` tests the intact option token,
            # while `after` tests it *after* strtok_r has truncated it to
            # "track", so its by_string branch can never fire. Confirmed against
            # the engine: `after: track by_string` alone is rejected at load,
            # which is only possible if the token contributes nothing, while the
            # same expression under `threshold` loads. Grouping on the username
            # here would invent a distinction Sagan does not make.
            draft.degrade(
                Degradation(
                    code=DegradationCode.AFTER_BY_STRING_INERT,
                    detail=(
                        f"{keyword} tracked by_string, which the engine's after "
                        "parser never recognises (it tests a token strtok_r has "
                        "already truncated), so Sagan groups on the remaining "
                        "keys only; the inert key was dropped"
                    ),
                )
            )
            continue
        internal = TRACK_TO_INTERNAL.get(token)
        if internal is None:
            raise Refusal(
                code=RefusalCode.GROUPBY_UNRESOLVED,
                detail=f"unknown tracking key: {token!r}",
                keywords=(keyword,),
            )
        keys.append(
            resolve_group_key(internal, rule, draft, context, resolver, keyword)
        )
    if not keys:
        # Every key was inert. Sagan refuses to load such a rule at all, so
        # there is nothing faithful to emit.
        raise Refusal(
            code=RefusalCode.PARSE,
            detail=(
                f"{keyword} declares no tracking key the engine recognises "
                f"({tracks!r}); Sagan rejects the rule at load time"
            ),
            keywords=(keyword,),
        )
    return tuple(dict.fromkeys(keys))


@handler("after")
def handle_after(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``after: track by_src, count 10, seconds 300;`` onto ``event_count``."""
    for option in rule.iter_options("after"):
        if option.value is None:
            continue
        count = _COUNT.search(option.value)
        seconds = _SECONDS.search(option.value)
        track = _TRACK.search(option.value)
        if not (count and seconds and track):
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=f"incomplete after: {option.value!r}",
                keywords=("after",),
            )

        timespan = format_timespan(int(seconds.group(1)))
        # `after: count N` alerts from the N+1th event, not the Nth. The engine
        # creates its tracking entry with ``count = 1`` on the first match and
        # then alerts only while ``after2_count < count`` (``src/after.c``), so
        # the comparison is strictly greater: N events pass in silence and the
        # next one alerts. A Sigma ``event_count`` with ``gte: N`` fires as soon
        # as the window holds N, which is one event early, so the threshold is
        # emitted as N+1. Confirmed by running both engines on the same six
        # events: Sagan alerts on the 4th, 5th and 6th for ``count 3``, and
        # rsigma reproduces exactly that with ``gte: 4``.
        threshold = int(count.group(1)) + 1
        draft.correlations.append(
            CorrelationSpec(
                correlation_type="event_count",
                group_by=_group_by(
                    track.group("keys"), rule, draft, context, resolver, "after"
                ),
                timespan=timespan,
                condition={"gte": threshold},
                title_suffix=f"threshold {count.group(1)} in {timespan}",
                description=(
                    "Correlation derived from the Sagan after keyword. The base "
                    "rule must not alert on its own."
                ),
            )
        )


@handler("threshold")
def handle_threshold(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``threshold: type suppress, ...`` onto ``rsigma.suppress``."""
    for option in rule.iter_options("threshold"):
        if option.value is None:
            continue
        kind = _TYPE.search(option.value)
        seconds = _SECONDS.search(option.value)
        if kind is None:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=f"threshold without type: {option.value!r}",
                keywords=("threshold",),
            )

        if kind.group("kind") == "suppress" and seconds is not None:
            draft.custom_attributes["rsigma.suppress"] = format_timespan(
                int(seconds.group(1))
            )
            draft.degrade(
                Degradation(
                    code=DegradationCode.THRESHOLD_SUPPRESS,
                    detail=(
                        "threshold type suppress caps alert volume rather than "
                        "detection; carried over as rsigma.suppress"
                    ),
                )
            )
        else:
            draft.degrade(
                Degradation(
                    code=DegradationCode.THRESHOLD_LIMIT,
                    detail=(
                        "threshold type limit bounds alerts per window; Sigma "
                        "has no equivalent, so the constraint is dropped"
                    ),
                )
            )


@handler("xbits", "flexbits")
def handle_bits(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``xbits: {set|unset|isset|isnotset}, name, track ip_src [, expire N];``.

    ``set`` and ``isset`` operations are recorded on the draft; the correlation
    documents are emitted on the converter's second pass, once every rule that
    sets a given bit is known.

    ``flexbits`` uses a different argument order for the test forms:
    ``flexbits: isset, by_src, name;`` places the tracking key before the name.
    """
    for keyword in ("xbits", "flexbits"):
        for option in rule.iter_options(keyword):
            if option.value is None:
                continue
            parts = [part.strip() for part in option.value.split(",") if part.strip()]
            if not parts:
                continue
            operation = parts[0].lower()

            if operation in ("noalert", "noeve"):
                continue

            if operation == "isnotset":
                raise Refusal(
                    code=RefusalCode.STATE_ABSENCE,
                    detail=(
                        "the rule requires that an earlier event did not occur; "
                        "Sigma cannot express a negative correlation"
                    ),
                    keywords=(keyword,),
                )

            if len(parts) < 2:
                raise Refusal(
                    code=RefusalCode.PARSE,
                    detail=f"{keyword} without a bit name: {option.value!r}",
                    keywords=(keyword,),
                )

            name = bit_name(parts, operation)
            if operation == "set":
                expire = _EXPIRE.search(option.value)
                draft.sets_bits[name] = (
                    int(expire.group(1)) if expire else DEFAULT_STATE_TIMESPAN_SECONDS
                )
            elif operation == "isset":
                draft.tests_bits.add(name)
                draft.bit_group_by = _bit_group_by(
                    option.value, rule, draft, context, resolver, keyword
                )
            elif operation == "unset":
                draft.degrade(
                    Degradation(
                        code=DegradationCode.SIDE_EFFECT_DROPPED,
                        detail=(
                            f"{keyword} unset clears engine state, which has no "
                            f"Sigma equivalent"
                        ),
                    )
                )


def bit_name(parts: list[str], operation: str) -> str:
    """Extract the bit name, accounting for the ``flexbits`` argument order.

    ``xbits`` puts the name second. ``flexbits`` inserts a tracking key before
    the name on ``isset``, ``isnotset`` and ``unset``.

    >>> bit_name(['set', 'brute_force', 'track ip_src'], 'set')
    'brute_force'
    >>> bit_name(['isset', 'by_src', 'windows_reboot'], 'isset')
    'windows_reboot'
    >>> bit_name(['isset', 'brute_force', 'track ip_src'], 'isset')
    'brute_force'
    """
    candidate = parts[1]
    if operation in ("isset", "unset") and candidate.lower() in FLEXBIT_TRACK_KEYS:
        return parts[2] if len(parts) > 2 else candidate
    return candidate


def _bit_group_by(
    value: str,
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    keyword: str,
) -> tuple[str, ...]:
    """Group-by key of a correlation rebuilt from an ``isset``."""
    match = _XBIT_TRACK.search(value)
    internals = XBIT_TO_INTERNAL.get(match.group("key") if match else "ip_src")
    if internals is None:  # pragma: no cover - defensive
        internals = ("src_ip",)
    return tuple(
        dict.fromkeys(
            resolve_group_key(internal, rule, draft, context, resolver, keyword)
            for internal in internals
        )
    )
