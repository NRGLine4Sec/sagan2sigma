"""Handlers for envelope selectors: program, event_id, facility, level, tag.

These keywords do not search the message body; they filter on envelope fields.
They therefore produce predicates on named fields rather than on the message
field.
"""

from __future__ import annotations

from ..errors import Degradation, DegradationCode, Refusal, RefusalCode
from ..sagan.config import PRIORITY_TO_LEVEL
from ..sagan.hexdec import decode_hex
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import Predicate, RuleDraft, Scalar
from .registry import handler
from .values import (
    CasePolicy,
    case_modifiers,
    coerce_scalar,
    split_alternatives,
    split_csv,
)


@handler("program", "event_type")
def handle_program(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``program: sshd|openssh`` onto the program field.

    Sagan's comparison (``Wildcard()`` in ``src/util.c``) is a full-string
    match supporting ``*`` and ``?``, and it is case-sensitive. That is exactly
    the semantics of a plain Sigma value bar the case, so wildcards are carried
    through unescaped and ``|cased`` is added under the faithful policy.

    ``event_type`` is documented as an alias of ``program``.
    """
    for option in rule.options:
        if option.name not in ("program", "event_type") or option.value is None:
            continue
        values = [decode_hex(item) for item in split_alternatives(option.value)]
        if not values:
            continue
        draft.add(
            Predicate(
                field=resolver.program,
                modifiers=case_modifiers(nocase=False, policy=policy),
                values=tuple(values),
                origin=option.name,
            )
        )


@handler("event_id")
def handle_event_id(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``event_id: 4624,4625`` onto an EventID field.

    The documentation spells out both behaviours: on mapped JSON the value of
    the key bound to ``event_id`` is used, and on unstructured text the keyword
    degrades to ``meta_content: " %sagan%: ", {id}...; meta_depth: 10;``,
    because most Windows agents put the event ID at the start of the message.

    Only the structured form is emitted. The positional heuristic exists solely
    to compensate for missing structure and has no Sigma equivalent, so it is
    recorded as a degradation.
    """
    field = resolver.resolve("event_id")
    if field is None:
        field = "EventID"
        draft.degrade(
            Degradation(
                code=DegradationCode.EVENT_ID_HEURISTIC,
                detail=(
                    "no json_map binds event_id, so Sagan searches ' <id>: ' in "
                    "the first 10 bytes of the message; the converted rule "
                    "assumes a structured EventID field instead"
                ),
            )
        )

    for option in rule.iter_options("event_id"):
        if option.value is None:
            continue
        values: list[Scalar] = [coerce_scalar(item) for item in split_csv(option.value)]
        if not values:
            continue
        draft.add(
            Predicate(
                field=field, modifiers=(), values=tuple(values), origin="event_id"
            )
        )


def _envelope_selector(
    rule: SaganRule,
    draft: RuleDraft,
    keyword: str,
    field: str,
    policy: CasePolicy,
) -> None:
    """Emit a case-insensitive predicate on an envelope field."""
    for option in rule.iter_options(keyword):
        if option.value is None:
            continue
        values = split_alternatives(option.value)
        if not values:
            continue
        draft.add(
            Predicate(
                field=field,
                modifiers=case_modifiers(nocase=True, policy=policy),
                values=tuple(values),
                origin=keyword,
            )
        )


@handler("syslog_facility")
def handle_facility(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``syslog_facility: daemon|auth`` onto the profile facility field.

    Only the prefixed form exists. A bare ``facility:`` is not an alias, it is
    not a keyword at all: Sagan aborts the whole ruleset on it, verified
    against the engine. Accepting one here would convert a rule that cannot
    load anywhere into working Sigma, so it falls through to
    ``E_UNKNOWN_KEYWORD`` like any other invalid option.
    """
    _envelope_selector(
        rule, draft, "syslog_facility", resolver.envelope("facility"), policy
    )


@handler("syslog_level")
def handle_level(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``syslog_level: notice|warning`` onto the profile severity field.

    As with ``syslog_facility``, the bare ``level:`` form is not a keyword.
    """
    _envelope_selector(rule, draft, "syslog_level", resolver.envelope("level"), policy)


@handler("syslog_priority")
def handle_syslog_priority(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``syslog_priority: warning`` selects on the envelope priority field.

    This is a real detection selector, distinct from ``priority``/``pri``: those
    set the alert's own severity through ``atoi`` into ``s_pri``, while this one
    compares a string against the envelope, with ``|`` alternation and an exact
    ``strcmp`` (``engine.c``). Both facts were confirmed against the engine, as
    was the field being distinct from ``syslog_level``: one event carrying
    ``priority=warning`` and ``level=notice`` matches each keyword only on its
    own value.

    It is refused rather than mapped. Sagan's pipe input carries priority and
    level as separate fields, but decoded syslog has no third value: the PRI
    byte yields a facility and a severity, and that is all RSigma exposes.
    Mapping this onto the severity would silently answer a question the event
    cannot answer. No upstream rule uses the keyword.
    """
    if not rule.has("syslog_priority"):
        return
    raise Refusal(
        code=RefusalCode.NO_DETECTION,
        detail=(
            "syslog_priority selects on an envelope field decoded syslog does "
            "not carry: the PRI byte yields a facility and a severity, and "
            "Sagan's priority is neither. Match on syslog_level instead if the "
            "severity is what the rule means"
        ),
        keywords=("syslog_priority",),
    )


@handler("syslog_tag")
def handle_tag(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``syslog_tag: 2d`` onto a conventional ``syslog_tag`` field.

    Neither output profile exposes this field: neither RSigma nor Vector keeps
    the RFC 3164 tag separate from the app name. The predicate is emitted
    against a conventional field name and the gap is reported.
    """
    if not rule.has("syslog_tag"):
        return
    _envelope_selector(rule, draft, "syslog_tag", "syslog_tag", policy)
    draft.degrade(
        Degradation(
            code=DegradationCode.SIDE_EFFECT_DROPPED,
            detail=(
                "syslog_tag targets a field neither RSigma nor Vector exposes "
                "separately; the predicate assumes the pipeline supplies a "
                "syslog_tag field"
            ),
        )
    )


@handler("priority", "pri")
def handle_priority(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``priority: 1`` overrides the level derived from ``classtype``.

    ``pri`` is an exact alias of ``priority`` in the engine (``src/rules.c``,
    where ``strcmp(rulesplit, "pri")`` and ``"priority"`` both set ``s_pri``), so
    both are handled here. The override is sticky: option order inside a rule is
    arbitrary, so a ``classtype`` appearing after it must not win.
    """
    raw = rule.first("priority") or rule.first("pri")
    if raw is None:
        return
    try:
        priority = int(raw.strip())
    except ValueError as error:
        raise Refusal(
            code=RefusalCode.PARSE,
            detail=f"non-numeric priority: {raw!r}",
            keywords=("priority", "pri"),
        ) from error
    level = PRIORITY_TO_LEVEL.get(priority)
    if level is not None:
        draft.set_level(level, locked=True)


@handler("append_program")
def handle_append_program(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``append_program;`` widens the search surface Sagan matches against.

    Sagan appends the program to the message as ``message | program`` before
    running ``content`` and ``pcre``, so a rule may legitimately match on the
    program name through a ``content``. Sigma cannot concatenate two fields, so
    the converted rule searches the message alone.
    """
    draft.degrade(
        Degradation(
            code=DegradationCode.APPEND_PROGRAM,
            detail=(
                "append_program makes Sagan search 'message | program'; the "
                "converted rule searches the message field only, so patterns "
                "that relied on the appended program will not match"
            ),
        )
    )
