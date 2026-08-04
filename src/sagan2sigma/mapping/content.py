"""Handlers for message-body searches: ``content`` and ``meta_content``.

Together these two keywords cover roughly 81% and 13% of the upstream corpus.
They emit ``|contains`` predicates on the field the message search resolves to,
which is the raw body under a plain syslog profile and a JSON key when the rule
carries ``json_map: "message", ".key"``.
"""

from __future__ import annotations

import re

from ..errors import Degradation, DegradationCode, Refusal, RefusalCode
from ..sagan.hexdec import decode_hex
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import Predicate, RuleDraft
from .registry import handler
from .values import CasePolicy, case_modifiers, escape_literal, strip_quotes

#: ``meta_content: "prefix %sagan% suffix", value1,value2`` or ``, $VAR``.
_META = re.compile(r'^\s*(?P<neg>!?)\s*"(?P<pattern>.*?)"\s*,\s*(?P<values>.+)$', re.S)

#: Substitution marker of ``meta_content``.
PLACEHOLDER = "%sagan%"


@handler("content")
def handle_content(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``content: "authentication failure"; nocase;``.

    Two inversions must be respected:

    * Sagan compares case-sensitively and ``nocase`` turns that off, while
      Sigma is case-insensitive by default. ``|cased`` is therefore emitted in
      the *absence* of ``nocase``;
    * ``*`` and ``?`` are literal inside a Sagan ``content`` but are wildcards
      in Sigma, so they are escaped.
    """
    _reject_unreachable(rule, resolver, "content")
    for option in rule.iter_options("content"):
        if option.value is None:
            continue
        negated, text = strip_quotes(option.value)
        nocase = "nocase" in rule.modifiers_after(option.index, frozenset({"nocase"}))
        draft.add(
            Predicate(
                field=resolver.message,
                modifiers=("contains", *case_modifiers(nocase, policy)),
                values=(escape_literal(decode_hex(text)),),
                negated=negated,
                origin="content",
            )
        )
    _flag_portability(draft, resolver)


@handler("meta_content")
def handle_meta_content(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``meta_content: "Username|3a| %sagan%", $USERS;``.

    The pattern is instantiated once per value, producing a Sigma list, that is
    an OR. A ``$VAR`` is resolved from the ``sagan.yaml`` when one was
    supplied, otherwise the rule is refused: turning ``%sagan%`` into a
    wildcard would silently widen the rule far beyond the original.

    A ``meta_content`` without the ``%sagan%`` helper is refused too, because
    Sagan itself rejects such a rule at load time (``src/rules.c``: "lacks the
    meta_content 'helper' (%sagan%)").
    """
    _reject_unreachable(rule, resolver, "meta_content")
    for option in rule.iter_options("meta_content"):
        if option.value is None:
            continue
        match = _META.match(option.value)
        if match is None:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=f"unparsable meta_content: {option.value!r}",
                keywords=("meta_content",),
            )

        negated = match.group("neg") == "!"
        pattern = decode_hex(match.group("pattern"))
        if PLACEHOLDER not in pattern:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=(
                    "meta_content lacks the %sagan% helper; Sagan itself "
                    "refuses to load such a rule"
                ),
                keywords=("meta_content",),
            )

        values = _resolve_values(match.group("values"), context)
        nocase = "meta_nocase" in rule.modifiers_after(
            option.index, frozenset({"meta_nocase"})
        )
        expanded = tuple(
            escape_literal(pattern.replace(PLACEHOLDER, value)) for value in values
        )
        draft.add(
            Predicate(
                field=resolver.message,
                modifiers=("contains", *case_modifiers(nocase, policy)),
                values=expanded,
                negated=negated,
                origin="meta_content",
            )
        )
    _flag_portability(draft, resolver)


def _reject_unreachable(rule: SaganRule, resolver: FieldResolver, keyword: str) -> None:
    """Refuse a text search that has no field to run against.

    A rule using JSON operators targets JSON-bodied events, where RSigma
    exposes the parsed object and no raw field. A ``content`` search that no
    ``json_map`` redirected would therefore never match, and emitting it would
    silently reduce coverage behind a rule that looks correct.
    """
    if not rule.has(keyword) or not resolver.raw_search_is_unreachable:
        return
    raise Refusal(
        code=RefusalCode.RAW_TEXT_ON_JSON_EVENT,
        detail=(
            f"{keyword} searches the raw body while the rule also uses JSON "
            f"operators; on a JSON-bodied event there is no raw field to "
            f"search. Add json_map binding message to the key holding the text."
        ),
        keywords=(keyword,),
    )


def _resolve_values(raw: str, context: Context) -> list[str]:
    """Resolve the value list of a ``meta_content``, variables included."""
    values: list[str] = []
    for token in (part.strip() for part in raw.split(",")):
        if not token:
            continue
        if token.startswith("$"):
            expanded = context.config.expand(token)
            if expanded is None:
                raise Refusal(
                    code=RefusalCode.VAR_UNRESOLVED,
                    detail=(
                        f"variable {token} is undefined; supply the sagan.yaml "
                        f"with --sagan-yaml"
                    ),
                    keywords=("meta_content",),
                )
            values.extend(decode_hex(value) for value in expanded)
        else:
            values.append(decode_hex(token.strip('"')))
    if not values:
        raise Refusal(
            code=RefusalCode.PARSE,
            detail="meta_content carries no usable value",
            keywords=("meta_content",),
        )
    return values


def _flag_portability(draft: RuleDraft, resolver: FieldResolver) -> None:
    """Record the portability warning when matching against the raw body."""
    if resolver.targets_json:
        return
    draft.degrade(
        Degradation(
            code=DegradationCode.RAW_TEXT_MATCH,
            detail=(
                "detection runs against the raw message body; the rule works "
                "under RSigma but translating it to another Sigma backend "
                "would yield an unusable full-text search"
            ),
        )
    )
