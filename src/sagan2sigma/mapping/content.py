"""Handlers for message-body searches: ``content`` and ``meta_content``.

Together these two keywords cover roughly 81% and 13% of the upstream corpus.
They emit ``|contains`` predicates on the field the message search resolves to,
which is the raw body under a plain syslog profile and a JSON key when the rule
carries ``json_map: "message", ".key"``.
"""

from __future__ import annotations

from ..errors import Degradation, DegradationCode, Refusal, RefusalCode
from ..sagan.hexdec import decode_hex
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import Predicate, RuleDraft
from .positional import POSITIONAL_KEYWORDS
from .registry import handler
from .values import CasePolicy, case_modifiers, escape_literal, strip_quotes

#: Substitution marker of ``meta_content``.
PLACEHOLDER = "%sagan%"


def between_quotes(text: str) -> str:
    r"""Reproduce Sagan's ``Between_Quotes`` (``src/util.c``).

    The engine walks the string, starts capturing after the first ``"``, and
    drops every ``"`` it meets while resetting its flag on each, so the net
    effect is: discard anything before the first quote, then keep every
    character except the quotes themselves. It is not a balanced-quote parser,
    which is exactly why a stray quote left inside a value survives.

    >>> between_quotes('"Username|3a| %sagan%"')
    'Username|3a| %sagan%'
    >>> between_quotes('"%sagan%')
    '%sagan%'
    """
    out: list[str] = []
    started = False
    for char in text:
        if char == '"':
            started = True
            continue
        if started:
            out.append(char)
    return "".join(out)


def split_meta_content(value: str) -> tuple[bool, str, str]:
    """Split a ``meta_content`` value the way ``src/rules.c`` does.

    Sagan grabs the first comma-delimited token as the helper, runs it through
    ``Between_Quotes``, then takes everything after that first comma as the
    search-value string. The first comma is the separator wherever it sits, even
    inside the quotes, which is why a rule that writes its values inside the
    closing quote, ``"eventName|22 3a 20 22|%sagan%,A,B"``, still parses: the
    helper is ``eventName": "%sagan%`` and the values are ``A`` and ``B"``, the
    trailing quote and all, exactly as the engine sees them.

    Returns ``(negated, helper, values_string)``. Raises :class:`Refusal` when
    there is no comma, since the engine aborts on a helper with no search data.
    """
    text = value.strip()
    negated = text.startswith("!")
    if negated:
        text = text[1:].strip()
    helper_token, separator, values = text.partition(",")
    if not separator:
        raise Refusal(
            code=RefusalCode.PARSE,
            detail=f"meta_content has no search value: {value!r}",
            keywords=("meta_content",),
        )
    return negated, between_quotes(helper_token), values


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
        # nocase can sit after the content's positional modifiers, for example
        # `content:"x"; distance:0; nocase`, so the scan looks through the inert
        # positional keywords rather than stopping at the first of them.
        nocase = "nocase" in rule.modifiers_after(
            option.index, frozenset({"nocase"}) | POSITIONAL_KEYWORDS
        )
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
        negated, helper, values_string = split_meta_content(option.value)
        pattern = decode_hex(helper)
        if PLACEHOLDER not in pattern:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=(
                    "meta_content lacks the %sagan% helper; Sagan itself "
                    "refuses to load such a rule"
                ),
                keywords=("meta_content",),
            )

        values = _resolve_values(values_string, context)
        nocase = "meta_nocase" in rule.modifiers_after(
            option.index, frozenset({"meta_nocase"}) | POSITIONAL_KEYWORDS
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
            # No quote stripping: the engine does not trim a value, so a stray
            # quote left in one, such as the closing quote of a rule that wrote
            # its values inside the quotes, is part of the search string.
            values.append(decode_hex(token))
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
