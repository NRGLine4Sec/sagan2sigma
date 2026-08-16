"""Handlers for the Sagan JSON operators.

These are the only keywords in the corpus that yield idiomatic Sigma: they name
a key, therefore a field, and are portable to other backends. They cover about
a quarter of the upstream corpus (CloudTrail, Azure Event Hub, CrowdStrike,
GuardDuty, Okta, Box and similar sources).

Reference semantics, from the rule-keywords documentation:

* ``json_content`` compares the key value **literally**; the ``json_contains``
  flag switches it to a substring search;
* ``json_meta_content`` accepts a value list, that is an OR;
* case is significant by default and ``json_nocase`` turns it off, exactly like
  ``content``, so the same inversion against Sigma applies;
* the ``json_decode_base64`` family decodes the *field value* before comparing,
  which Sigma's ``base64`` modifier cannot mirror.
"""

from __future__ import annotations

import re

from ..errors import Refusal, RefusalCode
from ..sagan.hexdec import decode_hex
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import Predicate, RuleDraft, Scalar
from .regexes import DELIMITED, normalise_regex, validate_regex
from .registry import handler
from .values import CasePolicy, case_modifiers, coerce_scalar, escape_literal

#: ``".key", "value"`` or ``!".key", value1,value2``.
_JSON_ARGS = re.compile(
    r'^\s*(?P<neg>!?)\s*"?\.?(?P<key>[A-Za-z0-9_.\[\]@-]+)"?\s*,\s*(?P<rest>.+)$', re.S
)

_CONTENT_MODIFIERS = frozenset(
    {
        "json_nocase",
        "json_contains",
        "json_strstr",
        "json_decode_base64",
        "json_base64_decode",
    }
)
_META_MODIFIERS = frozenset(
    {
        "json_meta_nocase",
        "json_meta_contains",
        "json_meta_strstr",
        "json_decode_base64_meta",
        "json_base64_decode_meta",
    }
)
_BASE64_FLAGS = frozenset(
    {
        "json_decode_base64",
        "json_base64_decode",
        "json_decode_base64_meta",
        "json_base64_decode_meta",
        "json_decode_base64_pcre",
        "json_base64_decode_pcre",
    }
)


def parse_json_args(value: str, keyword: str) -> tuple[bool, str, str]:
    """Split negation, JSON key and the remaining argument."""
    match = _JSON_ARGS.match(value)
    if match is None:
        raise Refusal(
            code=RefusalCode.PARSE,
            detail=f"unparsable {keyword} arguments: {value!r}",
            keywords=(keyword,),
        )
    return match.group("neg") == "!", match.group("key"), match.group("rest").strip()


def reject_base64(modifiers: frozenset[str], keyword: str) -> None:
    """Refuse the base64 variants, which have no faithful Sigma equivalent.

    Sigma does own a ``base64`` modifier, but it encodes the *searched value*
    before comparison, whereas Sagan decodes the *field value* before
    comparing. The two only agree when the encoding aligns on byte boundaries,
    which is not guaranteed, so approximating would produce silently wrong
    rules.
    """
    offenders = modifiers & _BASE64_FLAGS
    if offenders:
        raise Refusal(
            code=RefusalCode.BASE64_FIELD_DECODE,
            detail=(
                "Sagan decodes the field value before comparing, Sigma encodes "
                "the searched pattern instead; the two are not equivalent"
            ),
            keywords=(keyword, *sorted(offenders)),
        )


def _scalar(text: str, contains: bool) -> Scalar:
    """Coerce a JSON value, escaping wildcards for substring searches.

    A ``json_content: ".EventID","4624"`` must yield ``EventID: 4624``: logs
    expose an integer and Sigma distinguishes the two types. Under
    ``json_contains`` the comparison is textual, so the value stays a string.
    """
    if not contains:
        value = coerce_scalar(text)
        if isinstance(value, int):
            return value
    return escape_literal(text)


def _numeric(values: tuple[Scalar, ...]) -> bool:
    """Whether every value is numeric, which makes ``|cased`` meaningless.

    pySigma rejects ``field|cased: 4624`` outright: case sensitivity is not
    defined on a number. Sagan has the same property, it simply never says so.
    """
    return all(isinstance(value, int) for value in values)


def _modifiers(
    contains: bool, nocase: bool, policy: CasePolicy, values: tuple[Scalar, ...]
) -> tuple[str, ...]:
    """Assemble the Sigma modifiers for a JSON predicate."""
    prefix: tuple[str, ...] = ("contains",) if contains else ()
    if _numeric(values):
        return prefix
    return prefix + case_modifiers(nocase, policy)


@handler("json_content")
def handle_json_content(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``json_content: ".eventName","CreateTrail";``."""
    for option in rule.iter_options("json_content"):
        if option.value is None:
            continue
        negated, key, rest = parse_json_args(option.value, "json_content")
        modifiers = rule.modifiers_after(option.index, _CONTENT_MODIFIERS)
        reject_base64(modifiers, "json_content")

        nocase = "json_nocase" in modifiers
        contains = bool(modifiers & {"json_contains", "json_strstr"})
        text = decode_hex(rest.strip().strip('"'))
        values = (_scalar(text, contains),)

        draft.add(
            Predicate(
                field=key,
                modifiers=_modifiers(contains, nocase, policy, values),
                values=values,
                negated=negated,
                origin="json_content",
            )
        )


@handler("json_meta_content")
def handle_json_meta_content(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``json_meta_content: ".threat",medium,low;``."""
    for option in rule.iter_options("json_meta_content"):
        if option.value is None:
            continue
        negated, key, rest = parse_json_args(option.value, "json_meta_content")
        modifiers = rule.modifiers_after(option.index, _META_MODIFIERS)
        reject_base64(modifiers, "json_meta_content")

        nocase = "json_meta_nocase" in modifiers
        contains = bool(modifiers & {"json_meta_contains", "json_meta_strstr"})

        raw_values = [
            decode_hex(part.strip().strip('"'))
            for part in rest.split(",")
            if part.strip()
        ]
        if not raw_values:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail="json_meta_content carries no value",
                keywords=("json_meta_content",),
            )

        values = tuple(_scalar(value, contains) for value in raw_values)
        draft.add(
            Predicate(
                field=key,
                modifiers=_modifiers(contains, nocase, policy, values),
                values=values,
                negated=negated,
                origin="json_meta_content",
            )
        )


@handler("json_pcre")
def handle_json_pcre(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    r"""``json_pcre: ".sni", "/www\.example\.com/i";``."""
    for option in rule.iter_options("json_pcre"):
        if option.value is None:
            continue
        negated, key, rest = parse_json_args(option.value, "json_pcre")
        reject_base64(
            rule.modifiers_after(
                option.index,
                frozenset({"json_decode_base64_pcre", "json_base64_decode_pcre"}),
            ),
            "json_pcre",
        )

        text = rest.strip().strip('"')
        match = DELIMITED.match(text)
        if match is None:
            raise Refusal(
                code=RefusalCode.PCRE_UNSUPPORTED,
                detail=f"json_pcre has no delimiters: {text!r}",
                keywords=("json_pcre",),
            )
        body = normalise_regex(match.group("body"))
        validate_regex(body, "json_pcre")

        modifiers = ["re"]
        modifiers.extend(
            flag for flag in match.group("flags") if flag in ("i", "m", "s")
        )
        draft.add(
            Predicate(
                field=key,
                modifiers=tuple(modifiers),
                values=(body,),
                negated=negated,
                origin="json_pcre",
            )
        )
