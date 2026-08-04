"""Handler for ``pcre``: a regular expression over the message body.

Sigma accepts a subset of PCRE through the ``re`` modifier and the ``i``, ``m``
and ``s`` flags. Constructs outside that subset (recursion, control verbs,
subroutine calls) are refused rather than approximated: a wrong expression in a
detection rule is worse than a missing rule.
"""

from __future__ import annotations

import re

from ..errors import Refusal, RefusalCode
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import Predicate, RuleDraft
from .registry import handler
from .values import CasePolicy

#: ``/pattern/flags``, the form Sagan uses.
DELIMITED = re.compile(r"^/(?P<body>.*)/(?P<flags>[a-zA-Z]*)$", re.S)

#: PCRE flags with a Sigma modifier equivalent.
_FLAG_MAP = {"i": "i", "m": "m", "s": "s"}

#: Flags that are tolerable but have no effect on the Sigma side.
_FLAG_IGNORED = frozenset("gxAEOSUD")

#: PCRE constructs outside the Sigma subset.
_UNSUPPORTED: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\(\?[0-9+-]"), "subroutine call"),
    (re.compile(r"\(\?R\)"), "recursion"),
    (re.compile(r"\(\?&"), "named subroutine call"),
    (re.compile(r"\(\*[A-Z]"), "control verb"),
    (re.compile(r"\(\?\("), "conditional pattern"),
    (re.compile(r"\\[GKZ]"), "non-portable PCRE anchor"),
)


def validate_regex(body: str, keyword: str = "pcre") -> None:
    """Check that a pattern fits the Sigma subset.

    Raises :class:`~sagan2sigma.errors.Refusal` when a non-portable construct is
    found, or when the pattern does not even compile under Python's ``re``.
    """
    for pattern, label in _UNSUPPORTED:
        if pattern.search(body):
            raise Refusal(
                code=RefusalCode.PCRE_UNSUPPORTED,
                detail=f"non-portable PCRE construct: {label}",
                keywords=(keyword,),
            )
    try:
        re.compile(body)
    except re.error as error:
        raise Refusal(
            code=RefusalCode.PCRE_UNSUPPORTED,
            detail=f"pattern does not compile: {error}",
            keywords=(keyword,),
        ) from error


def parse_pcre(value: str, keyword: str = "pcre") -> tuple[bool, str, tuple[str, ...]]:
    """Parse ``!"/pattern/i"`` into (negated, pattern, Sigma modifiers)."""
    text = value.strip()
    negated = False
    if text.startswith("!"):
        negated = True
        text = text[1:].strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]

    match = DELIMITED.match(text)
    if match is None:
        raise Refusal(
            code=RefusalCode.PCRE_UNSUPPORTED,
            detail=f"{keyword} has no recognisable delimiters: {value!r}",
            keywords=(keyword,),
        )

    body = match.group("body")
    validate_regex(body, keyword)

    modifiers: list[str] = ["re"]
    for flag in match.group("flags"):
        if flag in _FLAG_MAP:
            modifiers.append(_FLAG_MAP[flag])
        elif flag not in _FLAG_IGNORED:
            raise Refusal(
                code=RefusalCode.PCRE_UNSUPPORTED,
                detail=f"unsupported PCRE flag: {flag!r}",
                keywords=(keyword,),
            )
    return negated, body, tuple(modifiers)


@handler("pcre")
def handle_pcre(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``pcre: "/broken system|breaking system/i";`` onto ``|re|i``."""
    if rule.has("pcre") and resolver.raw_search_is_unreachable:
        raise Refusal(
            code=RefusalCode.RAW_TEXT_ON_JSON_EVENT,
            detail=(
                "pcre searches the raw body while the rule also uses JSON "
                "operators; on a JSON-bodied event there is no raw field to "
                "search. Add json_map binding message to the key holding the "
                "text, or use json_pcre."
            ),
            keywords=("pcre",),
        )
    for option in rule.iter_options("pcre"):
        if option.value is None:
            continue
        negated, body, modifiers = parse_pcre(option.value)
        draft.add(
            Predicate(
                field=resolver.message,
                modifiers=modifiers,
                values=(body,),
                negated=negated,
                origin="pcre",
            )
        )
