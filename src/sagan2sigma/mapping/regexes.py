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
#:
#: The lookaround and backreference entries are not theoretical. RSigma
#: compiles Sigma regular expressions with the Rust ``regex`` crate, which
#: guarantees linear-time matching and therefore supports neither. Python's
#: ``re`` accepts both, so a converter that validates only against ``re`` emits
#: rules the target engine refuses. Worse, RSigma aborts the **entire** rule
#: load on one such rule, so a single unconverted lookahead takes the whole
#: ruleset offline. 34 rules of the upstream corpus are in that position.
_UNSUPPORTED: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\(\?[0-9+-]"), "subroutine call"),
    (re.compile(r"\(\?R\)"), "recursion"),
    (re.compile(r"\(\?&"), "named subroutine call"),
    (re.compile(r"\(\*[A-Z]"), "control verb"),
    (re.compile(r"\(\?\("), "conditional pattern"),
    (re.compile(r"\\[GKZ]"), "non-portable PCRE anchor"),
    (re.compile(r"\(\?=|\(\?!"), "lookahead, unsupported by the Rust regex engine"),
    (
        re.compile(r"\(\?<=|\(\?<!"),
        "lookbehind, unsupported by the Rust regex engine",
    ),
    (
        re.compile(r"(?<!\\)\\[1-9]"),
        "backreference, unsupported by the Rust regex engine",
    ),
    (
        re.compile(r"\\k<"),
        "named backreference, unsupported by the Rust regex engine",
    ),
)


def has_invalid_class_range(body: str) -> bool:
    r"""Whether a character class contains an escaped hyphen mid-class.

    ``[\!\-\%]`` is accepted by Python, which reads the escaped hyphen as a
    literal, and rejected by the Rust ``regex`` crate, which reads it as the
    start of an invalid range. Catching it statically avoids emitting a rule
    that takes the whole ruleset down at load time.

    >>> has_invalid_class_range(r"[\!\-\%]")
    True
    >>> has_invalid_class_range(r"[a-z]"), has_invalid_class_range(r"[\-abc]")
    (False, False)
    """
    depth = 0
    index = 0
    class_start = -1
    while index < len(body):
        char = body[index]
        if char == "\\":
            # An escaped hyphen that is neither the first nor the last element
            # of the class is what the Rust regex engine rejects.
            if (
                depth
                and body[index : index + 2] == "\\-"
                and index > class_start + 1
                and body[index + 2 : index + 3] != "]"
            ):
                return True
            index += 2
            continue
        if char == "[" and not depth:
            depth = 1
            class_start = index
        elif char == "]" and depth:
            depth = 0
        index += 1
    return False


#: A well-formed counted repetition: ``{m}``, ``{m,}`` or ``{m,n}``.
_QUANTIFIER = re.compile(r"\{\d+(?:,\d*)?\}")


def has_unsupported_brace(body: str) -> bool:
    r"""Whether the pattern carries a ``{`` the Rust regex engine rejects.

    Python's ``re`` treats a ``{`` that does not open a counted repetition as a
    literal brace, so ``{\d}`` matches a literal ``{``, a digit and a literal
    ``}``. The Rust ``regex`` crate behind RSigma rejects such a brace outright,
    and one rejected rule takes the whole ruleset down at load time. Only an
    unescaped ``{`` outside a character class is considered; an escaped ``\{``
    and a class member ``[{]`` are literals to both engines.

    >>> has_unsupported_brace(r"{\d}"), has_unsupported_brace(r"a\{3\}")
    (True, False)
    >>> has_unsupported_brace(r"\d{3}"), has_unsupported_brace(r"[a{]b")
    (False, False)
    """
    depth = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[" and not depth:
            depth = 1
        elif char == "]" and depth:
            depth = 0
        elif char == "{" and not depth and not _QUANTIFIER.match(body, index):
            return True
        index += 1
    return False


def validate_regex(body: str, keyword: str = "pcre") -> None:
    """Check that a pattern fits the subset both Sigma and RSigma accept.

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
    if has_invalid_class_range(body):
        raise Refusal(
            code=RefusalCode.PCRE_UNSUPPORTED,
            detail=(
                "escaped hyphen inside a character class: Python reads it as a "
                "literal, the Rust regex engine as an invalid range"
            ),
            keywords=(keyword,),
        )
    if has_unsupported_brace(body):
        raise Refusal(
            code=RefusalCode.PCRE_UNSUPPORTED,
            detail=(
                "a '{' that is not a counted repetition: Python reads it as a "
                "literal brace, the Rust regex engine rejects it"
            ),
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
