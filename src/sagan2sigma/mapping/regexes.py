"""Handler for ``pcre``: a regular expression over the message body.

Sigma accepts a subset of PCRE through the ``re`` modifier and the ``i``, ``m``
and ``s`` flags. Before refusing a pattern the handler applies the
meaning-preserving rewrites that the Rust engine can express (inlining a
numbered subroutine, escaping a literal brace, turning the whole-string
``^((?!X).)*$`` idiom into a negated search, dropping an inert flag). What
remains outside the subset (recursion, look-around, back-references, control
verbs) is refused rather than approximated: a wrong expression in a detection
rule is worse than a missing rule.
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

#: Flags Sagan accepts but that have no Sigma-side effect, so they are dropped
#: rather than refused. The engine's flag switch (``src/rules.c``) handles
#: ``i s m x A E G`` and has **no default case**, so any other letter is
#: silently ignored at load time; refusing a rule over such a letter would make
#: the converter stricter than the engine it targets. ``H`` is the one the
#: corpus carries: a Suricata ``http_header`` buffer modifier Sagan never
#: implemented and therefore treats as a no-op.
_FLAG_IGNORED = frozenset("gxAEOSUDH")

#: PCRE constructs outside the Sigma subset.
#:
#: The lookaround and backreference entries are not theoretical. RSigma
#: compiles Sigma regular expressions with the Rust ``regex`` crate, which
#: guarantees linear-time matching and therefore supports neither. Python's
#: ``re`` accepts both, so a converter that validates only against ``re`` emits
#: rules the target engine refuses. Worse, RSigma aborts the **entire** rule
#: load on one such rule, so a single unconverted lookahead takes the whole
#: ruleset offline. What the crate accepts is checked against the engine, not
#: guessed: an escaped hyphen inside a character class, once refused here, was
#: found to compile in the RSigma versions this targets and is no longer
#: rejected.
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


#: A numbered subroutine call, ``(?1)`` .. ``(?99)``.
_SUBROUTINE = re.compile(r"\(\?(\d+)\)")


def _capturing_group_spans(body: str) -> dict[int, tuple[int, int]]:
    r"""Map each capturing group's number to the span of its inner pattern.

    Groups are numbered by opening parenthesis, as PCRE and the Rust engine
    both number them. Non-capturing ``(?:...)`` and the assertions ``(?=`` /
    ``(?!`` / ``(?<=`` / ``(?<!`` do not count; named groups do. Parentheses
    inside a character class or escaped are literals and ignored.
    """
    spans: dict[int, tuple[int, int]] = {}
    stack: list[tuple[int | None, int]] = []
    number = 0
    depth = 0
    index = 0
    length = len(body)
    while index < length:
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[" and not depth:
            depth = 1
        elif char == "]" and depth:
            depth = 0
        elif not depth and char == "(":
            capturing = True
            if body[index : index + 2] == "(?":
                third = body[index + 2 : index + 3]
                # (?<name> is a named capture; (?<= and (?<! are look-behinds.
                named_angle = third == "<" and body[index + 3 : index + 4] not in (
                    "=",
                    "!",
                )
                capturing = third == "P" or named_angle
            if capturing:
                number += 1
                stack.append((number, index + 1))
            else:
                stack.append((None, index + 1))
        elif not depth and char == ")" and stack:
            tag, start = stack.pop()
            if tag is not None:
                spans[tag] = (start, index)
        index += 1
    return spans


def expand_subroutines(body: str, _max_passes: int = 32) -> str:
    r"""Inline non-recursive numbered subroutine calls ``(?N)`` as ``(?:...)``.

    A subroutine call re-runs the *subpattern* of capturing group ``N`` (not its
    captured text, which is a back-reference). When the reference is not
    recursive, that is pure macro expansion: substituting the group's pattern
    text, wrapped in a non-capturing group, yields an ordinary regex with
    identical matches that the Rust engine accepts. Inserting a non-capturing
    wrapper never renumbers the earlier groups the calls resolve against, so
    repeated passes stay correct.

    A recursive reference (a group that reaches itself) cannot be flattened this
    way, and inlining it would grow without bound, so the call is left in place
    the moment recursion is detected and :func:`validate_regex` refuses it as a
    subroutine call. The pass cap is a second safety net for any other
    non-terminating shape.
    """
    for _ in range(_max_passes):
        match = _SUBROUTINE.search(body)
        if match is None:
            return body
        spans = _capturing_group_spans(body)
        span = spans.get(int(match.group(1)))
        if span is None:
            # Reference to a group that does not exist: leave it for validation.
            return body
        if span[0] <= match.start() < span[1]:
            # The call sits inside its own target group: recursion. Inlining it
            # would never terminate, so leave every call for validate_regex.
            return body
        inner = body[span[0] : span[1]]
        body = f"{body[: match.start()]}(?:{inner}){body[match.end() :]}"
    return body


def escape_literal_braces(body: str) -> str:
    r"""Escape a ``{`` that is a literal rather than the start of a repetition.

    Python's ``re`` reads a ``{`` that does not open ``{m}`` / ``{m,}`` /
    ``{m,n}`` as a literal brace; the Rust ``regex`` crate rejects it outright
    (see :func:`has_unsupported_brace`). Escaping exactly that ``{`` leaves the
    meaning unchanged for both engines. Only the ``{`` is touched: the Rust
    engine already accepts a literal ``}``, so escaping it would alter the output
    of rules that were never broken. A ``{`` inside a character class, or already
    escaped, is a literal to both engines and left alone, so a well-formed
    pattern passes through byte for byte.
    """
    out: list[str] = []
    depth = 0
    index = 0
    length = len(body)
    while index < length:
        char = body[index]
        if char == "\\":
            out.append(body[index : index + 2])
            index += 2
            continue
        if char == "[" and not depth:
            depth = 1
        elif char == "]" and depth:
            depth = 0
        elif not depth and char == "{":
            quantifier = _QUANTIFIER.match(body, index)
            if quantifier:
                out.append(quantifier.group(0))
                index = quantifier.end()
                continue
            out.append(r"\{")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


#: ``^((?!X).)*$``: the whole line contains no occurrence of X.
_TEMPERED_PREFIX = "^((?!"
_TEMPERED_SUFFIX = ").)*$"


def strip_tempered_negation(body: str) -> str | None:
    r"""Return ``X`` when ``body`` is the whole-string "does not contain X" idiom.

    ``^((?!X).)*$`` matches a line in which ``X`` never starts, that is, a line
    that does not contain ``X``. On the single-line events Sagan matches, that
    is exactly the negation of a search for ``X``, so the caller can emit ``X``
    as a *negated* predicate instead of refusing the lookahead. The inner ``X``
    is located by balancing parentheses, so a stray ``)`` inside ``X`` does not
    fool the match; any other shape returns ``None``.
    """
    if not (body.startswith(_TEMPERED_PREFIX) and body.endswith(_TEMPERED_SUFFIX)):
        return None
    # Scan X with the look-ahead paren already open (depth 1); it ends at the
    # ')' that closes it, which must be immediately followed by the suffix.
    depth = 1
    index = len(_TEMPERED_PREFIX)
    length = len(body)
    class_open = False
    while index < length:
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[" and not class_open:
            class_open = True
        elif char == "]" and class_open:
            class_open = False
        elif not class_open and char == "(":
            depth += 1
        elif not class_open and char == ")":
            depth -= 1
            if depth == 0:
                # This ')' closes the look-ahead; the rest must be the suffix.
                return (
                    body[len(_TEMPERED_PREFIX) : index]
                    if body[index:] == (_TEMPERED_SUFFIX)
                    else None
                )
        index += 1
    return None


def normalise_regex(body: str) -> str:
    """Rewrite the safe, meaning-preserving subset into the Rust-accepted form.

    Both steps are identity on a pattern that does not need them, so a
    well-formed expression passes through unchanged.
    """
    return escape_literal_braces(expand_subroutines(body))


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
    inner = strip_tempered_negation(body)
    if inner is not None:
        # ^((?!X).)*$ matches when X is absent, so negate a search for X.
        body = inner
        negated = not negated
    body = normalise_regex(body)
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
