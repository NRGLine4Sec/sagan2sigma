"""Synthesis of events that satisfy a Sigma rule's detection.

Comparing two rules behaviourally needs events to compare them on, and
hand-writing those would only test what the author already believed. This
module derives them from the rule instead.

pySigma does most of the hard work: by the time a rule is parsed, modifiers are
already folded into values, so ``CommandLine|contains: admin`` arrives as the
string ``*admin*`` and ``|all`` has become a conjunction. What remains is a
small satisfiability problem over a boolean tree of field constraints.

The approach:

1. walk the condition AST, pushing negations inward with De Morgan, and
   enumerate satisfying branch choices, bounded so that a rule with many
   alternatives does not explode;
2. for each branch, group the positive constraints per field and build one
   concrete value satisfying all of them, honouring prefix and suffix anchors;
3. discard the branch if a negative constraint ends up satisfied.

Step 3 is deliberately conservative rather than clever: a rejected branch costs
nothing because other branches remain, whereas a wrong event would silently
weaken every conclusion drawn from it.

Nothing here is trusted on its own. Every synthesised event is put through the
real engine, and one that fails to fire the rule it was built from is discarded
and counted. That failure rate is reported, so the coverage of the analysis is
visible rather than assumed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from functools import lru_cache
from itertools import product
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

#: Filler woven around required substrings. Chosen to be inert: no wildcard
#: meaning, no regex meaning, and unlikely to satisfy another rule by accident.
FILLER = "zq"

#: Field holding a keyword search, which has no field of its own. RSigma
#: searches the whole event for keywords, so any field carries them.
KEYWORD_FIELD = "_raw"

#: Ceiling on enumerated branch combinations per rule.
MAX_BRANCHES = 12


class Unsatisfiable(Exception):
    """The constraint set cannot be met by any single event."""


@dataclass(frozen=True, slots=True)
class Constraint:
    """One field constraint, positive or negated.

    ``keyword`` marks an unbound search term. Sigma keywords match anywhere in
    the event rather than equalling a field, so they are woven in as substrings
    even when the value carries no wildcard. Treating them as exact values is
    what makes a rule like ``all of selection_*`` over two keyword lists look
    unsatisfiable when it is not.
    """

    field: str
    value: Any
    negated: bool = False
    keyword: bool = False


def _negate(node: Any) -> Any:
    """Push a negation one level inward, De Morgan style."""
    if isinstance(node, ConditionAND):
        return ConditionOR([ConditionNOT([arg]) for arg in node.args])
    if isinstance(node, ConditionOR):
        return ConditionAND([ConditionNOT([arg]) for arg in node.args])
    if isinstance(node, ConditionNOT):
        return node.args[0]
    return ConditionNOT([node])


def branches(node: Any, negated: bool = False) -> list[list[Constraint]]:
    """Enumerate constraint sets that satisfy the node.

    Returns a list of alternatives; satisfying any one of them satisfies the
    node. Each alternative is a conjunction of constraints.
    """
    if isinstance(node, ConditionNOT):
        inner = _negate(node.args[0])
        if isinstance(inner, ConditionNOT):
            return branches(inner.args[0], not negated)
        return branches(inner, negated)

    if isinstance(node, ConditionAND):
        per_arg = [branches(arg, negated) for arg in node.args]
        if any(not alternatives for alternatives in per_arg):
            return []
        combined: list[list[Constraint]] = []
        for combination in product(*per_arg):
            merged: list[Constraint] = []
            for part in combination:
                merged.extend(part)
            combined.append(merged)
            if len(combined) >= MAX_BRANCHES:
                break
        return combined

    if isinstance(node, ConditionOR):
        alternatives: list[list[Constraint]] = []
        for arg in node.args:
            alternatives.extend(branches(arg, negated))
            if len(alternatives) >= MAX_BRANCHES:
                break
        return alternatives[:MAX_BRANCHES]

    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [[Constraint(field=node.field, value=node.value, negated=negated)]]

    if isinstance(node, ConditionValueExpression):
        return [
            [
                Constraint(
                    field=KEYWORD_FIELD,
                    value=node.value,
                    negated=negated,
                    keyword=True,
                )
            ]
        ]

    return []  # pragma: no cover - pySigma emits no other node types


# ----------------------------------------------------------------------------
# Value materialisation
# ----------------------------------------------------------------------------


@dataclass(slots=True)
class StringSpec:
    """Accumulated string requirements for one field."""

    exact: str | None = None
    prefix: str = ""
    suffix: str = ""
    contains: list[str] = dataclass_field(default_factory=list)

    def render(self) -> str:
        """Build one string meeting every accumulated requirement."""
        if self.exact is not None:
            return self.exact
        middle = FILLER.join(self.contains) if self.contains else FILLER
        return f"{self.prefix}{FILLER}{middle}{FILLER}{self.suffix}"


def _string_parts(value: SigmaString) -> tuple[bool, bool, list[str]]:
    r"""Split a Sigma string into (open_start, open_end, literal fragments).

    ``*admin*`` yields ``(True, True, ["admin"])``; ``*\\cmd.exe`` yields
    ``(True, False, ["\\cmd.exe"])``; ``SYSTEM`` yields
    ``(False, False, ["SYSTEM"])``.
    """
    parts = list(value.s)
    open_start = bool(parts) and parts[0] is SpecialChars.WILDCARD_MULTI
    open_end = bool(parts) and parts[-1] is SpecialChars.WILDCARD_MULTI

    fragments: list[str] = []
    current: list[str] = []
    for part in parts:
        if isinstance(part, str):
            current.append(part)
        elif part is SpecialChars.WILDCARD_SINGLE:
            current.append(FILLER[0])
        else:
            if current:
                fragments.append("".join(current))
                current = []
    if current:
        fragments.append("".join(current))
    return open_start, open_end, fragments


def _apply_string(spec: StringSpec, value: SigmaString, loose: bool = False) -> None:
    """Fold one string constraint into the accumulated spec.

    ``loose`` relaxes an unanchored value into a substring requirement, which is
    the correct reading for a Sigma keyword.
    """
    open_start, open_end, fragments = _string_parts(value)
    if not fragments:
        return

    if loose:
        spec.contains.extend(fragments)
        return

    if not open_start and not open_end:
        candidate = "".join(fragments)
        if spec.exact is not None and spec.exact != candidate:
            raise Unsatisfiable(
                f"conflicting exact values {spec.exact!r}/{candidate!r}"
            )
        spec.exact = candidate
        return

    if not open_start:
        head, *rest = fragments
        if spec.prefix and not (
            spec.prefix.startswith(head) or head.startswith(spec.prefix)
        ):
            raise Unsatisfiable(f"conflicting prefixes {spec.prefix!r}/{head!r}")
        spec.prefix = head if len(head) > len(spec.prefix) else spec.prefix
        spec.contains.extend(rest)
        return

    if not open_end:
        *rest, tail = fragments
        if spec.suffix and not (
            spec.suffix.endswith(tail) or tail.endswith(spec.suffix)
        ):
            raise Unsatisfiable(f"conflicting suffixes {spec.suffix!r}/{tail!r}")
        spec.suffix = tail if len(tail) > len(spec.suffix) else spec.suffix
        spec.contains.extend(rest)
        return

    spec.contains.extend(fragments)


def _compare_value(expression: SigmaCompareExpression) -> int | float:
    """A number satisfying a comparison operator.

    pySigma names the operator by an enum whose ``name`` is ``LT``, ``LTE``,
    ``GT`` or ``GTE``, and whose ``value`` is an integer, so the previous
    lowercase substring test against ``value`` never matched and every
    comparison silently produced a non-satisfying value. The operator name is
    used instead. ``number - 1`` satisfies ``<`` and ``<=``; ``number + 1``
    satisfies ``>`` and ``>=``.
    """
    number = expression.number.number
    name = getattr(expression.op, "name", str(expression.op)).lower()
    if "lt" in name:
        return number - 1
    if "gt" in name:
        return number + 1
    return number


def _cidr_value(expression: SigmaCIDRExpression) -> str:
    """An address inside the network."""
    network = ipaddress.ip_network(str(expression.cidr), strict=False)
    if network.num_addresses > 2:
        return str(next(network.hosts()))
    return str(network.network_address)


@lru_cache(maxsize=4096)
def _regex_value(pattern: str) -> str:
    """A string matching the regular expression.

    Two generators, because neither is sufficient alone. ``hypothesis`` handles
    lazy quantifiers and nested groups that ``exrex`` mangles, while ``exrex``
    produces more literal-looking output for simple alternations. Whatever
    comes out is verified against the pattern before being used, so a generator
    that quietly returns a non-match cannot corrupt the analysis.
    """
    compiled = re.compile(pattern)

    try:
        from hypothesis import HealthCheck, find, settings
        from hypothesis import strategies as st

        candidate = find(
            st.from_regex(compiled),
            lambda value: bool(compiled.search(value)),
            settings=settings(max_examples=60, suppress_health_check=list(HealthCheck)),
        )
        if compiled.search(candidate):
            return candidate
    except Exception:
        pass

    try:
        import exrex  # type: ignore[import-untyped]

        for _ in range(5):
            candidate = str(exrex.getone(pattern, limit=4))
            if compiled.search(candidate):
                return candidate
    except Exception:
        pass

    raise Unsatisfiable(f"could not generate a string matching {pattern!r}")


def _regex_is_anchored(pattern: str) -> bool:
    """Whether the pattern pins both ends, making its match the whole value."""
    return pattern.startswith("^") and pattern.endswith("$")


def split_condition(node: Any) -> tuple[Any | None, list[Any]]:
    """Separate the positive part of a condition from its negated subtrees."""
    from .negation import split

    return split(node)


def materialise(
    constraints: list[Constraint], allow_empty: bool = False
) -> dict[str, Any]:
    """Build one event satisfying every positive constraint.

    Raises :class:`Unsatisfiable` when the constraints conflict, or when they
    use a construct with no single satisfying value.
    """
    strings: dict[str, StringSpec] = {}
    event: dict[str, Any] = {}
    absent: set[str] = set()
    references: list[tuple[str, str]] = []

    for constraint in constraints:
        if constraint.negated:
            continue
        field, value = constraint.field, constraint.value

        if isinstance(value, SigmaExpansion):
            value = value.values[0]

        if isinstance(value, (SigmaString, SigmaCasedString)):
            _apply_string(
                strings.setdefault(field, StringSpec()), value, loose=constraint.keyword
            )
        elif isinstance(value, SigmaNumber):
            event[field] = value.number
        elif isinstance(value, SigmaBool):
            event[field] = bool(value.boolean)
        elif isinstance(value, SigmaNull):
            absent.add(field)
        elif isinstance(value, SigmaExists):
            if value.exists:
                strings.setdefault(field, StringSpec())
            else:
                absent.add(field)
        elif isinstance(value, SigmaCompareExpression):
            event[field] = _compare_value(value)
        elif isinstance(value, SigmaCIDRExpression):
            event[field] = _cidr_value(value)
        elif isinstance(value, SigmaRegularExpression):
            pattern = str(value.regexp)
            generated = _regex_value(pattern)
            spec = strings.setdefault(field, StringSpec())
            # An anchored pattern owns the whole value; an unanchored one only
            # has to appear somewhere, so it composes with contains and
            # endswith constraints on the same field. Sigma rules routinely put
            # four such constraints on CommandLine at once.
            if _regex_is_anchored(pattern):
                if spec.exact is not None and spec.exact != generated:
                    raise Unsatisfiable(
                        f"regex conflicts with an exact value on {field!r}"
                    )
                spec.exact = generated
            else:
                spec.contains.append(generated)
        elif isinstance(value, SigmaFieldReference):
            references.append((field, value.field))
        else:  # pragma: no cover - defensive
            raise Unsatisfiable(f"unsupported value type {type(value).__name__}")

    for field, spec in strings.items():
        if field in event:
            raise Unsatisfiable(f"field {field!r} needs both a scalar and a string")
        event[field] = spec.render()

    for field, target in references:
        event[field] = event.get(target, FILLER)
        event.setdefault(target, event[field])

    for field in absent:
        event.pop(field, None)

    if not event:
        if not allow_empty:
            raise Unsatisfiable("no positive constraint to build an event from")
        # A negation-only rule fires on anything the filters miss, so an inert
        # event is a legitimate witness.
        event = {"_raw": FILLER}
    return event


# ----------------------------------------------------------------------------
# Local matching, used only to reject events that violate a negation
# ----------------------------------------------------------------------------


def satisfies(event: dict[str, Any], constraint: Constraint) -> bool:
    """Whether the event meets one constraint, ignoring its negation flag.

    This is a deliberately partial implementation: it exists to reject events
    that would trip a rule's own filters, not to replace the engine. Anything
    it cannot judge is reported as not satisfied, which errs towards keeping
    the event and letting the engine have the final say.
    """
    value = constraint.value
    if isinstance(value, SigmaExpansion):
        return any(
            satisfies(event, Constraint(constraint.field, item))
            for item in value.values
        )

    if isinstance(value, SigmaExists):
        return (constraint.field in event) is bool(value.exists)
    if isinstance(value, SigmaNull):
        return event.get(constraint.field) is None

    if constraint.field not in event:
        return False
    actual = event[constraint.field]

    if isinstance(value, (SigmaString, SigmaCasedString)):
        if not isinstance(actual, str):
            actual = str(actual)
        cased = isinstance(value, SigmaCasedString)
        haystack = actual if cased else actual.lower()
        open_start, open_end, fragments = _string_parts(value)
        needle = "".join(fragments) if not (open_start or open_end) else None
        if needle is not None:
            return haystack == (needle if cased else needle.lower())
        position = 0
        for index, fragment in enumerate(fragments):
            piece = fragment if cased else fragment.lower()
            if index == 0 and not open_start:
                if not haystack.startswith(piece):
                    return False
                position = len(piece)
                continue
            found = haystack.find(piece, position)
            if found < 0:
                return False
            position = found + len(piece)
        if not open_end and fragments:
            tail = fragments[-1] if cased else fragments[-1].lower()
            return haystack.endswith(tail)
        return True

    if isinstance(value, SigmaNumber):
        try:
            return float(actual) == float(value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(value, SigmaBool):
        return bool(actual) is bool(value.boolean)
    if isinstance(value, SigmaRegularExpression):
        return bool(re.search(str(value.regexp), str(actual)))
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
                str(value.cidr), strict=False
            )
        except ValueError:
            return False
    return False


def synthesise(rule: SigmaRule, limit: int = 4) -> list[dict[str, Any]]:
    """Build up to ``limit`` distinct events satisfying the rule.

    The positive part of the condition drives construction; negated subtrees
    are checked afterwards and repaired where a known pattern allows it. A
    branch that still trips a filter is dropped rather than emitted, because a
    wrong event would quietly weaken every conclusion drawn from it.

    An empty result means the analysis has no evidence for this rule. The
    caller reports that rather than papering over it.
    """
    from .negation import repair as repair_negations

    condition = rule.detection.parsed_condition[0].parse()
    positive, negatives = split_condition(condition)

    if positive is None:
        # Nothing but negations: any event outside the filters fires the rule.
        candidates: list[list[Constraint]] = [[]]
    else:
        candidates = branches(positive)

    events: list[dict[str, Any]] = []
    seen: set[str] = set()

    for alternative in candidates:
        try:
            event = materialise(alternative, allow_empty=positive is None)
        except Unsatisfiable:
            continue
        except Exception:
            continue

        # A negation nested inside an OR survives branch expansion rather than
        # being lifted out by split_condition, so it is verified here.
        if any(
            constraint.negated and satisfies(event, constraint)
            for constraint in alternative
        ):
            continue

        protected = {constraint.field for constraint in alternative}
        if negatives and not repair_negations(event, negatives, protected, satisfies):
            continue

        key = repr(sorted(event.items()))
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
        if len(events) >= limit:
            break
    return events
