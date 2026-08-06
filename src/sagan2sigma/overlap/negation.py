"""Negation handling for event synthesis.

Modern SigmaHQ rules are mostly ``selection and not 1 of filter_*``, often with
eight or more filters. Expanding that with De Morgan multiplies out into
hundreds of branches, most of them unsatisfiable, and the enumeration cap then
throws away the branch that would have worked. Roughly a third of the rules the
first version of the synthesiser could not satisfy failed for exactly that
reason.

So negations are not enumerated. The positive part of the condition drives
event construction, and the negated subtree is evaluated against the finished
event. When it trips, a small set of targeted repairs is attempted, each aimed
at a pattern that actually occurs in the corpus:

``field: null`` and ``field|exists: false``
    the filter fires precisely because the event omits the field, so adding it
    with an inert value disarms it. This is the single most common case:
    ``filter_main_null`` appears in hundreds of rules.
equality on an otherwise unconstrained field
    the event happens to carry a value the filter names, and nothing positive
    depends on that field, so the value can be changed.

A repair is only kept when it does not break a positive constraint, and the
branch is dropped when no repair works. Dropping costs a little coverage;
guessing would cost correctness.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.types import SigmaExists, SigmaNull

#: Signature of the local matcher: does this event meet this constraint?
Matcher = Callable[[dict[str, Any], Any], bool]

#: Inert values used to give an absent field a presence. They differ per field
#: because several rules filter on two fields being equal, and repairing both
#: to one value would satisfy exactly the filter being disarmed.
REPAIR_PREFIX = "zq-repair-"


def repair_value(field: str) -> str:
    """An inert value unique to the field, so equality filters stay unmet."""
    return f"{REPAIR_PREFIX}{abs(hash(field)) % 100000:05d}"


@dataclass(frozen=True, slots=True)
class Leaf:
    """One field constraint appearing inside a negated subtree."""

    field: str
    value: Any
    keyword: bool = False


def split(node: Any) -> tuple[Any | None, list[Any]]:
    """Separate a condition into its positive part and its negated subtrees.

    Returns ``(positive, negatives)``. ``positive`` is ``None`` when the rule
    is nothing but negations, which is rare but real: a Zeek rule reading
    ``condition: not selection`` fires on every event outside a CIDR list.
    """
    negatives: list[Any] = []

    def walk(current: Any) -> Any | None:
        if isinstance(current, ConditionNOT):
            negatives.append(current.args[0])
            return None
        if isinstance(current, ConditionAND):
            kept = [walk(arg) for arg in current.args]
            kept = [item for item in kept if item is not None]
            if not kept:
                return None
            return kept[0] if len(kept) == 1 else ConditionAND(kept)
        return current

    return walk(node), negatives


def leaves(node: Any) -> list[Leaf]:
    """Every field constraint inside a subtree, ignoring its boolean shape."""
    found: list[Leaf] = []

    def walk(current: Any) -> None:
        if isinstance(current, (ConditionAND, ConditionOR, ConditionNOT)):
            for arg in current.args:
                walk(arg)
        elif isinstance(current, ConditionFieldEqualsValueExpression):
            found.append(Leaf(field=current.field, value=current.value))
        elif isinstance(current, ConditionValueExpression):
            found.append(Leaf(field="_raw", value=current.value, keyword=True))

    walk(node)
    return found


def evaluate(node: Any, event: dict[str, Any], matcher: Matcher) -> bool:
    """Whether a subtree matches the event, using the local matcher."""
    from .synth import Constraint

    if isinstance(node, ConditionAND):
        return all(evaluate(arg, event, matcher) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(evaluate(arg, event, matcher) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not evaluate(node.args[0], event, matcher)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return matcher(event, Constraint(field=node.field, value=node.value))
    if isinstance(node, ConditionValueExpression):
        return matcher(event, Constraint(field="_raw", value=node.value, keyword=True))
    return False  # pragma: no cover - defensive


def repair(
    event: dict[str, Any],
    negatives: list[Any],
    protected: set[str],
    matcher: Matcher,
) -> bool:
    """Try to stop every negated subtree from matching.

    ``protected`` names fields a positive constraint depends on, which must not
    be touched. Returns whether the event ends up clear of every negation.
    """
    for _attempt in range(4):
        offending = [node for node in negatives if evaluate(node, event, matcher)]
        if not offending:
            return True

        progressed = False
        for node in offending:
            for leaf in leaves(node):
                if leaf.field in protected:
                    continue
                if isinstance(leaf.value, SigmaNull) or (
                    isinstance(leaf.value, SigmaExists) and not leaf.value.exists
                ):
                    # The filter fires because the field is missing. Give it one.
                    replacement = repair_value(leaf.field)
                    if event.get(leaf.field) != replacement:
                        event[leaf.field] = replacement
                        progressed = True
                elif leaf.field in event:
                    # Nothing positive needs this field, so its value can move.
                    replacement = repair_value(leaf.field)
                    if event[leaf.field] != replacement:
                        event[leaf.field] = replacement
                        progressed = True
        if not progressed:
            return False
    return not any(evaluate(node, event, matcher) for node in negatives)
