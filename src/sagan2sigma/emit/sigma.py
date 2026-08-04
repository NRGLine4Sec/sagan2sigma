"""Building Sigma documents from the intermediate representation.

Formatting decisions and their rationale.

**One block per predicate.** Merging several predicates into a single
``selection`` breaks as soon as two of them target the same key: a YAML mapping
cannot carry ``_raw|contains`` twice. Emitting one named block per predicate
makes the condition explicit and removes any possibility of collision.

**Grouped negations.** Sagan applies its ``content:!"x"`` conjunctively: the
rule fires when no negative pattern is present. The emitted expression is
therefore ``... and not (filter_1 or filter_2)``.

**Correlated base rules never alert alone.** A Sagan rule carrying ``after``
only alerts once N events occurred. The Sigma base rule must therefore stay
silent: it is given a ``name:``, referenced by the correlation, and the
correlation's ``generate`` flag is left at its default of false, which makes
RSigma suppress the base rule's own detection output.
"""

from __future__ import annotations

import uuid
from collections.abc import Container
from typing import Any

from ..errors import Degradation, DegradationCode
from ..mapping.context import LogSourceEntry
from ..mapping.ir import CorrelationSpec, Predicate, RuleDraft

#: Namespace for generated identifiers. Frozen: it guarantees that a given SID
#: always yields the same UUID, so two consecutive runs produce a reviewable
#: diff instead of a wall of changes.
UUID_NAMESPACE = uuid.UUID("6f0a4f3e-4a2b-5c3d-9e1f-2b7c8d9e0a1b")

#: Default false-positive statement. Claiming there are none would be worse
#: than admitting the rule has not been triaged.
DEFAULT_FALSEPOSITIVES = ["Unassessed: automatically converted, not yet tuned"]

#: Logsource applied to synthetic aggregate rules, which span source files.
AGGREGATE_LOGSOURCE = {"product": "syslog"}


def stable_uuid(*parts: str) -> str:
    """Deterministic UUID derived from the SID, stable across runs.

    >>> stable_uuid('rule', '5000116') == stable_uuid('rule', '5000116')
    True
    >>> stable_uuid('rule', '5000116') == stable_uuid('rule', '5000117')
    False
    """
    return str(uuid.uuid5(UUID_NAMESPACE, "|".join(parts)))


def rule_name(sid: str, namespace: str = "sagan") -> str:
    """Sigma reference name of a rule, used by correlations.

    >>> rule_name('5000116')
    'sagan_5000116'
    """
    return f"{namespace}_{sid}"


def slug(value: str) -> str:
    """Normalise a bit name into a safe Sigma identifier.

    Hyphens and underscores are preserved rather than folded together. The
    upstream corpus carries both ``brute_force`` and ``brute-force`` as
    distinct xbits that never correlate with each other, so collapsing them
    would silently merge two unrelated state machines.

    >>> slug('system.reboot')
    'system_reboot'
    >>> slug('Brute-Force!')
    'brute-force_'
    >>> slug('brute_force') != slug('brute-force')
    True
    """
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in value).lower()


def build_detection(
    predicates: list[Predicate], prefix: str = ""
) -> tuple[dict[str, Any], str]:
    """Build the detection blocks and the condition expression.

    Returns ``(blocks, condition)``; the caller assembles the ``condition:``
    key itself.
    """
    blocks: dict[str, Any] = {}
    positive: list[str] = []
    negative: list[str] = []

    for index, predicate in enumerate(predicates, start=1):
        bucket = "filter" if predicate.negated else "selection"
        name = f"{prefix}{bucket}_{index}"
        blocks[name] = {predicate.key: predicate.rendered_value}
        (negative if predicate.negated else positive).append(name)

    if not positive:
        raise ValueError("no positive predicate: a Sigma condition is impossible")

    condition = " and ".join(positive)
    if negative:
        joined = " or ".join(negative)
        condition += (
            f" and not ({joined})" if len(negative) > 1 else f" and not {joined}"
        )
    return blocks, condition


def build_rule_document(
    draft: RuleDraft,
    sid: str,
    rev: str,
    source_file: str,
    logsource: LogSourceEntry,
    needs_name: bool,
) -> dict[str, Any]:
    """Assemble the Sigma detection document for one rule."""
    blocks, condition = build_detection(draft.predicates)

    document: dict[str, Any] = {
        "title": draft.title,
        "id": stable_uuid("rule", sid),
    }
    if needs_name:
        document["name"] = rule_name(sid)

    document["status"] = "experimental"
    document["description"] = (
        f"Converted from Sagan rule SID {sid} (rev {rev}), file {source_file}."
    )
    if draft.references:
        document["references"] = list(dict.fromkeys(draft.references))
    document["author"] = "sagan2sigma"
    document["logsource"] = dict(logsource.logsource)
    document["detection"] = {**blocks, "condition": condition}
    document["falsepositives"] = list(DEFAULT_FALSEPOSITIVES)
    document["level"] = draft.level
    if draft.tags:
        document["tags"] = sorted(draft.tags)

    document["custom_attributes"] = {
        "sagan.sid": sid,
        "sagan.rev": rev,
        "sagan.source_file": source_file,
        **draft.custom_attributes,
    }
    return document


def build_correlation_document(
    spec: CorrelationSpec,
    draft: RuleDraft,
    correlation_id: str,
    base_name: str,
) -> dict[str, Any]:
    """Assemble the Sigma correlation document attached to a rule."""
    title = draft.title
    if spec.title_suffix:
        title = f"{title} ({spec.title_suffix})"

    correlation: dict[str, Any] = {
        "type": spec.correlation_type,
        "rules": list(spec.referenced_rules or (base_name,)),
        "group-by": list(spec.group_by),
        "timespan": spec.timespan,
    }
    if spec.condition is not None:
        correlation["condition"] = dict(spec.condition)

    document: dict[str, Any] = {
        "title": title[:256],
        "id": stable_uuid("correlation", spec.correlation_type, correlation_id),
        "status": "experimental",
    }
    if spec.description:
        document["description"] = spec.description
    document["correlation"] = correlation
    document["level"] = draft.level
    return document


def aggregate_name(bit: str, taken: Container[str] = ()) -> str:
    """Reference name of a bit aggregate rule, guaranteed not to collide.

    Bit names come from an external corpus, so two different bits can normalise
    onto the same identifier. When that happens a short deterministic suffix
    derived from the original name is appended, which keeps the name stable
    across runs while restoring uniqueness.
    """
    candidate = f"sagan_xbit_{slug(bit)}"
    if candidate not in taken:
        return candidate
    return f"{candidate}_{stable_uuid('xbit-name', bit)[:8]}"


def build_xbit_aggregate(
    bit: str,
    setters: list[tuple[str, RuleDraft]],
    max_branches: int,
    taken_names: Container[str] = (),
) -> tuple[dict[str, Any], Degradation | None]:
    """Aggregate rule standing for "any setter of this bit fired".

    Sigma cannot express an OR between the rules a correlation references:
    ``rules: [a, b]`` in a ``temporal_ordered`` demands that **both** occur. A
    single rule is therefore built whose detection is the disjunction of every
    setter rule's detection, each branch keeping its own negations.
    """
    blocks: dict[str, Any] = {}
    branches: list[str] = []

    ordered = sorted(setters, key=lambda item: item[0])
    truncated = len(ordered) > max_branches
    if truncated:
        ordered = ordered[:max_branches]

    for position, (_, draft) in enumerate(ordered, start=1):
        branch_blocks, branch_condition = build_detection(
            draft.predicates, prefix=f"s{position}_"
        )
        blocks.update(branch_blocks)
        branches.append(f"({branch_condition})")

    if not branches:
        raise ValueError(f"no usable setter for bit {bit!r}")

    document: dict[str, Any] = {
        "title": f"Aggregate of rules setting Sagan bit {bit}",
        "id": stable_uuid("xbit-aggregate", bit),
        "name": aggregate_name(bit, taken_names),
        "status": "experimental",
        "description": (
            f"Synthetic rule. Sagan set the '{bit}' bit from {len(setters)} "
            f"rule(s); since Sigma cannot express an OR between correlated "
            f"rules, their detections are gathered here. This rule is not "
            f"meant to alert on its own."
        ),
        "author": "sagan2sigma",
        "logsource": dict(AGGREGATE_LOGSOURCE),
        "detection": {**blocks, "condition": " or ".join(branches)},
        "falsepositives": list(DEFAULT_FALSEPOSITIVES),
        "level": "informational",
        "custom_attributes": {
            "sagan.xbit": bit,
            "sagan.xbit_setters": str(len(setters)),
        },
    }

    degradation = None
    if truncated:
        degradation = Degradation(
            code=DegradationCode.XBIT_AGGREGATE_TRUNCATED,
            detail=(
                f"bit '{bit}' is set by {len(setters)} rules; the aggregate was "
                f"truncated to {max_branches} branches"
            ),
        )
    return document, degradation
