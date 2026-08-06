"""Behavioural overlap analysis between converted rules and SigmaHQ.

The question is which converted Sagan rules add nothing on top of SigmaHQ, and
the answer has to be earned rather than guessed. Two rules with similar titles
may fire on disjoint events; two rules with nothing in common textually may be
exact duplicates. Only running them decides.

The method
----------

Every rule, from both corpora, is turned into events that satisfy it. Those
events are then evaluated by the real RSigma engine against **both rule sets at
once**, in a single pass. That one pass yields, for every event, the complete
set of rules it fires, which is all the analysis needs:

* an event built from Sagan rule *A* that also fires SigmaHQ rule *B* proves
  the two can fire together;
* if **every** event built from *A* fires *B*, then within the evidence
  available *B* covers *A*, and deploying *B* makes *A* redundant;
* running the same test in reverse separates equivalence from containment.

The taxonomy
------------

``EQUIVALENT``
    each rule fires on all of the other's events. Deploying either covers both.
``SAGAN_REDUNDANT``
    every event from the Sagan rule also fires the SigmaHQ rule, but not the
    reverse. SigmaHQ is broader; the converted rule adds nothing.
``SAGAN_BROADER``
    the converse. The converted rule catches everything the SigmaHQ rule does,
    and more.
``OVERLAP``
    they fire together on at least one event, but neither contains the other.
``DISJOINT``
    no event fires both. Not reported, since it is the default state of any two
    unrelated rules.

What a verdict is worth
-----------------------

A verdict is a statement about the events this tool could build, not a proof
over all possible events. Two guards keep it honest. First, no rule enters the
analysis until the engine has confirmed at least one synthesised event actually
fires it, so a rule whose events were wrong is excluded rather than compared.
Second, every reported verdict carries the number of events behind it and a
witness event, so a conclusion resting on a single event is visible as such.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from sigma.rule import SigmaRule

from .cache import SynthesisCache
from .engine import RsigmaBatch, compilable
from .synth import synthesise

#: Events synthesised per rule. More events make containment claims stronger
#: and cost one engine evaluation each.
DEFAULT_EVENTS_PER_RULE = 4


class Relation(str, Enum):
    """How two rules relate behaviourally."""

    EQUIVALENT = "EQUIVALENT"
    SAGAN_REDUNDANT = "SAGAN_REDUNDANT"
    SAGAN_BROADER = "SAGAN_BROADER"
    OVERLAP = "OVERLAP"


RELATION_HELP: dict[Relation, str] = {
    Relation.EQUIVALENT: (
        "Each rule fires on every event built from the other. Deploying either "
        "one covers both, so the converted rule can be dropped."
    ),
    Relation.SAGAN_REDUNDANT: (
        "Every event built from the converted rule also fires the SigmaHQ rule, "
        "but not the reverse. SigmaHQ is broader and the converted rule adds "
        "nothing on the evidence available."
    ),
    Relation.SAGAN_BROADER: (
        "Every event built from the SigmaHQ rule also fires the converted rule, "
        "but not the reverse. Keeping the converted rule widens coverage."
    ),
    Relation.OVERLAP: (
        "The two fire together on at least one event, but neither covers the "
        "other. They are related, not interchangeable."
    ),
}


@dataclass(slots=True)
class RuleRecord:
    """One rule, its origin, and the events the engine confirmed for it."""

    key: str
    origin: str
    title: str
    document: dict[str, Any]
    events: list[dict[str, Any]] = field(default_factory=list)
    confirmed: list[int] = field(default_factory=list)
    source_file: str = ""
    sagan_sid: str = ""

    @property
    def usable(self) -> bool:
        """Whether the engine confirmed at least one event fires this rule."""
        return bool(self.confirmed)


@dataclass(slots=True)
class Verdict:
    """A tested relationship between one converted rule and one SigmaHQ rule."""

    sagan_key: str
    sagan_sid: str
    sagan_title: str
    sagan_source_file: str
    sigmahq_key: str
    sigmahq_title: str
    sigmahq_path: str
    relation: Relation
    sagan_events: int
    sagan_events_firing_sigmahq: int
    sigmahq_events: int
    sigmahq_events_firing_sagan: int
    witness: dict[str, Any]
    #: Whether the two rules declare compatible log sources. The engine does not
    #: enforce logsource, so a SigmaHQ keyword rule scoped to `cisco/aaa` will
    #: co-fire with any converted rule whose raw body contains one of its
    #: keywords, across every product. Such a co-firing is real but is not
    #: deployable coverage: in production the SigmaHQ rule runs only on its own
    #: log source. A covering verdict is only actionable when this is true.
    logsource_compatible: bool = True
    #: How many converted rules this SigmaHQ rule covers, a breadth signal.
    sigmahq_coverage_breadth: int = 0


@dataclass(slots=True)
class AnalysisResult:
    """Everything the run established, including what it could not."""

    verdicts: list[Verdict] = field(default_factory=list)
    sagan_total: int = 0
    sigmahq_total: int = 0
    sagan_usable: int = 0
    sigmahq_usable: int = 0
    sagan_unsynthesisable: list[str] = field(default_factory=list)
    sigmahq_unsynthesisable: list[str] = field(default_factory=list)
    #: Rules the engine itself refuses to compile. One of these aborts a whole
    #: rule load, so they are removed before anything else and reported.
    sagan_uncompilable: list[str] = field(default_factory=list)
    sigmahq_uncompilable: list[str] = field(default_factory=list)
    #: Rules that fire on the empty event, so they match on absence rather than
    #: on any field an event carries. They co-fire with almost anything, which
    #: would make every containment verdict resting on them spurious, so they
    #: take no part in the comparison. See the negative-control screen in
    #: :func:`analyse`.
    sagan_blanket: list[str] = field(default_factory=list)
    sigmahq_blanket: list[str] = field(default_factory=list)
    events_evaluated: int = 0

    @property
    def redundant_sagan_keys(self) -> set[str]:
        """Converted rules a SigmaHQ rule fully covers and could be deployed for.

        Restricted to log-source-compatible verdicts, since a co-firing across
        incompatible log sources is not coverage a SOC can act on.
        """
        return {
            verdict.sagan_key
            for verdict in self.verdicts
            if verdict.relation in (Relation.EQUIVALENT, Relation.SAGAN_REDUNDANT)
            and verdict.logsource_compatible
        }

    @property
    def cross_logsource_covered(self) -> int:
        """Covering co-firings rejected only because the log sources differ."""
        return sum(
            1
            for verdict in self.verdicts
            if verdict.relation in (Relation.EQUIVALENT, Relation.SAGAN_REDUNDANT)
            and not verdict.logsource_compatible
        )


def load_sigmahq(
    root: Path, skip_dirs: frozenset[str] = frozenset()
) -> list[RuleRecord]:
    """Load every SigmaHQ rule that pySigma accepts.

    ``skip_dirs`` names top-level directories to ignore. The default caller
    passes ``rules-placeholder``, whose rules carry unresolved ``%placeholder%``
    values that no synthesised event can satisfy, so including them would only
    inflate the unsynthesisable count.
    """
    import yaml

    records: list[RuleRecord] = []
    for path in sorted(root.rglob("*.yml")):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in skip_dirs:
            continue
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(document, dict) or "detection" not in document:
            continue
        identifier = str(document.get("id") or path.stem)
        records.append(
            RuleRecord(
                key=f"sigmahq:{identifier}",
                origin="sigmahq",
                title=str(document.get("title", path.stem)),
                document=document,
                source_file=str(path.relative_to(root)),
            )
        )
    return records


def load_converted(root: Path) -> list[RuleRecord]:
    """Load converted rules, skipping correlations which need event sequences."""
    import yaml

    records: list[RuleRecord] = []
    for path in sorted(root.glob("*.yml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not isinstance(document, dict) or "detection" not in document:
                continue
            attributes = document.get("custom_attributes") or {}
            records.append(
                RuleRecord(
                    key=f"sagan:{document['id']}",
                    origin="sagan",
                    title=str(document.get("title", "")),
                    document=document,
                    source_file=str(attributes.get("sagan.source_file", path.name)),
                    sagan_sid=str(attributes.get("sagan.sid", "")),
                )
            )
    return records


def _parse(document: dict[str, Any]) -> SigmaRule | None:
    try:
        return SigmaRule.from_dict(document)
    except Exception:
        return None


def analyse(
    sagan_rules: list[RuleRecord],
    sigmahq_rules: list[RuleRecord],
    workdir: Path,
    engine: str | None = None,
    events_per_rule: int = DEFAULT_EVENTS_PER_RULE,
    progress: Any = None,
    cache: SynthesisCache | None = None,
) -> AnalysisResult:
    """Run the full behavioural comparison."""
    result = AnalysisResult(
        sagan_total=len(sagan_rules), sigmahq_total=len(sigmahq_rules)
    )

    # A rule the engine cannot compile aborts the entire load, so both corpora
    # are screened first. Bisection makes this cheap relative to the analysis.
    sagan_rules, dropped_sagan = _screen(sagan_rules, workdir, engine)
    sigmahq_rules, dropped_sigmahq = _screen(sigmahq_rules, workdir, engine)
    result.sagan_uncompilable = [record.key for record in dropped_sagan]
    result.sigmahq_uncompilable = [record.key for record in dropped_sigmahq]

    records = sagan_rules + sigmahq_rules

    # --- synthesis ---------------------------------------------------------
    events: list[dict[str, Any]] = []
    owners: list[str] = []
    by_key: dict[str, RuleRecord] = {}

    for record in records:
        by_key[record.key] = record
        # Synthesis is deterministic, so a cached result is used verbatim; the
        # events are still confirmed by the engine below, so the cache can only
        # save work, never introduce an unverified event.
        built = cache.load(record, events_per_rule) if cache else None
        if built is None:
            parsed = _parse(record.document)
            if parsed is None:
                _note_unsynthesisable(result, record)
                continue
            try:
                built = synthesise(parsed, limit=events_per_rule)
            except Exception:
                built = []
            if cache is not None:
                cache.store(record, events_per_rule, built)
        if not built:
            _note_unsynthesisable(result, record)
            continue
        record.events = built
        for event in built:
            events.append(event)
            owners.append(record.key)
        if progress is not None:
            progress("synth", len(events))

    # --- one engine pass over every event against every rule ---------------
    batch = RsigmaBatch(
        (record.document for record in records), engine=engine, workdir=workdir
    )
    matches = batch.evaluate(events)
    result.events_evaluated = len(events)

    per_event: dict[str, list[set[str]]] = defaultdict(list)
    for event_index, (owner, matched) in enumerate(zip(owners, matches, strict=True)):
        # The engine reports bare rule ids; map them back to corpus-qualified
        # keys. An event is only kept when the engine confirms it fires the
        # rule it was built from, so a bad synthesis never becomes evidence.
        resolved = _resolve(matched, by_key)
        if owner in resolved:
            by_key[owner].confirmed.append(event_index)
            per_event[owner].append(resolved)

    result.sagan_usable = sum(1 for r in sagan_rules if r.usable)
    result.sigmahq_usable = sum(1 for r in sigmahq_rules if r.usable)

    # --- negative control --------------------------------------------------
    # A rule that fires on the empty event matches on absence: a pure negation
    # such as `not selection`, or `field|exists: false`. It co-fires with almost
    # any event regardless of content, so treating that co-firing as shared
    # detection would report it as covering, or covered by, thousands of
    # unrelated rules. The empty event is the control: any rule it fires is
    # excluded from containment and reported separately, rather than being
    # allowed to manufacture verdicts. This also removes the only rules that
    # would otherwise contaminate the sentinel segments, since they are exactly
    # the rules that fire on the near-empty sentinel events.
    empty_event: dict[str, Any] = {}
    blanket = _resolve(batch.evaluate([empty_event])[0], by_key)
    result.sagan_blanket = sorted(k for k in blanket if k in by_key and _is_sagan(k))
    result.sigmahq_blanket = sorted(
        k for k in blanket if k in by_key and not _is_sagan(k)
    )

    # --- containment -------------------------------------------------------
    sigmahq_keys = {r.key for r in sigmahq_rules if r.usable} - blanket
    sagan_keys = {r.key for r in sagan_rules if r.usable} - blanket
    breadth: dict[str, int] = defaultdict(int)
    verdicts: list[Verdict] = []

    # A converted rule broader than a SigmaHQ rule never fires that rule from its
    # own events, so scanning only what a converted rule's events hit would miss
    # every SAGAN_BROADER verdict, and every overlap visible only from the
    # SigmaHQ side. This reverse index records, for each converted rule, the
    # SigmaHQ rules whose own events fire it, so both directions are considered.
    reverse: dict[str, set[str]] = defaultdict(set)
    for sig_key in sigmahq_keys:
        sig_sets = per_event.get(sig_key)
        if not sig_sets:
            continue
        for converted_key in set.union(*sig_sets) & sagan_keys:
            reverse[converted_key].add(sig_key)

    for sagan in sagan_rules:
        if sagan.key in blanket:
            continue
        sets = per_event.get(sagan.key)
        if not sets:
            continue
        always = set.intersection(*sets) & sigmahq_keys
        ever = (set.union(*sets) & sigmahq_keys) | reverse.get(sagan.key, set())

        for candidate in sorted(ever):
            other = by_key[candidate]
            other_sets = per_event.get(other.key) or []
            reverse_always = bool(other_sets) and all(
                sagan.key in matched for matched in other_sets
            )
            forward = candidate in always

            if forward and reverse_always:
                relation = Relation.EQUIVALENT
            elif forward:
                relation = Relation.SAGAN_REDUNDANT
            elif reverse_always:
                relation = Relation.SAGAN_BROADER
            else:
                relation = Relation.OVERLAP

            witness_index = _witness_index(sagan, sets, other, other_sets, candidate)
            if forward or relation is Relation.EQUIVALENT:
                breadth[candidate] += 1

            verdicts.append(
                Verdict(
                    sagan_key=sagan.key,
                    sagan_sid=sagan.sagan_sid,
                    sagan_title=sagan.title,
                    sagan_source_file=sagan.source_file,
                    sigmahq_key=candidate,
                    sigmahq_title=other.title,
                    sigmahq_path=other.source_file,
                    relation=relation,
                    sagan_events=len(sets),
                    sagan_events_firing_sigmahq=sum(
                        1 for matched in sets if candidate in matched
                    ),
                    sigmahq_events=len(other_sets),
                    sigmahq_events_firing_sagan=sum(
                        1 for matched in other_sets if sagan.key in matched
                    ),
                    witness=events[witness_index],
                    logsource_compatible=_logsource_compatible(
                        sagan.document, other.document
                    ),
                )
            )

    for verdict in verdicts:
        verdict.sigmahq_coverage_breadth = breadth.get(verdict.sigmahq_key, 0)

    result.verdicts = sorted(
        verdicts,
        key=lambda v: (v.relation.value, -v.sagan_events_firing_sigmahq, v.sagan_sid),
    )
    return result


def _screen(
    records: list[RuleRecord], workdir: Path, engine: str | None
) -> tuple[list[RuleRecord], list[RuleRecord]]:
    """Drop rules the engine refuses to compile, returning both halves."""
    if not records:
        return [], []
    by_identity = {id(record.document): record for record in records}
    good, bad = compilable(
        [record.document for record in records], engine=engine, workdir=workdir
    )
    return (
        [by_identity[id(document)] for document in good],
        [by_identity[id(document)] for document in bad],
    )


def _is_sagan(key: str) -> bool:
    """Whether a corpus-qualified key belongs to the converted corpus."""
    return key.startswith("sagan:")


def _logsource_compatible(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Whether two rules would run on the same log stream.

    They must positively agree on at least one of ``product``, ``category`` or
    ``service`` and disagree on none they both specify. Requiring a shared
    dimension, rather than merely the absence of conflict, is what keeps an
    unbound SigmaHQ keyword rule scoped to ``category: database`` from being
    counted as covering a ``product: sonicwall`` rule whose raw body merely
    contains the word "dump": with no dimension in common, they would not run
    on the same logs, so the keyword co-firing is not deployable coverage.
    Converted rules always carry a product, so in practice this means a covering
    SigmaHQ rule must target the same product.
    """
    left = a.get("logsource") or {}
    right = b.get("logsource") or {}
    shared = False
    for dimension in ("product", "category", "service"):
        value_a = left.get(dimension)
        value_b = right.get(dimension)
        if value_a and value_b:
            if value_a != value_b:
                return False
            shared = True
    return shared


def _witness_index(
    sagan: RuleRecord,
    sagan_sets: list[set[str]],
    sigmahq: RuleRecord,
    sigmahq_sets: list[set[str]],
    candidate: str,
) -> int:
    """Pick an event that fires both rules, to stand as the verdict's witness.

    A converted-rule event that also fired the candidate is preferred; failing
    that, a candidate event that fired the converted rule, which is the witness
    for a SAGAN_BROADER verdict where the converted rule's own events never
    reach the narrower SigmaHQ rule. The final fallback cannot be hit for a
    recorded verdict, since a verdict exists only when some event links the two.
    """
    for position, matched in enumerate(sagan_sets):
        if candidate in matched:
            return sagan.confirmed[position]
    for position, matched in enumerate(sigmahq_sets):
        if sagan.key in matched:
            return sigmahq.confirmed[position]
    return sagan.confirmed[0]


def _resolve(matched: set[str], by_key: dict[str, RuleRecord]) -> set[str]:
    """Map raw engine rule ids onto corpus-qualified keys.

    A rule id can legitimately appear in both corpora, so both candidates are
    kept and the caller intersects with the corpus it cares about.
    """
    resolved: set[str] = set()
    for rule_id in matched:
        for prefix in ("sagan", "sigmahq"):
            key = f"{prefix}:{rule_id}"
            if key in by_key:
                resolved.add(key)
    return resolved


def _note_unsynthesisable(result: AnalysisResult, record: RuleRecord) -> None:
    target = (
        result.sagan_unsynthesisable
        if record.origin == "sagan"
        else result.sigmahq_unsynthesisable
    )
    target.append(record.key)
