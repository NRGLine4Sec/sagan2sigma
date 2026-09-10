"""Conversion orchestration, in two passes.

The first pass converts each rule in isolation and records which
``xbits``/``flexbits`` it sets or tests. The second pass uses that global view
to rebuild state correlations: a rule that tests a bit can only be correlated
once every rule that sets it is known.

That dependency is why the converter cannot be a plain ``map`` over the rules.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import mapping  # noqa: F401 - importing populates the handler registry
from .emit.sigma import (
    build_correlation_document,
    build_rule_document,
    build_xbit_aggregate,
    rule_name,
    stable_uuid,
)
from .errors import Degradation, DegradationCode, Refusal, RefusalCode
from .mapping.context import Context
from .mapping.correlation import format_timespan
from .mapping.fields import JSON_KEYWORDS, FieldResolver
from .mapping.ir import CorrelationSpec, RuleDraft
from .mapping.positional import POSITIONAL_KEYWORDS, effective_positional
from .mapping.registry import BLOCKING, IGNORED, MODIFIERS, get_handler
from .mapping.values import CasePolicy
from .sagan.model import ParseFailure, SaganRule
from .sagan.parser import iter_rule_files, parse_file
from .upstream import UpstreamDefect
from .upstream import inspect as inspect_upstream
from .validate.pysigma import ValidationIssue, resolve_references, validate_document

#: Maximum number of branches in a bit aggregate rule. Past this point the rule
#: stops being reviewable and its evaluation cost stops being justified.
DEFAULT_MAX_XBIT_BRANCHES = 250

#: Fallback state-correlation window when no setter declares an ``expire``.
FALLBACK_STATE_SECONDS = 86400

#: Source-file marker for rules this tool synthesises rather than converts.
SYNTHETIC_SOURCE = "(synthetic)"


@dataclass(slots=True)
class RefusedRule:
    """A rule that was not converted, with the context the report needs."""

    sid: str
    title: str
    source_file: str
    line_number: int
    category: str
    code: RefusalCode
    detail: str
    keywords: tuple[str, ...]


@dataclass(slots=True)
class ConvertedRule:
    """A converted rule and the semantic losses it carries."""

    sid: str
    title: str
    source_file: str
    category: str
    documents: list[dict[str, Any]]
    degradations: list[Degradation]
    #: True for rules this tool synthesises, such as xbit aggregates. They are
    #: emitted output but not corpus rules, so they must not inflate the
    #: conversion rate.
    is_synthetic: bool = False
    #: JSON keys whose country this rule reads, so the emitted pipeline can
    #: look them up. Empty for every rule that names no bound address.
    geoip_keys: frozenset[str] = frozenset()


@dataclass(slots=True)
class ConversionResult:
    """Complete outcome of converting a corpus."""

    converted: list[ConvertedRule] = field(default_factory=list)
    refused: list[RefusedRule] = field(default_factory=list)
    parse_failures: list[ParseFailure] = field(default_factory=list)
    validation_issues: list[ValidationIssue] = field(default_factory=list)
    disabled_rules: int = 0
    files_processed: int = 0
    unknown_keywords: dict[str, int] = field(default_factory=dict)
    upstream_defects: list[UpstreamDefect] = field(default_factory=list)

    @property
    def geoip_keys(self) -> set[str]:
        """Every JSON key a converted rule reads a country for."""
        return {key for rule in self.converted for key in rule.geoip_keys}

    @property
    def documents(self) -> list[dict[str, Any]]:
        """Every emitted Sigma document, in a stable order."""
        return [doc for rule in self.converted for doc in rule.documents]

    @property
    def synthetic_rules(self) -> list[ConvertedRule]:
        """Rules this tool synthesised rather than converted."""
        return [rule for rule in self.converted if rule.is_synthetic]

    @property
    def converted_rules(self) -> list[ConvertedRule]:
        """Converted corpus rules, excluding synthesised ones."""
        return [rule for rule in self.converted if not rule.is_synthetic]

    @property
    def total_rules(self) -> int:
        """Number of corpus rules seen, converted plus refused.

        Synthetic rules are excluded deliberately: counting them would let the
        conversion rate rise simply because more xbits became correlatable,
        which is not the same thing as converting more of the corpus.
        """
        return len(self.converted_rules) + len(self.refused)

    @property
    def conversion_rate(self) -> float:
        """Share of corpus rules converted, as a percentage."""
        if self.total_rules == 0:
            return 0.0
        return 100.0 * len(self.converted_rules) / self.total_rules


class Converter:
    """Converts a Sagan rule corpus into Sigma documents."""

    def __init__(
        self,
        context: Context,
        case_policy: CasePolicy = CasePolicy.FAITHFUL,
        validate: bool = True,
        max_xbit_branches: int = DEFAULT_MAX_XBIT_BRANCHES,
    ) -> None:
        """Bind the converter to a context and a set of conversion policies."""
        self.context = context
        self.case_policy = case_policy
        self.validate = validate
        self.max_xbit_branches = max_xbit_branches

    # ------------------------------------------------------------------
    # Pass 1: rule-by-rule conversion
    # ------------------------------------------------------------------

    def convert_rule(self, rule: SaganRule) -> RuleDraft:
        """Convert one rule in isolation into a draft.

        Raises :class:`~sagan2sigma.errors.Refusal` when the rule carries a
        construct with no equivalent. Blocking conditions are checked before any
        handler runs: there is no point half-converting a rule that will be
        refused.
        """
        self._reject_blocking_keywords(rule)
        self._reject_effective_positional(rule)
        self._reject_unknown_keywords(rule)

        draft = RuleDraft()
        if rule.header.action == "drop":
            draft.degrade(
                Degradation(
                    code=DegradationCode.DROP_ACTION,
                    detail=(
                        "the rule used the drop action; Sigma has no action "
                        "concept, so it was converted as a normal detection rule"
                    ),
                )
            )
        elif rule.header.action == "pass":
            draft.degrade(
                Degradation(
                    code=DegradationCode.PASS_SHORT_CIRCUIT,
                    detail=(
                        "the rule used the pass action; in Sagan a matching pass "
                        "rule still alerts and then stops evaluating the remaining "
                        "signatures for that event. The detection is converted "
                        "faithfully; only the suppression of other rules on the "
                        "same event is not reproduced"
                    ),
                )
            )

        resolver = FieldResolver.for_rule(rule, self.context)
        handled: set[str] = set()
        for option in rule.options:
            keyword_handler = get_handler(option.name)
            if keyword_handler is None:
                if IGNORED.get(option.name):
                    draft.degrade(
                        Degradation(
                            code=DegradationCode.SIDE_EFFECT_DROPPED,
                            detail=(
                                f"{option.name} is an engine-specific side "
                                f"effect with no Sigma equivalent"
                            ),
                        )
                    )
                continue
            if option.name in handled:
                continue
            handled.add(option.name)
            keyword_handler(rule, draft, self.context, resolver, self.case_policy)

        if not draft.has_detection:
            raise Refusal(
                code=RefusalCode.NO_DETECTION,
                detail=(
                    "no positive constraint remains after conversion: the rule "
                    "carried only negations or side effects"
                ),
                keywords=tuple(sorted(rule.keywords)),
            )
        return draft

    @staticmethod
    def _reject_blocking_keywords(rule: SaganRule) -> None:
        """Refuse rules using constructs with no Sigma equivalent."""
        blocking = sorted(rule.keywords & BLOCKING.keys())
        if not blocking:
            return
        raise Refusal(
            code=BLOCKING[blocking[0]],
            detail="keywords with no Sigma equivalent: " + ", ".join(blocking),
            keywords=tuple(blocking),
        )

    @staticmethod
    def _reject_effective_positional(rule: SaganRule) -> None:
        """Refuse rules whose positional constraints actually bite.

        A zero-valued ``offset``/``depth``/``distance``/``within`` is a no-op in
        the Sagan engine, so a rule carrying only inert ones converts exactly as
        if they were absent. A non-zero ``offset``, ``depth`` or ``distance`` is
        a real byte position Sigma string modifiers cannot express, so the rule
        is refused. See :mod:`.mapping.positional` for the engine reference.
        """
        effective = effective_positional(rule)
        if not effective:
            return
        detail = ", ".join(f"{keyword}:{value}" for keyword, value in effective)
        raise Refusal(
            code=RefusalCode.POSITIONAL,
            detail=(
                "the rule constrains a byte position that changes what matches "
                f"({detail}); Sigma string modifiers cannot express a byte "
                "distance, so no faithful translation exists"
            ),
            keywords=tuple(sorted({keyword for keyword, _ in effective})),
        )

    @staticmethod
    def _reject_unknown_keywords(rule: SaganRule) -> None:
        """Refuse rules using keywords no handler covers.

        Surfacing them is deliberate: a new upstream keyword must appear in the
        report rather than be silently dropped from the detection logic.
        """
        unknown = sorted(
            keyword
            for keyword in rule.keywords
            if get_handler(keyword) is None
            and keyword not in MODIFIERS
            and keyword not in IGNORED
            and keyword not in POSITIONAL_KEYWORDS
        )
        if not unknown:
            return
        raise Refusal(
            code=RefusalCode.UNKNOWN_KEYWORD,
            detail="keywords unknown to the converter: " + ", ".join(unknown),
            keywords=tuple(unknown),
        )

    # ------------------------------------------------------------------
    # Full chain
    # ------------------------------------------------------------------

    def convert_paths(self, paths: list[Path]) -> ConversionResult:
        """Convert one or more rule directories or files."""
        result = ConversionResult()
        drafts: list[tuple[SaganRule, RuleDraft]] = []

        for root in paths:
            for rule_path in iter_rule_files(root):
                rule_file = parse_file(rule_path)
                result.files_processed += 1
                result.disabled_rules += rule_file.disabled
                result.parse_failures.extend(rule_file.failures)

                for rule in rule_file.rules:
                    result.upstream_defects.extend(inspect_upstream(rule))
                    entry = self.context.catalog.resolve(rule.source_file)
                    try:
                        draft = self.convert_rule(rule)
                    except Refusal as refusal:
                        result.refused.append(
                            RefusedRule(
                                sid=rule.sid,
                                title=_title_of(rule),
                                source_file=rule.source_file,
                                line_number=rule.line_number,
                                category=entry.category,
                                code=refusal.code,
                                detail=refusal.detail,
                                keywords=refusal.keywords,
                            )
                        )
                        if refusal.code is RefusalCode.UNKNOWN_KEYWORD:
                            for keyword in refusal.keywords:
                                result.unknown_keywords[keyword] = (
                                    result.unknown_keywords.get(keyword, 0) + 1
                                )
                        continue
                    drafts.append((rule, draft))

        self._second_pass(drafts, result)
        if self.validate:
            self._validate(result)
        return result

    def _second_pass(
        self, drafts: list[tuple[SaganRule, RuleDraft]], result: ConversionResult
    ) -> None:
        """Emit documents, state correlations included."""
        setters: dict[str, list[tuple[str, RuleDraft]]] = defaultdict(list)
        expiries: dict[str, list[int]] = defaultdict(list)
        #: Whether each setter of a bit reads JSON-bodied events. RSigma
        #: exposes the syslog envelope under `syslog_` prefixed names for those
        #: and unprefixed for the rest, so a correlation grouping on the sender
        #: can only pair events of one shape.
        shapes: dict[str, list[bool]] = defaultdict(list)
        for rule, draft in drafts:
            json_bodied = bool(rule.keywords & JSON_KEYWORDS)
            for bit, expire in draft.sets_bits.items():
                setters[bit].append((rule.sid, draft))
                expiries[bit].append(expire)
                shapes[bit].append(json_bodied)

        tested = {bit for _, draft in drafts for bit in draft.tests_bits}
        aggregates = self._build_aggregates(tested, setters, drafts)

        for rule, draft in drafts:
            entry = self.context.catalog.resolve(rule.source_file)
            if entry.is_fallback:
                draft.degrade(
                    Degradation(
                        code=DegradationCode.LOGSOURCE_FALLBACK,
                        detail=(
                            f"no catalog entry for {rule.source_file}, generic "
                            f"logsource applied"
                        ),
                    )
                )

            specs = list(draft.correlations)
            specs.extend(
                self._state_specs(
                    draft,
                    aggregates,
                    expiries,
                    rule.sid,
                    shapes,
                    bool(rule.keywords & JSON_KEYWORDS),
                )
            )
            self._flag_orphan_bits(draft, aggregates)

            base_name = rule_name(rule.sid)
            documents: list[dict[str, Any]] = [
                build_rule_document(
                    draft=draft,
                    sid=rule.sid,
                    rev=rule.rev,
                    source_file=rule.source_file,
                    logsource=entry,
                    needs_name=bool(specs),
                )
            ]
            for index, spec in enumerate(specs):
                documents.append(
                    build_correlation_document(
                        spec=spec,
                        draft=draft,
                        correlation_id=f"{rule.sid}#{index}",
                        base_name=base_name,
                    )
                )

            result.converted.append(
                ConvertedRule(
                    sid=rule.sid,
                    title=draft.title,
                    source_file=rule.source_file,
                    category=entry.category,
                    documents=documents,
                    degradations=list(draft.degradations),
                    geoip_keys=frozenset(draft.geoip_keys),
                )
            )

        for bit in sorted(aggregates):
            aggregate = aggregates[bit]
            result.converted.append(
                ConvertedRule(
                    sid=f"xbit:{bit}",
                    title=aggregate["title"],
                    source_file=SYNTHETIC_SOURCE,
                    category="State correlations",
                    documents=[aggregate],
                    degradations=[],
                    is_synthetic=True,
                )
            )

    def _build_aggregates(
        self,
        tested: set[str],
        setters: dict[str, list[tuple[str, RuleDraft]]],
        drafts: list[tuple[SaganRule, RuleDraft]],
    ) -> dict[str, dict[str, Any]]:
        """Build one aggregate rule per bit that is both set and tested."""
        aggregates: dict[str, dict[str, Any]] = {}
        taken: set[str] = set()
        for bit in sorted(tested):
            candidates = setters.get(bit)
            if not candidates:
                continue
            document, degradation = build_xbit_aggregate(
                bit=bit,
                setters=candidates,
                max_branches=self.max_xbit_branches,
                taken_names=taken,
            )
            taken.add(document["name"])
            aggregates[bit] = document
            if degradation is not None:
                for _, draft in drafts:
                    if bit in draft.tests_bits:
                        draft.degrade(degradation)
        return aggregates

    def _state_specs(
        self,
        draft: RuleDraft,
        aggregates: dict[str, dict[str, Any]],
        expiries: dict[str, list[int]],
        sid: str,
        shapes: dict[str, list[bool]] | None = None,
        json_bodied: bool = False,
    ) -> list[CorrelationSpec]:
        """Build the ``temporal_ordered`` correlations from bit tests.

        The window comes from the ``expire`` declared by the setter rules, not
        by the tester: Sagan attaches the lifetime to ``set``. When setters
        disagree, the longest expiry wins, the only choice that cannot lose a
        correlation the original would have made.
        """
        specs: list[CorrelationSpec] = []
        for bit in sorted(draft.tests_bits):
            aggregate = aggregates.get(bit)
            if aggregate is None:
                continue
            timespan = format_timespan(
                max(expiries.get(bit) or [FALLBACK_STATE_SECONDS])
            )
            draft.degrade(
                Degradation(
                    code=DegradationCode.XBIT_ISSET_SYNTHETIC,
                    detail=(
                        f"state correlation on '{bit}' rebuilt through the "
                        f"aggregate rule {aggregate['name']}, window {timespan}"
                    ),
                )
            )
            # The fallback names the envelope for *this rule's* shape, not
            # the plain field. RSigma exposes the syslog sender as `hostname`
            # on a plain event and `syslog_hostname` once the body is JSON, so
            # the plain one on a JSON-bodied rule gives a key no event carries
            # and the correlation can never pair anything, which is the defect
            # `_flag_mixed_shapes` below reports when the two shapes meet.
            #
            # Measured on the corpus under both profiles: no rule reaches it.
            # Every `isset` sets `bit_group_by`, and `_bit_group_by` always
            # returns at least one key. It is kept because that invariant lives
            # in another module, and corrected because a fallback that reads
            # like a decision should not contradict the one made there.
            group_by = draft.bit_group_by or (
                self.context.profile.envelope_field("syslog_host", json_bodied),
            )
            self._flag_mixed_shapes(draft, bit, group_by, shapes, json_bodied)
            specs.append(
                CorrelationSpec(
                    correlation_type="temporal_ordered",
                    group_by=group_by,
                    timespan=timespan,
                    # By id, not by name. Both are legal references in the
                    # Sigma correlation spec, and this tool uses names
                    # everywhere else, but RSigma 0.21.0 resolves a name only
                    # for `event_count`: for `temporal` and `temporal_ordered`
                    # a name reference silently matches nothing, so the
                    # correlation never fires. Measured on one hand-written
                    # pair of rules, changing only the reference style:
                    # event_count fires either way, temporal_ordered fires by
                    # id and never by name. Revert this once RSigma resolves
                    # names for temporal correlations.
                    referenced_rules=(aggregate["id"], stable_uuid("rule", sid)),
                    title_suffix=f"correlated with {bit}",
                    description=(
                        f"Reconstruction of the Sagan '{bit}' bit. The window "
                        f"comes from the expire time declared by the rules that "
                        f"set the bit."
                    ),
                )
            )
        return specs

    def _flag_mixed_shapes(
        self,
        draft: RuleDraft,
        bit: str,
        group_by: tuple[str, ...],
        shapes: dict[str, list[bool]] | None,
        json_bodied: bool,
    ) -> None:
        """Report setters a host-grouped correlation cannot pair with.

        RSigma exposes the syslog envelope under `syslog_` prefixed names once
        the body is JSON and unprefixed otherwise, so a correlation grouping on
        the sender names one field and only events of that shape carry it. When
        a bit is set by rules of both shapes, the tester pairs with the matching
        half and silently misses the rest.

        This is a partial loss and not a dead correlation, which is why it is
        degraded rather than refused: sid 5003332 pairs with 105 of its 135
        setters, and dropping it would lose those 105 to spare the 30.
        """
        envelope = {
            self.context.syslog_host_field,
            self.context.profile.envelope_field("syslog_host", True),
        }
        if shapes is None or set(group_by) - envelope:
            return
        candidates = shapes.get(bit) or []
        unpairable = sum(1 for setter in candidates if setter != json_bodied)
        if not unpairable:
            return
        draft.degrade(
            Degradation(
                code=DegradationCode.GROUPBY_SHAPE_SPLIT,
                detail=(
                    f"the '{bit}' bit is set by rules reading a different event "
                    f"shape from this one, and the group-by names the envelope "
                    f"field of one shape only; {unpairable} of "
                    f"{len(candidates)} setters cannot pair with it"
                ),
            )
        )

    @staticmethod
    def _flag_orphan_bits(
        draft: RuleDraft, aggregates: dict[str, dict[str, Any]]
    ) -> None:
        """Report bits that are set or tested but never paired up."""
        orphan_tests = sorted(bit for bit in draft.tests_bits if bit not in aggregates)
        if orphan_tests:
            draft.degrade(
                Degradation(
                    code=DegradationCode.XBIT_SET_DROPPED,
                    detail=(
                        "tested but never set by a converted rule: "
                        + ", ".join(orphan_tests)
                    ),
                )
            )
        orphan_sets = sorted(bit for bit in draft.sets_bits if bit not in aggregates)
        if orphan_sets:
            draft.degrade(
                Degradation(
                    code=DegradationCode.XBIT_SET_DROPPED,
                    detail=(
                        "set but never tested by a converted rule: "
                        + ", ".join(orphan_sets)
                    ),
                )
            )

    def _validate(self, result: ConversionResult) -> None:
        """Validate every document and demote rejected rules to refusals."""
        kept: list[ConvertedRule] = []
        for converted in result.converted:
            issues = [
                issue
                for issue in (validate_document(doc) for doc in converted.documents)
                if issue is not None
            ]
            if not issues:
                kept.append(converted)
                continue
            result.validation_issues.extend(issues)
            result.refused.append(
                RefusedRule(
                    sid=converted.sid,
                    title=converted.title,
                    source_file=converted.source_file,
                    line_number=0,
                    category=converted.category,
                    code=RefusalCode.SIGMA_INVALID,
                    detail=issues[0].message[:400],
                    keywords=(),
                )
            )
        result.converted = kept
        result.validation_issues.extend(resolve_references(result.documents))


def _title_of(rule: SaganRule) -> str:
    """Best-effort title for a rule that could not be converted."""
    raw = rule.first("msg") or ""
    return " ".join(raw.strip().strip('"').split())[:256] or "(no msg)"


__all__ = [
    "DEFAULT_MAX_XBIT_BRANCHES",
    "SYNTHETIC_SOURCE",
    "ConversionResult",
    "ConvertedRule",
    "Converter",
    "RefusedRule",
]
