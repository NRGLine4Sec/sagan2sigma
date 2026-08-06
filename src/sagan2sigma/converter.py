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
)
from .errors import Degradation, DegradationCode, Refusal, RefusalCode
from .mapping.context import Context
from .mapping.correlation import format_timespan
from .mapping.fields import FieldResolver
from .mapping.ir import CorrelationSpec, RuleDraft
from .mapping.positional import POSITIONAL_KEYWORDS, effective_positional
from .mapping.registry import BLOCKING, IGNORED, MODIFIERS, get_handler
from .mapping.values import CasePolicy
from .sagan.model import ParseFailure, SaganRule
from .sagan.parser import iter_rule_files, parse_file
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
        self._reject_pass_action(rule)
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
    def _reject_pass_action(rule: SaganRule) -> None:
        """Refuse ``pass`` rules, which short-circuit the whole engine.

        The rule-syntax documentation is explicit: "When using the pass option
        and the signature's conditions are met, no other signatures are
        processed." That is a global abort, not a per-rule exception. Sigma's
        nearest construct is a global filter, which suppresses named rules and
        which RSigma does not implement. Emitting these as ``alert`` rules would
        invert their meaning, turning suppression into detection.
        """
        if rule.header.action != "pass":
            return
        raise Refusal(
            code=RefusalCode.PASS_RULE,
            detail=(
                "pass rules abort evaluation of every remaining signature; "
                "Sigma has no equivalent short-circuit and emitting the rule as "
                "an alert would invert its meaning"
            ),
            keywords=("pass",),
        )

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
        for rule, draft in drafts:
            for bit, expire in draft.sets_bits.items():
                setters[bit].append((rule.sid, draft))
                expiries[bit].append(expire)

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
            specs.extend(self._state_specs(draft, aggregates, expiries, rule.sid))
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
            specs.append(
                CorrelationSpec(
                    correlation_type="temporal_ordered",
                    group_by=draft.bit_group_by or (self.context.syslog_host_field,),
                    timespan=timespan,
                    referenced_rules=(aggregate["name"], rule_name(sid)),
                    title_suffix=f"correlated with {bit}",
                    description=(
                        f"Reconstruction of the Sagan '{bit}' bit. The window "
                        f"comes from the expire time declared by the rules that "
                        f"set the bit."
                    ),
                )
            )
        return specs

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
