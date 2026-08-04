"""Intermediate representation between a Sagan rule and a Sigma document.

Every keyword handler emits :class:`Predicate` objects. The emitter then groups
them into Sigma detection blocks and builds the condition expression. This
decoupling lets each handler be written and tested independently of YAML
serialisation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import Degradation

#: Value carried by a predicate. Sigma distinguishes integers from strings: an
#: ``EventID: 4624`` does not compare like ``EventID: "4624"``.
Scalar = str | int


@dataclass(frozen=True, slots=True)
class Predicate:
    """One elementary constraint, already expressed in Sigma vocabulary.

    ``field`` is already resolved against the output profile and the rule's
    ``json_map``: a handler never hardcodes ``_raw`` or ``message``.

    ``modifiers`` is the ordered list of Sigma modifiers appended to the field
    name: ``("contains", "cased")`` renders as ``field|contains|cased``.

    Several ``values`` on one predicate form an OR, matching Sigma list
    semantics.
    """

    field: str
    modifiers: tuple[str, ...]
    values: tuple[Scalar, ...]
    negated: bool = False
    origin: str = ""

    @property
    def key(self) -> str:
        """Full Sigma key, modifiers included."""
        return "|".join((self.field, *self.modifiers))

    @property
    def rendered_value(self) -> Scalar | list[Scalar]:
        """Value as it must appear in YAML."""
        if len(self.values) == 1:
            return self.values[0]
        return list(self.values)


@dataclass(frozen=True, slots=True)
class CorrelationSpec:
    """A Sigma correlation rule to emit alongside the detection rule."""

    correlation_type: str
    group_by: tuple[str, ...]
    timespan: str
    condition: dict[str, int] | None = None
    referenced_rules: tuple[str, ...] = ()
    title_suffix: str = ""
    description: str = ""


@dataclass(slots=True)
class RuleDraft:
    """Accumulator filled by the handlers for one rule."""

    predicates: list[Predicate] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    references: list[str] = field(default_factory=list)
    custom_attributes: dict[str, str] = field(default_factory=dict)
    degradations: list[Degradation] = field(default_factory=list)
    correlations: list[CorrelationSpec] = field(default_factory=list)
    #: Bits this rule sets, consumed on the second pass.
    sets_bits: dict[str, int] = field(default_factory=dict)
    #: Bits this rule tests, consumed on the second pass.
    tests_bits: set[str] = field(default_factory=set)
    #: Group-by key required by a bit test.
    bit_group_by: tuple[str, ...] = ()
    level: str = "medium"
    #: Set by ``priority``, which overrides ``classtype`` regardless of order.
    level_locked: bool = False
    title: str = ""

    def add(self, predicate: Predicate) -> None:
        """Append a predicate, skipping exact duplicates."""
        if predicate not in self.predicates:
            self.predicates.append(predicate)

    def degrade(self, degradation: Degradation) -> None:
        """Record a semantic loss, skipping exact duplicates."""
        if degradation not in self.degradations:
            self.degradations.append(degradation)

    def set_level(self, level: str, locked: bool = False) -> None:
        """Set the Sigma level, honouring the ``priority`` override.

        Sagan states that ``priority`` overrides the ``classtype`` priority.
        Because option order inside a rule is arbitrary, the override has to be
        sticky rather than last-write-wins.
        """
        if self.level_locked and not locked:
            return
        self.level = level
        self.level_locked = self.level_locked or locked

    @property
    def has_detection(self) -> bool:
        """Whether at least one non-negated constraint remains.

        A rule made only of negations is meaningless: it would fire on every
        event that does not contain a pattern.
        """
        return any(not predicate.negated for predicate in self.predicates)
