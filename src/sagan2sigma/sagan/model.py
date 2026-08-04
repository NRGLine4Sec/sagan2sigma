"""Immutable data model of a parsed Sagan rule."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

#: Rule actions Sagan accepts, per the rule-syntax documentation.
ACTIONS = frozenset({"alert", "drop", "pass"})


@dataclass(frozen=True, slots=True)
class Option:
    """One option from the parenthesised block.

    ``value`` is ``None`` for flag options such as ``nocase`` or ``normalize``.

    ``index`` preserves the original position, which is essential: Sagan
    modifiers are positional, so ``nocase`` applies to the ``content`` that
    precedes it and to nothing else.
    """

    name: str
    value: str | None
    index: int


@dataclass(frozen=True, slots=True)
class Header:
    """The ``<action> <proto> <src> <sport> <dir> <dst> <dport>`` header.

    Sagan keeps the Snort shape for rule-management tooling compatibility, but
    the address fields are not filters on the incoming log: they are populated
    *after* the fact from ``parse_src_ip``, ``parse_dst_ip`` or liblognorm, and
    fall back to the syslog sender otherwise. The header is therefore kept for
    traceability and ignored by the conversion, except for ``action``.
    """

    action: str
    protocol: str
    source: str
    source_port: str
    direction: str
    destination: str
    destination_port: str


@dataclass(frozen=True, slots=True)
class SaganRule:
    """A parsed Sagan rule."""

    header: Header
    options: tuple[Option, ...]
    source_file: str
    line_number: int
    raw: str

    def values(self, name: str) -> list[str | None]:
        """Every value carried by a keyword, in order of appearance."""
        return [option.value for option in self.options if option.name == name]

    def first(self, name: str) -> str | None:
        """First value of a keyword, ``None`` if absent or flag-only."""
        for option in self.options:
            if option.name == name:
                return option.value
        return None

    def has(self, name: str) -> bool:
        """Whether a keyword is present, flags included."""
        return any(option.name == name for option in self.options)

    def iter_options(self, name: str) -> Iterator[Option]:
        """Iterate the options carrying a given name."""
        return (option for option in self.options if option.name == name)

    @property
    def keywords(self) -> frozenset[str]:
        """Set of keywords present in the rule."""
        return frozenset(option.name for option in self.options)

    @property
    def sid(self) -> str:
        """Signature ID, or ``unknown`` when absent."""
        return (self.first("sid") or "unknown").strip()

    @property
    def rev(self) -> str:
        """Revision number, ``1`` by default."""
        return (self.first("rev") or "1").strip()

    def modifiers_after(self, index: int, names: frozenset[str]) -> frozenset[str]:
        """Flag modifiers immediately following the option at ``index``.

        Sagan applies ``nocase``, ``json_contains`` and friends to the option
        that precedes them. Consecutive flags are collected and the scan stops
        at the first keyword outside ``names``.
        """
        found: set[str] = set()
        for option in self.options:
            if option.index <= index:
                continue
            if option.name in names:
                found.add(option.name)
                continue
            break
        return frozenset(found)


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """A corpus line that could not be parsed."""

    source_file: str
    line_number: int
    raw: str
    reason: str


@dataclass(slots=True)
class RuleFile:
    """Outcome of parsing one ``.rules`` file."""

    path: str
    rules: list[SaganRule] = field(default_factory=list)
    failures: list[ParseFailure] = field(default_factory=list)
    disabled: int = 0
