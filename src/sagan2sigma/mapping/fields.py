"""Resolution of the Sigma field a Sagan keyword actually targets.

This is the least obvious part of the conversion, and getting it wrong
produces rules that parse cleanly and never fire.

Sagan keywords do not address log fields directly; they address *internal
engine values*. ``json_map`` rebinds those internal values to JSON keys, and
the rule-keywords documentation is explicit about the consequences:

    ``message`` - Replaces existing "syslog" message with the value within the
    specified key. Once mapped, the JSON value can be used with keywords like
    ``parse_src_ip``, ``parse_dst_ip``, ``pcre``, ``content``,
    ``meta_content``, etc.

    ``program`` - Replaces existing "program" message with the value within the
    specified key.

So in a rule carrying ``json_map: "message", ".RenderedDescription";`` a
``content:`` search runs against the ``RenderedDescription`` JSON key, not
against the raw syslog body. Roughly 1,000 rules of the upstream corpus are in
that situation. Emitting ``_raw|contains`` for them would produce rules that
never match, because RSigma exposes the JSON object, not the original line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..sagan.model import SaganRule
from .context import Context

#: Leading integer of a ``parse_src_ip``/``parse_dst_ip`` argument. The engine
#: runs the value through ``atoi()``, so trailing junk is ignored and a missing
#: or unparsable value means position 1.
_LEADING_INT = re.compile(r"\s*(\d+)")

#: Sagan keyword supplying the position for each internal value.
POSITION_KEYWORDS = {"src_ip": "parse_src_ip", "dest_ip": "parse_dst_ip"}

#: Keywords that only make sense when the log body is a JSON document. Their
#: presence is what tells the converter which envelope field names apply, since
#: RSigma exposes a different set once it parses the body.
JSON_KEYWORDS = frozenset(
    {"json_content", "json_meta_content", "json_pcre", "json_map"}
)

#: Internal Sagan values that ``json_map`` can rebind.
#:
#: Taken from the engine (``src/rules.c``, the ``strcmp(json_map_type, ...)``
#: chain), not from the documentation, which omits ``username``, ``flow_id``
#: and ``ja3``. The corpus uses ``username`` in more than a thousand rules, so
#: following the docs here would break every correlation grouped by user.
INTERNAL_VALUES = frozenset(
    {
        "dest_ip",
        "dest_port",
        "event_id",
        "event_type",
        "filename",
        "flow_id",
        "hostname",
        "ja3",
        "md5",
        "message",
        "program",
        "proto",
        "sha1",
        "sha256",
        "src_ip",
        "src_port",
        "url",
        "username",
    }
)


def json_map(rule: SaganRule) -> dict[str, str]:
    """Return the ``internal value -> JSON key`` table declared by the rule.

    >>> from sagan2sigma.sagan.parser import parse_rule
    >>> line = ('alert any any any -> any any (msg:"t"; '
    ...         'json_map: "message", ".RenderedDescription"; sid:1;)')
    >>> json_map(parse_rule(line, 'f.rules', 1))
    {'message': 'RenderedDescription'}
    """
    mapping: dict[str, str] = {}
    for option in rule.iter_options("json_map"):
        if option.value is None:
            continue
        parts = [part.strip().strip('"') for part in option.value.split(",", 1)]
        if len(parts) == 2 and parts[0] in INTERNAL_VALUES:
            mapping[parts[0]] = parts[1].lstrip(".")
    return mapping


def parse_positions(rule: SaganRule) -> dict[str, int]:
    """Positions declared by ``parse_src_ip`` and ``parse_dst_ip``.

    Sagan indexes its address cache from 1: ``parse_src_ip: 2`` means the
    second address in the message, not merely "a source address". Reproducing
    that index is what makes the enriched conversion exact rather than a guess.

    >>> from sagan2sigma.sagan.parser import parse_rule
    >>> line = ('alert any any any -> any any (msg:"t"; parse_src_ip: 2; '
    ...         'parse_dst_ip: 3; sid:1;)')
    >>> parse_positions(parse_rule(line, "f.rules", 1))
    {'src_ip': 2, 'dest_ip': 3}
    """
    positions: dict[str, int] = {}
    for internal, keyword in POSITION_KEYWORDS.items():
        if not rule.has(keyword):
            continue
        raw = rule.first(keyword) or ""
        match = _LEADING_INT.match(raw)
        positions[internal] = int(match.group(1)) if match else 1
    return positions


@dataclass(frozen=True, slots=True)
class FieldResolver:
    """Maps Sagan internal values onto concrete Sigma field names."""

    context: Context
    mapping: dict[str, str]
    positions: dict[str, int]
    #: Whether the rule targets JSON-bodied events.
    json_event: bool = False

    @classmethod
    def for_rule(cls, rule: SaganRule, context: Context) -> FieldResolver:
        """Build a resolver for one rule."""
        return cls(
            context=context,
            mapping=json_map(rule),
            positions=parse_positions(rule),
            json_event=bool(rule.keywords & JSON_KEYWORDS),
        )

    def envelope(self, internal: str) -> str:
        """Envelope field name matching the event shape this rule targets."""
        return self.context.profile.envelope_field(internal, self.json_event)

    def positional(self, internal: str) -> str | None:
        """Enriched field holding the position this rule asked for.

        Returns ``None`` when the rule declares no position for that internal
        value, or when the active profile supplies no enrichment for it.
        """
        position = self.positions.get(internal)
        if position is None:
            return None
        return self.context.profile.positional_field(internal, position)

    def resolve(self, internal: str) -> str | None:
        """Concrete field name for an internal value, ``None`` if unresolvable.

        A ``json_map`` binding always wins. Otherwise the output profile
        supplies the syslog-level fallback for the values that have one.
        """
        if internal in self.mapping:
            return self.mapping[internal]
        return self.context.profile.fields.get(internal)

    @property
    def message(self) -> str:
        """Field a ``content`` or ``pcre`` search runs against.

        A ``json_map`` binding wins. Otherwise, on a JSON-bodied event a profile
        whose pipeline preserves the raw body exposes it as ``json_raw``, and the
        raw search runs against that; on a plain event the profile's ``message``
        field is used.
        """
        if "message" in self.mapping:
            return self.mapping["message"]
        if self.json_event and self.context.profile.json_raw is not None:
            return self.context.profile.json_raw
        resolved = self.context.profile.fields.get("message")
        if resolved is None:  # pragma: no cover - profiles always define it
            raise KeyError("output profile defines no 'message' field")
        return resolved

    @property
    def raw_search_is_unreachable(self) -> bool:
        """Whether a raw-text search could never match on this rule's events.

        On a JSON-bodied event RSigma returns the parsed object and no raw
        field, so a ``content`` search that was not redirected by a ``json_map``
        binding has nothing to run against, and emitting it would produce a rule
        that validates and never fires. Unless the profile's pipeline preserves
        the raw body (``json_raw``), in which case the search runs against that.
        """
        return (
            self.json_event
            and not self.targets_json
            and self.context.profile.json_raw is None
        )

    @property
    def program(self) -> str:
        """Field a ``program`` selector runs against."""
        if "program" in self.mapping:
            return self.mapping["program"]
        return self.envelope("program")

    @property
    def targets_json(self) -> bool:
        """Whether the message search was redirected to a JSON key.

        Used to decide if the ``D_RAW_TEXT_MATCH`` portability warning
        applies: a rule redirected to a JSON key is portable, one left on the
        raw body is not.
        """
        return "message" in self.mapping
