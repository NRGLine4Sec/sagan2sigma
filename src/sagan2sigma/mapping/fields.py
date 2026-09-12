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

#: Keywords no plain-text event can satisfy, because each reads a key out of a
#: parsed document.
#:
#: ``json_map`` is deliberately absent, and that absence was measured on the
#: engine rather than argued: a rule carrying ``json_map: "src_ip", ".ip"``
#: alongside ``program`` and ``content`` fires on a plain syslog line exactly as
#: the same rule without the binding does. The binding is not a condition. It
#: names where a value would be read *if* the body were a document, and stays
#: empty otherwise. 41 corpus rules are in that state, and treating their
#: ``json_map`` as a JSON requirement converted them for one shape when Sagan
#: matches both.
HARD_JSON_KEYWORDS = frozenset({"json_content", "json_meta_content", "json_pcre"})

#: Keywords whose search runs against the body as text rather than against a
#: parsed key.
RAW_TEXT_KEYWORDS = frozenset({"content", "meta_content", "pcre"})

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
            key = parts[1].lstrip(".")
            # Upstream clips a key path at 31 characters when the engine would
            # otherwise never match it, and records the original above the rule.
            # A json_map key decides a field name and a correlation group-by, so
            # a clipped one propagates further than a json_content does; 13 keys
            # in the corpus are in that state.
            mapping[parts[0]] = rule.key_restorations.get(key, key)
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
    #: Whether the rule reads JSON-bodied events at all.
    json_event: bool = False
    #: Whether a plain-text event could never satisfy it. See
    #: :data:`HARD_JSON_KEYWORDS`.
    json_required: bool = False
    #: Whether the rule searches the body as text. Such a search needs a field
    #: holding the body, which not every profile has once the body is a
    #: document. See :attr:`document_arm_reachable`.
    raw_search: bool = False

    @classmethod
    def for_rule(cls, rule: SaganRule, context: Context) -> FieldResolver:
        """Build a resolver for one rule."""
        mapping = json_map(rule)
        return cls(
            context=context,
            mapping=mapping,
            positions=parse_positions(rule),
            json_event=bool(rule.keywords & JSON_KEYWORDS),
            raw_search=bool(rule.keywords & RAW_TEXT_KEYWORDS),
            # A `json_map` binding `message` redirects the raw search into a key
            # of the document, so that rule does need one.
            json_required=(
                bool(rule.keywords & HARD_JSON_KEYWORDS) or "message" in mapping
            ),
        )

    @property
    def shape_agnostic(self) -> bool:
        """Whether a plain event and a JSON-bodied one can both satisfy the rule.

        True of everything except a rule reading a key out of a parsed
        document, and that includes the rules naming no JSON at all: measured
        on the engine, ``program: sshd; content:"needle"`` fires on a JSON
        document whose serialised text holds the literal, exactly as it fires
        on a plain line. Sagan has no notion of a log source, only of a
        ``program``, so nothing narrows such a rule to one shape.

        Such a rule has to be converted for both: the ingestion chain renames
        the syslog envelope once the body is a document, so naming one shape's
        fields would leave the other unmatched.
        """
        return not self.json_required

    @property
    def document_arm_reachable(self) -> bool:
        """Whether a JSON-bodied event could satisfy the converted rule at all.

        A text search needs a field holding the body, and a profile keeping
        none once the body is parsed cannot serve one. The converted rule then
        covers the plain-text events only, and an envelope alternative naming
        the document's field names would be an alternative nothing can satisfy.
        """
        return not (self.raw_search and self.context.profile.json_raw is None)

    def envelope(self, internal: str) -> str:
        """Envelope field name matching the event shape this rule targets.

        A shape-agnostic rule gets the name of the shape it reads first, which
        is the JSON one when it names JSON at all. The callers that need a
        single name are the correlations, whose group-by key has to be the one
        the rules setting the same bit use. Detection predicates call
        :meth:`envelope_names` instead and accept both.
        """
        return self.context.profile.envelope_field(internal, self.json_event)

    def envelope_names(self, internal: str) -> tuple[str, ...]:
        """Every envelope name a matching event could carry this value under.

        Two on a profile that renames the envelope and can serve both shapes of
        event, the rule's own first so that the name a reader expects is the one
        already there. One otherwise, and it is the name of the shape that can
        actually match: the document's for a rule only a document satisfies, the
        plain event's for a rule whose text search this profile cannot run on a
        document.
        """
        json_name = self.context.profile.envelope_field(internal, True)
        plain_name = self.context.profile.envelope_field(internal, False)
        if json_name == plain_name or self.json_required:
            return (json_name,)
        if not self.document_arm_reachable:
            return (plain_name,)
        return (json_name, plain_name) if self.json_event else (plain_name, json_name)

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

        A ``json_map`` binding wins. Otherwise the profile's ``json_raw`` field
        is used whenever it has one, because that is the field carrying the body
        whatever its shape: ``sagan-json.vrl`` assigns it on every event and
        drops ``message`` once the body is a document, so a search on ``message``
        can only ever see half the events the rule matches. The pipeline's own
        transforms settled this question the same way, ``sagan-parse-ip.vrl``
        and ``username-extraction.vrl`` both reading the raw field with
        ``message`` as a fallback. A profile with no such field falls back to
        ``message``, which there is the whole body.
        """
        if "message" in self.mapping:
            return self.mapping["message"]
        if self.context.profile.json_raw is not None:
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

        Only a rule that *requires* a document is unreachable. A shape-agnostic
        one still matches the plain-text events it was always able to match, and
        loses the JSON-bodied half instead; that is a degradation, not a
        refusal. See :attr:`json_body_arm_lost`.
        """
        return (
            self.json_required
            and not self.targets_json
            and self.context.profile.json_raw is None
        )

    @property
    def json_body_arm_lost(self) -> bool:
        """Whether a raw search costs a rule naming JSON its document half.

        The profile preserves no raw body, so on a JSON-bodied event there is
        nothing for a ``content`` search to run against, and the converted rule
        covers the plain-text half of the original only.

        Restricted to rules that name JSON, which is where the rule's own text
        says the source emits documents. The loss is the same for every
        raw-text rule under such a profile, all 6,417 of them, but that is a
        property of the profile rather than of any one rule: it is stated once
        in the documentation instead of 6,417 times in the conversion report,
        where it would bury the losses that belong to individual rules.
        """
        return (
            self.json_event and self.shape_agnostic and not self.document_arm_reachable
        )

    @property
    def program(self) -> str:
        """Field a ``program`` selector runs against."""
        if "program" in self.mapping:
            return self.mapping["program"]
        return self.envelope("program")

    @property
    def program_names(self) -> tuple[str, ...]:
        """Every field name a ``program`` selector has to accept."""
        if "program" in self.mapping:
            return (self.mapping["program"],)
        return self.envelope_names("program")

    @property
    def targets_json(self) -> bool:
        """Whether the message search was redirected to a JSON key.

        Used to decide if the ``D_RAW_TEXT_MATCH`` portability warning
        applies: a rule redirected to a JSON key is portable, one left on the
        raw body is not.
        """
        return "message" in self.mapping
