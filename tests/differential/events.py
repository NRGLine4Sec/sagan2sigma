"""Event generation for the differential harness.

The point of generating events rather than hand-writing them is that a
hand-written event encodes what the author expected, and the author is the same
person who wrote the converter. Generated events are derived mechanically from
the rule, and both evaluators then decide independently what should happen.

For each rule the generator produces a small battery:

``base``
    an event built to satisfy every positive condition. Both sides should fire.
``case_flipped``
    the same event with the message case inverted. This is the probe that
    catches the ``nocase`` inversion: Sagan is case-sensitive by default, Sigma
    is not, so a converter that copies the flag across instead of inverting it
    disagrees here and nowhere else.
``missing_<n>``
    one positive literal removed. Neither side should fire.
``negation_<n>``
    a negated literal added back in. Neither side should fire.
``json_negation_<n>``
    the same for a negated JSON condition: the key holds the value the rule
    excludes. Neither side should fire. The base event carries that key holding
    something else, since a negated JSON condition still requires the key to be
    present, so without both probes a dropped negation would go unnoticed.
``wrong_program``
    an unrelated program value. Neither side should fire.
``wildcard_probe``
    a message containing a literal asterisk, which distinguishes a correctly
    escaped literal from an accidental Sigma wildcard.

Each probe is composed from a *set of literals* rather than patched out of a
finished message, because on a JSON-bodied event the two are not the same
thing. The engine searches the serialised document there, so a literal has to
be placed somewhere the serialisation will actually contain it, and that
placement has to be redone for every probe. :func:`_place` does the placing and
verifies it by serialising; :func:`unplaceable` reports what it could not do,
which is the difference between a probe that decides a rule and one that leaves
both evaluators searching for text no document holds.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from sagan2sigma.errors import Refusal
from sagan2sigma.mapping.content import split_meta_content
from sagan2sigma.mapping.context import Profile, load_profile
from sagan2sigma.sagan.hexdec import decode_hex
from sagan2sigma.sagan.model import SaganRule

from .sagan_reference import SaganEvent, expand_values, json_map

_JSON_ARGS = re.compile(
    r'^\s*(?P<neg>!?)\s*"?\.?(?P<key>[A-Za-z0-9_.\[\]@-]+)"?\s*,\s*(?P<rest>.+)$', re.S
)

#: Filler placed between literals so that concatenation cannot accidentally
#: create a match for something the rule did not ask for.
FILLER = " ~ "

#: Keywords that make a rule target JSON-bodied events, mirroring the
#: converter's own criterion.
JSON_KEYWORDS = frozenset(
    {"json_content", "json_meta_content", "json_pcre", "json_map"}
)

#: Keywords whose search runs against the raw body rather than a JSON key.
RAW_TEXT_KEYWORDS = frozenset({"content", "meta_content", "pcre"})

#: Body key carrying the raw-text region of a JSON-bodied probe.
#:
#: Measured on the engine: when the syslog body is a JSON document, `content`,
#: `pcre` and `meta_content` search the *serialised document* and nothing else,
#: key names, braces and quotes included (`content:"|7b 22|Msg"` matches
#: `{"Msg":...}`). So a probe for such a rule cannot carry its literals beside
#: the document as a plain event would; they have to live inside it, or the
#: engine sees a document that does not contain them and both sides stay silent
#: for a reason belonging to the probe.
#:
#: The name is not one any rule reads. It exists so the battery has a region it
#: can vary without disturbing the JSON keys the same rule matches on: flipping
#: the case of the whole document would rename its keys and make json_content
#: fail on both sides at once, which would agree and measure nothing.
PROBE_TEXT_KEY = "sagan_probe_text"

#: Value given to a key a rule negates, so the key exists and the negation
#: holds. It has to fail a substring test as well as an equality one, since
#: `json_contains` turns the comparison into a search, hence a value no rule
#: value is a substring of. When one is, the key is left out and the rule falls
#: back to being unexercised rather than being decided on a value that matches.
DIFFERENT_VALUE = "sagan-probe-other-value"


@dataclass(frozen=True, slots=True)
class Probe:
    """One generated event and the reason it exists."""

    name: str
    event: SaganEvent


def _strip(value: str) -> tuple[bool, str]:
    text = value.strip()
    negated = text.startswith("!")
    if negated:
        text = text[1:].strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return negated, text


def positive_literals(
    rule: SaganRule, variables: dict[str, list[str]] | None = None
) -> list[str]:
    """Text fragments the message must contain for the rule to fire."""
    literals: list[str] = []
    for option in rule.iter_options("content"):
        if option.value is None:
            continue
        negated, text = _strip(option.value)
        if not negated:
            literals.append(decode_hex(text))
    for option in rule.iter_options("meta_content"):
        if option.value is None:
            continue
        # Split the way the engine does, through the converter's own reader,
        # which `sagan_reference` already uses. A private regex here required a
        # comma after the closing quote and quietly produced no literal for the
        # four corpus options that put it elsewhere, so those rules were judged
        # on their other conditions alone: sid 5013804 stayed silent while
        # carrying a real defect, and the run counted it as measured.
        try:
            negated, pattern, raw_values = split_meta_content(option.value)
        except Refusal:
            continue
        if negated:
            continue
        values = expand_values(raw_values, variables or {})
        if values:
            literals.append(decode_hex(pattern).replace("%sagan%", values[0]))
    return literals


def negative_literals(rule: SaganRule) -> list[str]:
    """Text fragments whose presence must stop the rule firing."""
    literals: list[str] = []
    for option in rule.iter_options("content"):
        if option.value is None:
            continue
        negated, text = _strip(option.value)
        if negated:
            literals.append(decode_hex(text))
    return literals


def program_value(rule: SaganRule) -> str:
    """A concrete program name satisfying the rule's ``program`` selector."""
    for option in rule.options:
        if option.name not in ("program", "event_type") or option.value is None:
            continue
        first = next((a.strip() for a in option.value.split("|") if a.strip()), "")
        # A glob is turned into a concrete value the glob accepts.
        return decode_hex(first).replace("*", "x").replace("?", "x")
    return "syslog"


def json_body(rule: SaganRule) -> dict[str, Any]:
    """A JSON document satisfying the rule's JSON conditions."""
    body: dict[str, Any] = {}

    def assign(key: str, value: Any) -> None:
        # The event has to carry the field a producer emits, not the one the
        # rule names. Where upstream clipped a key path to fit the engine's
        # 31-character limit, the rule says `data.authorizationInfo.operati`
        # and Confluent says `data.authorizationInfo.operation`; Sagan clips
        # the event's key on its way in and matches either way, so building the
        # probe from the rule text produced a document no producer emits and
        # made 11 rules disagree for a property of the probe.
        key = rule.key_restorations.get(key, key)
        parts = key.replace("[]", "").split(".")
        cursor = body
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = value

    # Negated keys first, so a key carrying both a positive and a negative
    # condition ends up holding the value the positive one asks for.
    for negated in (True, False):
        for keyword in ("json_content", "json_meta_content"):
            for option in rule.iter_options(keyword):
                if option.value is None:
                    continue
                parsed = _JSON_ARGS.match(option.value)
                if parsed is None or (parsed.group("neg") == "!") is not negated:
                    continue
                first = next(
                    (
                        v.strip().strip('"')
                        for v in parsed.group("rest").split(",")
                        if v.strip()
                    ),
                    "",
                )
                value = decode_hex(first)
                if negated:
                    # A negated JSON condition still requires the key to be
                    # there: measured, `json_content` on a key the event does
                    # not carry fails, negated or not, and the converter emits
                    # the `|exists: true` that says so. Leaving the key out
                    # therefore silenced both sides at once, which reads as
                    # agreement and decides nothing: 21 defender rules and 17
                    # fortinet ones were being counted as judged that way.
                    if value.lower() in DIFFERENT_VALUE:
                        continue  # nothing here is guaranteed not to match
                    value = DIFFERENT_VALUE
                assign(parsed.group("key"), value)

    mapping = json_map(rule)
    for option in rule.iter_options("event_id"):
        if option.value is None or "event_id" not in mapping:
            continue
        first = next((v.strip() for v in option.value.split(",") if v.strip()), "")
        assign(mapping["event_id"], int(first) if first.isdigit() else first)
    return body


def negated_json_conditions(rule: SaganRule) -> list[tuple[str, str]]:
    """Key and value of every negated JSON condition, keys as an event has them.

    The probe that sets one of these is what stops a converter from dropping
    the negation altogether: with the key present and holding something else,
    the base probe fires whether the negation was carried across or not.
    """
    found: list[tuple[str, str]] = []
    for keyword in ("json_content", "json_meta_content"):
        for option in rule.iter_options(keyword):
            if option.value is None:
                continue
            parsed = _JSON_ARGS.match(option.value)
            if parsed is None or parsed.group("neg") != "!":
                continue
            first = next(
                (
                    v.strip().strip('"')
                    for v in parsed.group("rest").split(",")
                    if v.strip()
                ),
                "",
            )
            key = parsed.group("key")
            found.append((rule.key_restorations.get(key, key), decode_hex(first)))
    return found


#: `event_id: 4663,567` and friends.
_EVENT_ID = re.compile(r"event_id\s*:\s*([0-9,\s]+)", re.I)


def unbound_event_id(rule: SaganRule) -> str | None:
    """The first id an `event_id` option lists, when nothing binds the key.

    With a `json_map` binding, `Event_ID()` compares the decoded value and this
    returns None. Without one, 1,959 corpus rules, it searches `" <id>: "` in
    the first nine characters of the message, and the converter does not
    reproduce that: it assumes a structured `EventID` field and says so with
    `D_EVENT_ID_HEURISTIC`.

    The probe therefore carries both, the prefix for the engine and the field
    for the converted rule, deliberately and for the same reason the clocks are
    aligned for `alert_time`: the divergence is declared and already measured,
    so what is left to compare is everything else in the rule. Without it those
    rules cannot fire on the Sagan side at all, and a run counts them as judged
    while deciding nothing about them.
    """
    if "event_id" in json_map(rule):
        return None
    match = _EVENT_ID.search(rule.raw)
    if match is None:
        return None
    ids = [part.strip() for part in match.group(1).split(",") if part.strip()]
    return ids[0] if ids else None


def event_id_field(rule: SaganRule) -> tuple[str, Any] | None:
    """The structured field a converted rule reads, when it assumes one.

    `EventID` is what `mapping/selectors.py` falls back to with no `json_map`
    binding. A pipeline does not produce it, so a differential taking its
    events from one has to add it after the fact, exactly as this does for a
    rendered event: the converted rule assumes a producer that emits it, and
    that assumption is what the probe grants so the rest of the rule can be
    compared.
    """
    identifier = unbound_event_id(rule)
    if identifier is None or rule.keywords & JSON_KEYWORDS:
        return None
    return "EventID", int(identifier) if identifier.isdigit() else identifier


def text_key(rule: SaganRule) -> str | None:
    """Body key the rule's raw-text search reaches, ``None`` on a plain event.

    Two ways a raw search ends up inside the document. ``json_map: "message"``
    redirects it to a named key, which the engine then searches instead of the
    body. Otherwise a rule combining raw text with JSON conditions arrives as a
    JSON document, and the engine searches that document as text, so the probe
    needs a region of its own inside it (:data:`PROBE_TEXT_KEY`).
    """
    mapping = json_map(rule)
    if "message" in mapping:
        return mapping["message"]
    if rule.keywords & JSON_KEYWORDS and rule.keywords & RAW_TEXT_KEYWORDS:
        return PROBE_TEXT_KEY
    return None


def _write(body: dict[str, Any], key: str, value: str) -> None:
    """Set a dotted key inside the document."""
    cursor = body
    parts = key.replace("[]", "").split(".")
    for part in parts[:-1]:
        cursor = cursor.setdefault(part, {})
    cursor[parts[-1]] = value


def wire_body(event: SaganEvent) -> str:
    """The exact text an event reaches the engine as.

    Both differentials and the enriched profile's ``sagan_raw`` field have to
    agree on this string, so it is produced in one place rather than
    reconstructed at each call site. For a JSON-bodied probe it is the
    serialisation chosen when the event was built, which is not always what
    ``json.dumps`` would produce today: see :func:`_serialise`.
    """
    return event.message


#: Templates tried when a raw literal has to be put back into a JSON document
#: as structure rather than as text. Each one wraps the literal into something
#: that may parse as an object, and the placement is kept only if the resulting
#: serialisation really contains the literal, so a template that lies is
#: harmless.
#:
#: They exist because the literals in these rules are slices of real documents:
#: `"mfaAuthenticated": "true"` is a whole member, `eventName": "CreateFunction`
#: one missing its outer quotes, `TrustType", "Value": "2"` a run starting in
#: the middle of one.
_MEMBER_TEMPLATES = (
    "{%s}",
    '{"%s"}',
    '{"sagan_probe_key"%s}',
    '{"sagan_probe_key": %s}',
    '{"sagan_probe_key": "%s}',
)

#: Serialisation styles tried for a JSON-bodied probe, spaced first. A rule's
#: literals were written against a real producer and producers differ on the
#: space after the colon: the AWS rules quote `"mfaAuthenticated": "true"` and
#: the Duo ones `:"confirmedSafe"`. Whichever style places more of the rule's
#: own literals is the one the probe uses.
_STYLES = ((", ", ": "), (",", ":"))


def _serialise(body: dict[str, Any], style: tuple[str, str]) -> str:
    return json.dumps(body, separators=style)


def _members(literal: str) -> dict[str, Any] | None:
    """The object members a literal is a fragment of, if it is one."""
    for template in _MEMBER_TEMPLATES:
        try:
            parsed = json.loads(template % literal)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _place(
    body: dict[str, Any], region: list[str], literal: str, style: tuple[str, str]
) -> bool:
    r"""Put one literal where the serialised document will contain it verbatim.

    Three placements are tried and each is *verified* by serialising, rather
    than reasoned about, because the reasoning is where this goes wrong: a
    literal carrying quotes is escaped when it lands in a string value, so both
    evaluators then search for text the document does not contain and agree on
    silence, which looks like success and measures nothing.

    ``region``  the plain-text area of the document, for literals that survive
                escaping unchanged;
    ``string``  the same area holding the literal's *unescaped* form, which is
                how a rule written against JSON-inside-JSON (``\\"TrustType\\"``)
                gets its escaped text back;
    ``members`` the literal rebuilt as structure, for fragments of the
                document's own shape.
    """
    trial = list(region)
    trial.append(literal)
    if literal in _serialise({**body, PROBE_TEXT_KEY: FILLER.join(trial)}, style):
        region.append(literal)
        return True

    try:
        unescaped = json.loads(f'"{literal}"')
    except ValueError:
        unescaped = None
    if isinstance(unescaped, str):
        trial = [*region, unescaped]
        if literal in _serialise({**body, PROBE_TEXT_KEY: FILLER.join(trial)}, style):
            region.append(unescaped)
            return True

    members = _members(literal)
    if (
        members is not None
        and not (members.keys() & body.keys())
        and literal in _serialise({**body, **members}, style)
    ):
        body.update(members)
        return True
    return False


def build_event(
    rule: SaganRule,
    literals: list[str],
    overrides: dict[str, str] | None = None,
) -> SaganEvent:
    """One event carrying exactly the raw-text literals it is given.

    Composing by literal rather than by editing a finished message is what lets
    the JSON path work at all: on a JSON-bodied event the engine searches the
    serialised document, so where a literal goes decides whether it is there to
    be found, and that placement has to be redone for every probe rather than
    patched into one.

    ``overrides`` replaces JSON keys after the body is built, which is how a
    probe puts back the value a rule negates.
    """
    body = json_body(rule)
    for name, value in (overrides or {}).items():
        _write(body, name, value)
    text = FILLER.join(literals) or "no conditions"
    key = text_key(rule)

    identifier = unbound_event_id(rule)

    if key is None:
        if not body:
            # A plain event carries the literals as its message.
            return _event(rule, _with_event_id(text, identifier), body)
        # A JSON-bodied rule with no raw-text option asks for no literal of its
        # own, so `probes` hands it none and the document is the whole event.
        # A caller that supplies one anyway means it: the correlation
        # differential plants addresses for a rule grouping on `parse_src_ip`,
        # and Sagan scans the serialised document for them like any other text.
        # Dropping them silently made the engine fall back to the syslog sender
        # and the case looked like a liblognorm resolution it never was.
        if literals:
            _write(body, PROBE_TEXT_KEY, text)
        return _event(rule, json.dumps(body), body)

    if key != PROBE_TEXT_KEY:
        # `json_map: "message"` redirects the search to a key, and the engine
        # then reads that key's parsed value, so the literals go in unchanged
        # and no escaping question arises.
        _write(body, key, text)
        return _event(rule, json.dumps(body), body)

    best: tuple[int, str, dict[str, Any]] | None = None
    for style in _STYLES:
        staged = json_body(rule)
        for name, value in (overrides or {}).items():
            _write(staged, name, value)
        region: list[str] = []
        placed = sum(_place(staged, region, literal, style) for literal in literals)
        staged[PROBE_TEXT_KEY] = FILLER.join(region) or "no conditions"
        if best is None or placed > best[0]:
            best = (placed, _serialise(staged, style), staged)
    assert best is not None
    return _event(rule, best[1], best[2])


def unplaceable(rule: SaganRule, literals: list[str]) -> list[str]:
    """Literals no probe for this rule can make the engine see.

    A literal that cannot be placed leaves both evaluators searching for text
    the document does not contain, so they agree without deciding anything.
    Reporting them is what keeps such a rule from being counted as measured.
    """
    event = build_event(rule, literals)
    return [literal for literal in literals if literal not in wire_body(event)]


def _with_event_id(message: str, identifier: str | None) -> str:
    """The message, carrying the id where the engine's nine-byte window sees it.

    A JSON-bodied probe gets nothing: the message there is the serialised
    document, and a prefix would stop it being JSON. Such a rule cannot satisfy
    the fallback on a real event either, the first characters of a document
    never being `" <id>: "`.
    """
    return f" {identifier}: {message}" if identifier else message


def _event(rule: SaganRule, message: str, body: dict[str, Any]) -> SaganEvent:
    facility = "daemon"
    for option in rule.iter_options("syslog_facility"):
        if option.value:
            facility = option.value.split("|")[0].strip()
    level = "info"
    for option in rule.iter_options("syslog_level"):
        if option.value:
            level = option.value.split("|")[0].strip()
    return SaganEvent(
        program=program_value(rule),
        message=message,
        facility=facility,
        level=level,
        json_body=body,
    )


def build_base(
    rule: SaganRule, variables: dict[str, list[str]] | None = None
) -> SaganEvent:
    """The event every positive condition is satisfied by."""
    return build_event(rule, positive_literals(rule, variables))


def probes(
    rule: SaganRule,
    variables: dict[str, list[str]] | None = None,
    context: Sequence[str] = (),
) -> list[Probe]:
    """Battery of events probing one rule's boundaries.

    ``context`` is text every probe carries, ahead of the rule's own literals,
    for a condition the rule depends on without naming it. A rule reading a
    denylist flag is the case: nothing in its text says which address has to be
    on the list, and an event carrying none leaves both evaluators silent, so
    the probe is given addresses the feed lists. It is placed first so the
    positional parse sees it before anything the rule's own literals contain.
    """
    positives = positive_literals(rule, variables)
    given = list(context)

    def event(literals: list[str]) -> SaganEvent:
        return build_event(rule, [*given, *literals])

    out = [Probe("base", event(positives))]

    flipped = [literal.swapcase() for literal in positives]
    if flipped != positives:
        out.append(Probe("case_flipped", event(flipped)))

    for index, _literal in enumerate(positives):
        remaining = [
            item for position, item in enumerate(positives) if position != index
        ]
        out.append(Probe(f"missing_{index}", event(remaining)))

    for index, literal in enumerate(negative_literals(rule)):
        out.append(Probe(f"negation_{index}", event([*positives, literal])))

    if rule.has("program") or rule.has("event_type"):
        out.append(
            Probe(
                "wrong_program",
                replace(event(positives), program="zzz-unrelated"),
            )
        )

    for index, (key, value) in enumerate(negated_json_conditions(rule)):
        out.append(
            Probe(
                f"json_negation_{index}",
                build_event(rule, [*given, *positives], overrides={key: value}),
            )
        )

    out.append(Probe("wildcard_probe", event([*positives, "literal*star"])))
    return out


def to_rsigma_event(
    event: SaganEvent, rule: SaganRule, profile: Profile | None = None
) -> dict[str, Any]:
    """Render a Sagan event exactly as the profile's pipeline would expose it.

    The shape is read from the profile rather than written out here, because
    the converter reads the same table: a name that drifts then breaks both
    sides at once instead of producing a disagreement nobody can attribute.

    Under ``rsigma-syslog`` the two shapes are genuinely different, and
    conflating them is what let a real defect hide for a while. Reading
    ``crates/rsigma-runtime/src/input/syslog.rs``:

    * a **JSON body** is parsed and returned as the object itself, with the
      envelope merged back in under ``syslog_`` prefixed names and **no**
      ``_raw`` field at all;
    * a **plain body** produces unprefixed ``appname``, ``hostname``,
      ``facility``, ``severity`` plus ``_raw``.

    Both were confirmed by running the engine, not merely read.

    Under ``vector-enriched`` there is one flat object either way, and the
    original body survives in the profile's ``json_raw`` field. The envelope
    still moves aside for a JSON body, under the same prefixed names, because
    the body's keys belong to a producer and two of them collide with the
    syslog envelope in the upstream corpus.
    """
    profile = profile or load_profile("rsigma-syslog")
    json_event = bool(rule.keywords & JSON_KEYWORDS)

    payload: dict[str, Any] = dict(event.json_body) if json_event else {}
    structured = event_id_field(rule)
    if structured is not None:
        payload[structured[0]] = structured[1]
    payload[profile.envelope_field("program", json_event)] = event.program
    payload[profile.envelope_field("syslog_host", json_event)] = "sensor01"
    payload[profile.envelope_field("facility", json_event)] = event.facility
    payload[profile.envelope_field("level", json_event)] = event.level

    if not json_event:
        payload[profile.field("message")] = event.message
    elif profile.json_raw is not None:
        # The raw body the pipeline preserves is the same string the engine was
        # handed, so both sides search identical text. The field the plain
        # events use is gone here: `sagan-json.vrl` drops it rather than let it
        # shadow a body key of the same name.
        payload[profile.json_raw] = wire_body(event)
    return payload
