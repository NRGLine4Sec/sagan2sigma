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
``wrong_program``
    an unrelated program value. Neither side should fire.
``wildcard_probe``
    a message containing a literal asterisk, which distinguishes a correctly
    escaped literal from an accidental Sigma wildcard.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any

from sagan2sigma.sagan.hexdec import decode_hex
from sagan2sigma.sagan.model import SaganRule

from .sagan_reference import SaganEvent, expand_values, json_map

_META = re.compile(r'^\s*(?P<neg>!?)\s*"(?P<pattern>.*?)"\s*,\s*(?P<values>.+)$', re.S)
_JSON_ARGS = re.compile(
    r'^\s*(?P<neg>!?)\s*"?\.?(?P<key>[A-Za-z0-9_.\[\]@-]+)"?\s*,\s*(?P<rest>.+)$', re.S
)

#: Filler placed between literals so that concatenation cannot accidentally
#: create a match for something the rule did not ask for.
FILLER = " ~ "


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
        match = _META.match(option.value)
        if match is None or match.group("neg") == "!":
            continue
        pattern = decode_hex(match.group("pattern"))
        values = expand_values(match.group("values"), variables or {})
        if values:
            literals.append(pattern.replace("%sagan%", values[0]))
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
        parts = key.replace("[]", "").split(".")
        cursor = body
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = value

    for keyword in ("json_content", "json_meta_content"):
        for option in rule.iter_options(keyword):
            if option.value is None:
                continue
            parsed = _JSON_ARGS.match(option.value)
            if parsed is None or parsed.group("neg") == "!":
                continue
            first = next(
                (
                    v.strip().strip('"')
                    for v in parsed.group("rest").split(",")
                    if v.strip()
                ),
                "",
            )
            assign(parsed.group("key"), decode_hex(first))

    mapping = json_map(rule)
    for option in rule.iter_options("event_id"):
        if option.value is None or "event_id" not in mapping:
            continue
        first = next((v.strip() for v in option.value.split(",") if v.strip()), "")
        assign(mapping["event_id"], int(first) if first.isdigit() else first)
    return body


def build_base(
    rule: SaganRule, variables: dict[str, list[str]] | None = None
) -> SaganEvent:
    """The event every positive condition is satisfied by."""
    body = json_body(rule)
    message = FILLER.join(positive_literals(rule, variables)) or "no conditions"

    mapping = json_map(rule)
    if "message" in mapping:
        # The rule redirects the text search into a JSON key, so that is where
        # the literals have to live.
        cursor = body
        parts = mapping["message"].replace("[]", "").split(".")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = message
        message = json.dumps(body)

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


def _with_text(event: SaganEvent, rule: SaganRule, text: str) -> SaganEvent:
    """Copy of the event whose searched text is replaced."""
    mapping = json_map(rule)
    if "message" not in mapping:
        return replace(event, message=text)
    body = json.loads(json.dumps(event.json_body))
    cursor = body
    parts = mapping["message"].replace("[]", "").split(".")
    for part in parts[:-1]:
        cursor = cursor.setdefault(part, {})
    cursor[parts[-1]] = text
    return replace(event, message=json.dumps(body), json_body=body)


def probes(
    rule: SaganRule, variables: dict[str, list[str]] | None = None
) -> list[Probe]:
    """Battery of events probing one rule's boundaries."""
    base = build_base(rule, variables)
    positives = positive_literals(rule, variables)
    searched = base.json_body if json_map(rule).get("message") else None
    text = (
        _read(searched, json_map(rule)["message"])
        if searched is not None
        else base.message
    )

    out = [Probe("base", base)]

    flipped = text.swapcase()
    if flipped != text:
        out.append(Probe("case_flipped", _with_text(base, rule, flipped)))

    for index, _literal in enumerate(positives):
        remaining = [
            item for position, item in enumerate(positives) if position != index
        ]
        out.append(
            Probe(f"missing_{index}", _with_text(base, rule, FILLER.join(remaining)))
        )

    for index, literal in enumerate(negative_literals(rule)):
        out.append(
            Probe(
                f"negation_{index}",
                _with_text(base, rule, text + FILLER + literal),
            )
        )

    if rule.has("program") or rule.has("event_type"):
        out.append(Probe("wrong_program", replace(base, program="zzz-unrelated")))

    out.append(
        Probe("wildcard_probe", _with_text(base, rule, text + FILLER + "literal*star"))
    )
    return out


def _read(body: dict[str, Any], key: str) -> str:
    cursor: Any = body
    for part in key.replace("[]", "").split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return ""
        cursor = cursor[part]
    return str(cursor)


#: Keywords that make a rule target JSON-bodied events, mirroring the
#: converter's own criterion.
JSON_KEYWORDS = frozenset(
    {"json_content", "json_meta_content", "json_pcre", "json_map"}
)


def to_rsigma_event(event: SaganEvent, rule: SaganRule) -> dict[str, Any]:
    """Render a Sagan event exactly as RSigma would expose it.

    The two shapes are genuinely different, and conflating them is what let a
    real defect hide for a while. Reading
    ``crates/rsigma-runtime/src/input/syslog.rs``:

    * a **JSON body** is parsed and returned as the object itself, with the
      envelope merged back in under ``syslog_`` prefixed names and **no**
      ``_raw`` field at all;
    * a **plain body** produces unprefixed ``appname``, ``hostname``,
      ``facility``, ``severity`` plus ``_raw``.

    Both were confirmed by running the engine, not merely read.
    """
    if rule.keywords & JSON_KEYWORDS:
        payload: dict[str, Any] = dict(event.json_body)
        payload["syslog_appname"] = event.program
        payload["syslog_hostname"] = "sensor01"
        payload["syslog_facility"] = event.facility
        payload["syslog_severity"] = event.level
        return payload

    return {
        "appname": event.program,
        "hostname": "sensor01",
        "facility": event.facility,
        "severity": event.level,
        "_raw": event.message,
    }
