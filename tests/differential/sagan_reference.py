"""An independent reference evaluator for Sagan detection semantics.

This module exists to be *wrong in different ways* from the converter.

Every other test in this suite checks that ``sagan2sigma`` produces the output
we expect. That cannot catch a mistaken belief about what Sagan does, because
the same belief shapes both the code and the expectation. A differential test
needs a second opinion, so this evaluator is written from the engine's C source
rather than from the converter's mapping layer, and deliberately imports
nothing from ``sagan2sigma.mapping``.

What it implements, and where the behaviour comes from:

``program``
    ``Wildcard()`` in ``src/util.c``: a full-string glob over ``*`` and ``?``,
    case-sensitive. ``|`` splits alternatives (``strtok_r`` in
    ``src/processors/engine.c``).
``content``
    case-sensitive substring search, disabled by a following ``nocase``.
    ``|xx|`` sequences are raw bytes. ``*`` and ``?`` are literal.
``meta_content``
    the ``%sagan%`` template instantiated once per value, matching if any
    instance is present.
``json_content`` / ``json_meta_content``
    value comparison on a JSON key, exact unless ``json_contains``, and
    case-sensitive unless ``json_nocase``.
``event_id``
    numeric comparison against the key bound by ``json_map``.
``syslog_facility`` / ``syslog_level``
    case-insensitive alternatives.

Negated options must all fail for the rule to fire, and every positive option
must succeed: Sagan ANDs its conditions.

Deliberately out of scope: ``pcre`` (event generation for an arbitrary regular
expression is a different problem), correlation keywords, and positional
matching. Rules using those are skipped by the harness rather than evaluated
approximately.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sagan2sigma.sagan.hexdec import decode_hex
from sagan2sigma.sagan.model import SaganRule

#: Options this evaluator understands. A rule using anything else is skipped.
SUPPORTED = frozenset(
    {
        "msg",
        "sid",
        "rev",
        "classtype",
        "reference",
        "metadata",
        "priority",
        "program",
        "event_type",
        "content",
        "nocase",
        "meta_content",
        "meta_nocase",
        "event_id",
        "syslog_facility",
        "syslog_level",
        "json_content",
        "json_nocase",
        "json_contains",
        "json_strstr",
        "json_meta_content",
        "json_meta_nocase",
        "json_meta_contains",
        "json_meta_strstr",
        "json_map",
        "default_proto",
        "default_dst_port",
        "default_src_port",
    }
)

_META = re.compile(r'^\s*(?P<neg>!?)\s*"(?P<pattern>.*?)"\s*,\s*(?P<values>.+)$', re.S)
_JSON_ARGS = re.compile(
    r'^\s*(?P<neg>!?)\s*"?\.?(?P<key>[A-Za-z0-9_.\[\]@-]+)"?\s*,\s*(?P<rest>.+)$', re.S
)


@dataclass(slots=True)
class SaganEvent:
    """One log line as the Sagan engine sees it."""

    program: str = "syslog"
    message: str = ""
    facility: str = "daemon"
    level: str = "info"
    #: Parsed JSON body, when the message is a JSON document.
    json_body: dict[str, Any] = field(default_factory=dict)


def wildcard(pattern: str, value: str) -> bool:
    """Sagan's ``Wildcard()``: full-string glob, case-sensitive.

    >>> wildcard("sshd", "sshd"), wildcard("ssh", "sshd")
    (True, False)
    >>> wildcard("*Security*", "MSWinEventLog Security Log")
    True
    >>> wildcard("ssh?", "sshd"), wildcard("SSHD", "sshd")
    (True, False)
    """
    if not pattern and not value:
        return True
    if pattern.startswith("*") and len(pattern) > 1 and not value:
        return False
    if pattern and value and (pattern[0] == "?" or pattern[0] == value[0]):
        return wildcard(pattern[1:], value[1:])
    if pattern.startswith("*"):
        return wildcard(pattern[1:], value) or wildcard(pattern, value[1:])
    return False


def _contains(haystack: str, needle: str, nocase: bool) -> bool:
    if nocase:
        return needle.lower() in haystack.lower()
    return needle in haystack


def _json_lookup(body: dict[str, Any], key: str) -> Any:
    """Resolve a dotted JSON key, tolerating the ``[]`` array marker."""
    current: Any = body
    for part in key.replace("[]", "").split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def json_map(rule: SaganRule) -> dict[str, str]:
    """``json_map`` bindings, read straight from the rule."""
    mapping: dict[str, str] = {}
    for option in rule.iter_options("json_map"):
        if option.value is None:
            continue
        parts = [p.strip().strip('"') for p in option.value.split(",", 1)]
        if len(parts) == 2:
            mapping[parts[0]] = parts[1].lstrip(".")
    return mapping


def is_supported(rule: SaganRule) -> bool:
    """Whether every option of the rule is one this evaluator implements."""
    return rule.keywords <= SUPPORTED


def expand_values(raw: str, variables: dict[str, list[str]]) -> list[str]:
    """Expand a Sagan value list, resolving ``$NAME`` against the variables.

    An unknown variable expands to nothing, which makes the enclosing condition
    unsatisfiable. That mirrors the engine, which refuses to start rather than
    match on a literal dollar sign.

    >>> expand_values("root,$USERS", {"USERS": ["bob", "frank"]})
    ['root', 'bob', 'frank']
    """
    values: list[str] = []
    for token in (part.strip() for part in raw.split(",")):
        if not token:
            continue
        if token.startswith("$"):
            values.extend(variables.get(token[1:].upper(), []))
        else:
            values.append(decode_hex(token.strip('"')))
    return values


class SaganEvaluator:
    """Evaluates one rule against one event."""

    def __init__(
        self, rule: SaganRule, variables: dict[str, list[str]] | None = None
    ) -> None:
        """Bind the evaluator to a rule and the variables it may reference."""
        self.rule = rule
        self.mapping = json_map(rule)
        self.variables = variables or {}

    def search_target(self, event: SaganEvent) -> str:
        """Text that ``content`` and ``meta_content`` search.

        ``json_map: "message", ".key"`` redirects the search to that key, which
        is the behaviour the converter mirrors with its FieldResolver.
        """
        redirect = self.mapping.get("message")
        if redirect is None:
            return event.message
        value = _json_lookup(event.json_body, redirect)
        return "" if value is None else str(value)

    def program_value(self, event: SaganEvent) -> str:
        """Value a ``program`` selector compares against."""
        redirect = self.mapping.get("program")
        if redirect is None:
            return event.program
        value = _json_lookup(event.json_body, redirect)
        return "" if value is None else str(value)

    def matches(self, event: SaganEvent) -> bool:
        """Whether the rule fires on this event."""
        return all(
            check(event)
            for check in (
                self._program,
                self._facility,
                self._level,
                self._event_id,
                self._content,
                self._meta_content,
                self._json_content,
                self._json_meta_content,
            )
        )

    # -- individual keywords ------------------------------------------------

    def _program(self, event: SaganEvent) -> bool:
        value = self.program_value(event)
        for option in self.rule.options:
            if option.name not in ("program", "event_type") or option.value is None:
                continue
            alternatives = [a.strip() for a in option.value.split("|") if a.strip()]
            if alternatives and not any(
                wildcard(decode_hex(a), value) for a in alternatives
            ):
                return False
        return True

    def _alternatives(self, event: SaganEvent, keyword: str, actual: str) -> bool:
        for option in self.rule.iter_options(keyword):
            if option.value is None:
                continue
            alternatives = [a.strip().lower() for a in option.value.split("|")]
            if alternatives and actual.lower() not in alternatives:
                return False
        return True

    def _facility(self, event: SaganEvent) -> bool:
        return self._alternatives(event, "syslog_facility", event.facility)

    def _level(self, event: SaganEvent) -> bool:
        return self._alternatives(event, "syslog_level", event.level)

    def _event_id(self, event: SaganEvent) -> bool:
        key = self.mapping.get("event_id")
        for option in self.rule.iter_options("event_id"):
            if option.value is None:
                continue
            wanted = {v.strip() for v in option.value.split(",") if v.strip()}
            if key is None:
                return False
            actual = _json_lookup(event.json_body, key)
            if actual is None or str(actual) not in wanted:
                return False
        return True

    def _content(self, event: SaganEvent) -> bool:
        target = self.search_target(event)
        for option in self.rule.iter_options("content"):
            if option.value is None:
                continue
            text = option.value.strip()
            negated = text.startswith("!")
            if negated:
                text = text[1:].strip()
            if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
                text = text[1:-1]
            nocase = "nocase" in self.rule.modifiers_after(
                option.index, frozenset({"nocase"})
            )
            present = _contains(target, decode_hex(text), nocase)
            if present == negated:
                return False
        return True

    def _meta_content(self, event: SaganEvent) -> bool:
        target = self.search_target(event)
        for option in self.rule.iter_options("meta_content"):
            if option.value is None:
                continue
            match = _META.match(option.value)
            if match is None:
                return False
            pattern = decode_hex(match.group("pattern"))
            values = expand_values(match.group("values"), self.variables)
            nocase = "meta_nocase" in self.rule.modifiers_after(
                option.index, frozenset({"meta_nocase"})
            )
            present = any(
                _contains(target, pattern.replace("%sagan%", value), nocase)
                for value in values
            )
            if present == (match.group("neg") == "!"):
                return False
        return True

    def _json_content(self, event: SaganEvent) -> bool:
        modifiers = frozenset({"json_nocase", "json_contains", "json_strstr"})
        for option in self.rule.iter_options("json_content"):
            if option.value is None:
                continue
            parsed = _JSON_ARGS.match(option.value)
            if parsed is None:
                return False
            flags = self.rule.modifiers_after(option.index, modifiers)
            actual = _json_lookup(event.json_body, parsed.group("key"))
            wanted = decode_hex(parsed.group("rest").strip().strip('"'))
            present = self._compare(
                actual,
                [wanted],
                nocase="json_nocase" in flags,
                substring=bool(flags & {"json_contains", "json_strstr"}),
            )
            if present == (parsed.group("neg") == "!"):
                return False
        return True

    def _json_meta_content(self, event: SaganEvent) -> bool:
        modifiers = frozenset(
            {"json_meta_nocase", "json_meta_contains", "json_meta_strstr"}
        )
        for option in self.rule.iter_options("json_meta_content"):
            if option.value is None:
                continue
            parsed = _JSON_ARGS.match(option.value)
            if parsed is None:
                return False
            flags = self.rule.modifiers_after(option.index, modifiers)
            actual = _json_lookup(event.json_body, parsed.group("key"))
            wanted = [
                decode_hex(v.strip().strip('"'))
                for v in parsed.group("rest").split(",")
                if v.strip()
            ]
            present = self._compare(
                actual,
                wanted,
                nocase="json_meta_nocase" in flags,
                substring=bool(flags & {"json_meta_contains", "json_meta_strstr"}),
            )
            if present == (parsed.group("neg") == "!"):
                return False
        return True

    @staticmethod
    def _compare(actual: Any, wanted: list[str], nocase: bool, substring: bool) -> bool:
        if actual is None:
            return False
        text = str(actual)
        if substring:
            return any(_contains(text, value, nocase) for value in wanted)
        if nocase:
            return text.lower() in {value.lower() for value in wanted}
        return text in set(wanted)
