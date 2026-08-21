"""Stable taxonomy of conversion refusals and degradations.

The values of :class:`RefusalCode` and :class:`DegradationCode` are part of the
public contract of the tool: they appear in the Markdown conversion report and
in the JSON output. They may gain new members, but existing values must never
change, because downstream tooling keys off them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RefusalCode(str, Enum):
    """Why a Sagan rule could not be converted."""

    PARSE = "E_PARSE"
    NO_DETECTION = "E_NO_DETECTION"
    POSITIONAL = "E_POSITIONAL"
    EXTERNAL_ENRICHMENT = "E_EXTERNAL_ENRICHMENT"
    TIME_WINDOW = "E_TIME_WINDOW"
    STATE_ABSENCE = "E_STATE_ABSENCE"
    GROUPBY_UNRESOLVED = "E_GROUPBY_UNRESOLVED"
    VAR_UNRESOLVED = "E_VAR_UNRESOLVED"
    PCRE_UNSUPPORTED = "E_PCRE_UNSUPPORTED"
    BASE64_FIELD_DECODE = "E_BASE64_FIELD_DECODE"
    PASS_RULE = "E_PASS_RULE"
    RAW_TEXT_ON_JSON_EVENT = "E_RAW_TEXT_ON_JSON_EVENT"
    UNKNOWN_KEYWORD = "E_UNKNOWN_KEYWORD"
    SIGMA_INVALID = "E_SIGMA_INVALID"


class DegradationCode(str, Enum):
    """Semantic loss accepted on an otherwise converted rule."""

    THRESHOLD_SUPPRESS = "D_THRESHOLD_SUPPRESS"
    THRESHOLD_LIMIT = "D_THRESHOLD_LIMIT"
    XBIT_SET_DROPPED = "D_XBIT_SET_DROPPED"
    XBIT_ISSET_SYNTHETIC = "D_XBIT_ISSET_SYNTHETIC"
    XBIT_AGGREGATE_TRUNCATED = "D_XBIT_AGGREGATE_TRUNCATED"
    SIDE_EFFECT_DROPPED = "D_SIDE_EFFECT_DROPPED"
    LOGSOURCE_FALLBACK = "D_LOGSOURCE_FALLBACK"
    RAW_TEXT_MATCH = "D_RAW_TEXT_MATCH"
    GROUPBY_SYSLOG_HOST = "D_GROUPBY_SYSLOG_HOST"
    APPEND_PROGRAM = "D_APPEND_PROGRAM"
    DROP_ACTION = "D_DROP_ACTION"
    PASS_SHORT_CIRCUIT = "D_PASS_SHORT_CIRCUIT"
    EVENT_ID_HEURISTIC = "D_EVENT_ID_HEURISTIC"
    NORMALIZE_PRECEDENCE = "D_NORMALIZE_PRECEDENCE"
    POSITIONAL_IP_FIELD = "D_POSITIONAL_IP_FIELD"
    GEOIP_COUNTRY_ENRICHMENT = "D_GEOIP_COUNTRY_ENRICHMENT"
    ALERT_TIME_EVENT_CLOCK = "D_ALERT_TIME_EVENT_CLOCK"
    DENYLIST_USERNAME_INERT = "D_DENYLIST_USERNAME_INERT"
    DENYLIST_ENRICHMENT = "D_DENYLIST_ENRICHMENT"
    ZEEK_INTEL_ENRICHMENT = "D_ZEEK_INTEL_ENRICHMENT"
    BLUEDOT_SUBSTITUTION = "D_BLUEDOT_SUBSTITUTION"
    AFTER_BY_STRING_INERT = "D_AFTER_BY_STRING_INERT"


REFUSAL_HELP: dict[RefusalCode, str] = {
    RefusalCode.PARSE: (
        "The rule could not be parsed, or it uses a construct that Sagan "
        "itself would reject at load time."
    ),
    RefusalCode.NO_DETECTION: (
        "The rule can never produce an alert: nothing is left to match on after "
        "conversion (it carried only side effects or metadata), or it carries a "
        "mandatory condition the engine can never satisfy, so it never fires in "
        "Sagan either."
    ),
    RefusalCode.POSITIONAL: (
        "The rule constrains where a pattern sits in the log line with a "
        "non-zero offset, depth or distance. Sigma string modifiers cannot "
        "express a byte position, so no faithful translation exists. A "
        "zero-valued positional is a no-op in the Sagan engine and is converted."
    ),
    RefusalCode.EXTERNAL_ENRICHMENT: (
        "The rule queries an external source. Bluedot threat intelligence is out "
        "of scope. GeoIP country_code, blacklist denylists and zeek-intel feeds "
        "do convert under --profile vector-enriched, whose bundled transforms "
        "supply the country and threat-intel fields from a database; they are "
        "refused here only when that profile is not in use or the tracked address "
        "is not parsed."
    ),
    RefusalCode.TIME_WINDOW: (
        "The rule only fires on given weekdays or hour ranges (alert_time). "
        "Sigma has no recurring-time operator, so this is refused unless "
        "--profile vector-enriched is used, whose bundled time transform "
        "supplies the weekday and hour-of-day fields the window matches on."
    ),
    RefusalCode.STATE_ABSENCE: (
        "The rule requires that an earlier event did NOT happen (xbits or "
        "flexbits isnotset). Sigma cannot express a negative correlation."
    ),
    RefusalCode.GROUPBY_UNRESOLVED: (
        "The group-by key required by after does not exist as a field in any "
        "event: Sagan derives it by regular expression from the raw text or "
        "through liblognorm. It has to be produced upstream, in the ingestion "
        "pipeline."
    ),
    RefusalCode.VAR_UNRESOLVED: (
        "The rule references a sagan.yaml variable that was not supplied. "
        "Re-run with --sagan-yaml to resolve it."
    ),
    RefusalCode.PCRE_UNSUPPORTED: (
        "The regular expression uses a PCRE construct the Rust engine cannot "
        "express and the converter cannot safely rewrite (recursion, "
        "look-around, back-references, control verbs). Recoverable constructs "
        "(numbered subroutines, literal braces, the whole-string negation "
        "idiom, inert flags) are rewritten instead of refused."
    ),
    RefusalCode.BASE64_FIELD_DECODE: (
        "Sagan decodes the field value before comparing; Sigma's base64 "
        "modifier encodes the searched pattern instead. The two only agree "
        "when the encoding aligns on byte boundaries, which is not guaranteed."
    ),
    RefusalCode.PASS_RULE: (
        "Retained for backward compatibility; no longer emitted. Pass rules were "
        "once refused on the assumption that they suppressed silently. The Sagan "
        "engine source shows a matching pass rule still emits an alert and only "
        "then stops evaluating the remaining signatures, so pass rules now "
        "convert as alerts and carry the D_PASS_SHORT_CIRCUIT degradation."
    ),
    RefusalCode.RAW_TEXT_ON_JSON_EVENT: (
        "The rule searches the raw message body while also using JSON "
        "operators. When the syslog body is a JSON document, RSigma exposes the "
        "parsed object and no raw field at all, so the text search could never "
        "match. Convert with --profile vector-enriched, whose pipeline keeps the "
        "original body in sagan_raw for the text search to run against; or add a "
        "json_map binding message to the key that carries the text."
    ),
    RefusalCode.UNKNOWN_KEYWORD: (
        "The rule uses a Sagan keyword that no handler covers. This is how the "
        "tool surfaces new upstream keywords instead of silently dropping them."
    ),
    RefusalCode.SIGMA_INVALID: (
        "The emitted document was rejected by pySigma. This is a converter "
        "defect; please open an issue with the offending SID."
    ),
}

DEGRADATION_HELP: dict[DegradationCode, str] = {
    DegradationCode.THRESHOLD_SUPPRESS: (
        "threshold type suppress caps alert volume, not detection. Carried "
        "over as custom_attributes['rsigma.suppress']."
    ),
    DegradationCode.THRESHOLD_LIMIT: (
        "threshold type limit caps alert volume, not detection. Sigma has no "
        "equivalent, so the constraint is dropped."
    ),
    DegradationCode.XBIT_SET_DROPPED: (
        "The rule set or tested an xbit that no converted rule consumes. The "
        "state link is lost."
    ),
    DegradationCode.XBIT_ISSET_SYNTHETIC: (
        "The state correlation was rebuilt through a synthetic aggregate rule "
        "gathering every rule that sets the bit."
    ),
    DegradationCode.XBIT_AGGREGATE_TRUNCATED: (
        "The bit has more setter rules than the aggregate branch limit; the "
        "aggregate rule covers only the first branches."
    ),
    DegradationCode.SIDE_EFFECT_DROPPED: (
        "Engine-specific side effect (external, email, dynamic_load, unset) "
        "with no Sigma equivalent."
    ),
    DegradationCode.LOGSOURCE_FALLBACK: (
        "No catalog entry covers this source file, so a generic logsource was applied."
    ),
    DegradationCode.RAW_TEXT_MATCH: (
        "Detection runs against the raw message body. The rule works under "
        "RSigma but is not portable to other Sigma backends."
    ),
    DegradationCode.GROUPBY_SYSLOG_HOST: (
        "after track by_src with no IP extraction: Sagan falls back to the "
        "syslog sender, so grouping is per emitting host, not per attacker IP."
    ),
    DegradationCode.APPEND_PROGRAM: (
        "append_program makes Sagan append the program field to the message "
        "before matching. The converted rule searches the message alone."
    ),
    DegradationCode.DROP_ACTION: (
        "The rule used the drop action. Sigma has no action concept; it was "
        "converted as a normal detection rule."
    ),
    DegradationCode.PASS_SHORT_CIRCUIT: (
        "The rule used the pass action. In Sagan a matching pass rule still "
        "emits an alert (Send_Alert runs before the pass check) and then stops "
        "evaluating the remaining signatures for that event. The detection is "
        "converted faithfully; only the short-circuit, the suppression of other "
        "rules on the same event, is not reproduced, since Sigma evaluates every "
        "rule independently."
    ),
    DegradationCode.EVENT_ID_HEURISTIC: (
        "Without a json_map for event_id, Sagan looks for ' <id>: ' in the "
        "first 10 bytes of the message. The converted rule assumes a proper "
        "EventID field instead."
    ),
    DegradationCode.NORMALIZE_PRECEDENCE: (
        "The rule carries both normalize and parse_src_ip. Sagan lets "
        "liblognorm win when it resolves the address and falls back to "
        "positional parsing otherwise; only the fallback is reproduced."
    ),
    DegradationCode.POSITIONAL_IP_FIELD: (
        "The group-by key comes from the bundled VRL transform rather than "
        "from the log itself. The correlation only works if that transform "
        "runs in the ingestion pipeline."
    ),
    DegradationCode.GEOIP_COUNTRY_ENRICHMENT: (
        "country_code is resolved against a GeoIP country field produced by the "
        "bundled Vector enrichment, not from the log itself. The rule only fires "
        "if that enrichment, and its IP-to-country database (DB-IP by default; "
        "MaxMind or IPLocate also work), run in the ingestion pipeline. Sagan "
        "evaluates GeoIP on the address at processing time; the converted rule "
        "evaluates it on the extracted address field."
    ),
    DegradationCode.DENYLIST_USERNAME_INERT: (
        "The blacklist keyword tracked by_username, which the engine's denylist "
        "processor ignores: it matches IP addresses only (src/processors/"
        "blacklist.c), and the rule parser sets no flag for by_username "
        "(src/rules.c), so the option is inert. It is dropped and the rest of the "
        "rule is converted, exactly as the engine evaluates it."
    ),
    DegradationCode.DENYLIST_ENRICHMENT: (
        "blacklist matches the address against an IP denylist the bundled Vector "
        "enrichment carries, not the log itself. The rule only fires if that "
        "enrichment, built from a feed such as SANS DShield, runs in the ingestion "
        "pipeline. Sagan evaluates the denylist on the address at processing time; "
        "the converted rule evaluates it on the extracted address field."
    ),
    DegradationCode.ZEEK_INTEL_ENRICHMENT: (
        "zeek-intel matches the address against a Zeek Intelligence Framework feed "
        "the bundled Vector enrichment carries, not the log itself. The rule only "
        "fires if that enrichment, built from a feed such as CriticalPathSecurity's "
        "Zeek-Intelligence-Feeds, runs in the ingestion pipeline. Only the address "
        "indicators the rule keyword uses are reproduced, not the domain, hash or "
        "URL indicators the feed may also carry."
    ),
    DegradationCode.BLUEDOT_SUBSTITUTION: (
        "bluedot queries Quadrant's Bluedot threat-intelligence API, which is a "
        "closed commercial source that cannot be redistributed. This conversion "
        "deliberately SUBSTITUTES it: the rule matches the parsed address against "
        "open-source feeds you supply, one per Bluedot category (Tor, Proxy, "
        "Malicious, Honeypot), so it fires on your feed's addresses, not on "
        "Bluedot's. This is the project's one accepted break from faithful "
        "conversion, taken because a bluedot rule that is not converted can never "
        "fire under RSigma at all, whereas a substituted one keeps the detection "
        "intent. Fidelity varies by category: Tor is near-authoritative (the Tor "
        "Project exit list is the same public ground truth Bluedot derives from); "
        "Malicious, Proxy and Honeypot depend entirely on the feed you choose and "
        "will diverge from Bluedot's verdicts. Only the address (ip_reputation) "
        "lookup is reproduced; hash and URL lookups are still refused."
    ),
    DegradationCode.AFTER_BY_STRING_INERT: (
        "after tracked by_string, which that parser never recognises: it tests "
        "an option token strtok_r has already truncated to 'track', so the "
        "branch is dead. Sagan groups on the remaining keys only, and rejects "
        "the rule outright when by_string is the only key. Confirmed against a "
        "locally built engine. threshold is unaffected: its parser tests the "
        "intact token, so there by_string really is a synonym for by_username."
    ),
    DegradationCode.ALERT_TIME_EVENT_CLOCK: (
        "alert_time matches against weekday and hour-of-day fields the bundled "
        "Vector time transform derives from the event timestamp. Sagan evaluates "
        "the window against the wall clock at processing time, not the event's "
        "own time; the two coincide in near-real-time ingestion. The comparison "
        "uses the timezone Vector formats in, which must match the Sagan host's "
        "local time for the window to align."
    ),
}


class ConversionError(Exception):
    """Base error of the converter."""


@dataclass(frozen=True)
class Refusal(ConversionError):
    """Structured refusal carrying a stable code and a readable detail."""

    code: RefusalCode
    detail: str
    keywords: tuple[str, ...] = ()

    def __str__(self) -> str:
        """Render as ``[CODE] detail``, the form used throughout the report."""
        return f"[{self.code.value}] {self.detail}"


@dataclass(frozen=True)
class Degradation:
    """Semantic loss recorded against a converted rule."""

    code: DegradationCode
    detail: str
