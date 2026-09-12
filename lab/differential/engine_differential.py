#!/usr/bin/env python3
"""Judge converted rules against the real Sagan engine instead of a model of it.

`tests/differential/` already compares each converted rule's behaviour against
Sagan's, but the Sagan side is `sagan_reference.py`: 386 lines of Python written
by reading the engine's C. Its own docstring names the limitation:

    What it cannot catch: a misreading of the Sagan source that this evaluator
    and the converter happen to share.

That is not hypothetical. `after: count N` was read the same way twice, so the
harness reported perfect agreement while 970 correlations alerted an event
early, and only running the engine exposed it. This tool removes the model:
Sagan itself decides the Sagan side.

Two things follow. The agreement it reports is worth more, since no shared
misreading can survive it. And it judges rules the model had to skip: `pcre`
and effective positional constructs are ordinary work for the engine, and
together they are most of what `is_supported()` excludes.

The engine used is `bin/sagan-sane`, upstream plus two local fixes. The second
one matters for measurement rather than for crashes: upstream never initialises
`rulestruct[].after2` and grows that array with `realloc`, so a rule declaring
no correlation at all can read a stale flag, enter the `after` path, and then
alert only from the N+1th event. Measuring detection semantics against a binary
that can silently turn a rule into a correlation would attribute heap noise to
the converter.

Correlation rules are still out of scope here, for a different and honest
reason: `after`, `threshold` and the bit keywords need a sequence of events and
carry state between them, so a single probe cannot decide them. The engine lab
covers those separately, case by case, in `checks/check_correlation.py` and
`checks/check_flexbits.py`.

This cannot run in CI, which is why it lives here: it needs a compiled Sagan.
The Python harness stays in the repository as the light net that runs on every
push; this is the heavy one, run deliberately.

Usage
-----
    ./differential/engine_differential.py --rules <corpus dir> [--limit N]
                                         [--profile <name>]

Both sides are batched, which is what makes the corpus tractable: one Sagan run
carries hundreds of rules and hundreds of events, and one rsigma run does the
same, so 4,000 rules cost dozens of invocations rather than thousands.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Any

# Importing the repository writes .pyc files into its tree unless this is set,
# and the repository is the user's working copy, not scratch space.
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "differential"))

from harness import event as pipe_event  # noqa: E402
from harness import SANE  # noqa: E402
from harness import MissingBinary  # noqa: E402
from harness import alerts as run_sagan  # noqa: E402
from harness import config_with_processors  # noqa: E402

#: The converter and the probe generator both come from the repository, so this
#: tool always judges the code as it currently stands rather than a copy.
#: The lab lives inside the repository it measures, so the converter and
#: the probe generator it imports are always the ones in this checkout.
REPO = LAB.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from sagan2sigma.converter import Converter  # noqa: E402
from sagan2sigma.emit.sigma import build_rule_document, stable_uuid  # noqa: E402
from sagan2sigma.emit.yaml_io import dump_collection  # noqa: E402
from sagan2sigma.errors import DegradationCode, Refusal  # noqa: E402
from sagan2sigma.mapping.context import (  # noqa: E402
    Context,
    Profile,
    available_profiles,
    load_catalog,
    load_profile,
)
from sagan2sigma.sagan.config import load_config  # noqa: E402
from sagan2sigma.mapping.values import CasePolicy  # noqa: E402
from sagan2sigma.sagan.parser import parse_file  # noqa: E402
from sagan2sigma.upstream import DefectCode  # noqa: E402
from sagan2sigma.upstream import inspect as inspect_upstream  # noqa: E402
from sagan2sigma.mapping.geoip import COUNTRY_CODE, resolve_country_codes  # noqa: E402
from sagan2sigma.mapping.aetas import (  # noqa: E402
    _DAYS,
    _HOURS,
    _expand_variables,
)
from sagan2sigma.mapping.positional import effective_positional  # noqa: E402
from tests.differential.pcre_sample import sample_for  # noqa: E402
from sagan2sigma.sagan.pcre import engine_pattern  # noqa: E402
from tests.differential.events import (  # noqa: E402
    event_id_field,
    pcre_literals,
    JSON_KEYWORDS,
    json_arm_reachable,
    json_body,
    json_map,
    matches_either_shape,
    positive_literals,
    probes,
    to_rsigma_event,
    unplaceable,
    wire_body,
)
from vector_pipeline import (  # noqa: E402
    PRODUCED_BY,
    VectorPipeline,
    feed_files,
    listed_addresses,
    source_event,
)

RSIGMA = "rsigma"

#: Keywords whose verdict depends on events other than the one being judged.
#: A single probe cannot decide them, so such rules are counted and skipped
#: rather than reported as disagreements.
#:
#: `xbits` and `flexbits` are deliberately absent, because the keyword alone
#: does not make a rule stateful: it depends on the operation. Only `isset` and
#: `isnotset` consult state; `set` and `unset` write it after the rule has
#: already decided, so the detection is as local as any other. Measured: a rule
#: whose only bit option is `xbits: set` alerts on the first matching event,
#: exactly like the same rule without it, and so does `unset`. Excluding on the
#: keyword withheld 487 rules from judgement for no reason.
STATEFUL = frozenset({"after", "flexbits_pause", "xbits_pause"})

#: Bit operations that consult state written by an earlier event.
STATEFUL_BIT_OPS = frozenset({"isset", "isnotset"})

#: Probes that satisfy every positive condition of their rule, so that both
#: sides firing on one means the rule was decided rather than agreed about in
#: silence. The other two are the second shape of a rule the engine matches
#: either way: `plain_body` for a rule naming JSON without requiring it, where
#: for fourteen corpus rules the plain line is the arm the probe can satisfy,
#: the document being unable to carry an unbound `event_id` prefix or a literal
#: with quotes in it; `document_body` for a rule naming no JSON at all, which
#: the engine still matches against a document's serialised text. Counting only
#: `base` reported such rules as undecided while the run had decided them.
POSITIVE_PROBES = frozenset({"base", "plain_body", "document_body"})

#: Bit operations that suppress the alert. The rule still matches and still
#: writes its bit, but Sagan emits nothing, so the engine looks silent while
#: the converted rule fires. That is a property of the probe, not a defect, so
#: these rules are skipped. Measured on both keywords: identical rules with and
#: without `noalert` alert and stay silent respectively.
SILENCING_BIT_OPS = frozenset({"noalert", "noeve"})


def _bit_operations(rule: Any) -> set[str]:
    """The leading token of every `xbits` and `flexbits` option on a rule."""
    operations: set[str] = set()
    for keyword in ("xbits", "flexbits"):
        for option in rule.iter_options(keyword):
            if option.value:
                operations.add(option.value.split(",")[0].strip().lower())
    return operations


#: `threshold` is not in that set, because it caps alert volume rather than
#: changing detection: the first matching event alerts whatever the threshold
#: says, which is the converter's whole argument for carrying it as an
#: attribute instead of a correlation.
#:
#: It does bite the probe battery. Under `type suppress, count 1` only the
#: first match alerts, and the budget is consumed by *any* earlier matching
#: event in the batch, including probes belonging to other rules. Dropping the
#: rule's own second matching probe is not enough, which a first attempt here
#: assumed and measurement disproved.
#:
#: So the option is removed from the Sagan rule before the engine sees it.
#: That is the like-for-like comparison: the Sigma side carries no threshold
#: either, because the converter records it as an attribute rather than a
#: correlation. What the engine does with a threshold is pinned separately, in
#: checks/check_correlation.py, which is where that claim belongs.
_THRESHOLD_OPTION = re.compile(r"\s*threshold\s*:[^;]*;", re.I)


def strip_threshold(raw: str) -> str:
    """The rule as written, minus any `threshold` option."""
    return _THRESHOLD_OPTION.sub(" ", raw)


#: Keywords that stop the engine from loading the ruleset at all here.
#:
#: `dynamic_load` makes Sagan pull in further rule files when it sees matching
#: traffic, and it refuses to load a rule using it unless that processor is
#: configured. Enabling the processor would have the engine load rules this tool
#: never chose, so the comparison would no longer be about the rules under test.
#: The converter treats the keyword as a side effect with no detection meaning,
#: which is why skipping costs nothing that could be judged here anyway.
UNLOADABLE = frozenset({"dynamic_load"})

#: Defect codes that put a rule beyond this tool's reach, and why.
#:
#: A rule the engine refuses, or one that loads and can never match, is dead in
#: Sagan for a reason the converter deliberately does not reproduce: carrying an
#: engine defect into the converted rule would be faithful and useless. The two
#: sides then disagree by design, so judging such a rule measures the policy
#: rather than the conversion.
#:
#: This replaces an earlier `--skip-colon` flag, which dropped every rule whose
#: meta_content held a colon. That was both too broad and too narrow: too broad
#: because a positive meta_content is not dead, only wider than written, and too
#: narrow because it said nothing about the other ways a rule can be dead. The
#: exclusion now names the defect, and the run reports how many rules each code
#: accounted for, so the reader can check the list rather than take it on trust.
#: `INVERTED_CONDITION` joins them for the same reason in the other direction:
#: `pcre:!` is read as a positive `pcre` by the engine, and the converter
#: deliberately emits the negation the rule asks for rather than the assertion
#: the engine performs. Reproducing that one would be faithful and absurd.
#: `INERT_CONDITION` is here for the same reason as `INVERTED_CONDITION`, and
#: was found by the probe added for it. A `json_meta_content` item wrapped in
#: quotes is compared with its quotes, so a negated list of quoted items
#: excludes nothing; the converter emits the exclusion the rule reads, and the
#: engine ignores it. Judging that measures the policy, not the conversion.
#:
#: `PARTIAL_MATCH` is deliberately **not** here, though it was for a day. A
#: comma inside a quoted `meta_content` template pushes the closing quote onto
#: the first value, and the converter's own reader reproduces that split, so
#: both sides look for `"\powershell` and agree. The rule does not do what its
#: author meant, which is what the defect reports, but the conversion is
#: faithful and the differential can say so.
UNJUDGEABLE_DEFECTS = frozenset(
    {
        DefectCode.WILL_NOT_LOAD,
        DefectCode.CANNOT_MATCH,
        DefectCode.INVERTED_CONDITION,
        DefectCode.INERT_CONDITION,
    }
)

#: Degradations that record a divergence from the engine this tool chose not to
#: reproduce. Such a rule is expected to disagree, so judging it measures the
#: decision rather than the conversion, and the run reports how many were set
#: aside for each. Keeping the list here rather than in a flag means the
#: declared divergences and the exclusions are the same thing.
#:
#: `JSON_PCRE_ABSENT_KEY`: Sagan treats a key the event does not carry as a
#: match for `json_pcre`, alone among the JSON operators. Reproducing it would
#: make the converted rule fire on every event lacking the key, which is a
#: flood rather than a detection.
#:
#: `BLUEDOT_SUBSTITUTION`: Bluedot is Quadrant's closed threat-intel service,
#: which the engine queries over the network. The converted rule matches flags
#: an operator's own feeds produce instead, which the degradation states
#: outright, so the two sides are answering questions about different data and
#: would still be doing so if the service were reachable from here. That is a
#: substitution rather than a translation, and no run can judge it. 134 corpus
#: rules carry it.
#: `GEOIP_ADDRESS_NOT_THE_BOUND_ONE` used to be here and is gone: the converter
#: now emits a lookup for the key a rule binds, so the country it tests is the
#: country of that address rather than of whichever one the pipeline parsed
#: first. Those rules are judged like any other, which is the point of removing
#: a declared divergence rather than living with it.
DECLARED_DIVERGENCES = frozenset(
    {
        DegradationCode.JSON_PCRE_ABSENT_KEY,
        DegradationCode.BLUEDOT_SUBSTITUTION,
    }
)

#: Keywords whose rules need an address the feed lists, and the lab feed that
#: lists it. Nothing in such a rule's text says which address has to be on the
#: list, so an ordinary probe leaves both sides silent and the rule unjudged.
FEED_KEYWORDS = {
    "blacklist": "denylist",
    "zeek-intel": "zeek",
    # The old spelling, which the converter honours as an alias and two
    # corpus rules still use.
    "bro-intel": "zeek",
}


class DeclaredDivergence(Exception):
    """Raised for a rule whose conversion states it will not match the engine."""

    def __init__(self, code: DegradationCode) -> None:
        super().__init__(code.value)
        self.code = code


#: Internal values every profile resolves from the syslog line itself, so the
#: probe generator can produce them. Anything else a profile names is supplied
#: by a transform outside Sagan, which the probe does not run.
CARRIED_BY_THE_EVENT = frozenset(
    {"message", "program", "syslog_host", "facility", "level"}
)


def unsynthesised(
    profile: Profile, flags: dict[str, bool] | None = None
) -> tuple[set[str], list[re.Pattern[str]]]:
    """Fields the active profile promises that this run cannot produce.

    A rule reading such a field is silent on the Sigma side for a reason
    belonging to the instrument, so it is counted and skipped rather than
    reported.

    With no pipeline the probe is a syslog line, so every enrichment a profile
    names is out of reach. With one, ``flags`` says which transforms are
    running, and only the fields their absent siblings would have produced stay
    excluded: `vector_pipeline.PRODUCED_BY` maps each internal value to the
    transform that makes it. The set is empty for `rsigma-syslog` either way,
    that profile naming no enrichment at all.
    """
    excluded = {
        internal
        for internal in (*profile.fields, *profile.positional)
        if internal not in CARRIED_BY_THE_EVENT and not _is_produced(internal, flags)
    }
    exact = {
        profile.fields[internal] for internal in excluded if internal in profile.fields
    }
    patterns = [
        re.compile("^" + re.escape(template).replace(r"\{position\}", r"\d+") + "$")
        for internal, template in profile.positional.items()
        if internal in excluded
    ]
    return exact, patterns


def _is_produced(internal: str, flags: dict[str, bool] | None) -> bool:
    """Whether a running transform supplies this internal value."""
    if flags is None or internal not in PRODUCED_BY:
        return False
    required = PRODUCED_BY[internal]
    return required is None or bool(flags.get(required))


def detection_fields(document: dict[str, Any]) -> set[str]:
    """Every event field the emitted detection reads, modifiers stripped."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                found.add(str(key).split("|")[0])
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name, block in (document.get("detection") or {}).items():
        if name == "condition":
            continue
        walk(block)
    return found


def needs_enrichment(
    document: dict[str, Any], exact: set[str], patterns: list[re.Pattern[str]]
) -> str | None:
    """The first enriched field this rule reads, if any."""
    for field_name in sorted(detection_fields(document)):
        if field_name in exact or any(p.match(field_name) for p in patterns):
            return field_name
    return None


#: Set by --judge-dead-upstream; see the flag's help.
JUDGE_DEAD_UPSTREAM = False


#: A `content` hex sequence carrying 0a or 0d, which no probe can deliver.
#:
#: Sagan's pipe input is one event per line, so a probe built from such a
#: value carries a literal newline and arrives as two truncated lines: the
#: engine searches for the whole string and sees only the part before the
#: break. Verified on sid 5002210, whose `|28 29 0a 20 7b|` decodes to `()\n {`
#: and whose probe reaches the engine as `()`. The converted rule matches the
#: string in full, so the two sides disagree over a property of the transport
#: and not of the conversion.
#: Case-insensitive on purpose: the corpus writes both `|0d 0a|` and `|0D 0A|`,
#: and a case-sensitive pattern let the four zscaler rules through to be
#: reported as disagreements.
_CONTROL_IN_CONTENT = re.compile(r"\|[0-9a-f |]*\b0[ad]\b[0-9a-f |]*\|", re.I)


def _unprobeable(rule: Any) -> bool:
    """Whether no syslog line can carry this rule's own probe."""
    return bool(_CONTROL_IN_CONTENT.search(rule.raw))


def _upstream_defect(rule: Any) -> DefectCode | None:
    """The first defect that puts this rule beyond judgement, if any."""
    for defect in inspect_upstream(rule):
        if defect.code in UNJUDGEABLE_DEFECTS:
            return defect.code
    return None


@dataclass(frozen=True, slots=True)
class Verdict:
    """What each side decided about one rule and one probe."""

    sid: str
    probe: str
    sagan: bool
    sigma: bool
    message: str

    def __str__(self) -> str:
        fired = (
            "Sagan fired, Sigma did not" if self.sagan else "Sigma fired, Sagan did not"
        )
        return f"  sid {self.sid} probe {self.probe}: {fired}\n    {self.message[:120]}"


#: JSON keys the converted rules read a country for, filled by
#: `sigma_document` and handed to the pipeline once every rule has been
#: converted. The shipped transforms resolve the addresses they parse; a rule
#: binding one by name needs that key looked up as well.
GEOIP_KEYS: set[str] = set()


def sigma_document(rule: Any, converter: Converter) -> dict[str, Any] | None:
    """The Sigma document the converter emits, or None when it refuses.

    The document is returned rather than its YAML: a batch is serialised in one
    call, so ``dump_collection`` writes the ``---`` separators. Joining
    individually dumped documents leaves one malformed blob in which the engine
    sees only the first rule, and every other rule then reads as "Sigma did not
    fire" against a Sagan that did.
    """
    try:
        draft = converter.convert_rule(rule)
    except Refusal:
        return None
    if any(d.code in DECLARED_DIVERGENCES for d in draft.degradations):
        raise DeclaredDivergence(
            next(d.code for d in draft.degradations if d.code in DECLARED_DIVERGENCES)
        )
    GEOIP_KEYS.update(draft.geoip_keys)
    entry = converter.context.catalog.resolve(rule.source_file)
    document = build_rule_document(
        draft=draft,
        sid=rule.sid,
        rev=rule.rev,
        source_file=rule.source_file,
        logsource=entry,
        needs_name=False,
    )
    return document


def rsigma_hits(rules_file: Path, events: list[dict[str, Any]]) -> set[tuple[str, str]]:
    """Every ``(rule_title, event json)`` pair the engine reports as a match.

    One invocation for the whole batch. The event is echoed back with
    ``--include-event``, which is what lets a hit be tied to the probe that
    produced it without assuming the order of the output.
    """
    payload = "\n".join(json.dumps(e, sort_keys=True) for e in events)
    completed = subprocess.run(
        [
            RSIGMA,
            "engine",
            "eval",
            "--rules",
            str(rules_file),
            "--output-format",
            "ndjson",
            "--no-stats",
            "--include-event",
        ],
        input=payload,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"rsigma exited {completed.returncode}: {completed.stderr[-500:]}"
        )
    hits: set[tuple[str, str]] = set()
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        if "rule_id" not in row:
            continue
        hits.add((row["rule_id"], json.dumps(row["event"], sort_keys=True)))
    return hits


def _rfc3339(clock: tuple[str, str]) -> str:
    """The faked instant as the timestamp the pipeline reads.

    Both sides then decide on the same moment: Sagan because `faketime` moves
    its wall clock there, the converted rule because the event says so. The
    zone is applied to the wall-clock string rather than assumed, since
    `aetas.c` reads localtime() and the transform formats what it is given.
    """
    moment = datetime.strptime(clock[0], "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=ZoneInfo(clock[1])
    )
    return moment.isoformat()


def _instant_inside(rule: Any, context: Context) -> tuple[str, str] | None:
    """A date and time the rule's own `alert_time` window accepts.

    The regexes and the variable expansion come from the converter rather than
    from a second reading of the same grammar: the two have to agree about what
    `days 12345, hours 1800-0800` means, and a private copy here would drift.

    Sagan counts days from Sunday. A window whose end is before its start runs
    through midnight, so an hour just after the start is inside it either way.
    """
    option = next(iter(rule.iter_options("alert_time")), None)
    if option is None or option.value is None:
        return None
    try:
        value = _expand_variables(option.value, context)
    except Refusal:
        return None
    days, hours = _DAYS.search(value), _HOURS.search(value)
    if days is None or hours is None:
        return None
    weekday = sorted({int(character) for character in days.group(1)})[0]
    # 2026-08-16 is a Sunday, so adding Sagan's own day number lands on the day
    # the rule names.
    date = datetime(2026, 8, 16) + timedelta(days=weekday)
    start = int(hours.group(1)[:2])
    inside = (start + 1) % 24
    return f"{date:%Y-%m-%d} {inside:02d}:30:00", "UTC"


def silence_reasons(rule: Any, rule_probes: list[Any], context: Context) -> list[str]:
    """Everything about the probe that stops this rule, not just the first.

    This used to return one reason, the first branch that matched, and that is
    how two rules were reported as blocked by an unplaceable literal when
    removing the literal changed nothing: they also carried a pcre the sampler
    refuses, and the pcre was what stopped them. `checks/check_silence.py`
    found it by removing the blamed option and asking the engine again, which
    is the only way a reason of this kind is worth anything.

    A rule can therefore appear under a combined label. That is the honest
    shape: the run does not know which cause would bite first, only that each
    one is enough on its own.

    These are properties of the probe, not verdicts about the rule: each names
    something the generator cannot deliver, so both engines are asked about an
    event that was never going to satisfy the rule.
    """
    found: list[str] = []
    literals = positive_literals(rule, context.config.variables)
    body = json_body(rule)
    # A rule that matches a plain line as well as a document is probed with
    # both, and everything a document cannot carry the plain probe carries. So
    # none of the reasons below that blame the serialised document apply to it,
    # and reporting one would name a cause the run has already ruled out.
    document_only = not matches_either_shape(rule)

    if rule.has("alert_time"):
        # A property of the instant this run chose, not of the rule: a window
        # excluding it silences the rule whatever the probe carries.
        found.append("an alert_time window that excludes the instant this run used")
    if effective_positional(rule):
        found.append("an effective offset, depth or distance the probe cannot honour")
    if document_only and literals and unplaceable(rule, literals):
        found.append("a literal no serialised document can carry")
    if any(
        option.value
        and not option.value.lstrip().startswith("!")
        and sample_for(*(engine_pattern(option.value) or ("", ""))) is None
        for option in rule.iter_options("pcre")
    ):
        found.append("a pcre the generated text does not satisfy")
    samples = pcre_literals(rule)
    if document_only and samples and unplaceable(rule, [*literals, *samples]):
        # A sampled pattern is text like any other, and a JSON body escapes it:
        # `C:\\ProgramData` sampled from a Windows path comes back doubled in
        # the serialised document, so the engine never sees what the pattern
        # asks for. Three rules were reported as blocked by a literal alone
        # until `checks/check_silence.py` removed that literal and found them
        # still silent.
        found.append("a pcre sample no serialised document can carry")
    if (
        rule.has("event_id")
        and document_only
        and rule.keywords & JSON_KEYWORDS
        and not json_map(rule).get("event_id")
    ):
        found.append(
            "event_id with no json_map on a JSON body, where the ' <id>: ' "
            "prefix cannot go"
        )
    if not literals and not body:
        found.append("no condition the generator can turn into text")
    return found or ["unexplained"]


#: What the lab's `config/country.mmdb` places where, and which address to
#: plant to obtain each country. Fixed and tiny on purpose, the README records
#: the whole table.
LAB_COUNTRIES = {"RU": "5.5.5.5", "US": "8.8.8.8", "FR": "203.0.113.9"}


def _country_context(rule: Any, context: Context) -> list[str]:
    """An address whose country satisfies the rule's own `country_code` test.

    Such a rule names no address at all, so an ordinary probe carries none, the
    engine resolves no country and neither side fires: 157 rules of the
    enriched run sat in the `unexplained` bucket for this one reason. Measured
    in the lab: `country_code` needs a *resolved* country for `is` and `isnot`
    alike, so an address the database cannot place satisfies neither.

    The address is planted five times, so whichever position the rule's
    `parse_src_ip` declares resolves to the same country.
    """
    planted: list[str] = []
    for option in rule.iter_options("country_code"):
        match = COUNTRY_CODE.match(option.value or "")
        if match is None:
            continue
        try:
            codes = {
                code.upper()
                for code in resolve_country_codes(match.group("codes"), context)
            }
        except Refusal:
            continue
        wanted = match.group("test") == "is"
        address = next(
            (
                candidate
                for country, candidate in LAB_COUNTRIES.items()
                if (country in codes) is wanted
            ),
            None,
        )
        if address is not None:
            planted.extend([address] * 5)
    return planted


def _country_bindings(rule: Any, context: Context) -> dict[str, str]:
    """The bound key a `country_code` rule reads, holding a placeable address.

    `json_map: "src_ip", ".ClientIP"` makes the engine resolve the country of
    that key alone, and the converted rule tests `ClientIP_country`, which the
    pipeline fills from the same key. Text elsewhere in the document satisfies
    neither, so 138 rules were judged and stayed silent until the probe put the
    address where both sides look.
    """
    addresses = _country_context(rule, context)
    if not addresses:
        return {}
    mapping = json_map(rule)
    return {
        mapping[internal]: addresses[0]
        for internal in ("src_ip", "dest_ip")
        if internal in mapping
    }


def _feed_context(
    rule: Any, flags: dict[str, bool] | None, context: Context
) -> list[str]:
    """Text a rule needs but never names: a listed address, a placeable country."""
    if not flags:
        return []
    listed = [
        address
        for keyword, flag in FEED_KEYWORDS.items()
        if rule.has(keyword) and flags.get(flag)
        for address in listed_addresses(flag)
    ]
    return listed + _country_context(rule, context)


def run_batch(
    batch: list[tuple[Any, dict[str, Any], list[Any]]],
    scratch: Path,
    profile: Profile,
    pipeline: VectorPipeline | None = None,
    sagan_config: Path | None = None,
    clock: tuple[str, str] | None = None,
) -> tuple[list[Verdict], set[str]]:
    """Compare one batch of rules, each with its own probes.

    ``batch`` carries ``(rule, sigma_yaml, probes)``. Both engines see every
    rule and every event in the batch, so a rule firing on another rule's probe
    is simply judged by both and agrees; only the pairs a rule owns are
    compared, which keeps the result readable.

    Returns the disagreements and the sids whose ``base`` probe fired on both
    sides, the second being how the run says what it actually exercised.
    """
    # Not under work/: every engine run wipes that directory, so a file left
    # there disappears between the Sagan side and the rsigma side.
    rules_yaml = scratch / "batch.yml"
    rules_yaml.write_text(
        dump_collection([doc for _, doc, _ in batch]), encoding="utf-8"
    )

    sagan_rules: list[str] = []
    pipe_lines: list[str] = []
    rsigma_events: list[dict[str, Any]] = []
    owned: list[tuple[Any, Any, str, str, dict[str, Any]]] = []

    for rule, _, rule_probes in batch:
        sagan_rules.append(strip_threshold(rule.raw))
        for probe in rule_probes:
            # A JSON rule keeps its keys in json_body and leaves `message` as
            # the literal text. The Sigma side is handed the parsed object, so
            # the Sagan side has to be handed the document itself: the engine
            # parses the syslog message as JSON, and sending the text instead
            # means json_content can never match. That mistake produced 3,812
            # one-sided disagreements, every one of them the tool's fault.
            body = wire_body(probe.event)
            program = probe.event.program or "syslog"
            pipe_lines.append(
                pipe_event(
                    body,
                    program=program,
                    facility=probe.event.facility,
                    level=probe.event.level,
                )
            )
            payload = to_rsigma_event(probe.event, rule, profile)
            rsigma_events.append(payload)
            owned.append((rule, probe, program, body, payload))

    if pipeline is not None:
        # The rendered events are replaced by what the shipped transforms make
        # of the very lines Sagan was given, so the pipeline is judged with the
        # rules rather than modelled beside them.
        stamp = _rfc3339(clock) if clock else None
        rsigma_events = pipeline.run(
            [
                source_event(
                    body,
                    program,
                    probe.event.facility,
                    probe.event.level,
                    timestamp=stamp,
                )
                for _, probe, program, body, _ in owned
            ]
        )
        # Vector produces no `EventID`: that field is what the converted rule
        # assumes a Windows shipper emits when no json_map binds the key, and
        # the rendered events carry it already.
        for (rule, probe, _, _, _), event in zip(owned, rsigma_events, strict=True):
            # The shape is the probe's, not the rule's: a rule carrying only
            # `json_map` is probed both ways, and the engine can resolve an
            # unbound event id from a plain line only.
            structured = event_id_field(rule, bool(probe.event.json_body))
            if structured is not None:
                event[structured[0]] = structured[1]
        owned = [
            (rule, probe, program, body, payload)
            for (rule, probe, program, body, _), payload in zip(
                owned, rsigma_events, strict=True
            )
        ]

    # Attribution is on (program, message), not the message alone: a rule's
    # `base` and `wrong_program` probes carry the same text and differ only in
    # the program, so a message-only key credits the second with the first's
    # alert and every such probe reads as a disagreement.
    fired: dict[tuple[str, str], set[str]] = defaultdict(set)
    #: The same alerts keyed on the message alone, for the rules below.
    by_message: dict[str, set[str]] = defaultdict(set)
    for row in run_sagan(
        sagan_rules,
        pipe_lines,
        binary=SANE,
        config=sagan_config,
        at_time=clock[0] if clock else None,
        timezone=clock[1] if clock else None,
    ):
        fired[(row.get("program", ""), row["message"])].add(row["sid"])
        by_message[row["message"]].add(row["sid"])
    hits = rsigma_hits(rules_yaml, rsigma_events)

    found: list[Verdict] = []
    #: Rules whose positive probe fired on both sides. Agreement on two silent
    #: evaluators is agreement about nothing, and on this family it is the
    #: likely outcome: a literal carrying quotes that could not be placed in
    #: the document leaves both sides searching for absent text. So the run
    #: reports how many rules it actually made fire, and a rule that never
    #: fires is a rule this tool did not decide.
    exercised: set[str] = set()
    for rule, probe, program, body, payload in owned:
        # `json_map: "program", ".Something"` replaces the program with a value
        # taken from the event body, so Sagan logs that instead of the program
        # this tool sent and the pair never matches. sid 5005158 sends `syslog`
        # and is logged as `SharePoint`. Falling back to the message alone is
        # safe for exactly these rules: the program a probe carries is
        # overridden by the body, so no two probes of such a rule can be told
        # apart by it anyway.
        remapped = "program" in json_map(rule)
        sagan_fired = rule.sid in fired.get((program, body), set())
        if not sagan_fired and rule.has("append_program"):
            # The keyword makes the engine log the message with ` | <program>`
            # appended, so the text it writes is not the text this tool sent
            # and the pair never matches. Measured: an event sent as
            # `%ASA-1-216001 ~ %ASA` is logged as `%ASA-1-216001 ~ %ASA |
            # syslog`. 75 corpus rules carry it, and every probe of every one
            # of them read as "Sagan did not fire" until their pcre samples
            # made the Sigma side fire and turned it into 296 disagreements.
            sagan_fired = rule.sid in fired.get((program, f"{body} | {program}"), set())
        if remapped:
            sagan_fired = rule.sid in by_message.get(body, set())
        rule_id = stable_uuid("rule", rule.sid)
        sigma_fired = (rule_id, json.dumps(payload, sort_keys=True)) in hits
        if probe.name in POSITIVE_PROBES and sagan_fired and sigma_fired:
            exercised.add(rule.sid)
        if sagan_fired != sigma_fired:
            found.append(Verdict(rule.sid, probe.name, sagan_fired, sigma_fired, body))
    return found, exercised


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--batch", type=int, default=200)
    parser.add_argument(
        "--case-policy",
        default="faithful",
        choices=["faithful", "relaxed"],
        help=(
            "relaxed drops |cased everywhere, which is a documented trade of "
            "fidelity for recall. It is also how this tool proves it can fail: "
            "under relaxed the case_flipped probe must disagree, and a run that "
            "still reports nothing is not measuring anything."
        ),
    )
    parser.add_argument(
        "--profile",
        default="rsigma-syslog",
        choices=available_profiles(),
        help=(
            "conversion profile to judge. The default is the ingestion chain "
            "the other differentials use. Under vector-enriched the converter "
            "emits rules that syslog alone refuses, so the probe carries the "
            "fields that pipeline adds and those rules become judgeable."
        ),
    )
    parser.add_argument(
        "--events",
        default="auto",
        choices=["auto", "model", "pipeline"],
        help=(
            "where the RSigma side comes from. `pipeline` runs the syslog line "
            "through the transforms sagan2sigma emits, using a real Vector, so "
            "the rules and the pipeline are judged together; `model` uses the "
            "probe generator's rendering of them, which is all that is "
            "available for a profile with no pipeline. `auto` takes the "
            "pipeline when the profile declares one and Vector runs."
        ),
    )
    parser.add_argument(
        "--vector",
        default="vector",
        help="the Vector binary used by --events pipeline",
    )
    parser.add_argument(
        "--at-time",
        default=None,
        help=(
            "run the engine under faketime at this instant, and stamp the "
            "pipeline's events with it, which is what makes alert_time "
            "judgeable. Sagan compares its window against the wall clock at "
            "processing time and the converted rule against the event's own "
            "timestamp, a divergence the conversion declares; aligning the two "
            "is what lets the window arithmetic itself be compared. Format: "
            '"2026-08-18 14:30:00".\n'
            "The corpus declares two windows and no more, 0700-1800 on "
            "weekdays for 27 rules and 1800-0800 for 3, so two runs cover "
            "them: a weekday afternoon and the same weekday at 23:00. They "
            "are mutually exclusive by construction, and each run names the "
            "rules the other one judges."
        ),
    )
    parser.add_argument(
        "--timezone",
        default="UTC",
        help="TZ for the engine run; aetas.c reads localtime()",
    )
    parser.add_argument(
        "--sagan-yaml",
        type=Path,
        default=LAB / "config" / "sagan.yaml",
        help=(
            "the sagan.yaml whose variables the conversion resolves. The "
            "lab's own by default, which is the one the engine runs with, so "
            "both sides read $SAGAN_HOURS and friends the same way."
        ),
    )
    parser.add_argument(
        "--judge-dead-upstream",
        action="store_true",
        help=(
            "judge the rules excluded as dead upstream instead of skipping "
            "them. They are expected to disagree, the converter not "
            "reproducing engine defects, so this is how the exclusion is "
            "checked: every rule it drops should reappear here as a "
            "disagreement, and any that does not was dropped for nothing."
        ),
    )
    parser.add_argument(
        "--silence-report",
        type=Path,
        help=(
            "write every silent rule and the reason the run gave it, as JSON. "
            "The printed lists stop at five sids, which is enough to recognise "
            "a bucket and not enough to check one."
        ),
    )
    args = parser.parse_args()
    global JUDGE_DEAD_UPSTREAM
    JUDGE_DEAD_UPSTREAM = args.judge_dead_upstream

    profile = load_profile(str(args.profile))
    # The engine's own configuration, so both sides resolve `$SAGAN_HOURS`,
    # `$USERS` and the rest to the same values. Built with an empty one, the
    # converter refused 165 corpus rules with E_VAR_UNRESOLVED that Sagan runs
    # perfectly well here, and no differential ever saw them.
    context = Context(
        profile=profile,
        config=load_config(rules_dir=args.rules, sagan_yaml=args.sagan_yaml),
        catalog=load_catalog(),
    )
    converter = Converter(context=context, case_policy=CasePolicy(args.case_policy))

    pipeline, flags = None, None
    sagan_config = None
    if args.events != "model" and profile.json_raw is not None:
        # A profile naming a raw field is one this repository ships a pipeline
        # for. Every transform whose data the lab holds is turned on: GeoIP
        # from config/country.mmdb, the denylist and Zeek intel from the feeds
        # in config/rules/, which the Sagan side is pointed at as well so both
        # engines consult the same list.
        flags = {"geoip": True, "denylist": True, "zeek": True}
        if args.at_time:
            # The time transform needs no data of its own, only an instant, so
            # it is turned on exactly when one is given.
            flags["time"] = True
        try:
            pipeline = VectorPipeline(binary=args.vector, flags=flags)
        except (FileNotFoundError, OSError) as failure:
            if args.events == "pipeline":
                raise
            print(f"  [pipeline] falling back to the rendered events: {failure}")
            flags = None
        if pipeline is not None:
            sagan_config = config_with_processors(feed_files(flags))
    clock = (args.at_time, args.timezone) if args.at_time else None
    if clock is not None and pipeline is None:
        parser.error("--at-time needs the pipeline, which supplies the time fields")
    print(
        "  events from "
        + ("the shipped Vector transforms" if pipeline else "the probe generator")
    )
    enriched_exact, enriched_patterns = unsynthesised(profile, flags)

    files = sorted(args.rules.glob("*.rules")) if args.rules.is_dir() else [args.rules]
    prepared: list[tuple[Any, dict[str, Any], list[Any]]] = []
    counts: dict[str, int] = defaultdict(int)

    for path in files:
        for rule in parse_file(path).rules:
            if rule.keywords & STATEFUL:
                counts["stateful"] += 1
                continue
            operations = _bit_operations(rule)
            if operations & STATEFUL_BIT_OPS:
                counts["stateful"] += 1
                continue
            if operations & SILENCING_BIT_OPS:
                counts["silenced"] += 1
                continue
            if rule.keywords & UNLOADABLE:
                counts["unloadable"] += 1
                continue
            if _unprobeable(rule):
                counts["unprobeable"] += 1
                continue
            if not rule.sid.isdigit():
                # Alerts are attributed by sid, and the engine writes atoi() of
                # it: sid 5015093's neighbour in ms-defender.rules carries the
                # placeholder `xxxxxxxx` and every alert it produces is logged
                # as sid 0. Measured: the rule loads, matches and alerts, so it
                # is not dead, only untraceable, and this tool cannot tell its
                # alerts from any other rule's.
                counts["sid is not a number"] += 1
                continue
            defect = _upstream_defect(rule)
            if defect is not None and not JUDGE_DEAD_UPSTREAM:
                counts[f"dead upstream ({defect.value})"] += 1
                continue
            try:
                document = sigma_document(rule, converter)
            except DeclaredDivergence as divergence:
                counts[f"declared divergence ({divergence.code.value})"] += 1
                continue
            if document is None:
                counts["refused"] += 1
                continue
            enriched = needs_enrichment(document, enriched_exact, enriched_patterns)
            if enriched is not None:
                counts[f"enrichment ({enriched})"] += 1
                continue
            rule_probes = list(
                probes(
                    rule,
                    context.config.variables,
                    context=_feed_context(rule, flags, context),
                    bindings=_country_bindings(rule, context),
                    # A rule matching both shapes is probed as a document only
                    # where the profile can see one. Under a profile that keeps
                    # no raw body its text search cannot run on a document at
                    # all, which the conversion declares (D_JSON_BODY_ARM_LOST),
                    # so the probe is the plain line the rule is converted for.
                    json_arm=json_arm_reachable(rule, context.profile),
                )
            )
            if not rule_probes:
                counts["no probe"] += 1
                continue
            prepared.append((rule, document, rule_probes))
            counts["judged"] += 1
            if args.limit and counts["judged"] >= args.limit:
                break
        if args.limit and counts["judged"] >= args.limit:
            break

    if pipeline is not None and GEOIP_KEYS:
        # Rebuilt now that every rule has been converted: the keys are a
        # property of the rules that converted, and a pipeline missing them
        # sets no country for a bound address, which made 138 rules fire on
        # Sagan and stay silent on RSigma. Measured before this line existed.
        pipeline = VectorPipeline(
            binary=args.vector, flags=flags or {}, geoip_keys=frozenset(GEOIP_KEYS)
        )

    scratch = Path(tempfile.mkdtemp(prefix="engine-differential-"))
    raw: list[Verdict] = []
    exercised: set[str] = set()
    for start in range(0, len(prepared), args.batch):
        chunk = prepared[start : start + args.batch]
        verdicts, fired = run_batch(
            chunk, scratch, profile, pipeline, sagan_config, clock
        )
        raw.extend(verdicts)
        exercised |= fired
        done = min(start + args.batch, len(prepared))
        print(f"  [{done}/{len(prepared)}] rules judged", flush=True)

    # Confirmation pass. Batching is what makes this affordable and also what
    # makes a verdict unsafe: Sagan's `pass` action stops evaluating the
    # remaining signatures for an event, so any rule sitting after a matching
    # pass rule in the same batch is silenced by a neighbour rather than by its
    # own detection. Eleven extraHop rules reported as disagreeing were doing
    # exactly this, and every one of them agreed when run alone.
    #
    # So each disagreement is re-judged with its rule as the only rule in the
    # run. What survives is a property of the rule; what does not is a property
    # of the batch, and is reported separately rather than quietly dropped.
    disagreements: list[Verdict] = []
    contaminated: list[Verdict] = []
    by_sid = {rule.sid: entry for entry in prepared for rule in (entry[0],)}
    suspects = sorted({verdict.sid for verdict in raw})
    for index, sid in enumerate(suspects, 1):
        entry = by_sid.get(sid)
        if entry is None:  # pragma: no cover - defensive
            continue
        alone = {
            v.probe
            for v in run_batch(
                [entry], scratch, profile, pipeline, sagan_config, clock
            )[0]
        }
        for verdict in raw:
            if verdict.sid != sid:
                continue
            (disagreements if verdict.probe in alone else contaminated).append(verdict)
        print(f"  [{index}/{len(suspects)}] disagreements re-judged alone", flush=True)

    print()
    for key in sorted(counts):
        print(f"  {key:10} {counts[key]}")
    probe_total = sum(len(p) for _, _, p in prepared)
    print(f"  probes     {probe_total}")
    # Silence is re-checked, for the reason the disagreements are: a matching
    # `pass` rule stops the engine evaluating the signatures after it, so a
    # rule can sit silent because of a neighbour rather than because of its
    # probe. Twelve consecutive extraHop rules, all `pass` and all matching
    # similar events, were doing exactly that.
    #
    # Only the `pass` rules are asked one at a time. A first attempt ran every
    # silent rule alone and cost 238 engine invocations on the syslog profile
    # against 35 for the whole run before it, which is not a re-check but a
    # second run: the rules that silence are a handful and the rules that are
    # silenced come back in one batch once those are out of it.
    silent = [entry for entry in prepared if entry[0].sid not in exercised]
    # Printed after the re-check below, so the number is the one that survived
    # being asked twice.
    if silent:
        passes = [e for e in silent if e[0].raw.lstrip().lower().startswith("pass ")]
        others = [e for e in silent if e not in passes]
        print(
            f"  re-checking {len(silent)} silent rules: {len(others)} together, "
            f"{len(passes)} alone",
            flush=True,
        )
        for chunk in ([others] if others else []) + [[entry] for entry in passes]:
            if not chunk:
                continue
            _, fired = run_batch(chunk, scratch, profile, pipeline, sagan_config, clock)
            exercised |= fired
        still = [e for e in silent if e[0].sid not in exercised]
        if len(still) != len(silent):
            print(
                f"  batch-silent {len(silent) - len(still)} rule(s) fired on "
                f"both sides once their neighbours were out of the run"
            )
        silent = still

        # A rule with an `alert_time` window is silent whenever the run's own
        # instant falls outside it, which says nothing about the rule. Each one
        # is asked again at an instant inside its own window instead: the
        # window is a condition like any other and the probe can satisfy it.
        timed = [
            (entry, _instant_inside(entry[0], context))
            for entry in silent
            if entry[0].has("alert_time")
        ]
        timed = [(entry, when) for entry, when in timed if when is not None]
        if timed and pipeline is not None:
            print(f"  re-checking {len(timed)} alert_time rule(s) inside their window")
            for entry, when in timed:
                _, fired = run_batch(
                    [entry], scratch, profile, pipeline, sagan_config, when
                )
                exercised |= fired
            silent = [e for e in silent if e[0].sid not in exercised]
    print(
        f"  exercised  {len(exercised)} of {len(prepared)} rules made both sides "
        f"fire on a probe satisfying every positive condition"
    )
    if silent:
        print(f"  silent     {len(silent)} rules, by what stops the probe:")
        reasons: dict[str, list[str]] = defaultdict(list)
        for rule, _, rule_probes in silent:
            reasons[" + ".join(silence_reasons(rule, rule_probes, context))].append(
                rule.sid
            )
        if args.silence_report:
            # The printed lists are cut at five, which is enough to recognise a
            # bucket and not enough to audit one. `checks/check_silence.py`
            # reads this file and tries to falsify each reason rule by rule.
            args.silence_report.write_text(
                json.dumps(
                    {reason: sorted(sids) for reason, sids in reasons.items()},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"  silence report written to {args.silence_report}")
        for reason in sorted(reasons, key=lambda r: (-len(reasons[r]), r)):
            sids = sorted(reasons[reason])
            # The unexplained bucket is listed whole: it is the one a reader
            # has to act on, and five examples of it are not a work list.
            shown = sids if reason == "unexplained" else sids[:5]
            suffix = "" if shown == sids else ", ..."
            print(f"    {len(sids):5}  {reason}: {', '.join(shown)}{suffix}")
    if contaminated:
        print(
            f"  batch-only {len(contaminated)} verdict(s) over "
            f"{len({v.sid for v in contaminated})} rule(s), which agreed alone"
        )
    print()
    if disagreements:
        # By rule first, then a sample. Printing the first 40 verdicts hid how
        # many rules were involved: 135 disagreements looked like a wide
        # failure and were 15 rules with three probes each, which is a
        # different problem and points somewhere else entirely.
        by_sid: dict[str, list[Verdict]] = defaultdict(list)
        for verdict in disagreements:
            by_sid[verdict.sid].append(verdict)
        print(f"{len(disagreements)} DISAGREEMENTS over {len(by_sid)} rules")
        print()
        for sid in sorted(by_sid, key=lambda s: (-len(by_sid[s]), s)):
            group = by_sid[sid]
            side = "Sagan only" if group[0].sagan else "Sigma only"
            probes_hit = ", ".join(sorted({v.probe for v in group}))
            print(f"  sid {sid:9} {len(group):2} probe(s), {side:10} [{probes_hit}]")
        print()
        for verdict in disagreements[:12]:
            print(verdict)
        return 1
    print("no disagreement")
    return 0


def _entry() -> int:
    """Run, turning an absent engine build into a message rather than a trace.

    This differential needs the engine built with two local patches the
    repository does not carry, so on a fresh clone it cannot run at all.
    Saying that plainly is better than a traceback out of the harness.
    """
    try:
        return main()
    except MissingBinary as missing:
        print(f"cannot run: {missing}", file=sys.stderr)
        print("see docs/LAB.md for what runs without those builds", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_entry())
