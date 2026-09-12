#!/usr/bin/env python3
"""Does a converted `after` correlation fire at the same event as Sagan's?

`after: track X, count N, seconds S` is the largest correlation family in the
corpus, 989 rules, and the one with the worst record here: four separate
defects have been found in it, every one by a hand-written check rather than
systematically. `after: count N` emitted `gte: N` and alerted an event early
across 970 rules; tracking keys the parser ignores were honoured; the flexbits
expiry was read with the xbits spelling. Each was caught by six events written
by hand.

This asks the same question of the whole family at once, and asks it the only
way that can settle it: by running both engines.

The test is the boundary, because that is where an off-by-one lives. For each
rule two sequences are built from the same satisfying event:

* **N events.** Sagan seeds its counter on the first match and alerts only
  while `after2_count < count`, so N events pass in silence. The Sigma
  correlation carries `gte: N+1` and must stay silent too.
* **N+1 events.** Both must alert.

The two sequences never share a run. Sagan keeps its counters in
`/dev/shm/sagan-*.shared`, keyed by rule and group-by value, and the harness
wipes that between runs; putting both sequences in one run would let the first
fill the counter the second is meant to test.

The sequence has to share one group-by value for the counter to accumulate, so
what this tool can judge depends on what the run can hold constant. Against a
profile with no enrichment that is the syslog sender alone, which is the
category the converter reports as `D_GROUPBY_SYSLOG_HOST`, and a rule deriving
its group-by from the message is skipped.

Under `--profile vector-enriched` it is more. The RSigma side then comes from a
real Vector running the transforms `sagan2sigma --emit-vector-config` writes, so
the parsed addresses exist, and a rule grouping on `parse_src_ip` is judgeable:
its probe is given addresses to be parsed, and both sides derive their own group
key from the same line. 294 corpus rules convert only under that profile and
none had ever been judged.

What stays out is named and counted rather than dropped: a `normalize` rule,
whose address Sagan takes from a liblognorm rulebase and the pipeline from the
text, and a tracking key no field can hold, `by_username` in particular, the
bundled username transform being a starter kit rather than a port.
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
from pathlib import Path
from typing import Any

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "differential"))

from harness import SANE  # noqa: E402
from harness import MissingBinary  # noqa: E402
from harness import event as pipe_event  # noqa: E402
from harness import alerts as engine_alerts  # noqa: E402
from harness import config_with_processors  # noqa: E402

#: The lab lives inside the repository it measures, so the converter and
#: the probe generator it imports are always the ones in this checkout.
REPO = LAB.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from sagan2sigma.converter import Converter  # noqa: E402
from sagan2sigma.emit.sigma import (  # noqa: E402
    build_correlation_document,
    build_rule_document,
    rule_name,
)
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
from sagan2sigma.sagan.parser import parse_file  # noqa: E402
from tests.differential.events import (  # noqa: E402
    build_event,
    json_map,
    event_id_field,
    positive_literals,
    to_rsigma_event,
    wire_body,
)
from vector_pipeline import (  # noqa: E402
    VectorPipeline,
    feed_files,
    listed_addresses,
    source_event,
)

RSIGMA = "rsigma"

#: `after: track <keys>, count <n>, seconds <s>`, in any spacing.
AFTER = re.compile(
    r"after:\s*track\s*(?P<keys>[a-z_&]+)\s*,\s*count\s*(?P<count>\d+)"
    r"\s*,\s*seconds\s*(?P<seconds>\d+)",
    re.I,
)

#: Group-by keys this tool can hold constant across a sequence with nothing but
#: the syslog sender, which is all a profile without enrichment offers.
HOST_TRACKED = frozenset({"by_src", "by_dst"})

#: Keys an enriched pipeline resolves to a parsed address.
#:
#: `by_username` is not among them, and the reason is narrower than it looks:
#: it is out only when a liblognorm rulebase is what resolves the name, since
#: the bundled transform is a best-effort starter kit rather than a port and
#: the two sides would then group on values derived by different means. A rule
#: binding the username through `json_map` reads a key of the document instead,
#: which the probe sets, and `prepare` admits it.
ADDRESS_TRACKED = frozenset({"by_src", "by_dst"})


def probe_addresses(index: int) -> str:
    """Addresses for the probe of a rule that parses one out of the message.

    The sequence repeats a single event, so whatever each side reads at a given
    position is constant for it, and the counters accumulate the same way even
    if the two disagreed about which address sits where. What must hold is that
    the position *exists* on both sides: a missing group-by field drops the
    event from the RSigma correlation while Sagan still counts it, and that
    asymmetry would read as a defect.

    One set per case, not one for the corpus. With a shared address every
    enriched case groups under the same key, so a neighbour's event that also
    satisfies this rule's detection joins its counter and can tip it over the
    threshold a step early. Distinct addresses make a neighbour's event land in
    a different group on *both* sides, which is the symmetric way to remove the
    coupling rather than hiding it.

    Five of them, the transform exposing sagan_ip_1 through sagan_ip_5 and no
    more.
    """
    return " ".join(
        f"10.{index // 256 % 256}.{index % 256}.{position}" for position in range(1, 6)
    )


#: Keywords whose rules need an address the feed lists, and the lab feed that
#: lists it. Such a rule gets those addresses instead of the per-case ones: it
#: cannot fire at all on an address nobody listed, and the listed set is what
#: both engines are pointed at.
FEED_KEYWORDS = {
    "blacklist": "denylist",
    "zeek-intel": "zeek",
    # The old spelling, which the converter honours as an alias and two
    # corpus rules still use.
    "bro-intel": "zeek",
}

#: The highest position the pipeline produces a field for.
MAX_POSITION = 5

#: `parse_src_ip: 2`, whose argument is the position, defaulting to 1.
_PARSE_POSITION = re.compile(r"parse_(?:src|dst)_ip\s*:\s*(\d+)", re.I)

#: Degradations recording a divergence from the engine that the converter chose
#: not to reproduce, so a rule carrying one is expected to disagree and judging
#: it measures the decision rather than the conversion.
#:
#: `JSON_PCRE_ABSENT_KEY`: Sagan treats a key the event does not carry as a
#: match for `json_pcre`, alone among the JSON operators. Reproducing it would
#: make the converted rule fire on every event lacking the key. sid 5014487 is
#: the case that made this necessary here: its `json_pcre` on `.srcip` matches
#: on the Sagan side because the probe has no such key, and the converted rule
#: requires the field, so the correlation reaches its threshold on one side
#: only. `engine_differential.py` excludes the same code for the same reason.
DECLARED_DIVERGENCES = frozenset({DegradationCode.JSON_PCRE_ABSENT_KEY})

#: Set by --reintroduce-off-by-one; see the flag's help.
OFF_BY_ONE = False


@dataclass(frozen=True, slots=True)
class Case:
    """One rule, its threshold, and the events that probe the boundary."""

    sid: str
    count: int
    raw: str
    documents: list[dict[str, Any]]
    correlation_id: str
    event: Any
    rule: Any
    #: Addresses the probe planted, when the group-by comes from one. The
    #: pre-flight checks the engine resolved one of them; see `_rows`.
    planted: tuple[str, ...]


def _addresses(rule: Any, parses: bool, enriched: bool, index: int) -> list[str]:
    """The addresses this rule's probe has to carry, ahead of its literals.

    A rule reading a denylist or Zeek intel flag can only fire on an address the
    feed lists, and the feed is shared, so those rules take the listed set
    rather than a per-case one. Everything else takes addresses of its own, so
    a neighbour's event lands in a different group on both sides.
    """
    if not enriched:
        return []
    for keyword, flag in FEED_KEYWORDS.items():
        if rule.has(keyword):
            return listed_addresses(flag)
    return [probe_addresses(index)] if parses else []


def prepare(
    rule: Any,
    converter: Converter,
    counts: dict[str, int],
    enriched: bool,
    index: int = 0,
) -> Case | None:
    """Everything needed to judge one `after` rule, or None if out of scope.

    ``enriched`` says the run has a pipeline producing the parsed addresses, in
    which case a rule that derives its group-by from the message is judgeable
    and its probe is given addresses to be derived from. Without one the tool
    can only hold the syslog sender constant, which is what it did when this
    family was first measured.
    """
    match = AFTER.search(rule.raw)
    if match is None:
        return None
    keys = {k for k in match.group("keys").lower().split("&") if k}
    parses = rule.has("parse_src_ip") or rule.has("parse_dst_ip")
    planted = _addresses(rule, parses, enriched, index)

    trackable = set(ADDRESS_TRACKED if (enriched and parses) else HOST_TRACKED)
    if "username" in json_map(rule):
        # The username comes from a JSON key here, not from a liblognorm
        # rulebase, and the probe sets that key. Both sides then group on the
        # same value, which is all a correlation needs. 420 of the 446
        # `by_username` correlations are of this shape; the family was excluded
        # whole on the strength of the other 24.
        trackable.add("by_username")
    if not keys <= trackable:
        counts[f"tracks {'&'.join(sorted(keys))}"] += 1
        return None
    if rule.has("normalize") and not enriched:
        # Sagan resolves the address through a liblognorm rulebase here, and
        # positional parsing is only its fallback (engine.c:797). Without the
        # enriched pipeline there is no positional field either, so nothing can
        # be held constant and the case is out of reach.
        #
        # With it, the case is judgeable and checked rather than assumed: the
        # probe plants addresses, and the pre-flight reads back which one the
        # engine resolved. A generated message matches no rulebase pattern, so
        # the engine falls back to Parse_IP and both sides derive the same key,
        # measured on six corpus rules before this was allowed. What the run
        # then says nothing about is the liblognorm path itself, which is
        # exactly what `D_NORMALIZE_PRECEDENCE` declares as not reproduced.
        counts["normalize, no pipeline to resolve the address"] += 1
        return None
    if parses and not enriched:
        counts["needs the enriched pipeline"] += 1
        return None
    if parses and any(
        int(position) > MAX_POSITION for position in _PARSE_POSITION.findall(rule.raw)
    ):
        counts[f"position above {MAX_POSITION}"] += 1
        return None

    try:
        draft = converter.convert_rule(rule)
    except Refusal as refusal:
        counts[f"refused ({refusal.code.value})"] += 1
        return None
    if not draft.correlations:
        counts["no correlation emitted"] += 1
        return None
    declared = next(
        (d.code for d in draft.degradations if d.code in DECLARED_DIVERGENCES), None
    )
    if declared is not None:
        counts[f"declared divergence ({declared.value})"] += 1
        return None

    entry = converter.context.catalog.resolve(rule.source_file)
    base = build_rule_document(
        draft=draft,
        sid=rule.sid,
        rev=rule.rev,
        source_file=rule.source_file,
        logsource=entry,
        needs_name=True,
    )
    spec = draft.correlations[0]
    correlation = build_correlation_document(
        spec=spec,
        draft=draft,
        correlation_id=f"{rule.sid}#0",
        base_name=rule_name(rule.sid),
    )
    if OFF_BY_ONE:
        condition = correlation["correlation"].get("condition")
        if isinstance(condition, dict) and "gte" in condition:
            condition["gte"] = max(1, condition["gte"] - 1)
    return Case(
        sid=rule.sid,
        count=int(match.group("count")),
        raw=rule.raw,
        documents=[base, correlation],
        correlation_id=correlation["id"],
        event=build_event(
            rule,
            [
                *planted,
                *positive_literals(rule, converter.context.config.variables),
            ],
        ),
        planted=tuple(address for group in planted for address in group.split()),
        rule=rule,
    )


#: `after: track ..., count N, seconds S;` as written in a rule.
_AFTER_OPTION = re.compile(r"\s*after\s*:[^;]*;", re.I)


def sagan_alerts(
    cases: list[Case],
    repeats: dict[str, int],
    strip_after: bool = False,
    config: Path | None = None,
) -> set[str]:
    """SIDs that alerted, given how many copies each case contributes."""
    return {row["sid"] for row in sagan_rows(cases, repeats, strip_after, config)}


def sagan_rows(
    cases: list[Case],
    repeats: dict[str, int],
    strip_after: bool = False,
    config: Path | None = None,
) -> list[dict[str, str]]:
    """Every alert of one run, with the addresses the engine resolved.

    ``strip_after`` removes the correlation so the detection can be judged on
    its own, which is what the pre-flight needs.
    """
    rules = [
        _AFTER_OPTION.sub(" ", case.raw) if strip_after else case.raw for case in cases
    ]
    lines: list[str] = []
    for case in cases:
        # The `event_id` prefix the fallback heuristic looks for is part of the
        # event the generator builds, not something added here: the detection
        # differential needs the same thing and one of the two would drift.
        body = wire_body(case.event)
        line = pipe_event(
            body,
            program=case.event.program or "syslog",
            facility=case.event.facility,
            level=case.event.level,
        )
        lines.extend([line] * repeats[case.sid])
    # `alerts` rather than a regex over the log, because the addresses the
    # engine resolved are what makes the group key checkable. A rule carrying
    # `normalize` takes its address from a liblognorm rulebase when one matches
    # and from `Parse_IP` otherwise, and only the second is what the pipeline
    # reproduces, which the conversion declares as `D_NORMALIZE_PRECEDENCE`.
    # So the probe plants addresses and the pre-flight reads back which one the
    # engine chose, rather than assuming it took the planted one.
    return engine_alerts(rules, lines, binary=SANE, config=config)


def rsigma_alerts(
    cases: list[Case],
    repeats: dict[str, int],
    scratch: Path,
    profile: Profile,
    pipeline: VectorPipeline | None = None,
) -> set[str]:
    """Correlation rule ids that fired, for the same sequences."""
    documents = [doc for case in cases for doc in case.documents]
    rules_file = scratch / "after.yml"
    rules_file.write_text(dump_collection(documents), encoding="utf-8")

    if pipeline is None:
        rendered = [to_rsigma_event(case.event, case.rule, profile) for case in cases]
    else:
        # One pass over the distinct events, not over the repeats: the sequence
        # is the same event many times, and only its timestamp changes.
        rendered = pipeline.run(
            [
                source_event(
                    wire_body(case.event),
                    case.event.program or "syslog",
                    case.event.facility,
                    case.event.level,
                )
                for case in cases
            ]
        )
        for event in rendered:
            # The pipeline stamps its own ingest time, and the loop below sets
            # the one the correlation window is meant to see.
            event.pop("timestamp", None)

    payload: list[str] = []
    for case, base_event in zip(cases, rendered, strict=True):
        event = base_event
        structured = event_id_field(case.rule, bool(case.event.json_body))
        if structured is not None and structured[0] not in event:
            # A rendered event carries it already; one that came out of the
            # pipeline does not, Vector producing no such field.
            event = {**event, structured[0]: structured[1]}
        for index in range(repeats[case.sid]):
            # One burst, strictly ordered, inside any window a rule declares.
            # An earlier version numbered the seconds modulo 60, so a sequence
            # longer than a minute walked back to :00 and handed the engine a
            # timestamp before the one it had just seen, repeatedly. The
            # shortest window in the corpus is measured in seconds, and a
            # millisecond step keeps 251 events inside a quarter of one.
            event = dict(event)
            event["@timestamp"] = (
                f"2026-08-24T10:00:{index // 1000:02d}.{index % 1000:03d}Z"
            )
            payload.append(json.dumps(event, sort_keys=True))

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
        ],
        input="\n".join(payload),
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"rsigma exited {completed.returncode}: {completed.stderr[-400:]}"
        )
    fired: set[str] = set()
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            row = json.loads(line)
            if "rule_id" in row:
                fired.add(row["rule_id"])
    return fired


def _unique(cases: list[Case]) -> list[Case]:
    """The same cases, each once, in the order they were reported."""
    seen: set[str] = set()
    out: list[Case] = []
    for case in cases:
        if case.sid not in seen:
            seen.add(case.sid)
            out.append(case)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--batch", type=int, default=60)
    parser.add_argument(
        "--profile",
        default="rsigma-syslog",
        choices=available_profiles(),
        help=(
            "conversion profile to judge. Under an enriched profile the rules "
            "whose group-by comes from an address parsed out of the message "
            "become judgeable, the pipeline producing that address."
        ),
    )
    parser.add_argument(
        "--events",
        default="auto",
        choices=["auto", "model", "pipeline"],
        help=(
            "where the RSigma side comes from: the transforms sagan2sigma "
            "emits, run by a real Vector, or the probe generator's rendering "
            "of them. `auto` takes the pipeline when the profile declares one."
        ),
    )
    parser.add_argument(
        "--vector",
        default="vector",
        help="the Vector binary used by --events pipeline",
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
        "--reintroduce-off-by-one",
        action="store_true",
        help=(
            "emit gte: N instead of gte: N+1, the defect this family carried "
            "across 970 rules. The N-event sequence must then fire on the Sigma "
            "side and not on Sagan's. A run that still reports nothing is not "
            "measuring the boundary, and a differential that cannot fail is "
            "worth nothing."
        ),
    )
    args = parser.parse_args()
    global OFF_BY_ONE
    OFF_BY_ONE = args.reintroduce_off_by_one

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
    converter = Converter(context=context)

    pipeline, sagan_config = None, None
    if args.events != "model" and profile.json_raw is not None:
        flags = {"geoip": True, "denylist": True, "zeek": True}
        try:
            pipeline = VectorPipeline(binary=args.vector, flags=flags)
        except (FileNotFoundError, OSError) as failure:
            if args.events == "pipeline":
                raise
            print(f"  [pipeline] falling back to the rendered events: {failure}")
        if pipeline is not None:
            sagan_config = config_with_processors(feed_files(flags))
    print(
        "  events from "
        + ("the shipped Vector transforms" if pipeline else "the probe generator")
    )

    files = sorted(args.rules.glob("*.rules")) if args.rules.is_dir() else [args.rules]
    cases: list[Case] = []
    counts: dict[str, int] = defaultdict(int)
    for path in files:
        for rule in parse_file(path).rules:
            case = prepare(
                rule,
                converter,
                counts,
                enriched=pipeline is not None,
                index=len(cases),
            )
            if case is not None:
                cases.append(case)
            if args.limit and len(cases) >= args.limit:
                break
        if args.limit and len(cases) >= args.limit:
            break

    scratch = Path(tempfile.mkdtemp(prefix="after-differential-"))
    early: list[str] = []
    late: list[str] = []

    inconclusive = 0
    contaminated: list[str] = []
    suspects: list[Case] = []
    for start in range(0, len(cases), args.batch):
        chunk = cases[start : start + args.batch]

        # Pre-flight: does the rule's *detection* match the generated event?
        #
        # Asked with the after option removed, because with it in place a
        # single event can never alert: suppressing the first N is the whole
        # point of the keyword. The first version of this check left it in and
        # declared every case untriggered.
        #
        # The probe generator builds its event from the rule's literals, and a
        # rule whose only condition is a pcre yields "no conditions" and
        # satisfies nothing. Both engines then stay silent, which is agreement
        # rather than a defect, but a boundary test learns nothing from it. The
        # first version of this tool counted 359 such cases as failures, which
        # is exactly the kind of one-sided result that accuses the instrument.
        single = {case.sid: 1 for case in chunk}
        rows = sagan_rows(chunk, single, strip_after=True, config=sagan_config)
        triggered = {row["sid"] for row in rows}
        chunk = [case for case in chunk if case.sid in triggered]
        inconclusive += len(single) - len(chunk)

        # The group key has to be the one the probe planted. A rule carrying
        # `normalize` takes its address from a liblognorm rulebase when one
        # matches, and only the positional fallback is what the pipeline
        # reproduces; a generated message matches no rulebase pattern, but that
        # is measured here rather than assumed, once per case.
        # Matched on the event as well as the rule: in a batch a rule fires on
        # its neighbours' events too, and such a row carries their addresses.
        # Reading the rule alone credited one case with another's parse and
        # dropped it for a resolution that was never its own.
        resolved = {
            (row["sid"], row.get("message", "")): row.get("src", "") for row in rows
        }
        elsewhere = [
            case
            for case in chunk
            if case.planted
            and resolved.get((case.sid, wire_body(case.event))) not in case.planted
        ]
        for _ in elsewhere:
            counts["engine resolved an address the probe did not plant"] += 1
        chunk = [case for case in chunk if case not in elsewhere]
        inconclusive += len(elsewhere)
        if not chunk:
            continue

        # Exactly `count` events: neither side should alert.
        repeats = {case.sid: case.count for case in chunk}
        sagan_hit = sagan_alerts(chunk, repeats, config=sagan_config)
        sigma_hit = rsigma_alerts(chunk, repeats, scratch, profile, pipeline)
        for case in chunk:
            in_sagan = case.sid in sagan_hit
            in_sigma = case.correlation_id in sigma_hit
            if in_sagan != in_sigma:
                early.append(
                    f"  sid {case.sid} count {case.count}: disagree at N "
                    f"(Sagan {in_sagan}, Sigma {in_sigma})"
                )
                suspects.append(case)
            elif in_sagan:
                # Both alerted a step early, so they agree; the sequence simply
                # carried more matching events than it meant to, because a case
                # in the same batch produced events this rule also matches. The
                # boundary was not tested for it.
                contaminated.append(case.sid)

        # One more: both should alert.
        repeats = {case.sid: case.count + 1 for case in chunk}
        sagan_hit = sagan_alerts(chunk, repeats, config=sagan_config)
        sigma_hit = rsigma_alerts(chunk, repeats, scratch, profile, pipeline)
        for case in chunk:
            in_sagan = case.sid in sagan_hit
            in_sigma = case.correlation_id in sigma_hit
            if in_sagan != in_sigma:
                late.append(
                    f"  sid {case.sid} count {case.count}: disagree at N+1 "
                    f"(Sagan {in_sagan}, Sigma {in_sigma})"
                )
                suspects.append(case)

        done = min(start + args.batch, len(cases))
        print(f"  [{done}/{len(cases)}] rules judged", flush=True)

    # Confirmation pass, the one this tool lacked. A batch puts hundreds of
    # rules and thousands of events in front of both engines at once, so a
    # neighbour's event that also satisfies a rule's detection joins its
    # counter, and a `pass` rule ahead of it can silence it outright. Either
    # way the verdict then belongs to the batch and not to the rule. Each
    # disagreement is re-judged with its case alone; what survives is a
    # property of the rule, and what does not is reported separately rather
    # than quietly kept.
    confirmed_early, confirmed_late = [], []
    batch_only: list[str] = []
    for index, case in enumerate(_unique(suspects), 1):
        at_n = {case.sid: case.count}
        alone_n = case.sid in sagan_alerts([case], at_n, config=sagan_config)
        alone_n_sigma = case.correlation_id in rsigma_alerts(
            [case], at_n, scratch, profile, pipeline
        )
        at_next = {case.sid: case.count + 1}
        alone_next = case.sid in sagan_alerts([case], at_next, config=sagan_config)
        alone_next_sigma = case.correlation_id in rsigma_alerts(
            [case], at_next, scratch, profile, pipeline
        )
        if alone_n != alone_n_sigma:
            confirmed_early.append(
                f"  sid {case.sid} count {case.count}: disagree at N alone "
                f"(Sagan {alone_n}, Sigma {alone_n_sigma})"
            )
        if alone_next != alone_next_sigma:
            confirmed_late.append(
                f"  sid {case.sid} count {case.count}: disagree at N+1 alone "
                f"(Sagan {alone_next}, Sigma {alone_next_sigma})"
            )
        if alone_n == alone_n_sigma and alone_next == alone_next_sigma:
            batch_only.append(case.sid)
        print(f"  [{index}/{len(_unique(suspects))}] re-judged alone", flush=True)
    early, late = confirmed_early, confirmed_late

    print()
    for key in sorted(counts):
        print(f"  skipped, {key}: {counts[key]}")
    print(f"  cases      {len(cases)}")
    print(f"  no trigger {inconclusive}")
    print(f"  judged     {len(cases) - inconclusive}")
    print(f"  over-count {len(contaminated)}")
    if batch_only:
        print(f"  batch-only {len(batch_only)} case(s), which agreed alone")
    print(f"  disagree N {len(early)}")
    print(f"  disagree+1 {len(late)}")
    print()
    for line in (early + late)[:40]:
        print(line)
    return 1 if (early or late) else 0


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
