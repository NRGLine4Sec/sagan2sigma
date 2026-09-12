#!/usr/bin/env python3
"""Does a converted xbit correlation fire where Sagan's state machine does?

`xbits` and `flexbits` are the third correlation family, and the only one no
differential had ever exercised. They are not a counter like `after`: one rule
writes a named bit, another refuses to alert until that bit is set. The
converter rebuilds this as a Sigma `temporal_ordered` correlation over two
rules, an aggregate of every rule that sets the bit and the rule that tests it.

That reconstruction rests on several claims at once. The aggregate must match
what the setters match; the window must come from the setter's expiry rather
than the tester's; the group-by must name a field both events carry. A single
converted document being well formed says nothing about any of them.

The test is the prerequisite, because that is the whole content of the
mechanism. For each correlation two sequences are built:

* **setter then tester.** Sagan alerts on the tester, its bit being set. The
  correlation must fire.
* **tester alone.** Sagan stays silent, the bit never having been written. The
  correlation must not fire.

A tool that only ran the first sequence would pass while proving nothing: a
correlation that fires unconditionally satisfies it. `--ignore-prerequisite`
exists to show the second sequence is load bearing.

The two sequences never share a run. Sagan keeps bits in
`/dev/shm/sagan-*.shared`, which outlives the process, and the harness wipes
that between runs; one run for both would let the first sequence set the bit
the second is meant to find missing. Each case also gets its own run, because
several testers share a bit name and one case's setter would prime another's.

Scope is limited to correlations grouping on the syslog hostname. The sequence
has to share one group-by value for the bit to be found, and this tool controls
only the sender. That is the same restriction `after_differential.py` works
under, and the same category the converter reports as `D_GROUPBY_SYSLOG_HOST`.
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

from harness import SANE  # noqa: E402
from harness import MissingBinary  # noqa: E402
from harness import event as pipe_event  # noqa: E402
from harness import run_sagan  # noqa: E402

#: The lab lives inside the repository it measures, so the converter and
#: the probe generator it imports are always the ones in this checkout.
REPO = LAB.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from sagan2sigma.converter import Converter  # noqa: E402
from sagan2sigma.emit.yaml_io import dump_collection  # noqa: E402
from sagan2sigma.mapping.context import Context, load_catalog, load_profile  # noqa: E402
from sagan2sigma.sagan.config import SaganConfig  # noqa: E402
from sagan2sigma.sagan.parser import parse_file  # noqa: E402
from sagan2sigma.mapping.correlation import SET_OPERATIONS  # noqa: E402
from sagan2sigma.mapping.fields import JSON_KEYWORDS  # noqa: E402
from tests.differential.events import build_base, to_rsigma_event, wire_body  # noqa: E402

RSIGMA = "rsigma"

#: Group-by fields this tool can hold constant across a sequence, both naming
#: the syslog sender. Which one a rule gets depends on its body: RSigma exposes
#: the envelope under `syslog_` prefixed names once the payload is JSON, so a
#: correlation over JSON events groups on `syslog_hostname`. Accepting only the
#: unprefixed name silently dropped the three JSON cases from judgement.
HOST_TRACKED = frozenset({"hostname", "syslog_hostname"})

#: Set by --ignore-prerequisite; see the flag's help.
IGNORE_PREREQUISITE = False

#: `xbits: set, name, track ...;` as written in a rule, for the pre-flight that
#: asks whether a rule's *detection* matches at all. With the bit option left
#: in, a tester cannot alert until its bit is set and every case would report
#: as untriggerable, which says nothing about the detection.
_BIT_OPTION = re.compile(r"\s*(?:xbits|flexbits)\s*:[^;]*;", re.I)

#: `SET_OPERATIONS` comes from the converter rather than being restated here.
#: The list is not obvious, `set_srcport` and friends being setters too, and a
#: local copy that fell behind would quietly stop this tool from pairing a
#: tester with the rule that primes it.


def bit_operations(rule: Any) -> list[tuple[str, str, list[str]]]:
    """Every bit option on a rule as (keyword, operation, remaining parts)."""
    found: list[tuple[str, str, list[str]]] = []
    for keyword in ("xbits", "flexbits"):
        for option in rule.iter_options(keyword):
            if not option.value:
                continue
            parts = [p.strip() for p in option.value.split(",") if p.strip()]
            if parts:
                found.append((keyword, parts[0].lower(), parts[1:]))
    return found


def bit_name(keyword: str, operation: str, rest: list[str]) -> str | None:
    """The bit a option names, accounting for the two argument orders.

    `xbits` puts the name first after the operation. `flexbits` puts a tracking
    key there for the test forms, `flexbits: isset, by_src, name`, and the name
    first for `set`, `flexbits: set, name, 300`.
    """
    if not rest:
        return None
    if keyword == "flexbits" and operation in ("isset", "isnotset"):
        return rest[1] if len(rest) > 1 else None
    return rest[0]


@dataclass(frozen=True, slots=True)
class Case:
    """One tester, one setter that primes it, and their converted documents."""

    bit: str
    tester: Any
    setter: Any
    documents: list[dict[str, Any]]
    correlation_id: str


def _pipe_line(event: Any, rule: Any) -> str:
    """One input line for Sagan, carrying the rule's event id where needed."""
    body = wire_body(event)
    return pipe_event(
        body,
        program=event.program or "syslog",
        facility=event.facility,
        level=event.level,
    )


def sagan_alerts(rules: list[str], events: list[str]) -> set[str]:
    """SIDs that alerted for one sequence, in a run of its own."""
    work = run_sagan(rules, events, binary=SANE)
    alert = work / "log" / "alert.log"
    if not alert.exists():
        return set()
    return set(
        re.findall(r"\[\*\*\] \[\d+:(\d+):\d+\]", alert.read_text(errors="replace"))
    )


def matches_its_probe(rule_text: str, sid: str, line: str) -> bool:
    """Whether a rule alerts on its own probe, asked twice before giving up.

    Two runs of this tool over the same corpus, same code and same binary,
    judged 7 cases and 10: three cases reported `setter does not match its
    probe` in one and passed in the other. The same rule with the same probe
    line, repeated on its own, alerts 6 times out of 6, and a reduced rule 10
    out of 10, so the variability is not in the pair being asked about. Where
    it does come from is not established; the sequence of runs and the
    machine's memory pressure are both candidates, since a run allocates some
    346 MB of shared state and this one is on a small VM.

    Asking again is sound whatever the cause: one rule and one event carry no
    state between runs, `_reset_state` wipes what the last one left, and a rule
    that matches its probe matches it every time it is asked in isolation. What
    a single ask costs is a case silently dropped from judgement, which is the
    failure mode this tool exists to avoid.
    """
    return any(sid in sagan_alerts([rule_text], [line]) for _ in range(2))


def rsigma_fired(case: Case, events: list[dict[str, Any]], scratch: Path) -> bool:
    """Whether the case's correlation fired for one sequence."""
    rules_file = scratch / f"xbit-{case.tester.sid}.yml"
    rules_file.write_text(dump_collection(case.documents), encoding="utf-8")

    payload = []
    for index, event in enumerate(events):
        event = dict(event)
        event["@timestamp"] = f"2026-08-24T10:00:{index:02d}Z"
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
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            row = json.loads(line)
            if row.get("rule_id") == case.correlation_id:
                return True
    return False


def collect(rules_dir: Path, converter: Converter) -> list[Case]:
    """Every correlation this tool can judge, with the events to judge it."""
    files = sorted(rules_dir.glob("*.rules"))
    corpus = [rule for path in files for rule in parse_file(path).rules]

    setters: dict[str, list[Any]] = defaultdict(list)
    testers: dict[str, list[Any]] = defaultdict(list)
    for rule in corpus:
        for keyword, operation, rest in bit_operations(rule):
            name = bit_name(keyword, operation, rest)
            if name is None:
                continue
            if operation in SET_OPERATIONS:
                setters[name].append(rule)
            elif operation == "isset":
                testers[name].append(rule)

    by_sid = {rule.sid: rule for rule in corpus}
    result = converter.convert_paths(files)
    # Indexed by both, because a correlation may reference either. The spec
    # allows a name or an id, and the converter emits ids for temporal
    # correlations to work around RSigma resolving names for `event_count`
    # only. Keying on one of them alone made this tool collect zero cases and
    # report success, which is the failure mode it exists to avoid.
    aggregates: dict[str, dict[str, Any]] = {}
    for converted in result.synthetic_rules:
        for document in converted.documents:
            for key in (document.get("name"), document.get("id")):
                if key:
                    aggregates[key] = document

    cases: list[Case] = []
    for converted in result.converted:
        base = next(
            (
                d
                for d in converted.documents
                if d.get("name") and "correlation" not in d
            ),
            None,
        )
        correlation = next(
            (
                d
                for d in converted.documents
                if d.get("correlation", {}).get("type") == "temporal_ordered"
            ),
            None,
        )
        if base is None or correlation is None:
            continue
        spec = correlation["correlation"]
        if not set(spec.get("group-by") or []) <= HOST_TRACKED:
            continue
        aggregate_name = next(
            (name for name in spec["rules"] if name in aggregates), None
        )
        if aggregate_name is None:
            continue

        tester = by_sid.get(converted.sid)
        if tester is None:
            continue
        bit = next(
            (
                name
                for keyword, operation, rest in bit_operations(tester)
                if operation == "isset"
                and (name := bit_name(keyword, operation, rest)) is not None
            ),
            None,
        )
        if bit is None or not setters.get(bit):
            continue

        if IGNORE_PREREQUISITE:
            # Drop the aggregate from the correlation, leaving a temporal rule
            # that only needs the tester. The negative sequence must then fire
            # on the Sigma side and not on Sagan's.
            spec["rules"] = [name for name in spec["rules"] if name != aggregate_name]

        # Prefer a setter reading the same body shape as the tester. RSigma
        # names the syslog envelope `hostname` for a plain body and
        # `syslog_hostname` for a JSON one, so a correlation grouping on the
        # sender can only pair events of one shape; the converter declares that
        # loss as D_GROUPBY_SHAPE_SPLIT. Taking the first setter regardless
        # picked the unpairable half for sid 5014047 and measured the declared
        # gap instead of the conversion.
        candidates = setters[bit]
        shaped = [
            candidate
            for candidate in candidates
            if bool(candidate.keywords & JSON_KEYWORDS)
            == bool(tester.keywords & JSON_KEYWORDS)
        ]
        cases.append(
            Case(
                bit=bit,
                tester=tester,
                setter=(shaped or candidates)[0],
                documents=[aggregates[aggregate_name], base, correlation],
                correlation_id=correlation["id"],
            )
        )
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument(
        "--ignore-prerequisite",
        action="store_true",
        help=(
            "remove the aggregate rule from the correlation, so the tester "
            "alone satisfies it. The tester-only sequence must then disagree. "
            "A differential that cannot fail is worth nothing, and this one "
            "would pass on a correlation that fires unconditionally."
        ),
    )
    args = parser.parse_args()
    global IGNORE_PREREQUISITE
    IGNORE_PREREQUISITE = args.ignore_prerequisite

    context = Context(
        profile=load_profile("rsigma-syslog"),
        config=SaganConfig(),
        catalog=load_catalog(),
    )
    converter = Converter(context=context)
    cases = collect(args.rules, converter)
    if args.limit:
        cases = cases[: args.limit]

    scratch = Path(tempfile.mkdtemp(prefix="xbits-differential-"))
    no_trigger: list[str] = []
    primed: list[str] = []
    unprimed: list[str] = []

    for index, case in enumerate(cases, 1):
        setter_event = build_base(case.setter, context.config.variables)
        tester_event = build_base(case.tester, context.config.variables)
        setter_line = _pipe_line(setter_event, case.setter)
        tester_line = _pipe_line(tester_event, case.tester)

        # Pre-flight: both detections have to match their own probe before the
        # correlation between them can be judged. Asked with the bit options
        # removed, because with the isset in place the tester can never alert
        # on its own, which is the whole point of the keyword.
        # The probe generator builds its event from the rule's literals, and a
        # rule whose only condition is a pcre yields "no conditions". Sagan
        # then matches anything while the converted rule matches nothing in
        # particular, so the pair proves nothing about the correlation. Judging
        # it anyway reported sid 5001881 as a disagreement for a property of
        # the probe.
        # A JSON-bodied rule legitimately has "no conditions" as its text: its
        # conditions live in the body, which is where the probe puts them.
        # Testing the message alone would drop those cases as inconclusive
        # while they are perfectly judgeable.
        if any(
            probe.message == "no conditions" and not probe.json_body
            for probe in (setter_event, tester_event)
        ):
            no_trigger.append(
                f"  sid {case.tester.sid}: no literal to build a probe from"
            )
            continue

        bare_setter = _BIT_OPTION.sub(" ", case.setter.raw)
        bare_tester = _BIT_OPTION.sub(" ", case.tester.raw)
        if not matches_its_probe(bare_setter, case.setter.sid, setter_line):
            no_trigger.append(
                f"  sid {case.tester.sid}: setter does not match its probe"
            )
            continue
        if not matches_its_probe(bare_tester, case.tester.sid, tester_line):
            no_trigger.append(
                f"  sid {case.tester.sid}: tester does not match its probe"
            )
            continue

        rules = [case.setter.raw, case.tester.raw]
        rsigma_setter = to_rsigma_event(setter_event, case.setter)
        rsigma_tester = to_rsigma_event(tester_event, case.tester)

        # Sequence 1: the bit is set first, so both sides must fire.
        in_sagan = case.tester.sid in sagan_alerts(rules, [setter_line, tester_line])
        in_sigma = rsigma_fired(case, [rsigma_setter, rsigma_tester], scratch)
        if in_sagan != in_sigma:
            primed.append(
                f"  sid {case.tester.sid} bit {case.bit}: disagree when primed "
                f"(Sagan {in_sagan}, Sigma {in_sigma})"
            )

        # Sequence 2: no setter, so neither side may fire.
        in_sagan = case.tester.sid in sagan_alerts(rules, [tester_line])
        in_sigma = rsigma_fired(case, [rsigma_tester], scratch)
        if in_sagan != in_sigma:
            unprimed.append(
                f"  sid {case.tester.sid} bit {case.bit}: disagree when unprimed "
                f"(Sagan {in_sagan}, Sigma {in_sigma})"
            )

        print(f"  [{index}/{len(cases)}] correlations judged", flush=True)

    print()
    print(f"  cases      {len(cases)}")
    print(f"  no trigger {len(no_trigger)}")
    print(f"  judged     {len(cases) - len(no_trigger)}")
    print(f"  disagree primed   {len(primed)}")
    print(f"  disagree unprimed {len(unprimed)}")
    print()
    for line in no_trigger[:20]:
        print(line)
    for line in primed + unprimed:
        print(line)
    return 1 if (primed or unprimed) else 0


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
