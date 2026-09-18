#!/usr/bin/env python3
"""Judge the Python model of Sagan against the real Sagan.

`tests/differential/` compares the *converted* rule against
`sagan_reference.py`, a model of the engine written by reading its C. That
comparison has a blind spot its own docstring names: a misreading shared by the
model and the converter survives it, both sides agreeing about the wrong thing.
`engine_differential.py` closes it for the converter, by putting the real engine
on one side. Nothing did for the model.

This does. Both sides here are Sagan: the engine on one, the model of it on the
other, on the same probes. A divergence cannot be an arbitration between two
readings, it is a defect in the model, and the model is what runs in CI on every
push. So an hour spent here makes the light net more faithful without the heavy
one ever running outside the lab.

What it measures is narrower than the corpus differential and deliberately so.
Only the rules `is_supported()` admits are judged, since the model declines the
rest by construction; the run reports how many it left out and why.

Usage
-----
    ./differential/model_differential.py --rules <corpus dir> [--limit N]
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "differential"))

from harness import SANE  # noqa: E402
from harness import alerts as run_sagan  # noqa: E402
from harness import event as pipe_event  # noqa: E402

REPO = LAB.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from sagan2sigma.sagan.parser import parse_file  # noqa: E402
from tests.differential.events import probes, wire_body  # noqa: E402
from attribution import AlertIndex  # noqa: E402
from tests.differential.sagan_reference import (  # noqa: E402
    SaganEvaluator,
    is_supported,
)

#: Keywords the engine cannot load here, so a rule carrying one is skipped
#: before either side sees it. `dynamic_load` makes Sagan pull in further rule
#: files, which would put rules nobody chose into the comparison.
UNLOADABLE = frozenset({"dynamic_load"})


@dataclass(frozen=True, slots=True)
class Divergence:
    """One rule and one probe the two readings of Sagan disagree about."""

    sid: str
    source_file: str
    probe: str
    engine: bool
    model: bool
    message: str

    def __str__(self) -> str:
        side = (
            "engine fired, model did not"
            if self.engine
            else "model fired, engine did not"
        )
        return f"  sid {self.sid} ({self.source_file}) probe {self.probe}: {side}\n    {self.message[:140]}"


def judge(batch: list[Any], counts: Counter[str]) -> list[Divergence]:
    """Run one batch of rules through both readings and compare, probe by probe."""
    rules: list[str] = []
    lines: list[str] = []
    owned: list[tuple[Any, Any, str, str]] = []

    for rule in batch:
        rule_probes = probes(rule)
        if not rule_probes:
            counts["no probe"] += 1
            continue
        rules.append(rule.raw)
        for probe in rule_probes:
            body = wire_body(probe.event)
            program = probe.event.program or "syslog"
            lines.append(
                pipe_event(
                    body,
                    program=program,
                    facility=probe.event.facility,
                    level=probe.event.level,
                )
            )
            owned.append((rule, probe, body, program))

    if not rules:
        return []

    # Tying an alert back to its probe is `attribution.AlertIndex`, shared with
    # engine_differential.py, which carries the three rewrites the engine
    # performs on what it logs. Writing it again here cost three failed runs.
    alerts = AlertIndex(run_sagan(rules, lines, binary=SANE))

    divergences: list[Divergence] = []
    for rule, probe, body, program in owned:
        evaluator = SaganEvaluator(rule)
        model = evaluator.matches(probe.event)
        engine = alerts.fired(rule, program, body)
        counts["judged probes"] += 1
        if model != engine:
            divergences.append(
                Divergence(
                    sid=str(rule.sid),
                    source_file=rule.source_file,
                    probe=probe.name,
                    engine=engine,
                    model=model,
                    message=body,
                )
            )
    return divergences


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--batch", type=int, default=200)
    args = parser.parse_args()

    files = sorted(args.rules.glob("*.rules")) if args.rules.is_dir() else [args.rules]
    counts: Counter[str] = Counter()
    selected: list[Any] = []
    for path in files:
        for rule in parse_file(path).rules:
            if rule.keywords & UNLOADABLE:
                counts["unloadable"] += 1
                continue
            if not rule.sid.isdigit():
                counts["no numeric sid"] += 1
                continue
            if not is_supported(rule):
                counts["outside the model"] += 1
                continue
            selected.append(rule)
            if args.limit and len(selected) >= args.limit:
                break
        if args.limit and len(selected) >= args.limit:
            break

    candidates: list[Divergence] = []
    for start in range(0, len(selected), args.batch):
        batch = selected[start : start + args.batch]
        candidates.extend(judge(batch, counts))
        print(
            f"  [{min(start + args.batch, len(selected))}/{len(selected)}] rules judged"
        )

    # Batching is what makes this affordable and also what makes a verdict
    # unsafe: Sagan's `pass` action stops evaluating the remaining signatures
    # for an event, so a rule sitting after a matching pass rule in the same
    # batch is silenced by a neighbour rather than by its own conditions. Every
    # candidate is therefore re-judged with its rule alone, and what does not
    # survive that is a property of the batch rather than of the model.
    by_sid = {rule.sid: rule for rule in selected}
    divergences: list[Divergence] = []
    for index, candidate in enumerate(sorted({d.sid for d in candidates}), start=1):
        rule = by_sid[candidate]
        divergences.extend(judge([rule], counts))
        print(
            f"  [{index}/{len({d.sid for d in candidates})}] divergences re-judged alone"
        )
    counts["dropped by the batch"] = len(candidates) - len(divergences)

    print()
    for key in sorted(counts):
        print(f"  {key:<18} {counts[key]}")
    print(f"  rules judged       {len(selected)}")
    print()
    if not divergences:
        print("the model reads the engine the same way on every probe")
        return 0

    by_rule: Counter[str] = Counter(d.sid for d in divergences)
    print(f"{len(divergences)} DIVERGENCES over {len(by_rule)} rules\n")
    for line in divergences[:40]:
        print(line)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
