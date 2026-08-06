"""Batch evaluation driver for the RSigma engine.

RSigma's ``engine eval`` reports which rules matched, but not which event
produced each match, and loading a large rule set costs far more than
evaluating one event. Running one process per event would therefore spend
almost all its time reloading rules.

The way around both problems is a **sentinel event**. A rule matching
``__sentinel__|exists: true`` is appended to the rule set, and a sentinel event
carrying the index of the event that precedes it is interleaved into the
stream. Because RSigma emits matches in event order, the sentinel matches
segment the output, and each sentinel's ``matched_fields`` carries the index it
belongs to. One invocation then yields an exact per-event match set for
thousands of events against thousands of rules.

The technique costs one extra rule and one extra event per real event, and it
relies only on documented output, not on internal ordering guarantees beyond
"results are emitted as events are processed".
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Field name carrying the event index. Chosen to be one no real rule matches.
SENTINEL_FIELD = "__sagan2sigma_sentinel__"

#: Identifier of the sentinel rule, used to recognise its matches.
SENTINEL_ID = "00000000-0000-5000-8000-0000000000ff"

SENTINEL_RULE = f"""\
title: __SAGAN2SIGMA_SENTINEL__
id: {SENTINEL_ID}
status: experimental
description: >-
  Stream marker used by the overlap analyser to attribute matches to events.
  It is never part of the analysed rule set.
logsource: {{}}
detection:
  sentinel:
    {SENTINEL_FIELD}|exists: true
  condition: sentinel
level: informational
"""


class EngineUnavailableError(RuntimeError):
    """The rsigma binary could not be found or refused to run."""


@dataclass(frozen=True, slots=True)
class Match:
    """One rule firing on one event."""

    rule_id: str
    rule_title: str


def find_engine(explicit: str | None = None) -> str:
    """Locate the rsigma binary, preferring an explicit path."""
    candidate = explicit or shutil.which("rsigma")
    if candidate is None or not Path(candidate).exists():
        raise EngineUnavailableError(
            "rsigma was not found. Install it with "
            "`cargo install --locked --features daemon rsigma`, or pass --engine."
        )
    return candidate


def compilable(
    documents: list[dict[str, Any]],
    engine: str | None = None,
    workdir: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split documents into those the engine accepts and those it rejects.

    A rule set is compiled as a whole, and a single rule the engine refuses
    aborts the entire load. pySigma validation does not catch these: the
    offending constructs are ones the Rust ``regex`` crate rejects but Python's
    ``re`` accepts, such as an unescaped ``-`` forming an invalid range inside
    a character class. Several SigmaHQ rules are in that position.

    Rather than parse error messages, which vary by construct, the set is
    bisected: a batch that compiles is accepted wholesale, and one that does not
    is split until the offenders are isolated. That costs O(k log n) engine
    invocations for k bad rules, and it is exact.
    """
    binary = find_engine(engine)
    root = workdir or Path()
    root.mkdir(parents=True, exist_ok=True)
    counter = {"n": 0}

    def compiles(batch: list[dict[str, Any]]) -> bool:
        if not batch:
            return True
        from ..emit.yaml_io import dump_collection

        counter["n"] += 1
        path = root / f"probe-{counter['n']}.yml"
        path.write_text(dump_collection(batch), encoding="utf-8")
        completed = subprocess.run(
            [
                binary,
                "engine",
                "eval",
                "--rules",
                str(path),
                "--event",
                "{}",
                "--output-format",
                "ndjson",
                "--no-stats",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        path.unlink(missing_ok=True)
        return "Error compiling rules" not in (completed.stderr + completed.stdout)

    good: list[dict[str, Any]] = []
    bad: list[dict[str, Any]] = []

    def bisect(batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        if compiles(batch):
            good.extend(batch)
            return
        if len(batch) == 1:
            bad.append(batch[0])
            return
        middle = len(batch) // 2
        bisect(batch[:middle])
        bisect(batch[middle:])

    bisect(documents)
    return good, bad


class RsigmaBatch:
    """Evaluates many events against one rule set in a single invocation."""

    def __init__(
        self,
        rules: Iterable[dict[str, Any]],
        engine: str | None = None,
        workdir: Path | None = None,
    ) -> None:
        """Write the rule set to disk and prepare the engine invocation."""
        from ..emit.yaml_io import dump_collection

        self.engine = find_engine(engine)
        self.workdir = workdir or Path()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.rules_path = self.workdir / "ruleset.yml"

        documents = list(rules)
        text = dump_collection(documents)
        self.rules_path.write_text(f"{text}---\n{SENTINEL_RULE}", encoding="utf-8")
        self.rule_count = len(documents)

    def evaluate(self, events: Sequence[dict[str, Any]]) -> list[set[str]]:
        """Return, for each event, the set of rule ids that matched it.

        The returned list is aligned with ``events``. An event nothing matched
        yields an empty set rather than being omitted, because "matched
        nothing" is a result the analysis needs.
        """
        if not events:
            return []

        stream = []
        for index, event in enumerate(events):
            stream.append(json.dumps(event, ensure_ascii=False))
            stream.append(json.dumps({SENTINEL_FIELD: index}))

        completed = subprocess.run(
            [
                self.engine,
                "engine",
                "eval",
                "--rules",
                str(self.rules_path),
                "--output-format",
                "ndjson",
                "--no-stats",
                "--quiet",
            ],
            input="\n".join(stream) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode not in (0, 1):
            raise EngineUnavailableError(
                f"rsigma exited with {completed.returncode}: "
                f"{completed.stderr.strip()[:400]}"
            )
        return self._segment(completed.stdout, len(events))

    @staticmethod
    def _segment(stdout: str, expected: int) -> list[set[str]]:
        """Split the match stream on sentinel markers."""
        results: list[set[str]] = [set() for _ in range(expected)]
        pending: set[str] = set()

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:  # pragma: no cover - defensive
                continue
            if payload.get("rule_id") == SENTINEL_ID:
                index = _sentinel_index(payload)
                if index is not None and 0 <= index < expected:
                    results[index] = pending
                pending = set()
                continue
            rule_id = payload.get("rule_id")
            if rule_id:
                pending.add(str(rule_id))
        return results


def _sentinel_index(payload: dict[str, Any]) -> int | None:
    """Read the event index a sentinel match carries."""
    for field in payload.get("matched_fields") or []:
        if field.get("field") == SENTINEL_FIELD:
            try:
                return int(field["value"])
            except (KeyError, TypeError, ValueError):  # pragma: no cover
                return None
    return None
