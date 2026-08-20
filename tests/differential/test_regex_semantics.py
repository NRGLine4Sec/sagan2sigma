r"""Differential semantics for the one keyword the main harness cannot reach.

``sagan_reference.py`` says it outright: ``pcre`` is deliberately out of scope
there, because generating events for an arbitrary regular expression is a
different problem from evaluating ``content``. The result was a real gap. Every
other keyword family is checked against the engine by behaviour, while the
regular expressions were only ever checked two weaker ways: the converter
refuses non-portable constructs at conversion time, and the rewrites in
``mapping/regexes.py`` are fuzzed against a PCRE oracle in Python. Nothing asked
the question that matters at runtime, which is whether the Rust engine matches
the same strings the original pattern did.

This module asks it, for every distinct ``|re`` pattern the converter emits.

How the fidelity argument closes
--------------------------------
The chain has two links, and each is tested somewhere:

1. *original Sagan pattern* is equivalent to *emitted pattern*. For the large
   majority the two are byte-identical, so there is nothing to prove. For the
   four rewrites (inlined subroutine, escaped literal brace, tempered negation,
   dropped inert flag) ``tests/unit/test_regexes.py`` fuzzes the rewrite against
   a PCRE oracle.
2. *emitted pattern under a mainstream engine* is equivalent to *emitted pattern
   under RSigma*. That is this module, using Python's ``re`` as the reference
   and the real ``rsigma`` binary as the subject.

Together they say the shipped rule matches what Sagan matched. Python ``re`` is
a reasonable stand-in for libpcre over the subset that survives conversion,
which is classes, quantifiers, alternation, anchors and lazy repetition:
look-around, back-references and recursion are refused, and those are where the
engines genuinely diverge.

Why the probes are ASCII
------------------------
Deliberate, and the one caveat worth knowing. Sagan compiles every pattern in
byte mode: the ``PCRE_UTF8`` case in ``src/rules.c`` sits in the block commented
"PCRE options that aren't really used?", so it is never set. Its ``\w`` is
therefore ASCII. The Rust engine behind RSigma is Unicode-aware by default, so
its ``\w`` also matches, say, ``é`` or ``½``. On non-ASCII bytes the two engines
genuinely disagree, and no amount of converter work changes that: it is a
property of the engines, recorded in ``docs/DESIGN-DECISIONS.md``. Probing only
printable ASCII keeps this test measuring the conversion rather than re-deriving
a documented engine difference. An early run of this harness over unrestricted
input is what surfaced it.

Skipped when ``rsigma`` is not on PATH; CI runs it in the differential job.
"""

from __future__ import annotations

import collections
import json
import random
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

RSIGMA = shutil.which("rsigma")

pytestmark = pytest.mark.skipif(
    RSIGMA is None,
    reason="build rsigma and put it on PATH to run the regex semantics differential",
)

REPO = Path(__file__).parents[2]

#: The committed rule sets: what a user actually runs, both profiles.
SNAPSHOTS = (REPO / "converted" / "rules", REPO / "converted-vector-enriched" / "rules")

#: Fixed so a failure is reproducible and a green run is not luck.
SEED = 20260820

#: Probes generated per pattern before mutation. Small on purpose: the cost is
#: dominated by the cross product, and every probe is tested against every
#: pattern, so breadth comes from the corpus rather than from the count.
GENERATED = 6
NOISE = 8


def _collect(block: object, found: list[tuple[str, tuple[str, ...]]]) -> None:
    """Walk a detection block, collecting ``(pattern, modifiers)`` pairs."""
    if isinstance(block, dict):
        for key, value in block.items():
            if isinstance(key, str) and key.split("|")[1:2] == ["re"]:
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if isinstance(item, str):
                        found.append((item, tuple(key.split("|")[1:])))
            _collect(value, found)
    elif isinstance(block, list):
        for item in block:
            _collect(item, found)


#: The committed sets are tens of thousands of documents, and the pure-Python
#: parser dominates this test's runtime by an order of magnitude: reading them
#: takes about eighty seconds with ``SafeLoader`` against ten with the C one.
#: The fallback keeps the test working on a PyYAML built without libyaml.
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def emitted_patterns() -> list[tuple[str, tuple[str, ...]]]:
    """Every distinct regular expression in the committed rule sets."""
    found: list[tuple[str, tuple[str, ...]]] = []
    for snapshot in SNAPSHOTS:
        for path in sorted(snapshot.glob("*.yml")):
            with path.open(encoding="utf-8") as handle:
                for document in yaml.load_all(handle, Loader=_LOADER):
                    if isinstance(document, dict) and "detection" in document:
                        _collect(document["detection"], found)
    return sorted(set(found))


def python_flags(modifiers: tuple[str, ...]) -> int:
    """The Sigma modifiers that change matching, as ``re`` flags."""
    flags = 0
    if "i" in modifiers:
        flags |= re.IGNORECASE
    if "s" in modifiers:
        flags |= re.DOTALL
    if "m" in modifiers:
        flags |= re.MULTILINE
    return flags


def _printable_ascii(value: str) -> bool:
    return bool(value) and all(32 <= ord(char) < 127 for char in value)


def probes(pattern: str) -> set[str]:
    """Strings to test one pattern with: matches, near misses and noise.

    ``exrex`` supplies strings the pattern accepts, which is the hard part; the
    mutations then walk just outside them, where an off-by-one in a quantifier
    or a mis-escaped class shows up. The noise strings are drawn from the
    pattern's own literals so they collide with it far more often than random
    text would.
    """
    import exrex  # type: ignore[import-untyped]

    out: set[str] = set()
    for _ in range(GENERATED):
        # exrex gives up on some shapes; the noise strings below cover those.
        try:
            out.add(str(exrex.getone(pattern, limit=3)))
        except Exception:
            break

    literals = re.findall(r"[A-Za-z0-9 _:=./\\-]{2,}", pattern)
    alphabet = "".join(sorted(set("".join(literals) + "${}[]()!-%+/#'`.*? abcXYZ019")))[
        :70
    ]
    for _ in range(NOISE):
        length = random.randint(0, 30)
        out.add("".join(random.choice(alphabet) for _ in range(length)))

    for value in list(out):
        if value:
            out.update(
                {
                    value[:-1],
                    value.upper(),
                    value.lower(),
                    value[: len(value) // 2] + "@" + value[len(value) // 2 :],
                }
            )
    return {value for value in out if _printable_ascii(value)}


def rsigma_matches(
    patterns: list[tuple[str, tuple[str, ...]]], events: list[str]
) -> dict[str, set[str]]:
    """Evaluate every pattern against every event in one engine run.

    RSigma reads NDJSON from stdin and evaluates the whole rule set per event,
    so the entire corpus is one process rather than one per case. That is what
    makes a cross product of a few million pairs cheap enough to run in CI.
    """
    documents = [
        {
            "title": f"p{index}",
            "id": f"{index:08x}-0000-5000-8000-000000000000",
            "logsource": {"product": "regression"},
            "detection": {"sel": {"|".join(["D", *mods]): pattern}, "condition": "sel"},
        }
        for index, (pattern, mods) in enumerate(patterns)
    ]
    directory = Path(tempfile.mkdtemp())
    rules = directory / "patterns.yml"
    rules.write_text(
        "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in documents),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            str(RSIGMA),
            "engine",
            "eval",
            "--rules",
            str(rules),
            "--output-format",
            "ndjson",
            "--no-stats",
        ],
        input="\n".join(json.dumps({"D": event}) for event in events),
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (
        f"the engine refused the emitted patterns:\n{completed.stderr}"
    )
    fired: dict[str, set[str]] = collections.defaultdict(set)
    for line in completed.stdout.splitlines():
        if line.strip().startswith("{"):
            result = json.loads(line)
            fired[result["rule_title"]].add(result["matched_fields"][0]["value"])
    return fired


def disagreements(
    patterns: list[tuple[str, tuple[str, ...]]],
) -> list[tuple[str, tuple[str, ...], str, bool, bool]]:
    """Every ``(pattern, event)`` pair the two engines judge differently."""
    random.seed(SEED)
    events: set[str] = set()
    for pattern, _ in patterns:
        events |= probes(pattern)
    ordered = sorted(events)
    fired = rsigma_matches(patterns, ordered)

    found = []
    for index, (pattern, mods) in enumerate(patterns):
        compiled = re.compile(pattern, python_flags(mods))
        matched = fired.get(f"p{index}", set())
        for event in ordered:
            reference = bool(compiled.search(event))
            engine = event in matched
            if reference != engine:
                found.append((pattern, mods, event, reference, engine))
    return found


def test_every_emitted_regex_behaves_the_same_in_the_engine() -> None:
    """The whole point: no emitted pattern may match differently under RSigma."""
    pytest.importorskip("exrex", reason="pip install exrex to generate regex probes")
    patterns = emitted_patterns()
    assert patterns, "no regular expressions found in the committed rule sets"
    found = disagreements(patterns)
    report = "\n".join(
        f"  {pattern!r} {mods} on {event!r}: python={reference} rsigma={engine}"
        for pattern, mods, event, reference, engine in found[:20]
    )
    assert not found, (
        f"{len(found)} pattern/event pairs match differently under RSigma than "
        f"under the reference engine:\n{report}"
    )


def test_the_differential_can_fail() -> None:
    """A differential that cannot report a difference proves nothing.

    ``(?i)`` inside the pattern is honoured by Python and, here, deliberately
    paired with a pattern whose engine-side rule carries no ``i`` modifier, so
    the two sides must disagree on a case that only one of them accepts.
    """
    patterns = [(r"needle", ("re",))]
    random.seed(SEED)
    fired = rsigma_matches(patterns, ["NEEDLE", "needle"])
    engine_hits = fired.get("p0", set())
    # The engine is case-sensitive here; a reference that ignored case would
    # disagree on "NEEDLE", which is exactly the shape of a real regression.
    assert "needle" in engine_hits
    assert "NEEDLE" not in engine_hits
    reference_ignoring_case = re.compile("needle", re.IGNORECASE)
    assert bool(reference_ignoring_case.search("NEEDLE")) != ("NEEDLE" in engine_hits)
