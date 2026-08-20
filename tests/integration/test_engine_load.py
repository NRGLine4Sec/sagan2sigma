"""Does the converted rule set actually load into the engine it targets?

Every other test asks whether a rule is *correct*. This one asks the cruder
question that comes first: will RSigma accept the ruleset at all.

The question is not academic, and the failure mode is unusually harsh. RSigma
compiles every rule up front, and one rule it cannot compile aborts the whole
load: no rules are registered, so a single bad regular expression silently takes
the entire detection set offline rather than costing one rule. That is why
``mapping/regexes.py`` refuses non-portable PCRE constructs instead of emitting
them and hoping. Until this module existed nothing checked the outcome: the
corpus job validates the emitted documents with pySigma, which is a different
and more permissive parser, and the differential job feeds the engine
rule-by-rule from generated documents, never the shipped set.

So these tests hand RSigma the whole thing and require a clean load. They are
cheap, they need no corpus, and they close the gap between "pySigma says the
YAML is valid" and "the target engine will run it".

Skipped when ``rsigma`` is not on PATH; CI installs it in the differential job.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

RSIGMA = shutil.which("rsigma")

pytestmark = pytest.mark.skipif(
    RSIGMA is None,
    reason="build rsigma and put it on PATH to run the engine load tests",
)

REPO = Path(__file__).parents[2]

#: The rule sets committed for use without installing the project. Loading these
#: is what a user does first, so a load failure here ships broken.
SNAPSHOTS = {
    "rsigma-syslog": REPO / "converted" / "rules",
    "vector-enriched": REPO / "converted-vector-enriched" / "rules",
}


def load_report(rules: Path) -> subprocess.CompletedProcess[str]:
    """Ask the engine to compile ``rules``, evaluating one throwaway event.

    ``engine eval`` compiles the whole rule set before it looks at the event, so
    a clean exit is the load check. The event is deliberately inert: what is
    asserted is that the rules compile, not that any of them match.
    """
    return subprocess.run(
        [
            str(RSIGMA),
            "engine",
            "eval",
            "--rules",
            str(rules),
            "--event",
            json.dumps({"message": "engine load probe"}),
            "--output-format",
            "ndjson",
            "--no-stats",
        ],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("profile", sorted(SNAPSHOTS))
def test_committed_snapshot_compiles(profile: str) -> None:
    """The committed rule sets must compile in the engine they are written for."""
    rules = SNAPSHOTS[profile]
    if not rules.is_dir():
        pytest.skip(f"no committed snapshot at {rules}")
    completed = load_report(rules)
    assert completed.returncode == 0, (
        f"the committed {profile} rule set does not load into RSigma, which means "
        f"none of it would run:\n{completed.stderr}"
    )


@pytest.mark.parametrize("profile", sorted(SNAPSHOTS))
def test_snapshot_registers_every_rule_file(profile: str) -> None:
    """A clean exit must also mean rules were registered, not silently zero.

    Guards the case where the engine accepts an empty or unreadable directory
    and exits successfully, which would make the compile test vacuous.
    """
    rules = SNAPSHOTS[profile]
    if not rules.is_dir():
        pytest.skip(f"no committed snapshot at {rules}")
    completed = load_report(rules)
    assert "Loaded" in completed.stderr, (
        f"expected the engine to report what it loaded, got: {completed.stderr!r}"
    )
    loaded = int(completed.stderr.split("Loaded", 1)[1].split()[0])
    assert loaded > 0, f"the engine registered no rules from {rules}"


def test_the_check_can_fail(tmp_path: Path) -> None:
    """A check that cannot fail proves nothing, so prove this one does.

    One rule carrying a construct the Rust engine rejects, next to a rule that is
    perfectly good. Both the non-zero exit and the good rule staying silent are
    asserted, because the second is the property that makes this whole module
    worth having: the cost of one bad rule is the entire rule set.
    """
    (tmp_path / "good.yml").write_text(
        "title: good\n"
        "id: 11111111-1111-5111-8111-111111111111\n"
        "logsource: {product: windows}\n"
        "detection:\n"
        "  sel: {message|contains: probe}\n"
        "  condition: sel\n",
        encoding="utf-8",
    )
    (tmp_path / "bad.yml").write_text(
        "title: bad\n"
        "id: 22222222-2222-5222-8222-222222222222\n"
        "logsource: {product: windows}\n"
        "detection:\n"
        "  sel: {message|re: '(?!look)x'}\n"
        "  condition: sel\n",
        encoding="utf-8",
    )
    completed = load_report(tmp_path)
    assert completed.returncode != 0
    # The good rule matches the probe event, yet nothing is reported: the load
    # aborted before any rule was registered.
    assert completed.stdout.strip() == ""
