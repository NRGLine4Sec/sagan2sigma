"""Differential semantics: does the converted rule match what the original did?

Every other test checks that the converter produces the output we expect. This
one checks that the output *behaves* like the input, which is a different and
much harder question, and the only one that actually matters to a SOC.

Both sides are computed independently:

* the Sagan side by ``sagan_reference.SaganEvaluator``, written from the engine
  C source and importing nothing from ``sagan2sigma.mapping``;
* the Sigma side by the real ``rsigma`` binary, evaluating the document the
  converter emitted.

Neither side knows what the other expects, and the events come from a generator
driven by the rule rather than from hand-written fixtures. A disagreement is
therefore evidence of a real defect rather than a stale expectation.

What this catches: case-sensitivity inversion, negation grouping, wildcard
escaping, hex decoding, ``json_map`` field redirection, numeric versus string
comparison, and alternative handling in ``program``.

What it cannot catch: a misreading of the Sagan source that this evaluator and
the converter happen to share. That limitation is why the reference evaluator
is written from the C rather than from the converter, and why it is worth
keeping the two apart.

The tests are skipped when ``rsigma`` is not on PATH. CI builds it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from sagan2sigma.converter import Converter
from sagan2sigma.emit.yaml_io import dump_collection
from sagan2sigma.errors import Refusal
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.sagan.config import SaganConfig
from sagan2sigma.sagan.model import SaganRule
from sagan2sigma.sagan.parser import iter_rule_files, parse_file, parse_rule

from .events import probes, to_rsigma_event
from .sagan_reference import SaganEvaluator, is_supported

RSIGMA = shutil.which("rsigma")

pytestmark = pytest.mark.skipif(
    RSIGMA is None, reason="build rsigma and put it on PATH to run differential tests"
)

#: Rules drawn from the upstream corpus when it is available. Kept modest so
#: the suite stays usable locally; CI raises it.
CORPUS_SAMPLE = int(os.environ.get("SAGAN2SIGMA_DIFF_SAMPLE", "150"))


@dataclass(frozen=True, slots=True)
class Disagreement:
    """One event on which the two evaluators differ."""

    sid: str
    probe: str
    sagan: bool
    sigma: bool
    event: dict
    rule: str

    def __str__(self) -> str:
        """Render the disagreement so a failing test explains itself."""
        return (
            f"SID {self.sid} probe {self.probe}: sagan={self.sagan} "
            f"sigma={self.sigma}\n  rule:  {self.rule[:220]}\n"
            f"  event: {json.dumps(self.event)[:220]}"
        )


def context() -> Context:
    """Conversion context used by the harness."""
    return Context(
        profile=load_profile("rsigma-syslog"),
        config=SaganConfig(
            classtypes={"attempted-admin": 1, "user-activity": 3},
            references={},
            variables={"USERS": ["bob", "frank"]},
        ),
        catalog=load_catalog(),
    )


def rsigma_matches(rules_file: Path, event: dict) -> bool:
    """Whether the real engine reports a match for this event."""
    completed = subprocess.run(
        [
            str(RSIGMA),
            "engine",
            "eval",
            "--rules",
            str(rules_file),
            "--event",
            json.dumps(event),
            "--output-format",
            "ndjson",
            "--no-stats",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return any(
        line.strip().startswith("{") and "rule_title" in line
        for line in completed.stdout.splitlines()
    )


def compare(rule: SaganRule, tmp_path: Path) -> list[Disagreement]:
    """Run every probe for one rule through both evaluators."""
    converter = Converter(context=context())
    try:
        draft = converter.convert_rule(rule)
    except Refusal:
        return []

    entry = converter.context.catalog.resolve(rule.source_file)
    from sagan2sigma.emit.sigma import build_rule_document

    document = build_rule_document(
        draft=draft,
        sid=rule.sid,
        rev=rule.rev,
        source_file=rule.source_file,
        logsource=entry,
        needs_name=False,
    )
    rules_file = tmp_path / f"{rule.sid}.yml"
    rules_file.write_text(dump_collection([document]), encoding="utf-8")

    variables = converter.context.config.variables
    evaluator = SaganEvaluator(rule, variables)
    found: list[Disagreement] = []
    for probe in probes(rule, variables):
        expected = evaluator.matches(probe.event)
        actual = rsigma_matches(rules_file, to_rsigma_event(probe.event, rule))
        if expected != actual:
            found.append(
                Disagreement(
                    sid=rule.sid,
                    probe=probe.name,
                    sagan=expected,
                    sigma=actual,
                    event=to_rsigma_event(probe.event, rule),
                    rule=rule.raw,
                )
            )
    return found


HAND_WRITTEN = [
    # Case sensitivity, the inversion that silently flips thousands of rules.
    'msg:"a"; program: sshd; content:"Authentication Failure"; sid:1;',
    'msg:"b"; program: sshd; content:"Authentication Failure"; nocase; sid:2;',
    # Negation, singly and grouped.
    'msg:"c"; program: sshd; content:"failed"; content:!"frank"; sid:3;',
    'msg:"d"; program: sshd; content:"failed"; content:!"frank"; content:!"bob"; sid:4;',
    # Alternatives and globs in program.
    'msg:"e"; program: sshd|openssh; content:"x"; sid:5;',
    'msg:"f"; program: *Security*; content:"x"; sid:6;',
    # Literal wildcards, which Sigma would otherwise treat as globs.
    'msg:"g"; program: app; content:"rate 100*"; sid:7;',
    'msg:"h"; program: app; content:"who?"; sid:8;',
    # Hex escapes.
    'msg:"i"; program: app; content:"User Agent|3a| curl"; sid:9;',
    # meta_content, inline and from a variable.
    'msg:"j"; program: sudo; meta_content:"USER=%sagan%",root,admin; sid:10;',
    'msg:"k"; program: sudo; meta_content:"USER=%sagan%",$USERS; sid:11;',
    'msg:"l"; program: sudo; meta_content:"USER=%sagan%",root; meta_nocase; sid:12;',
    # JSON rules, exact and substring, case-sensitive and not.
    'msg:"m"; program: cloudtrail; json_content:".eventName","CreateTrail"; sid:13;',
    'msg:"n"; program: cloudtrail; json_content:".eventName","create"; json_contains; sid:14;',
    'msg:"o"; program: cloudtrail; json_content:".eventName","createtrail"; json_nocase; sid:15;',
    'msg:"p"; program: cloudtrail; json_meta_content:".awsRegion",us-east-1,eu-west-1; sid:16;',
    'msg:"q"; program: cloudtrail; json_content:!".userIdentity.type","Root"; json_content:".eventName","X"; sid:17;',
    # Numeric JSON values, which must not carry a case modifier.
    'msg:"r"; program: azure; json_content:".resultType","0"; sid:18;',
    # json_map redirecting the text search into a JSON key.
    'msg:"s"; program: eventlog; json_map:"message",".Description"; content:"service installed"; sid:19;',
    # Envelope selectors.
    'msg:"t"; program: app; syslog_facility: daemon|auth; content:"x"; sid:20;',
    'msg:"u"; program: app; syslog_level: notice; content:"x"; sid:21;',
]


class TestHandWrittenRules:
    """Rules chosen to exercise each construct where the two formats diverge."""

    @pytest.mark.parametrize(
        "options", HAND_WRITTEN, ids=lambda o: o.split(";")[-2].strip()
    )
    def test_semantics_agree(self, options: str, tmp_path: Path) -> None:
        line = f"alert any any any -> any any ({options})"
        rule = parse_rule(line, "handwritten.rules", 1)
        assert is_supported(rule), "fixture uses a construct the reference cannot judge"
        disagreements = compare(rule, tmp_path)
        assert not disagreements, "\n".join(str(d) for d in disagreements)

    def test_the_harness_can_fail(self, tmp_path: Path) -> None:
        """A deliberately mis-converted rule must be caught.

        Without this, a harness that silently compared nothing would pass.
        """
        line = 'alert any any any -> any any (msg:"x"; program: sshd; content:"Failure"; sid:99;)'
        rule = parse_rule(line, "handwritten.rules", 1)
        evaluator = SaganEvaluator(rule)
        broken = tmp_path / "broken.yml"
        # Same rule with |cased dropped, the classic conversion mistake.
        broken.write_text(
            "title: broken\n"
            "id: 99999999-9999-5999-8999-999999999999\n"
            "logsource: {product: linux}\n"
            "detection:\n"
            "  selection_1: {appname: sshd}\n"
            "  selection_2: {_raw|contains: Failure}\n"
            "  condition: selection_1 and selection_2\n",
            encoding="utf-8",
        )
        flipped = next(p for p in probes(rule) if p.name == "case_flipped")
        assert evaluator.matches(flipped.event) is False
        assert rsigma_matches(broken, to_rsigma_event(flipped.event, rule)) is True


class TestSyntheticCorpus:
    def test_every_supported_fixture_rule_agrees(self, tmp_path: Path) -> None:
        path = Path(__file__).parents[1] / "fixtures" / "rules" / "synthetic.rules"
        disagreements: list[Disagreement] = []
        checked = 0
        for rule in parse_file(path).rules:
            if not is_supported(rule):
                continue
            checked += 1
            disagreements.extend(compare(rule, tmp_path))
        assert checked > 0, "no fixture rule was in scope for the reference evaluator"
        assert not disagreements, "\n".join(str(d) for d in disagreements)


CORPUS = os.environ.get("SAGAN_RULES_DIR")


@pytest.mark.skipif(
    not CORPUS or not Path(CORPUS).is_dir(),
    reason="set SAGAN_RULES_DIR to also run against the upstream corpus",
)
class TestUpstreamCorpus:
    def test_sampled_rules_agree(self, tmp_path: Path) -> None:
        """The real corpus is where constructs nobody anticipated live."""
        candidates: list[SaganRule] = []
        for path in iter_rule_files(Path(CORPUS)):
            for rule in parse_file(path).rules:
                if is_supported(rule):
                    candidates.append(rule)
        assert candidates, "no corpus rule was in scope for the reference evaluator"

        # Deterministic spread across the corpus rather than the first N rules,
        # which would all come from the alphabetically first products.
        step = max(1, len(candidates) // CORPUS_SAMPLE)
        sample = candidates[::step][:CORPUS_SAMPLE]

        disagreements: list[Disagreement] = []
        for rule in sample:
            disagreements.extend(compare(rule, tmp_path))
        assert not disagreements, (
            f"{len(disagreements)} disagreement(s) over {len(sample)} rules\n"
            + "\n".join(str(d) for d in disagreements[:10])
        )
