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
from sagan2sigma.upstream import DefectCode
from sagan2sigma.upstream import inspect as inspect_upstream

from .events import (
    json_arm_reachable,
    negative_literals,
    positive_literals,
    probes,
    to_rsigma_event,
    unplaceable,
)
from .sagan_reference import SaganEvaluator, SaganEvent, is_supported

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


def context(profile: str = "rsigma-syslog") -> Context:
    """Conversion context used by the harness."""
    return Context(
        profile=load_profile(profile),
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


def compare(
    rule: SaganRule, tmp_path: Path, profile: str = "rsigma-syslog"
) -> list[Disagreement]:
    """Run every probe for one rule through both evaluators."""
    converter = Converter(context=context(profile))
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
    shape = converter.context.profile
    found: list[Disagreement] = []
    for probe in probes(rule, variables, json_arm=json_arm_reachable(rule, shape)):
        expected = evaluator.matches(probe.event)
        event = to_rsigma_event(probe.event, rule, shape)
        actual = rsigma_matches(rules_file, event)
        if expected != actual:
            found.append(
                Disagreement(
                    sid=rule.sid,
                    probe=probe.name,
                    sagan=expected,
                    sigma=actual,
                    event=event,
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
    # JSON values the engine cuts at their first colon, which both sides have
    # to cut the same way. sid 5017909's shape: measured on the engine, an
    # event carrying `contentclass` fires and one carrying
    # `contentclass:STS_Site` does not.
    'msg:"x"; program: sharepoint; json_meta_content:".SearchQueryText",contentclass:STS_Site,contentclass:STS_Web; sid:24;',
    'msg:"y"; program: sharepoint; json_content:".Path","c:\\\\temp"; sid:25;',
    # Numeric JSON values, which must not carry a case modifier.
    'msg:"r"; program: azure; json_content:".resultType","0"; sid:18;',
    # event_id with no json_map binding: the engine searches ' <id>: ' in the
    # first nine characters and the converted rule reads a structured EventID,
    # a divergence the conversion declares. The probe carries both.
    'msg:"v"; program: *Security*; event_id: 4624,540; content:"Logon Type"; sid:22;',
    'msg:"w"; program: *Security*; event_id: 4624; content:!"anonymous"; sid:23;',
    # A binding and nothing else, which the engine matches on a plain line as
    # well as on a document. Under this profile the document arm is out of
    # reach, so the probes are plain and the converted rule has to read the
    # unprefixed envelope.
    'msg:"z"; program: sshd; json_map:"src_ip",".ip"; content:"needle"; sid:27;',
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


#: Rules whose text search runs against a JSON body, which only converts under
#: a profile whose pipeline keeps the raw document (`json_raw`). Plain syslog
#: refuses them, so nothing here can be exercised under the default profile.
#:
#: The shapes are the ones the corpus actually uses, and they differ in how the
#: literal has to reach the document. A literal without quotes survives inside
#: a string value; one carrying quotes does not, because serialising escapes
#: them, and it has to be rebuilt as structure instead. Getting that wrong does
#: not produce a failure, it produces two silent evaluators agreeing about
#: nothing, which is why these cases are pinned rather than trusted.
RAW_TEXT_ON_JSON = [
    # Plain text, which lands in a string value unchanged.
    'msg:"aa"; program: cloudtrail; json_content:".eventName","AssumeRole";'
    ' content:"AWSServiceRole"; sid:30;',
    # A whole JSON member, which has to be spliced back as structure.
    'msg:"bb"; program: cloudtrail; json_content:".eventName","ConsoleLogin";'
    ' content:!"|22|mfaAuthenticated|22 3a 20 22|true|22|"; sid:31;',
    # A member missing its outer quotes, the other half of the same problem.
    'msg:"cc"; program: cloudtrail; json_content:".awsRegion","us-east-1";'
    ' content:"eventName|22 3a 20 22|CreateFunction"; sid:32;',
    # Case sensitivity still has to survive the trip through the document.
    'msg:"dd"; program: cloudtrail; json_content:".eventName","AssumeRole";'
    ' content:"AWSServiceRole"; nocase; sid:33;',
]


class TestRawTextOnJsonBody:
    """The family that exists only under an enriched pipeline.

    Measured on the engine first: with a JSON body, `content`, `pcre` and
    `meta_content` search the serialised document and nothing else, key names,
    braces and quotes included. `content:"|7b 22|Msg"` matches `{"Msg":...}`.
    The converted rule searches the profile's `json_raw` field, which carries
    that same string, so the two sides are comparable.
    """

    @pytest.mark.parametrize(
        "options", RAW_TEXT_ON_JSON, ids=lambda o: o.split(";")[-2].strip()
    )
    def test_semantics_agree(self, options: str, tmp_path: Path) -> None:
        line = f"alert any any any -> any any ({options})"
        rule = parse_rule(line, "handwritten.rules", 1)
        assert is_supported(rule), "fixture uses a construct the reference cannot judge"
        disagreements = compare(rule, tmp_path, profile="vector-enriched")
        assert not disagreements, "\n".join(str(d) for d in disagreements)

    def test_the_literals_reach_the_document(self) -> None:
        """Every probe literal has to be findable in the text the engine sees.

        Without this the suite above passes on silence: a literal escaped out of
        recognition leaves Sagan and RSigma both matching nothing, which reads
        as agreement and decides nothing.
        """
        for options in RAW_TEXT_ON_JSON:
            rule = parse_rule(
                f"alert any any any -> any any ({options})", "handwritten.rules", 1
            )
            literals = positive_literals(rule) + negative_literals(rule)
            assert literals, f"sid {rule.sid} carries no raw literal to place"
            assert not unplaceable(rule, literals), (
                f"sid {rule.sid}: {unplaceable(rule, literals)} never reaches the "
                "serialised document, so no probe can decide the rule"
            )


#: Rules the engine matches on a plain line and on a document alike, which is
#: what a `json_map` binding and no other JSON keyword produces. Both arms are
#: probed under the enriched profile, the pipeline keeping a raw body either
#: way, so a conversion naming one shape's envelope fails here.
EITHER_SHAPE = [
    'msg:"ee"; program: sshd; json_map:"src_ip",".ip"; content:"needle"; sid:34;',
    'msg:"ff"; program: sshd; json_map:"username",".user"; syslog_facility: auth;'
    ' content:"needle"; sid:35;',
    # The binding alone, with no envelope selector to disambiguate the shape.
    'msg:"gg"; json_map:"dest_ip",".dst"; content:"needle"; sid:36;',
]


class TestARuleThatMatchesEitherShape:
    """Measured on the engine: the binding changes nothing about what matches.

    `program: sshd; json_map: "src_ip", ".ip"; content:"needle"` fires on a
    plain syslog line exactly as the same rule without the binding does, and on
    a JSON document as well. Converting it for one shape cost 41 corpus rules
    the other, and nothing caught it because the probe generator took its shape
    from the rule too.
    """

    @pytest.mark.parametrize(
        "options", EITHER_SHAPE, ids=lambda o: o.split(";")[-2].strip()
    )
    def test_semantics_agree(self, options: str, tmp_path: Path) -> None:
        line = f"alert any any any -> any any ({options})"
        rule = parse_rule(line, "handwritten.rules", 1)
        assert is_supported(rule), "fixture uses a construct the reference cannot judge"
        disagreements = compare(rule, tmp_path, profile="vector-enriched")
        assert not disagreements, "\n".join(str(d) for d in disagreements)

    def test_both_arms_are_probed(self) -> None:
        """Otherwise the suite above would pass on the document arm alone."""
        line = f"alert any any any -> any any ({EITHER_SHAPE[0]})"
        rule = parse_rule(line, "handwritten.rules", 1)
        shapes = {bool(probe.event.json_body) for probe in probes(rule)}
        assert shapes == {True, False}


class TestArrayMarkedJsonKey:
    """`[]` in a JSON key is part of the name, not a marker.

    Asserted here rather than as a differential fixture because both sides stay
    silent on such a rule, and two silences agree without deciding anything.
    What the engine does was measured one condition at a time: `.data.items[]`
    fires only on a document whose key is literally `items[]`, never on `items`
    holding an array, with or without json_contains.
    """

    RULE = 'alert any any any -> any any (msg:"z"; json_content:".data.items[]","alpha"; sid:26;)'

    def evaluate(self, body: dict[str, object]) -> bool:
        rule = parse_rule(self.RULE, "handwritten.rules", 1)
        return SaganEvaluator(rule).matches(SaganEvent(json_body=body))

    def test_a_key_spelled_with_brackets_matches(self) -> None:
        assert self.evaluate({"data": {"items[]": "alpha"}})

    def test_the_plain_key_does_not(self) -> None:
        assert not self.evaluate({"data": {"items": "alpha"}})

    def test_nor_does_an_array_under_the_plain_key(self) -> None:
        assert not self.evaluate({"data": {"items": ["alpha"]}})


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

#: Defects that make a rule behave in the engine in a way the converter
#: deliberately does not reproduce: a rule that will not load, one that loads
#: and can never match, one the engine reads as the opposite of what it says,
#: and one whose condition the engine can never satisfy. The two sides then
#: disagree by design, so judging such a rule measures that policy rather than
#: the conversion. `differential/engine_differential.py` excludes the same four
#: codes, and for the same reason. `U_PARTIAL_MATCH` is not among them: the
#: converter reproduces the split that causes it, so both sides look for the
#: same text and the rule is judgeable.
#:
#: This became visible when the reference evaluator learned to clip JSON keys
#: the way the engine's key table does. Before that it walked the document and
#: found `.properties.riskLevelDuringSignIn`, so a rule naming a path the
#: engine never stores looked alive and agreed with a converted rule that
#: matches. Modelling the limit made the rule dead, which is correct, and made
#: the disagreement appear, which is the exclusion's job to answer.
DEAD_UPSTREAM = frozenset(
    {
        DefectCode.WILL_NOT_LOAD,
        DefectCode.CANNOT_MATCH,
        DefectCode.INVERTED_CONDITION,
        DefectCode.INERT_CONDITION,
    }
)


def dead_upstream(rule: SaganRule) -> bool:
    """Whether the engine cannot run this rule as written."""
    return any(defect.code in DEAD_UPSTREAM for defect in inspect_upstream(rule))


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
                if is_supported(rule) and not dead_upstream(rule):
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
