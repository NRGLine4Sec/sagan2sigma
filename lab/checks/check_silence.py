#!/usr/bin/env python3
"""Try to falsify each reason the differential gives for a silent rule.

Why this exists
---------------
`silence_reason()` is a cascade of `if`s, and until this check existed not one
of them verified its own claim. One did not even try: any silent rule carrying
`country_code` was labelled "no address in the test database has the country the
rule wants", which was wrong for 138 rules and hid a real defect in the lab's
pipeline for a whole run. A reason nobody can check is worth less than no reason
at all, because it stops the reader looking.

The method
----------
Each reason blames one thing for the probe not satisfying the rule. So remove
exactly that thing and ask the engine again:

    the rule as it stands        expected: silent
    the rule without the blamed option   expected: fires

A reason survives when both hold. It fails when the reduced rule stays silent,
which means something else is stopping the probe and the label is a guess.

Only the Sagan side is run. The claim under test is about the probe, not about
the conversion: whether the generated event can satisfy the rule at all.

Usage
-----
    python checks/check_silence.py --report silence.json --rules <corpus>

`--report` is what `engine_differential.py --silence-report` writes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

LAB = Path(__file__).resolve().parent.parent
#: The lab lives inside the repository it measures, so the converter and
#: the probe generator it imports are always the ones in this checkout.
REPO = LAB.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "differential"))
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from engine_differential import (
    _country_bindings,
    _feed_context,
    strip_threshold,
)
from sagan2sigma.errors import Refusal
from sagan2sigma.mapping.content import split_meta_content
from sagan2sigma.mapping.context import (
    Context,
    load_catalog,
    load_profile,
)
from sagan2sigma.sagan.config import load_config
from sagan2sigma.sagan.hexdec import decode_hex
from sagan2sigma.sagan.parser import parse_rule
from tests.differential.events import (
    json_arm_reachable,
    positive_literals,
    probes,
    unplaceable,
    wire_body,
)

from harness import PATCHED, sagan
from harness import event as pipe_event

#: The option each reason blames, as a regular expression over the rule text.
#: A reason with no entry here cannot be falsified this way and is reported as
#: such rather than passed silently.
BLAMED: dict[str, str] = {
    "a pcre sample no serialised document can carry": r"\s*pcre\s*:[^;]*;",
    "an alert_time window that excludes the instant this run used": r"\s*alert_time\s*:[^;]*;",
    "a pcre the generated text does not satisfy": r"\s*pcre\s*:[^;]*;",
    "a literal no serialised document can carry": "",
    "event_id with no json_map on a JSON body, where the ' <id>: ' prefix "
    "cannot go": r"\s*event_id\s*:[^;]*;",
    "an effective offset, depth or distance the probe cannot honour": (
        r"\s*(?:offset|depth|distance|within)\s*:[^;]*;"
    ),
}


def line_for(sid: str, corpus: Path) -> tuple[str, str] | None:
    for path in sorted(corpus.glob("*.rules")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if f"sid:{sid};" in line or f"sid: {sid};" in line:
                return line, path.name
    return None


class NoProbe(Exception):
    """The generator produces no probe for this rule, so nothing can be asked."""


def fires(
    rule: Any,
    raw: str,
    context: Context,
    clock: tuple[str, str] | None = None,
) -> bool:
    """Whether Sagan alerts on the rule's own base probe.

    `strip_threshold` and the instant come from the differential: a rule judged
    there under those conditions has to be asked here under the same ones. The
    first version of this check did neither, and reported three `alert_time`
    rules as firing because it happened to run inside their window.
    """
    built = list(
        probes(
            rule,
            context.config.variables,
            context=_feed_context(rule, {"geoip": True}, context),
            bindings=_country_bindings(rule, context),
            json_arm=json_arm_reachable(rule, context.profile),
        )
    )
    base = next((p for p in built if p.name == "base"), None)
    if base is None:
        raise NoProbe(rule.sid)
    body = wire_body(base.event)
    line = pipe_event(
        body,
        program=base.event.program or "syslog",
        facility=base.event.facility,
        level=base.event.level,
    )
    got = sagan(
        rules=[strip_threshold(raw)],
        events=[line],
        binary=PATCHED,
        at_time=clock[0] if clock else None,
        timezone=clock[1] if clock else None,
    )
    return any(rule.sid in sids for sids in got.values())


#: The reason whose blamed thing is a set of literals rather than a keyword.
LITERAL_REASON = "a literal no serialised document can carry"


def strip_literal_carriers(raw: str, rule: Any, variables: Any) -> str:
    """The rule without the options carrying a literal no document can hold.

    Both keywords that search text are stripped, not just `content`: five rules
    carry theirs in a `meta_content` template, and a checker that only knew
    about one of the two reported them as unverifiable.
    """
    stuck = unplaceable(rule, positive_literals(rule, variables))
    if not stuck:
        return raw
    for keyword in ("content", "meta_content"):
        for option in rule.iter_options(keyword):
            text = decode_hex((option.value or "").strip().strip('"'))
            # A meta_content is a template: the literal that could not be
            # placed is `Name":"RedirectTo`, instantiated from
            # `Name":"%sagan%",RedirectTo,...`, and neither string contains the
            # other. Matching on the template's own fragments ties the two
            # together, and the template has to be decoded first: it reads
            # `Name|22 3a 22|%sagan%` in the rule and `Name":"` in the literal.
            if keyword == "meta_content":
                try:
                    _, template, _ = split_meta_content(option.value or "")
                except Refusal:
                    template = text
                text = decode_hex(template)
            fragments = [part for part in text.split("%sagan%") if part]
            if not any(
                literal in text
                or text in literal
                or all(fragment in literal for fragment in fragments)
                for literal in stuck
            ):
                continue
            for spelling in (
                f"{keyword}:{option.value}",
                f"{keyword}: {option.value}",
            ):
                if spelling in raw:
                    raw = raw.replace(spelling, "", 1)
                    break
    return raw


def reduce_rule(raw: str, rule: Any, causes: list[str], variables: Any) -> str | None:
    """The rule with every blamed option removed, or None when one has no rule.

    A rule can be blamed for more than one thing at once, and removing only the
    first leaves the others in place: that is what made three rules read as
    "the reason is wrong" when the reason was merely incomplete.
    """
    reduced = raw
    for cause in causes:
        if cause == LITERAL_REASON:
            reduced = strip_literal_carriers(reduced, rule, variables)
            continue
        pattern = BLAMED.get(cause)
        if pattern is None:
            return None
        reduced = re.sub(pattern, "", reduced, flags=re.IGNORECASE)
    return _drop_orphan_modifiers(reduced)


#: A modifier and the keyword it qualifies. Removing the keyword leaves the
#: modifier with nothing to attach to and the engine refuses the whole file:
#: "There is no 'meta_content' to apply a 'meta_nocase' to". Two rules failed
#: this check for that reason alone, which says nothing about the reason under
#: test.
_ORPHANS = {
    "meta_nocase": "meta_content",
    "meta_offset": "meta_content",
    "meta_depth": "meta_content",
    "nocase": "content",
}


def _drop_orphan_modifiers(raw: str) -> str:
    """The rule without modifiers whose keyword no longer precedes them.

    The engine's test is positional: `rules.c` refuses a `meta_nocase` while
    `meta_content_count` is still zero, so a negated `meta_content` further
    along the line does not save it. A first version of this checked that the
    keyword appeared anywhere in the rule, and the two rules kept failing.
    """
    inner_start = raw.index("(") + 1
    inner_end = raw.rindex(")")
    options = re.findall(
        r"[a-z_0-9]+\s*:\s*[^;]*;|[a-z_0-9]+\s*;", raw[inner_start:inner_end]
    )
    seen: set[str] = set()
    kept: list[str] = []
    for option in options:
        name = option.split(":")[0].strip().rstrip(";").strip()
        needed = _ORPHANS.get(name)
        if needed is not None and needed not in seen:
            continue
        seen.add(name)
        kept.append(option.strip())
    return raw[:inner_start] + " ".join(kept) + raw[inner_end:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--profile", default="vector-enriched")
    parser.add_argument(
        "--at-time",
        help="the instant the differential ran at, which alert_time rules need",
    )
    parser.add_argument("--timezone", default="UTC")
    args = parser.parse_args(argv)

    context = Context(
        profile=load_profile(args.profile),
        config=load_config(rules_dir=args.rules, sagan_yaml=LAB / "config/sagan.yaml"),
        catalog=load_catalog(),
    )
    report: dict[str, list[str]] = json.loads(args.report.read_text("utf-8"))
    outcomes: dict[str, list[str]] = defaultdict(list)
    clock = (args.at_time, args.timezone) if args.at_time else None

    for reason, sids in sorted(report.items()):
        print(f"\n{reason}  ({len(sids)} rules)")
        causes = reason.split(" + ")
        for sid in sids:
            found = line_for(sid, args.rules)
            if found is None:
                print(f"  {sid}: not in the corpus")
                outcomes["not in the corpus"].append(sid)
                continue
            raw, filename = found
            rule = parse_rule(raw, filename, 1)
            reduced_raw = reduce_rule(raw, rule, causes, context.config.variables)
            if reduced_raw is None:
                print(f"  {sid}: no option to remove for this reason")
                outcomes["not falsifiable"].append(sid)
                continue
            if reduced_raw == raw:
                print(f"  {sid}: nothing to remove, the blame does not land")
                outcomes["blamed option absent"].append(sid)
                continue
            try:
                as_is = fires(rule, raw, context, clock)
                without = fires(
                    parse_rule(reduced_raw, filename, 1), reduced_raw, context, clock
                )
            except NoProbe:
                print(f"  {sid}: the reduced rule has no probe to ask about")
                outcomes["reduced rule has no probe"].append(sid)
                continue
            except RuntimeError as failure:
                lines = str(failure).splitlines()
                detail = next((x for x in lines if "[E]" in x), lines[0])[:90]
                print(f"  {sid}: the engine refused the rule: {detail}")
                outcomes["engine refused the rule alone"].append(sid)
                continue
            verdict = (
                "confirmed"
                if not as_is and without
                else "fires as it stands"
                if as_is
                else "still silent without it"
            )
            print(f"  {sid}: {verdict}")
            outcomes[verdict].append(sid)

    print("\nsummary")
    for verdict, sids in sorted(outcomes.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(sids):4}  {verdict}")
    return 0 if not outcomes["still silent without it"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
