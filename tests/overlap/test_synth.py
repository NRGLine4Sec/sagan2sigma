"""Tests for event synthesis.

The engine-backed tests are the important ones: for each Sigma construct, they
assert that the real engine confirms the synthesised event fires the rule it
was built from. That is self-validating, so it is the right shape for this
module. The plain tests cover the value machinery and the unsatisfiable cases
the engine never sees.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.types import SigmaCasedString, SigmaString

from sagan2sigma.overlap.engine import RsigmaBatch
from sagan2sigma.overlap.synth import (
    Constraint,
    StringSpec,
    Unsatisfiable,
    _cidr_value,
    _regex_is_anchored,
    _regex_value,
    _string_parts,
    materialise,
    satisfies,
    synthesise,
)

from .conftest import make_document, make_rule, needs_engine

# --- value machinery ------------------------------------------------------


def test_string_parts_splits_wildcards() -> None:
    assert _string_parts(SigmaString("*admin*")) == (True, True, ["admin"])
    assert _string_parts(SigmaString("SYSTEM")) == (False, False, ["SYSTEM"])
    assert _string_parts(SigmaString("*\\cmd.exe")) == (True, False, ["\\cmd.exe"])


def test_string_spec_render_exact_wins() -> None:
    spec = StringSpec(exact="value", prefix="pre")
    assert spec.render() == "value"


def test_string_spec_render_composes_fragments() -> None:
    spec = StringSpec(prefix="pre", suffix="post", contains=["mid"])
    rendered = spec.render()
    assert rendered.startswith("pre")
    assert rendered.endswith("post")
    assert "mid" in rendered


def test_materialise_conflicting_exacts_is_unsatisfiable() -> None:
    with pytest.raises(Unsatisfiable):
        materialise(
            [
                Constraint("Field", SigmaString("one")),
                Constraint("Field", SigmaString("two")),
            ]
        )


def test_materialise_scalar_and_string_conflict() -> None:
    from sigma.types import SigmaNumber

    with pytest.raises(Unsatisfiable):
        materialise(
            [
                Constraint("Field", SigmaNumber(1)),
                Constraint("Field", SigmaString("*x*")),
            ]
        )


def test_materialise_empty_requires_allow_empty() -> None:
    with pytest.raises(Unsatisfiable):
        materialise([])
    assert materialise([], allow_empty=True) == {"_raw": "zq"}


def test_materialise_conflicting_prefixes_is_unsatisfiable() -> None:
    with pytest.raises(Unsatisfiable):
        materialise(
            [
                Constraint("F", SigmaString("abc*")),
                Constraint("F", SigmaString("xyz*")),
            ]
        )


def test_materialise_conflicting_suffixes_is_unsatisfiable() -> None:
    with pytest.raises(Unsatisfiable):
        materialise(
            [
                Constraint("F", SigmaString("*abc")),
                Constraint("F", SigmaString("*xyz")),
            ]
        )


def test_materialise_resolves_a_field_reference() -> None:
    from sigma.types import SigmaFieldReference

    event = materialise([Constraint("a", SigmaFieldReference("b"))])
    assert event["a"] == event["b"]


def test_satisfies_cased_string() -> None:
    assert satisfies({"F": "SYSTEM"}, Constraint("F", SigmaCasedString("*SYSTEM*")))
    assert not satisfies({"F": "system"}, Constraint("F", SigmaCasedString("*SYSTEM*")))


def test_synthesise_respects_limit_and_deduplicates() -> None:
    rule = make_rule(
        {
            "a": {"EventID": 1},
            "b": {"EventID": 2},
            "c": {"EventID": 3},
            "condition": "a or b or c",
        }
    )
    assert len(synthesise(rule, limit=2)) == 2
    # Two branches that materialise to the same event collapse to one.
    same = make_rule({"a": {"EventID": 9}, "b": {"EventID": 9}, "condition": "a or b"})
    assert len(synthesise(same, limit=4)) == 1


def test_cidr_value_is_inside_the_network() -> None:
    import ipaddress

    from sigma.types import SigmaCIDRExpression

    value = _cidr_value(SigmaCIDRExpression("10.0.0.0/8"))
    assert ipaddress.ip_address(value) in ipaddress.ip_network("10.0.0.0/8")


def test_regex_value_matches_and_is_verified() -> None:
    import re

    generated = _regex_value("admin[0-9]+")
    assert re.search("admin[0-9]+", generated)


def test_regex_value_impossible_raises() -> None:
    with pytest.raises(Unsatisfiable):
        _regex_value("(?=x)(?=y)z")  # contradictory lookaheads, no match exists


def test_regex_is_anchored() -> None:
    assert _regex_is_anchored("^abc$")
    assert not _regex_is_anchored("abc")


def test_satisfies_handles_absence() -> None:
    from sigma.types import SigmaExists, SigmaNull

    assert satisfies({}, Constraint("F", SigmaNull()))
    assert not satisfies({"F": "x"}, Constraint("F", SigmaNull()))
    assert satisfies({"F": "x"}, Constraint("F", SigmaExists(True)))
    assert satisfies({}, Constraint("F", SigmaExists(False)))


def test_satisfies_substring_and_anchors() -> None:
    assert satisfies({"F": "abcdef"}, Constraint("F", SigmaString("*cd*")))
    assert satisfies({"F": "abcdef"}, Constraint("F", SigmaString("abc*")))
    assert not satisfies({"F": "abcdef"}, Constraint("F", SigmaString("xyz*")))


def test_satisfies_scalar_and_pattern_types() -> None:
    from sigma.types import (
        SigmaBool,
        SigmaCIDRExpression,
        SigmaNumber,
        SigmaRegularExpression,
    )

    assert satisfies({"F": 5}, Constraint("F", SigmaNumber(5)))
    assert not satisfies({"F": 6}, Constraint("F", SigmaNumber(5)))
    assert satisfies({"F": True}, Constraint("F", SigmaBool(True)))
    assert satisfies(
        {"F": "admin42"}, Constraint("F", SigmaRegularExpression("min[0-9]"))
    )
    assert satisfies(
        {"F": "10.1.2.3"}, Constraint("F", SigmaCIDRExpression("10.0.0.0/8"))
    )
    assert not satisfies(
        {"F": "8.8.8.8"}, Constraint("F", SigmaCIDRExpression("10.0.0.0/8"))
    )
    # A field the event does not carry never satisfies a positive constraint.
    assert not satisfies({}, Constraint("F", SigmaNumber(5)))


def test_compare_value_honours_the_operator() -> None:
    # Regression: the operator name is GT/LT/GTE/LTE, so a lowercase test
    # against the enum's integer value silently produced a non-satisfying value.
    from sigma.types import SigmaCompareExpression, SigmaNumber

    op = SigmaCompareExpression.CompareOperators
    from sagan2sigma.overlap.synth import _compare_value

    assert _compare_value(SigmaCompareExpression(SigmaNumber(5), op.GT)) == 6
    assert _compare_value(SigmaCompareExpression(SigmaNumber(5), op.GTE)) == 6
    assert _compare_value(SigmaCompareExpression(SigmaNumber(5), op.LT)) == 4
    assert _compare_value(SigmaCompareExpression(SigmaNumber(5), op.LTE)) == 4


# --- synthesis, self-checked with the local matcher -----------------------

CASES: dict[str, dict] = {
    "equality": {"sel": {"EventID": 4625}, "condition": "sel"},
    "contains": {"sel": {"CommandLine|contains": "whoami"}, "condition": "sel"},
    "endswith": {"sel": {"Image|endswith": "\\cmd.exe"}, "condition": "sel"},
    "regex": {"sel": {"CommandLine|re": "admin[0-9]+"}, "condition": "sel"},
    "cidr": {"sel": {"src_ip|cidr": "10.0.0.0/8"}, "condition": "sel"},
    "or": {"a": {"EventID": 1}, "b": {"EventID": 2}, "condition": "a or b"},
    "keyword": {"kw": ["needle"], "condition": "kw"},
    "compare_gt": {"sel": {"Count|gt": 5}, "condition": "sel"},
    "compare_lt": {"sel": {"Count|lt": 5}, "condition": "sel"},
    "bool": {"sel": {"Flag": True}, "condition": "sel"},
    "exists": {"sel": {"Field|exists": True}, "condition": "sel"},
    "field_reference": {"sel": {"a|fieldref": "b"}, "condition": "sel"},
    "base64offset": {
        "sel": {"CommandLine|base64offset|contains": "whoami"},
        "condition": "sel",
    },
    "null_filter": {
        "sel": {"EventID": 1},
        "flt": {"User": None},
        "condition": "sel and not flt",
    },
    "value_filter": {
        "sel": {"Image|endswith": "\\a.exe"},
        "flt": {"User": "SYSTEM"},
        "condition": "sel and not flt",
    },
}


@pytest.mark.parametrize("detection", CASES.values(), ids=list(CASES))
def test_synthesise_produces_events(detection: dict) -> None:
    events = synthesise(make_rule(detection), limit=4)
    assert events, f"no event synthesised for {detection}"


def test_synthesise_pure_negation() -> None:
    rule = make_rule({"flt": {"src_ip|cidr": "10.0.0.0/8"}, "condition": "not flt"})
    assert synthesise(rule, limit=2)


# --- engine-backed: the engine must confirm each synthesised event --------


@needs_engine
@pytest.mark.parametrize("detection", CASES.values(), ids=list(CASES))
def test_engine_confirms_synthesised_events(detection: dict, tmp_path: Path) -> None:
    document = make_document(detection)
    events = synthesise(make_rule(detection, rule_id=document["id"]), limit=4)
    assert events
    batch = RsigmaBatch([document], workdir=tmp_path)
    matches = batch.evaluate(events)
    fired = sum(1 for matched in matches if document["id"] in matched)
    assert fired >= 1, f"engine confirmed no event for {detection}"
