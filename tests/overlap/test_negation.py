"""Tests for negation handling during synthesis."""

from __future__ import annotations

from sagan2sigma.overlap.negation import evaluate, leaves, repair, repair_value, split
from sagan2sigma.overlap.synth import satisfies

from .conftest import make_rule


def _condition(rule):
    return rule.detection.parsed_condition[0].parse()


def test_split_separates_positive_from_negated() -> None:
    rule = make_rule(
        {
            "selection": {"EventID": 4625},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        }
    )
    positive, negatives = split(_condition(rule))
    assert positive is not None
    assert len(negatives) == 1


def test_split_pure_negation_has_no_positive() -> None:
    rule = make_rule(
        {"filter": {"src_ip|cidr": "10.0.0.0/8"}, "condition": "not filter"}
    )
    positive, negatives = split(_condition(rule))
    assert positive is None
    assert len(negatives) == 1


def test_leaves_collects_field_constraints() -> None:
    rule = make_rule(
        {
            "selection": {"EventID": 1},
            "filter": {"User": "SYSTEM", "Image|endswith": "\\a.exe"},
            "condition": "selection and not filter",
        }
    )
    _, negatives = split(_condition(rule))
    found = {leaf.field for leaf in leaves(negatives[0])}
    assert found == {"User", "Image"}


def test_repair_fills_a_null_filter() -> None:
    # filter fires because the field is absent; repair must add it.
    rule = make_rule(
        {
            "selection": {"EventID": 1},
            "filter": {"User": None},
            "condition": "selection and not filter",
        }
    )
    _, negatives = split(_condition(rule))
    event = {"EventID": 1}
    assert repair(event, negatives, protected={"EventID"}, matcher=satisfies)
    assert event["User"] == repair_value("User")


def test_repair_moves_an_unprotected_value() -> None:
    rule = make_rule(
        {
            "selection": {"EventID": 1},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        }
    )
    _, negatives = split(_condition(rule))
    event = {"EventID": 1, "User": "SYSTEM"}
    assert repair(event, negatives, protected={"EventID"}, matcher=satisfies)
    assert event["User"] != "SYSTEM"


def test_repair_gives_up_when_field_is_protected() -> None:
    # The only way to disarm the filter is to change a field a positive
    # constraint depends on, which repair must refuse to do.
    rule = make_rule(
        {
            "selection": {"User": "SYSTEM"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        }
    )
    _, negatives = split(_condition(rule))
    event = {"User": "SYSTEM"}
    assert not repair(event, negatives, protected={"User"}, matcher=satisfies)


def test_repair_value_is_field_specific() -> None:
    assert repair_value("a") != repair_value("b")
    assert repair_value("a") == repair_value("a")


def test_evaluate_walks_boolean_tree() -> None:
    # A filter shaped `a and (b or c)` exercises AND, OR and the leaf matcher.
    rule = make_rule(
        {
            "selection": {"EventID": 1},
            "flt_a": {"User": "SYSTEM"},
            "flt_b": {"Image|endswith": "\\a.exe"},
            "condition": "selection and not (flt_a and flt_b)",
        }
    )
    _, negatives = split(_condition(rule))
    node = negatives[0]
    both = {"User": "SYSTEM", "Image": "c:\\a.exe"}
    assert evaluate(node, both, satisfies)
    only_one = {"User": "SYSTEM", "Image": "c:\\other.exe"}
    assert not evaluate(node, only_one, satisfies)


def test_leaves_includes_keyword_terms() -> None:
    rule = make_rule(
        {
            "selection": {"EventID": 1},
            "flt": ["forbidden"],
            "condition": "selection and not flt",
        }
    )
    _, negatives = split(_condition(rule))
    keyword_leaves = [leaf for leaf in leaves(negatives[0]) if leaf.keyword]
    assert keyword_leaves and keyword_leaves[0].field == "_raw"
