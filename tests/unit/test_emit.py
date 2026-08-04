"""Tests for Sigma document construction and serialisation."""

from __future__ import annotations

import pytest
import yaml

from sagan2sigma.emit.sigma import (
    build_detection,
    build_rule_document,
    build_xbit_aggregate,
    rule_name,
    slug,
    stable_uuid,
)
from sagan2sigma.emit.yaml_io import dump_collection, dump_document
from sagan2sigma.mapping.context import LogSourceEntry
from sagan2sigma.mapping.ir import Predicate, RuleDraft


def predicate(field="_raw", value="x", negated=False, modifiers=("contains",)):
    return Predicate(field=field, modifiers=modifiers, values=(value,), negated=negated)


class TestStableIdentifiers:
    def test_uuid_is_deterministic(self) -> None:
        assert stable_uuid("rule", "5000116") == stable_uuid("rule", "5000116")

    def test_uuid_differs_per_sid(self) -> None:
        assert stable_uuid("rule", "1") != stable_uuid("rule", "2")

    def test_uuid_differs_per_kind(self) -> None:
        assert stable_uuid("rule", "1") != stable_uuid("correlation", "1")

    def test_rule_name(self) -> None:
        assert rule_name("5000116") == "sagan_5000116"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("system.reboot", "system_reboot"),
            ("Brute-Force!", "brute-force_"),
            ("a b", "a_b"),
            ("brute_force", "brute_force"),
        ],
    )
    def test_slug(self, raw: str, expected: str) -> None:
        assert slug(raw) == expected

    def test_slug_keeps_hyphens_and_underscores_apart(self) -> None:
        assert slug("brute-force") != slug("brute_force")


class TestBuildDetection:
    def test_single_predicate(self) -> None:
        blocks, condition = build_detection([predicate()])
        assert blocks == {"selection_1": {"_raw|contains": "x"}}
        assert condition == "selection_1"

    def test_conjunction(self) -> None:
        _, condition = build_detection([predicate(value="a"), predicate(value="b")])
        assert condition == "selection_1 and selection_2"

    def test_single_negation(self) -> None:
        _, condition = build_detection(
            [predicate(value="a"), predicate(value="b", negated=True)]
        )
        assert condition == "selection_1 and not filter_2"

    def test_several_negations_are_grouped(self) -> None:
        _, condition = build_detection(
            [
                predicate(value="a"),
                predicate(value="b", negated=True),
                predicate(value="c", negated=True),
            ]
        )
        assert condition == "selection_1 and not (filter_2 or filter_3)"

    def test_same_key_twice_does_not_collide(self) -> None:
        """One block per predicate is exactly what makes this safe."""
        blocks, _ = build_detection([predicate(value="a"), predicate(value="b")])
        assert len(blocks) == 2

    def test_refuses_a_negation_only_rule(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            build_detection([predicate(negated=True)])

    def test_prefix_isolates_branches(self) -> None:
        blocks, condition = build_detection([predicate()], prefix="s1_")
        assert "s1_selection_1" in blocks
        assert condition == "s1_selection_1"


class TestBuildRuleDocument:
    @pytest.fixture
    def draft(self) -> RuleDraft:
        draft = RuleDraft()
        draft.title = "Test rule"
        draft.level = "high"
        draft.tags = {"attack.t1059"}
        draft.references = ["https://example.org"]
        draft.add(predicate())
        return draft

    @pytest.fixture
    def entry(self) -> LogSourceEntry:
        return LogSourceEntry(
            logsource={"product": "linux"}, category="Unix", is_fallback=False
        )

    def test_document_shape(self, draft: RuleDraft, entry: LogSourceEntry) -> None:
        doc = build_rule_document(
            draft, "5000116", "2", "ssh.rules", entry, needs_name=False
        )
        assert doc["title"] == "Test rule"
        assert doc["logsource"] == {"product": "linux"}
        assert doc["level"] == "high"
        assert doc["tags"] == ["attack.t1059"]
        assert doc["custom_attributes"]["sagan.sid"] == "5000116"
        assert "name" not in doc

    def test_name_appears_only_when_correlated(self, draft, entry) -> None:
        doc = build_rule_document(draft, "1", "1", "f.rules", entry, needs_name=True)
        assert doc["name"] == "sagan_1"

    def test_falsepositives_are_honest(self, draft, entry) -> None:
        doc = build_rule_document(draft, "1", "1", "f.rules", entry, needs_name=False)
        assert doc["falsepositives"] and "Unassessed" in doc["falsepositives"][0]


class TestXbitAggregate:
    def _draft(self, value: str) -> RuleDraft:
        draft = RuleDraft()
        draft.title = f"setter {value}"
        draft.add(predicate(value=value))
        return draft

    def test_branches_are_disjunctive(self) -> None:
        doc, _ = build_xbit_aggregate(
            "brute_force", [("1", self._draft("a")), ("2", self._draft("b"))], 250
        )
        assert doc["detection"]["condition"] == "(s1_selection_1) or (s2_selection_1)"
        assert doc["name"] == "sagan_xbit_brute_force"

    def test_truncation_is_reported(self) -> None:
        setters = [(str(i), self._draft(f"v{i}")) for i in range(5)]
        doc, degradation = build_xbit_aggregate("b", setters, max_branches=2)
        assert degradation is not None
        assert len(doc["detection"]) == 3  # two branches plus the condition

    def test_refuses_an_empty_setter_list(self) -> None:
        with pytest.raises(ValueError, match="no usable setter"):
            build_xbit_aggregate("b", [], 250)


class TestYamlSerialisation:
    def test_round_trips(self) -> None:
        document = {
            "title": "t",
            "detection": {"selection_1": {"a": 1}, "condition": "selection_1"},
        }
        assert yaml.safe_load(dump_document(document)) == document

    def test_preserves_key_order(self) -> None:
        text = dump_document({"title": "t", "id": "x", "status": "experimental"})
        assert text.index("title") < text.index("id") < text.index("status")

    def test_is_deterministic(self) -> None:
        document = {"b": 1, "a": 2, "c": [3, 4]}
        assert dump_document(document) == dump_document(document)

    def test_collection_separator(self) -> None:
        text = dump_collection([{"a": 1}, {"b": 2}])
        assert text.count("---") == 1
        assert len(list(yaml.safe_load_all(text))) == 2

    def test_no_anchors_on_repeated_objects(self) -> None:
        shared = {"x": 1}
        text = dump_document({"a": shared, "b": shared})
        assert "&id" not in text and "*id" not in text


class TestAggregateNameCollisions:
    """The upstream corpus carries both brute_force and brute-force as.

    separate xbits. Folding them onto one identifier would merge two unrelated
    state machines, so the slug keeps them apart and a suffix guards the rest.
    """

    def test_hyphen_and_underscore_stay_distinct(self) -> None:
        from sagan2sigma.emit.sigma import aggregate_name

        assert aggregate_name("brute_force") != aggregate_name("brute-force")

    def test_collision_gets_a_deterministic_suffix(self) -> None:
        from sagan2sigma.emit.sigma import aggregate_name

        first = aggregate_name("a.b")
        second = aggregate_name("a b", taken={first})
        assert first != second
        assert second == aggregate_name("a b", taken={first})

    def test_name_is_stable_without_collision(self) -> None:
        from sagan2sigma.emit.sigma import aggregate_name

        assert aggregate_name("brute_force") == "sagan_xbit_brute_force"
