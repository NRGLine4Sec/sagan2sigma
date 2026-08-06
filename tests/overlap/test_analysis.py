"""Tests for the overlap analysis.

The loaders and the id resolution are pure and tested directly. The four-way
classification is the heart of the module and is tested end-to-end against the
real engine, with a hand-built pair chosen to land on each relation.
"""

from __future__ import annotations

from pathlib import Path

from sagan2sigma.emit.yaml_io import dump_collection, dump_document
from sagan2sigma.overlap.analysis import (
    AnalysisResult,
    Relation,
    RuleRecord,
    Verdict,
    _logsource_compatible,
    _resolve,
    analyse,
    load_converted,
    load_sigmahq,
)

from .conftest import make_document, make_record, needs_engine


def _write_sigmahq(root: Path, document: dict, subdir: str = "rules") -> None:
    target = root / subdir
    target.mkdir(parents=True, exist_ok=True)
    (target / f"{document['id']}.yml").write_text(
        dump_document(document), encoding="utf-8"
    )


def test_load_sigmahq_skips_dirs_and_non_rules(tmp_path: Path) -> None:
    _write_sigmahq(tmp_path, make_document({"sel": {"EventID": 1}, "condition": "sel"}))
    _write_sigmahq(
        tmp_path,
        make_document({"sel": {"EventID": 2}, "condition": "sel"}),
        subdir="rules-placeholder",
    )
    # A file with no detection block must be ignored.
    (tmp_path / "rules" / "notarule.yml").write_text("title: x\n", encoding="utf-8")
    # Malformed YAML must be skipped rather than crash the load.
    (tmp_path / "rules" / "broken.yml").write_text("a: [unclosed\n", encoding="utf-8")

    records = load_sigmahq(tmp_path, skip_dirs=frozenset({"rules-placeholder"}))
    assert len(records) == 1
    assert records[0].origin == "sigmahq"


def test_load_converted_reads_multidoc(tmp_path: Path) -> None:
    one = make_document({"sel": {"EventID": 1}, "condition": "sel"})
    two = make_document({"sel": {"EventID": 2}, "condition": "sel"})
    one["custom_attributes"] = {
        "sagan.sid": "5000001",
        "sagan.source_file": "web.rules",
    }
    (tmp_path / "web.yml").write_text(dump_collection([one, two]), encoding="utf-8")

    records = load_converted(tmp_path)
    assert len(records) == 2
    assert records[0].sagan_sid == "5000001"
    assert records[0].source_file == "web.rules"


def test_resolve_maps_ids_to_keys() -> None:
    record = make_record({"sel": {"EventID": 1}, "condition": "sel"}, origin="sagan")
    rule_id = record.key.split(":", 1)[1]
    resolved = _resolve({rule_id, "unknown-id"}, {record.key: record})
    assert resolved == {record.key}


def test_rule_record_usable() -> None:
    record = RuleRecord(key="sagan:x", origin="sagan", title="t", document={})
    assert not record.usable
    record.confirmed.append(0)
    assert record.usable


def test_logsource_compatibility() -> None:
    cisco = {"logsource": {"product": "cisco", "service": "aaa"}}
    aws = {"logsource": {"product": "aws", "service": "cloudtrail"}}
    database = {"logsource": {"category": "database"}}
    windows = {"logsource": {"product": "windows"}}
    windows_svc = {"logsource": {"product": "windows", "service": "security"}}
    # Different products never share a log stream.
    assert not _logsource_compatible(cisco, aws)
    # A converted rule carries a product only, so a product-only rule and a
    # product+service SigmaHQ rule share the product and are compatible.
    assert _logsource_compatible(windows, windows_svc)
    # A conflicting service on both sides is a different stream, not compatible.
    assert not _logsource_compatible(
        cisco, {"logsource": {"product": "cisco", "service": "bgp"}}
    )
    # A category-only rule and a product-only rule share no dimension, so a
    # keyword co-firing between them is not deployable coverage.
    assert not _logsource_compatible(database, aws)
    # A missing logsource block shares nothing.
    assert not _logsource_compatible({}, cisco)


def test_redundant_keys_require_compatible_logsource() -> None:
    def verdict(compatible: bool, sid: str) -> Verdict:
        return Verdict(
            sagan_key=f"sagan:{sid}",
            sagan_sid=sid,
            sagan_title="t",
            sagan_source_file="f",
            sigmahq_key="sigmahq:x",
            sigmahq_title="s",
            sigmahq_path="p",
            relation=Relation.SAGAN_REDUNDANT,
            sagan_events=4,
            sagan_events_firing_sigmahq=4,
            sigmahq_events=4,
            sigmahq_events_firing_sagan=1,
            witness={},
            logsource_compatible=compatible,
        )

    result = AnalysisResult(verdicts=[verdict(True, "1"), verdict(False, "2")])
    assert result.redundant_sagan_keys == {"sagan:1"}
    assert result.cross_logsource_covered == 1


# --- engine-backed classification -----------------------------------------


@needs_engine
def test_classifies_equivalent(tmp_path: Path) -> None:
    # Identical detection: every event from one fires the other, both ways.
    detection = {"sel": {"EventID": 4625}, "condition": "sel"}
    sagan = make_record(detection, origin="sagan")
    sigmahq = make_record(detection, origin="sigmahq")
    result = analyse([sagan], [sigmahq], workdir=tmp_path)
    relations = {v.relation for v in result.verdicts}
    assert Relation.EQUIVALENT in relations


@needs_engine
def test_classifies_sagan_redundant(tmp_path: Path) -> None:
    # SigmaHQ matches on EventID alone; the Sagan rule adds a second condition,
    # so every Sagan event fires SigmaHQ but not the reverse.
    sagan = make_record(
        {
            "sel": {"EventID": 4625, "CommandLine|contains": "whoami"},
            "condition": "sel",
        },
        origin="sagan",
    )
    sigmahq = make_record(
        {"sel": {"EventID": 4625}, "condition": "sel"}, origin="sigmahq"
    )
    result = analyse([sagan], [sigmahq], workdir=tmp_path)
    redundant = [v for v in result.verdicts if v.relation == Relation.SAGAN_REDUNDANT]
    assert redundant
    assert sagan.key in result.redundant_sagan_keys


@needs_engine
def test_classifies_sagan_broader(tmp_path: Path) -> None:
    sagan = make_record({"sel": {"EventID": 4625}, "condition": "sel"}, origin="sagan")
    sigmahq = make_record(
        {
            "sel": {"EventID": 4625, "CommandLine|contains": "whoami"},
            "condition": "sel",
        },
        origin="sigmahq",
    )
    result = analyse([sagan], [sigmahq], workdir=tmp_path)
    assert any(v.relation == Relation.SAGAN_BROADER for v in result.verdicts)


@needs_engine
def test_absence_matcher_is_excluded(tmp_path: Path) -> None:
    # A pure-negation SigmaHQ rule fires on any event lacking the field, so it
    # would spuriously "cover" every converted rule. It must be flagged as a
    # blanket matcher and produce no verdict.
    blanket = make_record(
        {"sel": {"id.orig_h|cidr": "10.0.0.0/8"}, "condition": "not sel"},
        origin="sigmahq",
    )
    sagan = make_record({"sel": {"EventID": 4625}, "condition": "sel"}, origin="sagan")
    result = analyse([sagan], [blanket], workdir=tmp_path)
    assert blanket.key in result.sigmahq_blanket
    assert result.verdicts == []
    assert result.redundant_sagan_keys == set()


@needs_engine
def test_disjoint_rules_produce_no_verdict(tmp_path: Path) -> None:
    sagan = make_record({"sel": {"EventID": 111}, "condition": "sel"}, origin="sagan")
    sigmahq = make_record(
        {"sel": {"EventID": 222}, "condition": "sel"}, origin="sigmahq"
    )
    result = analyse([sagan], [sigmahq], workdir=tmp_path)
    assert result.verdicts == []
    assert result.sagan_usable == 1
    assert result.sigmahq_usable == 1
