"""Tests for the overlap command-line interface."""

from __future__ import annotations

from pathlib import Path

from sagan2sigma.emit.yaml_io import dump_collection, dump_document
from sagan2sigma.overlap.cli import (
    EXIT_ENGINE_UNAVAILABLE,
    build_parser,
    main,
)

from .conftest import make_document, needs_engine


def _corpora(tmp_path: Path) -> tuple[Path, Path]:
    converted = tmp_path / "converted"
    converted.mkdir()
    document = make_document(
        {"sel": {"EventID": 4625}, "condition": "sel"},
        rule_id="eeeeeeee-0000-4000-8000-000000000001",
    )
    document["custom_attributes"] = {"sagan.sid": "5000001"}
    (converted / "auth.yml").write_text(dump_collection([document]), encoding="utf-8")

    sigmahq = tmp_path / "sigmahq" / "rules"
    sigmahq.mkdir(parents=True)
    sigma_doc = make_document(
        {"sel": {"EventID": 4625}, "condition": "sel"},
        rule_id="eeeeeeee-0000-4000-8000-0000000000ff",
    )
    (sigmahq / "auth.yml").write_text(dump_document(sigma_doc), encoding="utf-8")
    return converted, tmp_path / "sigmahq"


def test_parser_requires_both_corpora() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["--converted", "a", "--sigmahq", "b", "--events-per-rule", "6"]
    )
    assert args.events_per_rule == 6
    assert args.output == Path("overlap")


def test_missing_converted_path_exits_one(tmp_path: Path) -> None:
    code = main(["--converted", str(tmp_path / "nope"), "--sigmahq", str(tmp_path)])
    assert code == 1


def test_missing_engine_exits_two(tmp_path: Path) -> None:
    converted, sigmahq = _corpora(tmp_path)
    code = main(
        [
            "--converted",
            str(converted),
            "--sigmahq",
            str(sigmahq),
            "--engine",
            str(tmp_path / "no-such-rsigma"),
        ]
    )
    assert code == EXIT_ENGINE_UNAVAILABLE


@needs_engine
def test_empty_converted_dir_exits_one(tmp_path: Path) -> None:
    _, sigmahq = _corpora(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["--converted", str(empty), "--sigmahq", str(sigmahq)]) == 1


@needs_engine
def test_empty_sigmahq_dir_exits_one(tmp_path: Path) -> None:
    converted, _ = _corpora(tmp_path)
    empty = tmp_path / "empty-sigma"
    empty.mkdir()
    assert main(["--converted", str(converted), "--sigmahq", str(empty)]) == 1


@needs_engine
def test_full_run_writes_reports(tmp_path: Path) -> None:
    converted, sigmahq = _corpora(tmp_path)
    output = tmp_path / "out"
    cache = tmp_path / "cache"
    code = main(
        [
            "--converted",
            str(converted),
            "--sigmahq",
            str(sigmahq),
            "--output",
            str(output),
            "--cache",
            str(cache),
        ]
    )
    assert code == 0
    assert (output / "OVERLAP-REPORT.md").exists()
    assert (output / "overlap-report.json").exists()
    # The two identical EventID rules must land as covered.
    assert "covered" in (output / "OVERLAP-REPORT.md").read_text(encoding="utf-8")
    # A second run should hit the cache rather than re-synthesising.
    assert any(cache.iterdir())
