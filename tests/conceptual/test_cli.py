"""Tests for the conceptual command-line interface."""

from __future__ import annotations

from pathlib import Path

from sagan2sigma.conceptual.cli import build_parser, main
from sagan2sigma.emit.yaml_io import dump_collection, dump_document

from .conftest import make_record


def _corpora(tmp_path: Path) -> tuple[Path, Path]:
    converted = tmp_path / "converted"
    converted.mkdir()
    docs = [
        make_record(
            "whoami recon",
            {"sel": {"CommandLine|contains": "whoami"}, "condition": "sel"},
            sagan_sid="5000001",
        ).document,
        *[
            make_record(
                f"filler {n}", {"sel": {"k|contains": f"zz{n}"}, "condition": "sel"}
            ).document
            for n in range(5)
        ],
    ]
    (converted / "all.yml").write_text(dump_collection(docs), encoding="utf-8")

    sigmahq = tmp_path / "sigmahq" / "rules"
    sigmahq.mkdir(parents=True)
    (sigmahq / "whoami.yml").write_text(
        dump_document(
            make_record(
                "Renamed Whoami Execution",
                {"sel": {"CommandLine|contains": "whoami"}, "condition": "sel"},
                origin="sigmahq",
            ).document
        ),
        encoding="utf-8",
    )
    return converted, tmp_path / "sigmahq"


def test_parser_defaults() -> None:
    args = build_parser().parse_args(["--converted", "a", "--sigmahq", "b"])
    assert args.output == Path("conceptual")
    assert args.top_k >= 1


def test_missing_path_exits_one(tmp_path: Path) -> None:
    assert (
        main(["--converted", str(tmp_path / "nope"), "--sigmahq", str(tmp_path)]) == 1
    )


def test_full_run_writes_reports(tmp_path: Path) -> None:
    converted, sigmahq = _corpora(tmp_path)
    output = tmp_path / "out"
    code = main(
        [
            "--converted",
            str(converted),
            "--sigmahq",
            str(sigmahq),
            "--output",
            str(output),
            "--min-lexical",
            "0.3",
        ]
    )
    assert code == 0
    report = (output / "CONCEPTUAL-OVERLAP-REPORT.md").read_text(encoding="utf-8")
    assert "review candidates" in report.lower()
    assert (output / "conceptual-overlap-report.json").exists()
