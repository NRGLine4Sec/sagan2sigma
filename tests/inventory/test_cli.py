"""Tests for the inventory command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

from sagan2sigma.inventory.cli import main

from .conftest import candidate, conceptual_report, overlap_report, verdict


def _write_reports(tmp_path: Path) -> tuple[Path, Path]:
    overlap = tmp_path / "overlap.json"
    overlap.write_text(
        json.dumps(overlap_report(verdict("a", "x", "SAGAN_REDUNDANT"))),
        encoding="utf-8",
    )
    conceptual = tmp_path / "conceptual.json"
    conceptual.write_text(
        json.dumps(conceptual_report(candidate("a", "x", 0.6))), encoding="utf-8"
    )
    return overlap, conceptual


def test_missing_report_exits_one(tmp_path: Path) -> None:
    _, conceptual = _write_reports(tmp_path)
    code = main(
        [
            "--overlap-report",
            str(tmp_path / "nope.json"),
            "--conceptual-report",
            str(conceptual),
            "--sagan-commit",
            "aaa",
            "--sigmahq-commit",
            "bbb",
        ]
    )
    assert code == 1


def test_without_a_commit_exits_one(tmp_path: Path) -> None:
    overlap, conceptual = _write_reports(tmp_path)
    # No checkout and no explicit commit: the inventory would be unpinnable.
    code = main(
        [
            "--overlap-report",
            str(overlap),
            "--conceptual-report",
            str(conceptual),
        ]
    )
    assert code == 1


def test_explicit_commits_write_pinned_reports(tmp_path: Path) -> None:
    overlap, conceptual = _write_reports(tmp_path)
    output = tmp_path / "OVERLAP-INVENTORY.md"
    code = main(
        [
            "--overlap-report",
            str(overlap),
            "--conceptual-report",
            str(conceptual),
            "--sagan-commit",
            "142303c749801b4882b73a36e94e8d76f79e7500",
            "--sigmahq-commit",
            "8eaafff1f2845a696050e05e72ba1140ee190698",
            "--engine-version",
            "0.21.0",
            "--output",
            str(output),
        ]
    )
    assert code == 0
    text = output.read_text(encoding="utf-8")
    assert "142303c749801b4882b73a36e94e8d76f79e7500" in text
    assert (tmp_path / "OVERLAP-INVENTORY.json").exists()


def test_reads_commit_from_a_git_checkout(tmp_path: Path) -> None:
    import subprocess

    repo = tmp_path / "corpus"
    repo.mkdir()
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@t"],
        ["git", "config", "user.name", "t"],
        ["git", "commit", "--allow-empty", "-q", "-m", "x"],
    ):
        subprocess.run(cmd, cwd=repo, check=True)
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    overlap, conceptual = _write_reports(tmp_path)
    output = tmp_path / "inv.md"
    code = main(
        [
            "--overlap-report",
            str(overlap),
            "--conceptual-report",
            str(conceptual),
            "--sagan-rules",
            str(repo),
            "--sigmahq-commit",
            "bbb",
            "--output",
            str(output),
        ]
    )
    assert code == 0
    assert head in output.read_text(encoding="utf-8")
