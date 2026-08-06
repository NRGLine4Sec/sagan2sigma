"""Command-line interface building the commit-pinned overlap inventory.

It consumes the JSON reports the two analyses already produce, rather than
re-running them, so the inventory is cheap and always consistent with the
reports it cites. The corpus commits are read from the checkouts the reports
were built from, which is the whole point: a list of overlapping rules is only
meaningful against a fixed state of two repositories that change every day.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

from .. import __version__ as _package_version
from .classify import classify
from .render import Corpus, Provenance, render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sagan2sigma-inventory",
        description=(
            "Merge the behavioural and conceptual reports into one "
            "confidence-tiered inventory of overlapping rules, pinned to the "
            "commit of each rule corpus."
        ),
    )
    parser.add_argument(
        "--overlap-report",
        type=Path,
        required=True,
        help="path to overlap-report.json from sagan2sigma-overlap",
    )
    parser.add_argument(
        "--conceptual-report",
        type=Path,
        required=True,
        help="path to conceptual-overlap-report.json from sagan2sigma-conceptual",
    )
    parser.add_argument(
        "--sagan-rules",
        type=Path,
        help="the sagan-rules checkout, to read its commit; or use --sagan-commit",
    )
    parser.add_argument(
        "--sigmahq",
        type=Path,
        help="the SigmaHQ checkout, to read its commit; or use --sigmahq-commit",
    )
    parser.add_argument("--sagan-commit", help="override the sagan-rules commit")
    parser.add_argument("--sigmahq-commit", help="override the SigmaHQ commit")
    parser.add_argument(
        "--engine-version",
        default="unknown",
        help="rsigma version the behavioural report was produced with",
    )
    parser.add_argument(
        "--profile",
        default="rsigma-syslog",
        help="conversion profile the converted rules used (default: rsigma-syslog)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("OVERLAP-INVENTORY.md"),
        help="output Markdown file (a .json sibling is written alongside)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {_package_version}"
    )
    return parser


def _git(directory: Path, *args: str) -> str | None:
    """Run a git command in a checkout, returning its output or None."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(directory), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _corpus(
    name: str,
    default_url: str,
    directory: Path | None,
    commit_override: str | None,
) -> Corpus | None:
    """Assemble a Corpus from a checkout, or from an explicit commit."""
    commit = commit_override
    url = default_url
    committed = "unknown"
    if directory is not None:
        commit = commit or _git(directory, "rev-parse", "HEAD")
        url = _git(directory, "config", "--get", "remote.origin.url") or default_url
        committed = _git(directory, "log", "-1", "--format=%cI") or "unknown"
    if not commit:
        return None
    return Corpus(name=name, url=url, commit=commit, committed=committed)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)

    for label, path in (
        ("--overlap-report", args.overlap_report),
        ("--conceptual-report", args.conceptual_report),
    ):
        if not path.exists():
            print(f"error: {label} not found: {path}", file=sys.stderr)
            return 1

    sagan = _corpus(
        "sagan-rules",
        "https://github.com/quadrantsec/sagan-rules.git",
        args.sagan_rules,
        args.sagan_commit,
    )
    sigmahq = _corpus(
        "SigmaHQ",
        "https://github.com/SigmaHQ/sigma.git",
        args.sigmahq,
        args.sigmahq_commit,
    )
    if sagan is None or sigmahq is None:
        print(
            "error: could not determine a commit for each corpus. Pass a git "
            "checkout via --sagan-rules/--sigmahq, or the commit directly via "
            "--sagan-commit/--sigmahq-commit.",
            file=sys.stderr,
        )
        return 1

    overlap_report = json.loads(args.overlap_report.read_text(encoding="utf-8"))
    conceptual_report = json.loads(args.conceptual_report.read_text(encoding="utf-8"))
    entries = classify(overlap_report, conceptual_report)

    provenance = Provenance(
        generated=date.today().isoformat(),
        sagan=sagan,
        sigmahq=sigmahq,
        engine_version=args.engine_version,
        profile=args.profile,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_markdown(entries, provenance), encoding="utf-8")
    json_path = args.output.with_suffix(".json")
    json_path.write_text(render_json(entries, provenance), encoding="utf-8")
    print(
        f"{len(entries)} overlapping pairs written to {args.output} "
        f"(pinned to sagan {sagan.commit[:12]}, sigmahq {sigmahq.commit[:12]})"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
