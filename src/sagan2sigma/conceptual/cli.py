"""Command-line interface for the conceptual analysis.

A separate command from ``sagan2sigma-overlap`` on purpose, so the two are never
run or read as one thing. It needs no engine: the comparison is lexical and
tag-based, pure Python and deterministic, so it runs in seconds and its output
is byte-identical between runs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import __version__ as _package_version
from .analysis import (
    DEFAULT_MIN_LEXICAL,
    DEFAULT_TOP_K,
    analyse,
    load,
)
from .report import render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sagan2sigma-conceptual",
        description=(
            "Propose conceptual-overlap candidates between converted rules and "
            "SigmaHQ, from shared distinctive search terms and ATT&CK techniques. "
            "These are candidates for human review, not tested equivalence: unlike "
            "sagan2sigma-overlap, this does not run the engine and is not grounds "
            "for retiring a rule."
        ),
    )
    parser.add_argument(
        "--converted",
        type=Path,
        required=True,
        help="directory of converted Sigma rules, the `rules/` output of sagan2sigma",
    )
    parser.add_argument(
        "--sigmahq",
        type=Path,
        required=True,
        help="root of a SigmaHQ checkout, or any directory of Sigma rules",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("conceptual"),
        help="output directory for the two reports (default: ./conceptual)",
    )
    parser.add_argument(
        "--min-lexical",
        type=float,
        default=DEFAULT_MIN_LEXICAL,
        help=(
            "minimum IDF-weighted lexical similarity for a pair to be proposed; "
            "raising it yields fewer, stronger candidates "
            f"(default: {DEFAULT_MIN_LEXICAL})"
        ),
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=DEFAULT_TOP_K,
        help=(
            "how many candidate SigmaHQ rules to keep per converted rule "
            f"(default: {DEFAULT_TOP_K})"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {_package_version}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)

    for label, path in (("--converted", args.converted), ("--sigmahq", args.sigmahq)):
        if not path.exists():
            print(f"error: {label} path does not exist: {path}", file=sys.stderr)
            return 1

    print("loading rules...", file=sys.stderr)
    converted, sigmahq = load(args.converted, args.sigmahq)
    print(f"  {len(converted)} converted, {len(sigmahq)} SigmaHQ", file=sys.stderr)
    if not converted:
        print(f"error: no converted rules under {args.converted}", file=sys.stderr)
        return 1
    if not sigmahq:
        print(f"error: no SigmaHQ rules under {args.sigmahq}", file=sys.stderr)
        return 1

    result = analyse(
        converted,
        sigmahq,
        min_lexical=args.min_lexical,
        top_k=args.top_k,
    )

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "CONCEPTUAL-OVERLAP-REPORT.md").write_text(
        render_markdown(result), encoding="utf-8"
    )
    (args.output / "conceptual-overlap-report.json").write_text(
        render_json(result), encoding="utf-8"
    )
    print(
        f"{len(result.candidates)} candidate pairs across "
        f"{result.sagan_with_candidate} converted rules; reports in {args.output}. "
        "These are review candidates, not tested equivalence.",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
