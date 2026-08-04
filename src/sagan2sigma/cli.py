"""Command-line interface.

Design choice: one output directory, three artefacts. The rules alone are not
enough to act on a conversion, and a report alone is not enough to run one, so
both are always produced together.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .converter import (
    DEFAULT_MAX_XBIT_BRANCHES,
    SYNTHETIC_SOURCE,
    ConversionResult,
    Converter,
)
from .emit.vector import write_pipeline
from .emit.yaml_io import dump_collection, dump_document
from .mapping.context import Context, available_profiles, load_catalog, load_profile
from .mapping.values import CasePolicy
from .report import json_report, markdown
from .sagan.config import load_config

#: Exit code returned when the run produced validation issues.
EXIT_VALIDATION_FAILED = 2
#: Exit code returned when the conversion rate fell below --min-rate.
EXIT_RATE_BELOW_THRESHOLD = 3


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sagan2sigma",
        description=(
            "Convert Sagan rules (Snort/Suricata syntax) into Sigma rules, "
            "with a conversion report covering everything that did not make it."
        ),
    )
    parser.add_argument(
        "rules",
        nargs="+",
        type=Path,
        help="one or more .rules files, or directories containing them",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("out"),
        help="output directory (default: ./out)",
    )
    parser.add_argument(
        "-p",
        "--profile",
        default="rsigma-syslog",
        help=(
            "output profile: a bundled name or a path to a YAML file. "
            "Bundled: " + ", ".join(available_profiles())
        ),
    )
    parser.add_argument(
        "--sagan-yaml",
        type=Path,
        help=(
            "path to a sagan.yaml, used to resolve $VARIABLE references in "
            "meta_content; without it those rules are refused"
        ),
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        help="path to an alternative logsource catalog",
    )
    parser.add_argument(
        "--case-policy",
        choices=[policy.value for policy in CasePolicy],
        default=CasePolicy.FAITHFUL.value,
        help=(
            "faithful reproduces Sagan case sensitivity exactly (|cased unless "
            "nocase); relaxed drops |cased everywhere, trading fidelity for "
            "recall (default: faithful)"
        ),
    )
    parser.add_argument(
        "--split",
        choices=["single", "per-source"],
        default="per-source",
        help=(
            "single writes one rules.yml collection, per-source writes one file "
            "per Sagan source file (default: per-source)"
        ),
    )
    parser.add_argument(
        "--max-xbit-branches",
        type=int,
        default=DEFAULT_MAX_XBIT_BRANCHES,
        help=(
            "maximum number of branches in a synthetic xbit aggregate rule "
            f"(default: {DEFAULT_MAX_XBIT_BRANCHES})"
        ),
    )
    parser.add_argument(
        "--emit-vector-config",
        action="store_true",
        help=(
            "also write a Vector pipeline carrying the bundled VRL transforms, "
            "which is what makes the vector-enriched profile's group-by fields "
            "exist; implied by --profile vector-enriched"
        ),
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="skip pySigma validation of the emitted documents",
    )
    parser.add_argument(
        "--min-rate",
        type=float,
        default=0.0,
        help=(
            "exit non-zero when the conversion rate falls below this "
            "percentage; useful as a CI regression gate"
        ),
    )
    parser.add_argument(
        "--fail-on-validation",
        action="store_true",
        help="exit non-zero when pySigma rejects any emitted document",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def _write_rules(result: ConversionResult, output: Path, split: str) -> int:
    """Write the Sigma rules and return the number of files written."""
    rules_dir = output / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    if split == "single":
        (rules_dir / "rules.yml").write_text(
            dump_collection(result.documents), encoding="utf-8"
        )
        return 1

    grouped: dict[str, list[str]] = {}
    for converted in result.converted:
        # Synthetic aggregate rules span every source file, so they get their
        # own file rather than a name derived from a placeholder.
        stem = (
            "_xbit-aggregates"
            if converted.source_file == SYNTHETIC_SOURCE
            else Path(converted.source_file).stem
        ) or "unnamed"
        grouped.setdefault(stem, []).extend(
            dump_document(document) for document in converted.documents
        )
    for stem, chunks in sorted(grouped.items()):
        (rules_dir / f"{stem}.yml").write_text("---\n".join(chunks), encoding="utf-8")
    return len(grouped)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)

    for path in args.rules:
        if not path.exists():
            print(f"error: no such path: {path}", file=sys.stderr)
            return 1

    context = Context(
        profile=load_profile(str(args.profile)),
        config=load_config(rules_dir=args.rules[0], sagan_yaml=args.sagan_yaml),
        catalog=load_catalog(str(args.catalog) if args.catalog else None),
    )
    converter = Converter(
        context=context,
        case_policy=CasePolicy(args.case_policy),
        validate=not args.no_validate,
        max_xbit_branches=args.max_xbit_branches,
    )

    result = converter.convert_paths(list(args.rules))

    args.output.mkdir(parents=True, exist_ok=True)
    files_written = _write_rules(result, args.output, args.split)
    (args.output / "CONVERSION-REPORT.md").write_text(
        markdown.render(result, context.profile.name, args.case_policy),
        encoding="utf-8",
    )
    (args.output / "conversion-report.json").write_text(
        json_report.render(result, context.profile.name, args.case_policy),
        encoding="utf-8",
    )

    # The enriched profile is only correct when the transforms run, so the
    # pipeline is emitted with it rather than left as an opt-in nobody reads.
    emit_pipeline = args.emit_vector_config or bool(context.profile.positional)
    if emit_pipeline:
        write_pipeline(args.output / "vector", __version__)

    print(
        f"{len(result.converted_rules)}/{result.total_rules} rules converted "
        f"({result.conversion_rate:.1f}%), "
        f"{len(result.documents)} Sigma documents in {files_written} file(s)"
    )
    if emit_pipeline:
        print(
            f"Vector pipeline written to {args.output / 'vector'}; set the two "
            f"placeholders in vector.yaml before starting it"
        )
    if result.validation_issues:
        print(
            f"warning: {len(result.validation_issues)} validation issue(s), "
            f"see CONVERSION-REPORT.md",
            file=sys.stderr,
        )
        if args.fail_on_validation:
            return EXIT_VALIDATION_FAILED
    if result.conversion_rate < args.min_rate:
        print(
            f"error: conversion rate {result.conversion_rate:.1f}% is below the "
            f"{args.min_rate:.1f}% threshold",
            file=sys.stderr,
        )
        return EXIT_RATE_BELOW_THRESHOLD
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
