"""Command-line interface for the behavioural overlap analysis.

One command, one question: which converted Sagan rules already have an
equivalent in SigmaHQ, judged by running both rule sets against synthesised
events rather than by comparing their text. It writes the same two artefacts
the conversion CLI does, a Markdown report to read and a JSON report to query,
and it leans on the engine for every claim, so it fails loudly when the engine
is absent rather than producing a report built on nothing.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .. import __version__ as _package_version
from .analysis import analyse, load_converted, load_sigmahq
from .cache import SynthesisCache
from .engine import EngineUnavailableError, find_engine
from .report import render_json, render_markdown

#: Directories on the SigmaHQ side skipped unless --include-placeholder is set.
#: ``rules-placeholder`` rules carry unresolved ``%placeholder%`` values that no
#: event can satisfy, so they only inflate the unsynthesisable count.
DEFAULT_SKIP_DIRS = frozenset({"rules-placeholder"})

#: Exit code when the engine is required but could not be found or run.
EXIT_ENGINE_UNAVAILABLE = 2


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sagan2sigma-overlap",
        description=(
            "Find which converted Sagan rules already have an equivalent in "
            "SigmaHQ, established by evaluating both rule sets against events "
            "synthesised from each rule with the RSigma engine."
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
        default=Path("overlap"),
        help="output directory for the two reports (default: ./overlap)",
    )
    parser.add_argument(
        "--engine",
        help="path to the rsigma binary; defaults to the one on PATH",
    )
    parser.add_argument(
        "--events-per-rule",
        type=int,
        default=4,
        help=(
            "events synthesised per rule; more events make containment claims "
            "stronger at one engine evaluation each (default: 4)"
        ),
    )
    parser.add_argument(
        "--cache",
        type=Path,
        help=(
            "directory for cached synthesised events; synthesis is deterministic, "
            "so a cache makes re-runs against a moved corpus much cheaper"
        ),
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        help=(
            "directory for the rule sets handed to the engine; a temporary one "
            "is used and removed when this is not given"
        ),
    )
    parser.add_argument(
        "--include-placeholder",
        action="store_true",
        help=(
            "include SigmaHQ `rules-placeholder/`, whose unresolved placeholder "
            "values no event can satisfy; excluded by default"
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

    # Fail on a missing engine before doing any of the slow loading, so a
    # misconfigured run stops in a second rather than after minutes of synthesis.
    try:
        find_engine(args.engine)
    except EngineUnavailableError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ENGINE_UNAVAILABLE

    skip_dirs = frozenset() if args.include_placeholder else DEFAULT_SKIP_DIRS

    print("loading rules...", file=sys.stderr)
    sagan_rules = load_converted(args.converted)
    sigmahq_rules = load_sigmahq(args.sigmahq, skip_dirs=skip_dirs)
    print(
        f"  {len(sagan_rules)} converted, {len(sigmahq_rules)} SigmaHQ",
        file=sys.stderr,
    )
    if not sagan_rules:
        print(f"error: no converted rules under {args.converted}", file=sys.stderr)
        return 1
    if not sigmahq_rules:
        print(f"error: no SigmaHQ rules under {args.sigmahq}", file=sys.stderr)
        return 1

    cache = SynthesisCache(args.cache) if args.cache else None

    # Print synthesis progress on stderr each time it crosses a 500-event mark,
    # so a detached run of tens of thousands of events shows it is alive.
    milestone = [0]

    def progress(stage: str, count: int) -> None:
        if count // 500 > milestone[0]:
            milestone[0] = count // 500
            print(f"  {stage}: {count} events", file=sys.stderr)

    with _working_dir(args.workdir) as workdir:
        print("analysing (synthesis, then one engine pass)...", file=sys.stderr)
        try:
            result = analyse(
                sagan_rules,
                sigmahq_rules,
                workdir=workdir,
                engine=args.engine,
                events_per_rule=args.events_per_rule,
                progress=progress,
                cache=cache,
            )
        except EngineUnavailableError as error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_ENGINE_UNAVAILABLE

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "OVERLAP-REPORT.md").write_text(
        render_markdown(result), encoding="utf-8"
    )
    (args.output / "overlap-report.json").write_text(
        render_json(result), encoding="utf-8"
    )

    covered = len(result.redundant_sagan_keys)
    print(
        f"{covered} converted rules are covered by a SigmaHQ rule "
        f"({len(result.verdicts)} verdicts over {result.events_evaluated} events); "
        f"reports in {args.output}"
    )
    if cache is not None:
        print(f"cache: {cache.hits} hits, {cache.misses} misses", file=sys.stderr)
    return 0


@contextmanager
def _working_dir(explicit: Path | None) -> Iterator[Path]:
    """Yield a working directory, a temporary one when none is given.

    A user-supplied directory is left in place, since they asked to keep it; a
    temporary one is removed on exit so a long run does not leave rule sets
    behind.
    """
    if explicit is not None:
        explicit.mkdir(parents=True, exist_ok=True)
        yield explicit
        return
    tmp = tempfile.mkdtemp(prefix="sagan2sigma-overlap-")
    try:
        yield Path(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
