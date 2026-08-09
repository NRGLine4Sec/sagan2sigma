#!/usr/bin/env python3
"""Regenerate the committed converted rule set and record its version.

Run in CI when the upstream ``quadrantsec/sagan-rules`` corpus moves, and once
by hand to finalise the first version entry. The whole corpus is reconverted
every time, never just the new files, so a rule modified or removed upstream is
reflected too: the ``converted/rules`` directory is wiped and rebuilt, and the
committing step below then sees additions, changes and deletions alike.

The rule set is identified by a version id, the short hash of the two commits it
was produced from: the ``sagan-rules`` commit that supplied the input and the
``sagan2sigma`` commit that did the conversion. Recording both is what makes a
version reproducible and what tells a reader, from the ``sagan-rules`` date, how
old the rules are.

Usage::

    python tools/refresh_converted_rules.py --sagan-rules /path/to/sagan-rules

Exit code 0 whether or not anything changed; the caller decides what to do with
a dirty tree. Nothing is committed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import date
from pathlib import Path

#: Sentinel a bootstrap row carries until the tooling fills in the real commits.
PENDING = "pending"

HEADER = [
    "# Converted rule set versions",
    "",
    "This table records each iteration of the converted rule sets, newest first,",
    "produced from",
    "[`quadrantsec/sagan-rules`](https://github.com/quadrantsec/sagan-rules) so they",
    "can be used without installing this project. Both profiles are refreshed",
    "together whenever the upstream corpus changes; see",
    "`.github/workflows/convert-rules.yml`. The default `rsigma-syslog` snapshot is",
    "under [`converted/`](rules); the `vector-enriched` one, which recovers more,",
    "is [`converted-vector-enriched/`](../converted-vector-enriched).",
    "",
    "The **version** is the short hash of the `sagan-rules` commit and the",
    "`sagan2sigma` commit the rules were produced from, so it is reproducible. The",
    "**sagan-rules date** is that commit's date, which is how old the rules are.",
    "",
    "| Version | sagan-rules commit | sagan-rules date | sagan2sigma | Generated | Default | Enriched |",  # noqa: E501
    "| --- | --- | --- | --- | --- | ---: | ---: |",
]


def git(directory: Path, *args: str) -> str:
    """Run a git command in a checkout and return its stripped output."""
    result = subprocess.run(
        ["git", "-C", str(directory), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def version_id(sagan_commit: str, sagan2sigma_commit: str) -> str:
    """The short hash identifying a rule set by its two source commits."""
    material = f"{sagan_commit}:{sagan2sigma_commit}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def convert(
    sagan_rules: Path, output: Path, profile: str | None = None
) -> tuple[int, int, float]:
    """Wipe and rebuild one converted snapshot, returning (converted, total, rate).

    ``profile`` selects the output profile; ``vector-enriched`` also emits the
    Vector pipeline into ``output/vector`` because ``--emit-vector-config`` is
    implied by that profile.
    """
    rules_dir = output / "rules"
    if rules_dir.exists():
        shutil.rmtree(rules_dir)
    output.mkdir(parents=True, exist_ok=True)
    command = ["sagan2sigma", str(sagan_rules), "-o", str(output)]
    if profile is not None:
        command += ["--profile", profile]
    subprocess.run(command, check=True, capture_output=True, text=True)
    report = json.loads((output / "conversion-report.json").read_text("utf-8"))
    summary = report["summary"]
    # The JSON report is large and machine-only; the Markdown report is kept.
    (output / "conversion-report.json").unlink(missing_ok=True)
    return (
        summary["rules_converted"],
        summary["rules_total"],
        summary["conversion_rate"],
    )


def _data_rows(text: str) -> list[str]:
    """The existing table data rows, in order, newest first."""
    rows: list[str] = []
    seen_separator = False
    for line in text.splitlines():
        if line.startswith("| ---"):
            seen_separator = True
            continue
        if seen_separator and line.startswith("| "):
            rows.append(line)
    return rows


def _is_pending(row: str) -> bool:
    return f"`{PENDING}`" in row.split("|")[1]


def _cell(converted: int, total: int, rate: float) -> str:
    """One `converted / total (rate%)` cell."""
    return f"{converted} / {total} ({rate:.1f}%)"


def _row(
    vid: str,
    sagan_commit: str,
    sagan_date: str,
    sagan_url: str,
    sagan2sigma_commit: str,
    default: tuple[int, int, float],
    enriched: tuple[int, int, float],
) -> str:
    base = sagan_url.removesuffix(".git")
    commit_link = f"[`{sagan_commit[:12]}`]({base}/commit/{sagan_commit})"
    day = sagan_date[:10]
    return (
        f"| `{vid}` | {commit_link} | {day} | `{sagan2sigma_commit[:12]}` | "
        f"{date.today().isoformat()} | {_cell(*default)} | {_cell(*enriched)} |"
    )


def update_versions(path: Path, new_row: str, rules_changed: bool) -> bool:
    """Rewrite VERSIONS.md, returning whether it changed.

    A bootstrap row (version ``pending``) is replaced in place; otherwise a new
    row is prepended only when the rules actually changed, so a converter change
    that leaves the output identical does not manufacture a version.
    """
    rows = _data_rows(path.read_text("utf-8")) if path.exists() else []
    if rows and _is_pending(rows[0]):
        rows[0] = new_row
    elif rules_changed or not rows:
        rows.insert(0, new_row)
    else:
        return False
    path.write_text("\n".join([*HEADER, *rows, ""]), encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sagan-rules", type=Path, required=True, help="a sagan-rules checkout"
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(),
        help="the sagan2sigma checkout (default: .)",
    )
    args = parser.parse_args(argv)

    sagan_commit = git(args.sagan_rules, "rev-parse", "HEAD")
    sagan_date = git(args.sagan_rules, "log", "-1", "--format=%cI")
    sagan_url = git(args.sagan_rules, "config", "--get", "remote.origin.url")
    sagan2sigma_commit = git(args.repo, "rev-parse", "HEAD")

    default_dir = args.repo / "converted"
    enriched_dir = args.repo / "converted-vector-enriched"
    default = convert(args.sagan_rules, default_dir)
    enriched = convert(args.sagan_rules, enriched_dir, profile="vector-enriched")

    vid = version_id(sagan_commit, sagan2sigma_commit)
    rules_changed = bool(
        git(
            args.repo,
            "status",
            "--porcelain",
            "--",
            str(default_dir / "rules"),
            str(enriched_dir / "rules"),
        )
    )
    row = _row(
        vid,
        sagan_commit,
        sagan_date,
        sagan_url,
        sagan2sigma_commit,
        default,
        enriched,
    )
    changed = update_versions(default_dir / "VERSIONS.md", row, rules_changed)

    print(
        f"sagan-rules {sagan_commit[:12]} -> version {vid}: "
        f"default {default[0]}/{default[1]}, enriched {enriched[0]}/{enriched[1]} "
        f"({'rules changed' if rules_changed else 'rules unchanged'}, "
        f"VERSIONS.md {'updated' if changed else 'unchanged'})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
