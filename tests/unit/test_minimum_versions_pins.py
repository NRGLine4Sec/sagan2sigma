"""The minimum-versions CI job has to pin what `pyproject.toml` declares.

That job installs each dependency at its declared floor and runs the suite, so
a lower bound nobody can install is caught here rather than by a user. The pins
live in `.github/workflows/ci.yml` and the floors in `pyproject.toml`, two files
nothing keeps in step: a Dependabot security update raises a floor and leaves
the workflow alone.

pip does refuse to install a version the project now forbids, so the drift
cannot ship, but it surfaces as a resolver error in a job whose name suggests
the code is at fault. These tests say what actually happened instead, and catch
the other direction too, a floor raised in the workflow but not in the project,
which pip accepts in silence and which makes the job test a version the project
does not claim to support.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
JOB = "minimum-versions"

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="tomllib arrived in 3.11 and the project takes no parser dependency for it",
)


def _declared_floors() -> dict[str, str]:
    """The `name>=version` lower bounds of the runtime dependencies."""
    import tomllib

    with PYPROJECT.open("rb") as handle:
        project = tomllib.load(handle)["project"]
    floors = {}
    for spec in project["dependencies"]:
        match = re.fullmatch(r"([A-Za-z0-9._-]+)\s*>=\s*([0-9][^,;\s]*)", spec.strip())
        if match:
            floors[match.group(1).lower()] = match.group(2)
    return floors


def _workflow_pins() -> dict[str, str]:
    """The `name==version` pins the minimum-versions job installs."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"][JOB]["steps"]
    commands = " ".join(step["run"] for step in steps if "run" in step)
    return {
        name.lower(): version
        for name, version in re.findall(r'"([A-Za-z0-9._-]+)==([^"]+)"', commands)
    }


class TestTheJobInstallsTheDeclaredFloors:
    """Both files name the same versions, or the job measures nothing."""

    def test_every_declared_floor_is_pinned(self) -> None:
        missing = sorted(_declared_floors().keys() - _workflow_pins().keys())
        assert not missing, (
            f"{missing} declare a lower bound in pyproject.toml that the {JOB} "
            f"job does not install by exact version, so nothing checks that the "
            f"floor is usable. Add the pin to the job's pip install line."
        )

    def test_no_pin_without_a_declared_floor(self) -> None:
        extra = sorted(_workflow_pins().keys() - _declared_floors().keys())
        assert not extra, (
            f"the {JOB} job pins {extra}, which pyproject.toml does not declare "
            f"with a >= lower bound. Either the dependency was dropped and the "
            f"pin is stale, or its constraint changed shape and this test needs "
            f"to learn the new one."
        )

    def test_each_pin_is_the_declared_floor(self) -> None:
        floors, pins = _declared_floors(), _workflow_pins()
        drifted = {
            name: (floor, pins[name])
            for name, floor in floors.items()
            if name in pins and pins[name] != floor
        }
        assert not drifted, (
            "pyproject.toml and the "
            + JOB
            + " job disagree about the oldest supported version: "
            + ", ".join(
                f"{name} declared >={floor} but pinned =={pin}"
                for name, (floor, pin) in sorted(drifted.items())
            )
            + ". Raising a floor means raising the pin in the same commit, which "
            "is what a Dependabot security update leaves for you to do."
        )
