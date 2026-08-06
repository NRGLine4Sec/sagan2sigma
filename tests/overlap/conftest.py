"""Fixtures and helpers for the overlap tests.

The engine-backed tests are gated on ``rsigma`` being on PATH, exactly as
``tests/differential`` gates its own. The rest run everywhere: synthesis, its
helpers, the report and the cache have no dependency on the engine and are
tested directly.
"""

from __future__ import annotations

import itertools
import shutil
from typing import Any

import pytest
from sigma.rule import SigmaRule

from sagan2sigma.overlap.analysis import RuleRecord

#: Path to the engine, or ``None`` when it is not installed.
RSIGMA = shutil.which("rsigma")

#: Marker for tests that need the real engine.
needs_engine = pytest.mark.skipif(
    RSIGMA is None,
    reason="build rsigma and put it on PATH to run the engine-backed overlap tests",
)

_ids = (f"{n:08d}-0000-4000-8000-000000000000" for n in itertools.count(1))


def make_rule(
    detection: dict[str, Any],
    logsource: dict[str, Any] | None = None,
    title: str = "test rule",
    rule_id: str | None = None,
) -> SigmaRule:
    """Build a parsed :class:`SigmaRule` from a detection block.

    pySigma rejects an empty log source, so a non-empty default is supplied;
    ``engine eval`` does not enforce it, which is what lets synthesis ignore it.
    """
    document = make_document(detection, logsource, title, rule_id)
    return SigmaRule.from_dict(document)


def make_document(
    detection: dict[str, Any],
    logsource: dict[str, Any] | None = None,
    title: str = "test rule",
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Build a raw Sigma document dict."""
    return {
        "title": title,
        "id": rule_id or next(_ids),
        "logsource": logsource or {"product": "test"},
        "detection": detection,
    }


def make_record(
    detection: dict[str, Any],
    origin: str = "sagan",
    logsource: dict[str, Any] | None = None,
    title: str = "test rule",
    rule_id: str | None = None,
) -> RuleRecord:
    """Build a :class:`RuleRecord` wrapping a fresh document."""
    document = make_document(detection, logsource, title, rule_id)
    return RuleRecord(
        key=f"{origin}:{document['id']}",
        origin=origin,
        title=title,
        document=document,
        sagan_sid="1000000" if origin == "sagan" else "",
    )
