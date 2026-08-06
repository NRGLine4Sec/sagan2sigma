"""Helpers for the conceptual-overlap tests.

The conceptual analysis needs no engine, so nothing here is gated. Records are
built directly, since the module reuses the behavioural analysis's RuleRecord.
"""

from __future__ import annotations

import itertools
from typing import Any

from sagan2sigma.overlap.analysis import RuleRecord

_ids = (f"{n:08d}-0000-4000-8000-000000000000" for n in itertools.count(1))


def make_record(
    title: str,
    detection: dict[str, Any],
    *,
    origin: str = "sagan",
    tags: list[str] | None = None,
    description: str = "",
    source_file: str = "test.rules",
    sagan_sid: str = "",
    rule_id: str | None = None,
) -> RuleRecord:
    """Build a RuleRecord with the fields the conceptual analysis reads."""
    document: dict[str, Any] = {
        "title": title,
        "id": rule_id or next(_ids),
        "logsource": {"product": "test"},
        "detection": detection,
    }
    if tags:
        document["tags"] = tags
    if description:
        document["description"] = description
    return RuleRecord(
        key=f"{origin}:{document['id']}",
        origin=origin,
        title=title,
        document=document,
        source_file=source_file,
        sagan_sid=sagan_sid or ("5000000" if origin == "sagan" else ""),
    )
