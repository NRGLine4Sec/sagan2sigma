"""Fixtures for the inventory tests: minimal report payloads."""

from __future__ import annotations

from typing import Any


def verdict(
    sagan_id: str,
    sigmahq_id: str,
    relation: str,
    *,
    compatible: bool = True,
    events: int = 2,
) -> dict[str, Any]:
    """One behavioural verdict shaped like overlap-report.json."""
    return {
        "relation": relation,
        "logsource_compatible": compatible,
        "sagan": {
            "sid": f"500{sagan_id}",
            "id": sagan_id,
            "title": f"converted {sagan_id}",
            "source_file": "windows-security.rules",
            "events": events,
        },
        "sigmahq": {
            "id": sigmahq_id,
            "title": f"sigma {sigmahq_id}",
            "path": f"rules/{sigmahq_id}.yml",
        },
        "witness_event": {"EventID": 4625},
    }


def candidate(
    sagan_id: str, sigmahq_id: str, lexical: float, terms: list[str] | None = None
) -> dict[str, Any]:
    """One conceptual candidate shaped like conceptual-overlap-report.json."""
    return {
        "sagan": {
            "sid": f"500{sagan_id}",
            "id": sagan_id,
            "title": f"converted {sagan_id}",
            "source_file": "windows-security.rules",
        },
        "sigmahq": {
            "id": sigmahq_id,
            "title": f"sigma {sigmahq_id}",
            "path": f"rules/{sigmahq_id}.yml",
        },
        "lexical_similarity": lexical,
        "technique_score": 0.0,
        "composite": lexical,
        "shared_terms": terms or ["mimikatz"],
        "shared_techniques": [],
    }


def overlap_report(*verdicts: dict[str, Any]) -> dict[str, Any]:
    return {"verdicts": list(verdicts)}


def conceptual_report(*candidates: dict[str, Any]) -> dict[str, Any]:
    return {"candidates": list(candidates)}
