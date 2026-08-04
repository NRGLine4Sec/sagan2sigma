"""Machine-readable conversion report.

The Markdown report truncates its tables to stay readable. This one does not:
it is the artefact to diff between two runs in CI, and the one to parse when
counting refusals per code over time.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from ..converter import ConversionResult


def build(result: ConversionResult, profile: str, case_policy: str) -> dict[str, Any]:
    """Build the JSON report payload."""
    return {
        "schema_version": 1,
        "settings": {"profile": profile, "case_policy": case_policy},
        "summary": {
            "files_processed": result.files_processed,
            "rules_total": result.total_rules,
            "rules_converted": len(result.converted_rules),
            "rules_synthetic": len(result.synthetic_rules),
            "rules_refused": len(result.refused),
            "rules_disabled": result.disabled_rules,
            "documents_emitted": len(result.documents),
            "parse_failures": len(result.parse_failures),
            "validation_issues": len(result.validation_issues),
            "conversion_rate": round(result.conversion_rate, 4),
        },
        "refused": [
            {
                "sid": item.sid,
                "title": item.title,
                "source_file": item.source_file,
                "line_number": item.line_number,
                "category": item.category,
                "code": item.code.value,
                "detail": item.detail,
                "keywords": list(item.keywords),
            }
            for item in sorted(result.refused, key=lambda r: (r.source_file, r.sid))
        ],
        "degradations": [
            {
                "sid": item.sid,
                "source_file": item.source_file,
                "category": item.category,
                "codes": [d.code.value for d in item.degradations],
                "details": [d.detail for d in item.degradations],
            }
            for item in sorted(result.converted, key=lambda r: (r.source_file, r.sid))
            if item.degradations
        ],
        "unknown_keywords": dict(sorted(result.unknown_keywords.items())),
        "validation_issues": [
            {
                "document_id": issue.document_id,
                "title": issue.title,
                "error_type": issue.error_type,
                "message": issue.message,
            }
            for issue in result.validation_issues
        ],
    }


def render(result: ConversionResult, profile: str, case_policy: str) -> str:
    """Serialise the JSON report deterministically."""
    return (
        json.dumps(
            build(result, profile, case_policy),
            indent=2,
            ensure_ascii=False,
            sort_keys=False,
        )
        + "\n"
    )
