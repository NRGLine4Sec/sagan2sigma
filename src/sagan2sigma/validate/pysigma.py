"""Validation of emitted documents against the reference implementation.

pySigma is SigmaHQ's official parser. Having it validate every emitted document
is the only way to claim the output is correct Sigma rather than YAML that
merely looks like it. Validation is on by default: silently producing invalid
rules would be the worst possible failure mode for this tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A document rejected by pySigma, or an unresolved rule reference."""

    document_id: str
    title: str
    error_type: str
    message: str


def validate_document(document: dict[str, Any]) -> ValidationIssue | None:
    """Validate a single document and return the issue, if any."""
    try:
        if "correlation" in document:
            SigmaCorrelationRule.from_dict(document)
        else:
            SigmaRule.from_dict(document)
    except Exception as error:
        return ValidationIssue(
            document_id=str(document.get("id", "?")),
            title=str(document.get("title", "?")),
            error_type=type(error).__name__,
            message=str(error),
        )
    return None


def validate_all(documents: list[dict[str, Any]]) -> list[ValidationIssue]:
    """Validate a list of documents and return every issue found."""
    issues: list[ValidationIssue] = []
    for document in documents:
        issue = validate_document(document)
        if issue is not None:
            issues.append(issue)
    return issues


def resolve_references(documents: list[dict[str, Any]]) -> list[ValidationIssue]:
    """Check that every correlation resolves the rules it references.

    A correlation pointing at a missing ``name:`` is syntactically valid but
    functionally dead. This catches reference breakage introduced by partial
    filtering of the corpus.
    """
    names = {doc["name"] for doc in documents if "name" in doc}
    issues: list[ValidationIssue] = []
    for document in documents:
        correlation = document.get("correlation")
        if not isinstance(correlation, dict):
            continue
        for reference in correlation.get("rules", []):
            if reference not in names:
                issues.append(
                    ValidationIssue(
                        document_id=str(document.get("id", "?")),
                        title=str(document.get("title", "?")),
                        error_type="UnresolvedRuleReference",
                        message=(
                            f"correlation references {reference!r}, "
                            f"absent from the batch"
                        ),
                    )
                )
    return issues
