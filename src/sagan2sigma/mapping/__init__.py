"""Mapping layer between Sagan keywords and Sigma constructs.

Importing this package registers every handler shipped with the tool.
"""

from __future__ import annotations

from . import (
    aetas,
    content,
    correlation,
    geoip,
    intel,
    json_ops,
    metadata,
    regexes,
    selectors,
)

__all__ = [
    "aetas",
    "content",
    "correlation",
    "geoip",
    "intel",
    "json_ops",
    "metadata",
    "regexes",
    "selectors",
]
