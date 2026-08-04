"""Loader for the Sagan configuration context.

Three files from the ``sagan-rules`` repository carry information the
conversion needs:

``classification.config``
    maps each ``classtype`` to a priority from 1 (most severe) to 4, which
    feeds the Sigma ``level`` field;
``reference.config``
    declares the URL prefixes used by ``reference`` (``cve``, ``url``,
    ``bugtraq``);
``sagan.yaml``
    holds the ``$USERS``, ``$HTTP_PORT`` and similar variables referenced by
    ``meta_content``, ``alert_time`` and the default port keywords.

The ``sagan.yaml`` is optional. Without it, rules depending on a variable are
refused with ``E_VAR_UNRESOLVED`` rather than converted on a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: Sagan priority (1 is most severe) to Sigma level.
PRIORITY_TO_LEVEL: dict[int, str] = {
    1: "high",
    2: "medium",
    3: "low",
    4: "informational",
}

#: Level used when the classtype is absent from the catalog.
DEFAULT_LEVEL = "medium"

_CLASSIFICATION = re.compile(
    r"^\s*config\s+classification\s*:\s*"
    r"(?P<name>[^,]+),(?P<description>[^,]+),(?P<priority>\d+)"
)
_REFERENCE = re.compile(r"^\s*config\s+reference\s*:\s*(?P<name>\S+)\s+(?P<prefix>\S+)")
_VAR_TOKEN = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(slots=True)
class SaganConfig:
    """Resolved configuration context."""

    classtypes: dict[str, int] = field(default_factory=dict)
    references: dict[str, str] = field(default_factory=dict)
    variables: dict[str, list[str]] = field(default_factory=dict)

    def level_for(self, classtype: str | None) -> str:
        """Sigma level matching a Sagan classtype."""
        if classtype is None:
            return DEFAULT_LEVEL
        priority = self.classtypes.get(classtype.strip().lower())
        if priority is None:
            return DEFAULT_LEVEL
        return PRIORITY_TO_LEVEL.get(priority, DEFAULT_LEVEL)

    def reference_url(self, kind: str, target: str) -> str:
        """Full URL of a Sagan reference.

        Sagan stores references as ``type,value`` and prefixes the value with
        the URL declared in ``reference.config``.
        """
        kind = kind.strip().lower()
        target = target.strip()
        if kind == "url":
            if target.startswith(("http://", "https://")):
                return target
            return "https://" + target
        prefix = self.references.get(kind)
        if prefix:
            return prefix + target
        return target

    def expand(self, token: str) -> list[str] | None:
        """Values of a ``$NAME`` variable, ``None`` when unknown."""
        return self.variables.get(token.lstrip("$").upper())

    def unresolved_variables(self, text: str) -> list[str]:
        """Variables referenced by ``text`` that are missing from the context."""
        return [
            name
            for name in _VAR_TOKEN.findall(text)
            if name.upper() not in self.variables
        ]


def load_classification(path: Path) -> dict[str, int]:
    """Load ``classification.config``."""
    result: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _CLASSIFICATION.match(line)
        if match:
            result[match.group("name").strip().lower()] = int(match.group("priority"))
    return result


def load_references(path: Path) -> dict[str, str]:
    """Load ``reference.config``."""
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _REFERENCE.match(line)
        if match:
            result[match.group("name").strip().lower()] = match.group("prefix").strip()
    return result


def _is_scalar_list(value: Any) -> bool:
    return isinstance(value, list) and all(
        not isinstance(item, (dict, list)) for item in value
    )


def _as_list(value: Any) -> list[str]:
    """Normalise a variable value to a list of strings.

    Sagan accepts both ``[bob, frank]`` and ``"bob, frank"``.
    """
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text] if text else []


def _flatten_variables(node: Any, out: dict[str, list[str]]) -> None:
    """Recursively flatten the variable blocks of a ``sagan.yaml``.

    Sagan groups variables under ``vars:`` and then by family
    (``address-groups``, ``port-groups``, ``sagan-groups``, ``aetas-groups``).
    Every scalar or scalar-list leaf is collected regardless of depth.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)) and not _is_scalar_list(value):
                _flatten_variables(value, out)
            else:
                out[str(key).upper()] = _as_list(value)
    elif isinstance(node, list):
        for item in node:
            _flatten_variables(item, out)


def load_sagan_yaml(path: Path) -> dict[str, list[str]]:
    """Load the variables declared in a ``sagan.yaml``."""
    document = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    variables: dict[str, list[str]] = {}
    if isinstance(document, dict):
        _flatten_variables(document.get("vars", {}), variables)
    return variables


def load_config(
    rules_dir: Path | None = None, sagan_yaml: Path | None = None
) -> SaganConfig:
    """Assemble the context from whichever files are present.

    Every file is optional; a missing one degrades the conversion without
    aborting it.
    """
    config = SaganConfig()
    if rules_dir is not None:
        directory = rules_dir if rules_dir.is_dir() else rules_dir.parent
        classification = directory / "classification.config"
        if classification.is_file():
            config.classtypes = load_classification(classification)
        reference = directory / "reference.config"
        if reference.is_file():
            config.references = load_references(reference)
    if sagan_yaml is not None and sagan_yaml.is_file():
        config.variables = load_sagan_yaml(sagan_yaml)
    return config
