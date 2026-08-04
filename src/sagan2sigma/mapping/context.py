"""Conversion context shared by every handler."""

from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import field as dataclass_field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from ..sagan.config import SaganConfig

_PROFILE_PACKAGE = "sagan2sigma.data.profiles"
_LOGSOURCE_PACKAGE = "sagan2sigma.data.logsource"


@dataclass(frozen=True, slots=True)
class Profile:
    """Field-alias table for one ingestion chain.

    Keys are Sagan internal value names, so that a profile and a rule's
    ``json_map`` can be consulted through the same interface.
    """

    name: str
    description: str
    fields: dict[str, str]
    #: Templates for internal values Sagan resolves by position rather than by
    #: name, keyed by internal value. ``{position}`` is substituted with the
    #: 1-based index the rule declared, so ``parse_src_ip: 2`` and
    #: ``parse_src_ip: 1`` resolve to different fields, as they must.
    positional: dict[str, str] = dataclass_field(default_factory=dict)
    #: Envelope field names to use when the event body is a JSON document.
    #: Empty when the ingestion chain names them the same either way.
    json_envelope: dict[str, str] = dataclass_field(default_factory=dict)

    def field(self, internal: str) -> str:
        """Concrete field name for an internal value.

        Raises ``KeyError`` rather than guessing: an incomplete profile must
        fail loudly instead of producing rules that never fire.
        """
        return self.fields[internal]

    def envelope_field(self, internal: str, json_event: bool) -> str:
        """Envelope field name for the shape of event the rule targets.

        RSigma exposes a different set of names once the syslog body is JSON, so
        a rule combining ``program`` with ``json_content`` has to select the
        prefixed variant or it can never fire.
        """
        if json_event and internal in self.json_envelope:
            return self.json_envelope[internal]
        return self.fields[internal]

    def positional_field(self, internal: str, position: int) -> str | None:
        """Field holding the ``position``-th occurrence of an internal value.

        Returns ``None`` when the profile does not supply the enrichment, which
        is what makes the converter refuse the rule rather than emit a
        correlation grouped on a field nobody produces.
        """
        template = self.positional.get(internal)
        if template is None:
            return None
        return template.replace("{position}", str(position))


@dataclass(frozen=True, slots=True)
class LogSourceEntry:
    """Logsource resolved for one rule file."""

    logsource: dict[str, str]
    category: str
    is_fallback: bool


@dataclass(slots=True)
class LogSourceCatalog:
    """Maps rule file names to a Sigma logsource and a report category."""

    fallback: dict[str, str] = field(default_factory=dict)
    exact: dict[str, dict[str, str]] = field(default_factory=dict)
    prefix: dict[str, dict[str, str]] = field(default_factory=dict)
    report_categories: dict[str, list[str]] = field(default_factory=dict)

    def resolve(self, source_file: str) -> LogSourceEntry:
        """Resolve the logsource and report category of a rule file."""
        stem = source_file[:-6] if source_file.endswith(".rules") else source_file

        entry = self.exact.get(stem)
        is_fallback = False
        if entry is None:
            matches = [prefix for prefix in self.prefix if stem.startswith(prefix)]
            if matches:
                entry = self.prefix[max(matches, key=len)]
            else:
                entry = self.fallback
                is_fallback = True

        return LogSourceEntry(
            logsource=dict(entry),
            category=self.category_for(stem),
            is_fallback=is_fallback,
        )

    def category_for(self, stem: str) -> str:
        """Report grouping, longest matching prefix wins."""
        best_length = 0
        best_category = "Unclassified"
        for category, prefixes in self.report_categories.items():
            for prefix in prefixes:
                if stem.startswith(prefix) and len(prefix) > best_length:
                    best_length = len(prefix)
                    best_category = category
        return best_category


def _read_packaged(package: str, name: str) -> Any:
    with resources.files(package).joinpath(name).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@lru_cache(maxsize=8)
def load_profile(name_or_path: str) -> Profile:
    """Load a bundled profile, or an external YAML file."""
    path = Path(name_or_path)
    if path.is_file():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        document = _read_packaged(_PROFILE_PACKAGE, f"{name_or_path}.yml")
    return Profile(
        name=document["name"],
        description=str(document.get("description", "")).strip(),
        fields=dict(document["fields"]),
        positional=dict(document.get("positional") or {}),
        json_envelope=dict(document.get("json_envelope") or {}),
    )


@lru_cache(maxsize=4)
def load_catalog(path: str | None = None) -> LogSourceCatalog:
    """Load the logsource catalog."""
    if path is not None:
        document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    else:
        document = _read_packaged(_LOGSOURCE_PACKAGE, "catalog.yml")
    return LogSourceCatalog(
        fallback=dict(document.get("fallback") or {}),
        exact={k: dict(v) for k, v in (document.get("exact") or {}).items()},
        prefix={k: dict(v) for k, v in (document.get("prefix") or {}).items()},
        report_categories={
            k: list(v) for k, v in (document.get("report_categories") or {}).items()
        },
    )


def available_profiles() -> list[str]:
    """Names of the profiles bundled with the package."""
    return sorted(
        entry.name[:-4]
        for entry in resources.files(_PROFILE_PACKAGE).iterdir()
        if entry.name.endswith(".yml")
    )


@dataclass(frozen=True, slots=True)
class Context:
    """Everything a handler needs, with no shared mutable state."""

    profile: Profile
    config: SaganConfig
    catalog: LogSourceCatalog

    @property
    def syslog_host_field(self) -> str:
        """Field holding the syslog sender, used as the ``by_src`` fallback."""
        return self.profile.field("syslog_host")
