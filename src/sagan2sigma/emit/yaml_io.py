"""Deterministic YAML serialisation of Sigma documents.

Two requirements the default ``yaml.dump`` does not meet.

**Determinism.** Two runs over the same corpus must produce byte-identical
files, otherwise the Git diff becomes useless and regressions go unnoticed in
CI. Key order is therefore insertion order, never alphabetical.

**Readability.** Converted rules are meant to be reviewed and tuned by hand, so
block style is forced, anchors are disabled and Unicode is not escaped.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import yaml


class SigmaDumper(yaml.SafeDumper):
    """Dumper without anchors or aliases, with indented sequences."""

    def ignore_aliases(self, data: Any) -> bool:
        """Never emit YAML anchors: they hurt readability and diffing."""
        return True

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        """Indent sequences under their key, which most Sigma tooling expects."""
        super().increase_indent(flow=flow, indentless=False)


def _represent_mapping(dumper: SigmaDumper, data: dict[str, Any]) -> yaml.Node:
    """Preserve key insertion order."""
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items())


def _represent_str(dumper: SigmaDumper, data: str) -> yaml.Node:
    """Use block style for multi-line strings."""
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


SigmaDumper.add_representer(dict, _represent_mapping)
SigmaDumper.add_representer(str, _represent_str)


def dump_document(document: Mapping[str, Any]) -> str:
    """Serialise one Sigma document."""
    return yaml.dump(
        document,
        Dumper=SigmaDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=100,
    )


def dump_collection(documents: Iterable[Mapping[str, Any]]) -> str:
    """Serialise a Sigma collection as ``---`` separated documents."""
    return "---\n".join(dump_document(document) for document in documents)
