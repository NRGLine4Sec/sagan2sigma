"""On-disk cache for synthesised events.

Synthesis is the slow half of the analysis, roughly three minutes for the
SigmaHQ corpus alone, and it is deterministic: the events built from a rule
depend only on its detection block and the requested event count, never on the
engine or on anything else in the run. That makes it exactly the kind of work
worth caching, because the user will re-run this study, most often after only
one of the two corpora has moved.

A cache entry is keyed by a hash of the detection block, the event limit and an
algorithm version. The version is bumped whenever the synthesiser changes in a
way that could alter its output, so a stale entry is never trusted: a cache
that silently served the previous synthesiser's events would quietly falsify
every verdict resting on them.

The stored events are the raw synthesised dictionaries. They are still put
through the engine on load like any other event, so a corrupt or hand-edited
cache file cannot smuggle an unconfirmed event into the analysis; at worst it
costs one wasted evaluation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .analysis import RuleRecord

#: Bump this whenever a change to synthesis could alter the events it produces.
#: An entry written under a different version is ignored rather than trusted.
#: v2: _compare_value now honours the operator, so numeric comparison rules
#: synthesise a satisfying value instead of a rejected one.
ALGORITHM_VERSION = 2


def _digest(record: RuleRecord, limit: int) -> str:
    """A stable key for the events a record synthesises at a given limit."""
    detection = record.document.get("detection", {})
    # ``default=str`` because SigmaHQ documents carry ``date`` values that are
    # not JSON serialisable; ``sort_keys`` because two byte-different but
    # semantically identical detection blocks must share a cache entry.
    canonical = json.dumps(detection, sort_keys=True, default=str, ensure_ascii=False)
    material = f"{ALGORITHM_VERSION}\0{limit}\0{record.origin}\0{canonical}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class SynthesisCache:
    """Reads and writes synthesised events under a directory.

    A ``None`` root disables the cache entirely, so callers can treat "no
    caching requested" and "caching to a directory" through one object without
    branching at every call site.
    """

    def __init__(self, root: Path | None) -> None:
        """Prepare the cache, creating the directory when one is given."""
        self.root = root
        self.hits = 0
        self.misses = 0
        if root is not None:
            root.mkdir(parents=True, exist_ok=True)

    def _path(self, record: RuleRecord, limit: int) -> Path:
        assert self.root is not None
        return self.root / f"{_digest(record, limit)}.json"

    def load(self, record: RuleRecord, limit: int) -> list[dict[str, Any]] | None:
        """Return cached events for the record, or ``None`` on a miss.

        A file that fails to parse is treated as a miss rather than an error, so
        a partially written entry from an interrupted run is simply rebuilt.
        """
        if self.root is None:
            return None
        path = self._path(record, limit)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.misses += 1
            return None
        events = payload.get("events")
        if not isinstance(events, list):
            self.misses += 1
            return None
        self.hits += 1
        return events

    def store(
        self, record: RuleRecord, limit: int, events: list[dict[str, Any]]
    ) -> None:
        """Persist the events synthesised for a record.

        The write goes through a temporary file and an atomic rename so a run
        interrupted mid-write leaves the previous entry, or no entry, never a
        truncated one.
        """
        if self.root is None:
            return
        path = self._path(record, limit)
        payload = {
            "key": record.key,
            "title": record.title,
            "limit": limit,
            "events": events,
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(payload, default=str, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(path)
