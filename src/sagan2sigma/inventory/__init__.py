"""A commit-pinned inventory of overlapping rules, tiered by confidence.

This merges the two analyses, behavioural (:mod:`sagan2sigma.overlap`) and
conceptual (:mod:`sagan2sigma.conceptual`), into one list of overlapping rule
pairs, each placed in the strongest confidence tier the evidence supports. The
tiers are defined by which analysis backs a pair and how strongly, so a reader
can act on the top of the list and treat the bottom as leads.

The inventory is a point-in-time snapshot. Both rule corpora change daily, so a
pair that overlaps today may not exist next month. Every inventory therefore
pins the exact commit of each corpus it was built from; without that, the list
is unfalsifiable and quietly rots.
"""

from __future__ import annotations

__all__ = ["classify", "cli", "render"]
