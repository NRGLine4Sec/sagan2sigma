"""Behavioural overlap analysis between converted rules and SigmaHQ.

The question this answers is not "do these two rules look alike" but "is there
an event on which both fire, and does one cover the other". Every claim the
report makes is backed by an event that the RSigma engine actually evaluated.
"""

from __future__ import annotations

__all__ = ["analysis", "cache", "cli", "engine", "negation", "report", "synth"]
