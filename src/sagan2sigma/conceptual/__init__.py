"""Conceptual overlap between converted rules and SigmaHQ.

This is a deliberately separate analysis from ``sagan2sigma.overlap``, and the
separation is not cosmetic. ``overlap`` establishes, by running the engine, that
two rules fire on the same event. This module does no such thing: it looks at
what a rule is *about*, using the distinctive terms it searches for and the
ATT&CK techniques it declares, and proposes pairs a human should review.

It exists because most converted rules match the raw message body and so cannot
be compared behaviourally against a SigmaHQ rule matching structured fields,
even when both are plainly written to catch the same thing. A lexical and
tag-based comparison says something useful there. What it produces are
**candidates for review, never verdicts**: a shared term is a hint, not proof
that two rules detect the same behaviour, and nothing here licenses dropping a
rule. That is what the behavioural analysis is for.
"""

from __future__ import annotations

__all__ = ["analysis", "cli", "features", "report", "similarity"]
