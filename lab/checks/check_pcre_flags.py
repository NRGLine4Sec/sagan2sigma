#!/usr/bin/env python3
"""What Sagan does with each PCRE flag letter.

The converter sorts flags into three buckets: mapped to a Sigma modifier
(`i`, `m`, `s`), dropped as having no Sigma-side effect, and refused. The
middle bucket is the risky one, because dropping a flag that changes matching
silently changes what the rule detects.

Sagan's flag switch in `src/rules.c` handles `i s m x A E G` and has **no
default case**, so any other letter is ignored at load time rather than
rejected. Two of the seven are in the converter's dropped bucket and are not
obviously inert:

* `A` is PCRE_ANCHORED, which forces the match to start at offset 0. Dropping
  it lets the converted rule match anywhere, so it fires where Sagan does not.
* `x` is PCRE_EXTENDED, which makes the engine ignore whitespace inside the
  pattern. Dropping it leaves that whitespace literal, so the converted rule
  matches something else entirely.

`G` (PCRE_UNGREEDY) is refused by the converter although the engine accepts it.
Greediness decides which text a match consumes, not whether one exists, so for
a detection that only asks "did it match" it should be safe to ignore.

Each case is measured rather than reasoned about.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, event, loads, rule, sagan  # noqa: E402

report = Report("pcre: which flag letters change matching")

#: One event, matched by content so the pcre is the only discriminator.
SUBJECT = "zzab tail"
PROBE = [event(SUBJECT)]


def matches(sid: int, pattern: str) -> bool:
    """Does this pcre fire on SUBJECT?"""
    fired = sagan([rule(sid, f'content:"zzab"; pcre:"{pattern}"')], PROBE)
    return str(sid) in fired.get(SUBJECT, set())


# --- the control: an unflagged pattern matches anywhere in the message -------
report.check("an unanchored pattern matches mid-message", matches(7001, "/ab/"), True)

# --- A: PCRE_ANCHORED --------------------------------------------------------
# "ab" appears at offset 2, so anchoring must suppress the match. If this
# reports True the flag is genuinely inert and dropping it is safe.
report.check("A anchors the match to offset 0", matches(7002, "/ab/A"), False)
report.check("A still allows a match at offset 0", matches(7003, "/zz/A"), True)

# --- x: PCRE_EXTENDED --------------------------------------------------------
# Whitespace inside the pattern is literal without the flag and ignored with it.
report.check("without x the spaces are literal", matches(7004, "/z z a b/"), False)
report.check("with x the spaces are ignored", matches(7005, "/z z a b/x"), True)

# --- G: PCRE_UNGREEDY --------------------------------------------------------
# Accepted by the engine, and greediness cannot change whether a match exists.
report.check("G loads", loads([rule(7006, 'content:"x"; pcre:"/a.*b/G"')]), True)
report.check("G does not change whether it matches", matches(7007, "/z.*b/G"), True)

# --- letters with no case in the switch --------------------------------------
# No default branch, so these are ignored rather than rejected. The corpus
# carries U and H, which is why the converter must not refuse them.
for letter in ("U", "H", "O", "S", "D", "g"):
    report.check(
        f"{letter} is ignored, not rejected",
        loads([rule(7008, f'content:"x"; pcre:"/ab/{letter}"')]),
        True,
    )

raise SystemExit(0 if report.done() else 1)
