#!/usr/bin/env python3
"""Does liblognorm normalization override parse_src_ip / parse_dst_ip?

sagan2sigma refuses to reproduce normalization and emits
``D_NORMALIZE_PRECEDENCE`` on the 88 corpus rules that carry both `normalize`
and a positional address keyword. The degradation text claims:

    Sagan lets liblognorm win when it resolves the address and falls back to
    positional parsing otherwise; only the fallback is reproduced.

That claim comes from `engine.c`, where the positional block is guarded by
``ip_src_is_valid == false``, and from the comment above it. Reading a guard is
not the same as watching it hold, and the whole degradation note depends on it:
if normalization did *not* win, the converter would be reproducing the wrong
half of the mechanism on 88 rules.

The addresses below are chosen so the two mechanisms disagree. See
``config/rules/lab-normalize.rulebase``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, alerts, config_with_rulebase, event, rule  # noqa: E402

LAB = Path(__file__).resolve().parent.parent
CONFIG = config_with_rulebase(LAB / "config" / "rules" / "lab-normalize.rulebase")

#: liblognorm resolves src=5.5.5.5 and dst=8.8.8.8; Parse_IP would order them
#: 5.5.5.5 first, 8.8.8.8 second.
NORMALIZABLE = "ACCESS x SRC 5.5.5.5 DEST 8.8.8.8 tail"
#: The same addresses in the same order, in a shape no rulebase rule matches.
OPAQUE = "zzz opaque 5.5.5.5 then 8.8.8.8 tail"
#: liblognorm resolves a source only, leaving the destination to Parse_IP.
SRC_ONLY = "SRCONLY 5.5.5.5 and 8.8.8.8 tail"

#: The syslog sender, which is what an unresolved address falls back to.
HOST = "192.168.2.1"

report = Report("normalize: precedence over positional address parsing")


def addresses(options: str, message: str) -> tuple[str, str]:
    """Run one rule against one message and return the alert's (src, dst)."""
    got = alerts([rule(1, options)], [event(message, program="cisco")], config=CONFIG)
    if not got:
        return ("no alert", "no alert")
    return (got[0].get("src", "?"), got[0].get("dst", "?"))


# --- normalization on its own actually resolves both addresses --------------
# Without this the rest of the file would be measuring nothing, which is how a
# first attempt at these checks silently "passed" against the bundled rulebase.
src, dst = addresses('content:"ACCESS"; normalize', NORMALIZABLE)
report.check("normalize resolves the source", src, "5.5.5.5")
report.check("normalize resolves the destination", dst, "8.8.8.8")

src, dst = addresses('content:"opaque"; normalize', OPAQUE)
report.check("nothing to normalize leaves the sender", src, HOST)

# --- positional parsing on its own, the control ------------------------------
src, _ = addresses('content:"ACCESS"; parse_src_ip: 2', NORMALIZABLE)
report.check("parse_src_ip:2 alone takes the 2nd address", src, "8.8.8.8")

_, dst = addresses('content:"ACCESS"; parse_dst_ip: 1', NORMALIZABLE)
report.check("parse_dst_ip:1 alone takes the 1st address", dst, "5.5.5.5")

# --- the precedence itself ---------------------------------------------------
# Both keywords present and disagreeing: normalization must win.
src, dst = addresses('content:"ACCESS"; normalize; parse_src_ip: 2', NORMALIZABLE)
report.check("normalize beats parse_src_ip", src, "5.5.5.5")
report.check("  and the destination stays normalized", dst, "8.8.8.8")

src, dst = addresses('content:"ACCESS"; normalize; parse_dst_ip: 1', NORMALIZABLE)
report.check("normalize beats parse_dst_ip", dst, "8.8.8.8")
report.check("  and the source stays normalized", src, "5.5.5.5")

# --- the fallback, which is the half sagan2sigma does reproduce --------------
src, _ = addresses('content:"opaque"; normalize; parse_src_ip: 2', OPAQUE)
report.check("normalization failing falls back to parse_src_ip", src, "8.8.8.8")

_, dst = addresses('content:"opaque"; normalize; parse_dst_ip: 1', OPAQUE)
report.check("normalization failing falls back to parse_dst_ip", dst, "5.5.5.5")

# --- the mixed branch: resolved source, unresolved destination ---------------
# "unless liblognorm failed to get src or dst", from the comment in engine.c.
src, dst = addresses('content:"SRCONLY"; normalize; parse_dst_ip: 2', SRC_ONLY)
report.check("a resolved source stays normalized", src, "5.5.5.5")
report.check("an unresolved destination falls back to position", dst, "8.8.8.8")

raise SystemExit(0 if report.done() else 1)
