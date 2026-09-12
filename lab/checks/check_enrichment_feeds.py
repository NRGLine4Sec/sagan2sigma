#!/usr/bin/env python3
"""`blacklist` and `zeek-intel`: which addresses they test, and when.

Both keywords carry a degradation telling the operator what the converted rule
depends on, and both rest on claims about the engine that had only been read:

* `D_DENYLIST_USERNAME_INERT` says `blacklist: by_username` is *inert*, that the
  option is dropped and the rest of the rule converted "exactly as the engine
  evaluates it". That is only true if an unrecognised direction leaves
  `blacklist_flag` unset, so the routing check is skipped entirely rather than
  failing. If instead the flag were set with no direction, the rule could never
  fire in Sagan, and dropping the option would turn a dead rule into a live one.
* `D_DENYLIST_ENRICHMENT` and `D_ZEEK_INTEL_ENRICHMENT` say the match is against
  the *address*, not the log text.

Neither processor is testable as shipped: both are disabled and expect feeds
that are not on this machine. `config_with_processor` enables one and points it
at a fixture in `config/rules/`, so the expected answers are known without a
live feed.

`bluedot` is deliberately absent. It queries Quadrant's closed threat-intel
service over the network, so there is nothing here to observe; the converter
treats it as out of scope, which is a decision rather than a claim about
behaviour.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import Report, config_with_processor, event, rule, sagan  # noqa: E402

LAB = Path(__file__).resolve().parent.parent
DENYLIST = config_with_processor(
    "blacklist", LAB / "config" / "rules" / "lab-blacklist.txt"
)
ZEEK = config_with_processor(
    "zeek-intel", LAB / "config" / "rules" / "lab-zeek-intel.dat"
)

#: In config/rules/lab-blacklist.txt: 203.0.113.7 and 198.51.100.0/24.
#: In config/rules/lab-zeek-intel.dat: 203.0.113.9 as an Intel::ADDR.
LISTED = "203.0.113.7"
IN_RANGE = "198.51.100.42"
CLEAN = "192.0.2.15"
INTEL = "203.0.113.9"

report = Report("blacklist and zeek-intel: address matching and inert options")


def fires(sid: int, options: str, message: str, config: Path) -> bool:
    fired = sagan(
        [rule(sid, f"program: cisco; {options}")],
        [event(message, program="cisco")],
        config=config,
    )
    return str(sid) in fired.get(message, set())


# --- the denylist tests the address, not the text -----------------------------
SRC = 'parse_src_ip: 1; content:"deny"; blacklist: by_src'
report.check(
    "a listed source fires",
    fires(9500, SRC, f"deny from {LISTED} tail", DENYLIST),
    True,
)
report.check(
    "an unlisted source does not",
    fires(9501, SRC, f"deny from {CLEAN} tail", DENYLIST),
    False,
)
report.check(
    "a CIDR entry covers the range",
    fires(9502, SRC, f"deny from {IN_RANGE} tail", DENYLIST),
    True,
)
# The fixture lists the /24 *before* the /32 on purpose. See the section on
# mask leakage at the bottom of this file: the other order silently narrows it.
# The listed address appearing anywhere in the text is not enough: by_src reads
# the parsed source, which here is the second address.
report.check(
    "by_src reads the parsed position, not the whole line",
    fires(
        9503,
        'parse_src_ip: 2; content:"deny"; blacklist: by_src',
        f"deny from {LISTED} to {CLEAN} tail",
        DENYLIST,
    ),
    False,
)

# --- by_dst and both ----------------------------------------------------------
PAIR = 'parse_src_ip: 1; parse_dst_ip: 2; content:"deny"'
report.check(
    "by_dst tests the destination",
    fires(
        9504, f"{PAIR}; blacklist: by_dst", f"deny from {CLEAN} to {LISTED} x", DENYLIST
    ),
    True,
)
# `both` is a disjunction in the engine: it requires *both* addresses to be
# valid but fires when *either* is listed (engine.c). The name suggests the
# opposite, which is why it is checked.
report.check(
    "both fires when only the source is listed",
    fires(
        9505, f"{PAIR}; blacklist: both", f"deny from {LISTED} to {CLEAN} x", DENYLIST
    ),
    True,
)
report.check(
    "both fires when only the destination is listed",
    fires(
        9506, f"{PAIR}; blacklist: both", f"deny from {CLEAN} to {LISTED} x", DENYLIST
    ),
    True,
)
report.check(
    "both stays silent when neither is",
    fires(
        9507, f"{PAIR}; blacklist: both", f"deny from {CLEAN} to {CLEAN} x", DENYLIST
    ),
    False,
)

# --- all scans the addresses Parse_IP found, not the raw line ----------------
# `Sagan_Blacklist_IPADDR_All` walks the lookup cache, and engine.c fills that
# cache only when the rule declares a position. Without one it is empty, so
# `all` scans nothing and the option is inert however many listed addresses the
# message carries.
ALL_LINE = f"deny from {CLEAN} to {LISTED} x"
report.check(
    "all finds a listed address once a position is declared",
    fires(9508, 'parse_src_ip: 1; content:"deny"; blacklist: all', ALL_LINE, DENYLIST),
    True,
)
report.check(
    "but is inert when the rule declares none",
    fires(9512, 'content:"deny"; blacklist: all', ALL_LINE, DENYLIST),
    False,
)

# --- the inert direction ------------------------------------------------------
# The claim behind D_DENYLIST_USERNAME_INERT. blacklist_flag is set only inside
# the four recognised token branches, so an unrecognised one leaves it clear and
# routing never consults the denylist. The rule then fires on its other
# conditions, which is what makes dropping the option faithful.
report.check(
    "by_username loads",
    fires(
        9509, 'content:"deny"; blacklist: by_username', f"deny from {CLEAN} x", DENYLIST
    )
    is not None,
    True,
)
report.check(
    "and is inert: the rule fires on an unlisted address",
    fires(
        9510, 'content:"deny"; blacklist: by_username', f"deny from {CLEAN} x", DENYLIST
    ),
    True,
)
report.check(
    "a recognised direction would have suppressed that",
    fires(9511, SRC, f"deny from {CLEAN} x", DENYLIST),
    False,
)

# --- zeek-intel ---------------------------------------------------------------
ZSRC = 'parse_src_ip: 1; content:"zeek"; zeek-intel: by_src'
report.check(
    "an indicator address fires",
    fires(9520, ZSRC, f"zeek from {INTEL} tail", ZEEK),
    True,
)
report.check(
    "an address absent from the feed does not",
    fires(9521, ZSRC, f"zeek from {CLEAN} tail", ZEEK),
    False,
)
report.check(
    "an address on the denylist but not the feed does not",
    fires(9522, ZSRC, f"zeek from {LISTED} tail", ZEEK),
    False,
)

# --- an engine defect: mask bits leak between denylist entries ---------------
# `maskbits` is declared once, outside the read loop in blacklist.c, and
# Mask2Bit only writes the leading bytes of the new mask. A shorter prefix
# following a longer one therefore inherits the leftover 0xff bytes, and the
# entry is silently narrowed to the longest prefix seen earlier in the file.
#
# Real feeds mix prefix lengths freely, so this is not academic: a /24 placed
# after any /32 covers only its own network address. The converter's bundled
# enrichment does ordinary CIDR matching, so it will match addresses Sagan's
# own denylist quietly misses, and the two disagree on the very same feed.
import tempfile  # noqa: E402


def with_denylist(lines: str, ip: str) -> bool:
    """Run one address against a denylist written on the spot."""
    path = Path(tempfile.mkdtemp()) / "denylist.txt"
    path.write_text(lines, encoding="utf-8")
    return fires(
        9530, SRC, f"deny from {ip} tail", config_with_processor("blacklist", path)
    )


report.check(
    "a /24 alone covers its range",
    with_denylist("198.51.100.0/24\n", IN_RANGE),
    True,
)
report.check(
    "the same /24 after a /32 does not",
    with_denylist("203.0.113.7\n198.51.100.0/24\n", IN_RANGE),
    False,
)
report.check(
    "it still covers its own network address",
    with_denylist("203.0.113.7\n198.51.100.0/24\n", "198.51.100.0"),
    True,
)
report.check(
    "the narrowing follows file order, not the entries",
    with_denylist("198.51.100.0/24\n203.0.113.7\n", IN_RANGE),
    True,
)
report.check(
    "and applies to any shortening, not only to /32",
    with_denylist("198.51.100.0/24\n10.0.0.0/16\n", "10.0.99.5"),
    False,
)
report.check(
    "which the same entry alone handles correctly",
    with_denylist("10.0.0.0/16\n", "10.0.99.5"),
    True,
)

raise SystemExit(0 if report.done() else 1)
