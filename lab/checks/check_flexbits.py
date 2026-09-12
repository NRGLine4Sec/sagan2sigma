#!/usr/bin/env python3
"""What sagan2sigma has to know about `flexbits`, checked against the engine.

`flexbits` is not `xbits` with another name. Its test forms put the tracking
direction *before* the bit name, so `bit_name()` in mapping/correlation.py has
to recognise a direction token to know which argument is the name. Get that
wrong and the converter rebuilds the correlation around a bit nobody sets,
which fails silently: valid Sigma that never fires.

`Flexbit_Type()` in `src/flexbit.c` is the authority on which tokens count as a
direction. It accepts fourteen, and the error branch at the end names them all.
This file checks that list against the running engine, because the converter's
own list is a copy of it and a copy can drift.

Direction semantics (`by_src` keys on the source, `none` on nothing) are checked
too, since they decide the group-by key of the rebuilt correlation.

The address-keyed directions turn out to carry an engine defect: they compare
the printable address buffer rather than the binary form the struct also holds,
16 bytes of it, so the outcome depends on the bytes following the address in the
message. See the section at the bottom. Rules whose address comes from
`parse_src_ip` therefore do not correlate in Sagan, while their conversions do.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import (  # noqa: E402
    PATCHED,
    Report,
    event,
    loads,
    rule,
    sagan,
    skip_unless_available,
)

#: Every token Flexbit_Type() accepts, in source order.
DIRECTIONS = [
    "none",
    "both",
    "by_src",
    "by_dst",
    "reverse",
    "src_xbitdst",
    "dst_xbitsrc",
    "both_p",
    "by_src_p",
    "by_dst_p",
    "reverse_p",
    "src_xbitdst_p",
    "dst_xbitsrc_p",
    "username",
]

report = Report("flexbits: direction tokens, argument order, keying")

if not skip_unless_available(report, PATCHED):
    raise SystemExit(0 if report.done() else 1)

# --- the token list ----------------------------------------------------------
# One load of all fourteen at once: Sagan aborts the whole load on the first
# unrecognised direction, so "everything passed" means every token was accepted.
every = [
    rule(4000 + i, f'content:"flexload"; flexbits: isset, {token}, somebit')
    for i, token in enumerate(DIRECTIONS)
]
report.check("all 14 documented directions load", loads(every), True)

# An undocumented token must fail, otherwise the check above proves nothing:
# it would pass for any string at all.
report.check(
    "by_username is not a direction",
    loads([rule(4100, 'content:"x"; flexbits: isset, by_username, somebit')]),
    False,
)
report.check(
    "a nonsense direction is rejected",
    loads([rule(4101, 'content:"x"; flexbits: isset, zzznotadirection, somebit')]),
    False,
)

# `set` takes an expire time, not a direction, and rejects a missing or zero one.
report.check(
    "set takes name and expire",
    loads([rule(4102, 'content:"x"; flexbits: set, somebit, 300')]),
    True,
)
report.check(
    "set without an expire is rejected",
    loads([rule(4103, 'content:"x"; flexbits: set, somebit')]),
    False,
)

# --- argument order ----------------------------------------------------------
# The discriminator. A bit is literally named "by_src" and set; the tester asks
# for direction by_src and bit "beta", which nothing sets. If Sagan read the
# name from the second argument, as xbits does, it would find the set bit and
# alert. Silence is what proves the name is the third argument.
order = [
    rule(4200, 'program: sshd; content:"ordset"; flexbits: set, by_src, 300'),
    rule(4201, 'program: sshd; content:"ordtest"; flexbits: isset, by_src, beta'),
]
order_probes = ["ordset first", "ordtest second"]
fired = sagan(order, [event(p) for p in order_probes], binary=PATCHED)
report.check(
    "the bit name is the third argument, not the second",
    "4201" in fired.get(order_probes[1], set()),
    False,
)

# --- set / isset over time, addresses from the syslog envelope ---------------
# The envelope path is used here on purpose. With the address taken from the
# sender, by_src behaves as documented, so these checks measure the keying
# rather than the defect pinned further down.
flow = [
    rule(4300, 'program: sshd; content:"fset"; flexbits: set, fbit, 300'),
    rule(4301, 'program: sshd; content:"ftest"; flexbits: isset, by_src, fbit'),
]
probes = [
    ("ftest before", "10.0.0.1"),
    ("fset setter", "10.0.0.1"),
    ("ftest after", "10.0.0.1"),
    ("ftest elsewhere", "10.0.0.9"),
]
fired = sagan(flow, [event(msg, host=host) for msg, host in probes], binary=PATCHED)
report.check("the setter still alerts", "4300" in fired.get(probes[1][0], set()), True)
report.check(
    "isset is silent before the set", "4301" in fired.get(probes[0][0], set()), False
)
report.check(
    "isset fires after the set", "4301" in fired.get(probes[2][0], set()), True
)
report.check(
    "by_src is keyed on the source address",
    "4301" in fired.get(probes[3][0], set()),
    False,
)

# --- the defect: address directions compare the ASCII buffer, not the address -
# Flexbit_Set is handed SaganProcSyslog_LOCAL->src_ip, the printable address,
# and memcpy's sizeof(dest) = MAXIPBIT = 16 bytes of it into an
# `unsigned char[16]`. isset memcmp's that whole 16-byte window. The struct
# carries a proper binary form in ip_src_bits, which is what the comparison
# should have used; xbits is unaffected.
#
# Sixteen bytes is longer than "10.0.0.1", so the compare runs past the
# terminator. Through the envelope the tail is filled identically for every
# event and the match holds. Through Parse_IP, engine.c copies MAXIP = 64 bytes
# out of the per-event lookup cache, so the tail carries whatever followed the
# address in *that* message. The result depends on the surrounding text.
tail = [
    rule(
        4500, 'program: sshd; parse_src_ip: 1; content:"pset"; flexbits: set, pbit, 300'
    ),
    rule(
        4501,
        'program: sshd; parse_src_ip: 1; content:"ptest"; '
        "flexbits: isset, by_src, pbit",
    ),
]

differing = ["pset 10.0.0.1 alpha", "ptest 10.0.0.1 omega"]
fired = sagan(tail, [event(p) for p in differing], binary=PATCHED)
report.check(
    "parsed address, differing tails: no correlation",
    "4501" in fired.get(differing[1], set()),
    False,
)

identical = ["pset 10.0.0.1 samesuffix", "ptest 10.0.0.1 samesuffix"]
fired = sagan(tail, [event(p) for p in identical], binary=PATCHED)
report.check(
    "parsed address, identical tails: correlates",
    "4501" in fired.get(identical[1], set()),
    True,
)

# --- the set variants that also record ports ---------------------------------
# The upstream rule validator lists set_srcport, set_dstport and set_ports
# alongside set, and reading that list is what prompted these checks. All three
# set a bit a later isset sees, so a converter ignoring them drops the setter
# and rebuilds the correlation without it.
for setter in ("set_srcport", "set_dstport", "set_ports"):
    pair = [
        rule(4500, f'program: sshd; content:"vset"; flexbits: {setter}, vbit, 300'),
        rule(4501, 'program: sshd; content:"vtest"; flexbits: isset, by_src, vbit'),
    ]
    msgs = ["vset setter", "vtest after"]
    fired = sagan(pair, [event(m, host="10.0.0.1") for m in msgs], binary=PATCHED)
    report.check(
        f"{setter} sets a bit isset can see",
        "4501" in fired.get(msgs[1], set()),
        True,
    )

# --- the expiry is positional, not `expire N` --------------------------------
# xbits appends `expire N`; flexbits puts a bare number third and rejects the
# rule without it. Reading only the xbits form made every flexbits setter fall
# back to a default window, which is what a rebuilt correlation is measured
# over.
report.check(
    "a numeric third argument is the expiry",
    loads([rule(4600, 'content:"x"; flexbits: set, b, 532800')]),
    True,
)
report.check(
    "the xbits spelling is not accepted here",
    loads([rule(4601, 'content:"x"; flexbits: set, b, expire 300')]),
    False,
)

# --- xbits toggle is rejected -------------------------------------------------
# Listed as valid by the engine's own error message and by the upstream
# validator, but the branch is commented out in src/rules.c, so xbit_type stays
# zero and the ruleset aborts.
report.check(
    "xbits toggle does not load",
    loads([rule(4700, 'content:"x"; xbits: toggle,b,track ip_src')]),
    False,
)
report.check(
    "while the actions beside it do",
    loads([rule(4701, 'content:"x"; xbits: set,b,track ip_src, expire 300')]),
    True,
)

# --- direction none ----------------------------------------------------------
# `none` tracks nothing, so the bit is global: a different source still sees it.
# This is why the converter must not emit a group-by for it.
loose = [
    rule(
        4400, 'program: sshd; parse_src_ip: 1; content:"nset"; flexbits: set, nbit, 300'
    ),
    rule(
        4401,
        'program: sshd; parse_src_ip: 1; content:"ntest"; flexbits: isset, none, nbit',
    ),
]
loose_probes = ["nset from 10.0.0.1 setter", "ntest from 10.0.0.9 elsewhere"]
fired = sagan(loose, [event(p) for p in loose_probes], binary=PATCHED)
report.check(
    "none ignores the address entirely",
    "4401" in fired.get(loose_probes[1], set()),
    True,
)

raise SystemExit(0 if report.done() else 1)
