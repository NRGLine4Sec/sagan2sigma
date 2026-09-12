#!/usr/bin/env python3
"""after, threshold, xbits: the family where both converter bugs were found.

Three claims are pinned here.

**`after: count N` alerts from the N+1th event.** `src/after.c` seeds its entry
with `count = 1` on the first match and alerts only while
`after2_count < count`, a strictly-greater comparison, so N events pass in
silence and the next one alerts. The converter emitted a Sigma `event_count`
with `gte: N`, which fires as soon as the window holds N: one event early, on
all 970 corpus correlations. It now emits `N+1`.

**`by_string` means different things to the two keywords.** `threshold` tests
the intact option token, so there it is a synonym for `by_username`. `after`
calls `strtok_r` first and then tests a token already truncated to `"track"`, so
its branch can never fire. The load check is what settles this: `after: track
by_string` alone is *rejected*, which is only possible if the key contributes
nothing to the parser's validity count.

**`threshold` caps alert volume, it does not change detection.** Both `limit`
and `suppress` alert on the first N events of the window and then fall silent.
Converting either into an `event_count` correlation would turn a rule that
*allows* N into one that *requires* N.

These checks use the patched binary: upstream's `after` path overruns its own
tracking entry and a hardened build aborts there. The patch changes one
destination size and leaves the counting logic untouched.
"""

from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from harness import (  # noqa: E402
    PATCHED,
    Report,
    event,
    loads,
    rule,
    sagan,
    skip_unless_available,
)


def check_after_threshold(report: Report) -> None:
    events = [event(f"aft from 10.0.0.1 evt{i}") for i in range(6)]
    for count in (1, 2, 3, 4):
        text = rule(
            3000 + count,
            f'program: sshd; content:"aft"; parse_src_ip: 1; '
            f"after: track by_src, count {count}, seconds 300",
        )
        fired = sagan([text], events, binary=PATCHED)
        indices = sorted(
            int(message.split("evt")[1])
            for message, sids in fired.items()
            if str(3000 + count) in sids
        )
        report.check(
            f"after count {count} alerts from the {count + 1}th event",
            indices,
            list(range(count, 6)),
        )


def check_threshold_volume(report: Report) -> None:
    events = [event(f"thr from 10.0.0.1 evt{i}") for i in range(6)]
    for kind in ("limit", "suppress"):
        for count in (1, 3):
            sid = 3100 + (0 if kind == "limit" else 50) + count
            text = rule(
                sid,
                f'program: sshd; content:"thr"; parse_src_ip: 1; '
                f"threshold: type {kind}, track by_src, count {count}, seconds 300",
            )
            fired = sagan([text], events, binary=PATCHED)
            indices = sorted(
                int(message.split("evt")[1])
                for message, sids in fired.items()
                if str(sid) in sids
            )
            report.check(
                f"threshold {kind} count {count} caps at the first {count}",
                indices,
                list(range(count)),
            )


def check_by_string(report: Report) -> None:
    # A load check, not an alert count: the question is whether the key counts
    # towards the parser's notion of a valid track expression.
    after_only = rule(
        3200, 'program: sshd; content:"x"; after: track by_string, count 2, seconds 300'
    )
    after_pair = rule(
        3201,
        'program: sshd; content:"x"; after: track by_src&by_string, count 2, seconds 300',
    )
    threshold_only = rule(
        3202,
        'program: sshd; content:"x"; '
        "threshold: type limit, track by_string, count 2, seconds 300",
    )
    after_user = rule(
        3203,
        'program: sshd; content:"x"; after: track by_username, count 2, seconds 300',
    )
    report.check("after: by_string alone is rejected", loads([after_only]), False)
    report.check("after: by_username alone loads", loads([after_user]), True)
    report.check("after: by_src&by_string loads", loads([after_pair]), True)
    report.check("threshold: by_string loads", loads([threshold_only]), True)


def check_xbits(report: Report) -> None:
    rules = [
        rule(
            3300,
            'program: sshd; parse_src_ip: 1; content:"setbit"; '
            "xbits: set,mybit,track ip_src, expire 300",
        ),
        rule(
            3301,
            'program: sshd; parse_src_ip: 1; content:"testbit"; '
            "xbits: isset,mybit,track ip_src",
        ),
        rule(
            3302,
            'program: sshd; parse_src_ip: 1; content:"testbit"; '
            "xbits: isnotset,mybit,track ip_src",
        ),
    ]
    probes = [
        "testbit from 10.0.0.1 before",
        "setbit from 10.0.0.1 set",
        "testbit from 10.0.0.1 after",
        "testbit from 10.0.0.9 other",
    ]
    fired = sagan(rules, [event(p) for p in probes], binary=PATCHED)

    def hit(sid: int, probe: str) -> bool:
        return str(sid) in fired.get(probe, set())

    report.check("the setter still alerts", hit(3300, probes[1]), True)
    report.check("isset is silent before the set", hit(3301, probes[0]), False)
    report.check("isset fires after the set", hit(3301, probes[2]), True)
    report.check("isset is keyed on the tracked address", hit(3301, probes[3]), False)
    report.check("isnotset is the complement, before", hit(3302, probes[0]), True)
    report.check("isnotset is the complement, after", hit(3302, probes[2]), False)

    pair = [
        rule(
            3310,
            'program: sshd; parse_src_ip: 1; parse_dst_ip: 2; content:"pairset"; '
            "xbits: set,pbit,track ip_pair, expire 300",
        ),
        rule(
            3311,
            'program: sshd; parse_src_ip: 1; parse_dst_ip: 2; content:"pairtest"; '
            "xbits: isset,pbit,track ip_pair",
        ),
    ]
    pair_probes = [
        "pairset from 10.0.0.1 to 10.0.0.2 p1",
        "pairtest from 10.0.0.1 to 10.0.0.2 same",
        "pairtest from 10.0.0.1 to 10.0.0.9 otherdst",
        "pairtest from 10.0.0.2 to 10.0.0.1 reversed",
    ]
    fired = sagan(pair, [event(p) for p in pair_probes], binary=PATCHED)
    report.check(
        "ip_pair matches the same pair",
        "3311" in fired.get(pair_probes[1], set()),
        True,
    )
    report.check(
        "ip_pair rejects another destination",
        "3311" in fired.get(pair_probes[2], set()),
        False,
    )
    report.check(
        "ip_pair is ordered", "3311" in fired.get(pair_probes[3], set()), False
    )


def main() -> bool:
    report = Report("correlation: after, threshold, by_string, xbits")
    if not skip_unless_available(report, PATCHED):
        return report.done()
    for step in (
        check_after_threshold,
        check_threshold_volume,
        check_by_string,
        check_xbits,
    ):
        report.measure(step)
    return report.done()


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
