#!/usr/bin/env python3
"""offset, depth, distance, within, and Parse_IP position semantics.

Two converter decisions rest on this file.

The first is that a zero-valued positional is a no-op, which is what lets 245
corpus rules convert instead of being refused. `content:"A"; content:"B";
distance:0` does **not** mean "B after A": the engine skips its positional block
entirely at zero, leaving two independent substring searches.

The second is that a non-zero `distance` is refused rather than approximated.
The reason is that Sagan's distance is not what the name suggests. It is an
absolute offset from the start of the message, computed from the previous
content's `depth` plus the distance, not a gap measured from where the previous
pattern matched. Emitting an ordered `A.*B` regex would be a different rule.

Parse_IP is checked here too, because `parse_src_ip: N` means the Nth address in
the message and the whole enriched profile is built on reproducing that exactly.
The alert record shows which address the engine picked, which makes it directly
observable.
"""

from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from harness import Report, alerts, event, rule, sagan  # noqa: E402


def check_offsets(report: Report) -> None:
    rules = [
        rule(2001, 'program: sshd; content:"AAA"; content:"BBB"; distance:0'),
        rule(2002, 'program: sshd; content:"AAA"; content:"BBB"; distance:5'),
        rule(2003, 'program: sshd; content:"BBB"; offset:5'),
        rule(2004, 'program: sshd; content:"BBB"; depth:5'),
        rule(2005, 'program: sshd; content:"AAA"; content:"BBB"; within:3'),
    ]
    probes = {
        "ab": "AAAxxxBBB",  # B at offset 6
        "ba": "BBBxxxAAA",  # B before A
        "tight": "AAABBB",  # B at offset 3
        "late": "xxxxxxxxBBB",  # B at offset 8
        "early": "BBBxxxxxxxx",  # B at offset 0
    }
    fired = sagan(rules, [event(f"{v} k{k}") for k, v in probes.items()])

    def hit(sid: int, key: str) -> bool:
        return str(sid) in fired.get(f"{probes[key]} k{key}", set())

    report.check("distance:0 does not impose order (A then B)", hit(2001, "ab"), True)
    report.check("distance:0 does not impose order (B then A)", hit(2001, "ba"), True)
    report.check("within alone is inert (B then A)", hit(2005, "ba"), True)

    # Absolute: the search starts at depth[z-1] + distance + 1 = 6, so B at 6
    # matches and B at 3 does not. A relative reading would predict the reverse.
    report.check("distance:5 is an absolute offset, B at 6", hit(2002, "ab"), True)
    report.check("distance:5 rejects B at 3", hit(2002, "tight"), False)

    report.check("offset:5 searches from byte 5 on", hit(2003, "late"), True)
    report.check("offset:5 ignores an earlier match", hit(2003, "early"), False)
    report.check("depth:5 searches only the head", hit(2004, "early"), True)
    report.check("depth:5 ignores a later match", hit(2004, "late"), False)


def check_parse_ip(report: Report) -> None:
    rules = [
        rule(2100 + n, f'program: sshd; content:"ipcase"; parse_src_ip: {n}')
        for n in (1, 2, 3)
    ]
    cases = {
        "plain": "ipcase from 192.168.1.50 to 10.0.0.2 via 172.16.0.9",
        "quoted": 'ipcase srcip="10.1.1.1" dstip="10.2.2.2" action=deny',
        "asa": "ipcase %ASA-4-106023 src outside:203.0.113.7/51234 dst inside:10.1.1.5/443",
        "bind": "ipcase client 198.51.100.9#41234 query example.com",
        "version": "ipcase agent version 1.2.3 build 4.5.6.7.8 started",
        "invalid": "ipcase invalid 999.1.1.1 and padded 01.2.3.4 present",
    }
    found = alerts(rules, [event(v) for v in cases.values()])
    picked: dict[str, dict[str, str]] = {}
    for record in found:
        picked.setdefault(record["message"], {})[record["sid"]] = record["src"]

    def src(key: str, position: int) -> str:
        return picked.get(cases[key], {}).get(str(2100 + position), "-")

    report.check("position 1 is the first address", src("plain", 1), "192.168.1.50")
    report.check("position 2 is the second", src("plain", 2), "10.0.0.2")
    report.check("position 3 is the third", src("plain", 3), "172.16.0.9")
    report.check("quotes and = are delimiters", src("quoted", 1), "10.1.1.1")
    report.check("colon and slash are delimiters", src("asa", 1), "203.0.113.7")
    report.check("both sides of a separator are tried", src("asa", 2), "10.1.1.5")
    report.check("hash is a delimiter", src("bind", 1), "198.51.100.9")

    # No address at that position: src_ip falls back to the syslog sender. The
    # engine leaves ip_src_is_valid false, which is why enrichment stays silent
    # on it; see check_enrichment.py.
    report.check("version strings are not addresses", src("version", 1), "192.168.2.1")
    report.check("invalid octets are rejected", src("invalid", 1), "192.168.2.1")
    report.check(
        "missing position falls back to syslog host", src("quoted", 3), "192.168.2.1"
    )


def main() -> bool:
    report = Report("positional: offset, depth, distance, within, Parse_IP")
    check_offsets(report)
    check_parse_ip(report)
    return report.done()


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
