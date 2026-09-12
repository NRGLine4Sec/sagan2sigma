#!/usr/bin/env python3
"""JSON handling, pass rules, and the GeoIP truth table.

**JSON.** `json_map: "message", ".Key"` redirects a `content` search to that key
rather than the raw body, which about 1,020 corpus rules depend on. Without such
a binding, `content` searches the raw JSON text, which is why a raw search on a
JSON event is refused under the default profiles. And `json_content` is an
*exact* match on the whole value, not a substring search: the converter emits an
equality, not `|contains`, and this is what says that is right.

**pass.** A matching `pass` rule still emits its alert and only then stops the
remaining signatures. Refusing pass rules on the assumption that they suppress
silently would have lost real detections.

**GeoIP.** `country_code` only compares when a country was actually resolved.
`GeoIP2_Lookup_Country` returns `GEOIP_SKIP` from every path that cannot
determine one, `engine.c` runs the is/isnot test only when the result is not
`GEOIP_SKIP`, and `routing.c` then drops the rule. So `isnot` does **not** mean
"anything but these countries": an address the database cannot place fires
neither form. Reading it the other way made every RFC1918 address alert on the
"connection from outside $HOME_COUNTRY" family.

The lab's `country.mmdb` is deliberately tiny and fixed: 5.5.5.0/24 is RU,
8.8.8.0/24 is US, 203.0.113.0/24 is FR, everything else is unknown. The config
sets `skip_networks: ""` because Sagan ships a default that skips 8.8.8.8, which
would silently turn the HIT case into a SKIP and invert the reading.
"""

from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from harness import Report, event, rule, sagan  # noqa: E402


def check_json(report: Report) -> None:
    rules = [
        rule(4001, 'program: sshd; json_map: "message", ".Msg"; content:"needle"'),
        rule(4002, 'program: sshd; content:"needle"'),
        rule(4003, 'program: sshd; json_content:".Msg","alpha beta gamma"'),
        rule(4004, 'program: sshd; json_content:".Msg","alpha"'),
        rule(4005, 'program: sshd; json_content:".Msg","beta"'),
        rule(4006, 'program: sshd; json_content:".Msg","ALPHA BETA GAMMA"'),
    ]
    inside = '{"Msg":"has needle here","Other":"clean"}'
    outside = '{"Msg":"clean","Other":"has needle here"}'
    whole = '{"Msg":"alpha beta gamma"}'
    fired = sagan(rules, [event(inside), event(outside), event(whole)])

    def hit(sid: int, body: str) -> bool:
        return str(sid) in fired.get(body, set())

    report.check("json_map redirects content to the key", hit(4001, inside), True)
    report.check("json_map ignores the rest of the body", hit(4001, outside), False)
    report.check("without json_map content reads the raw body", hit(4002, inside), True)
    report.check("without json_map any key matches", hit(4002, outside), True)

    report.check("json_content matches the whole value", hit(4003, whole), True)
    report.check("json_content is not a prefix search", hit(4004, whole), False)
    report.check("json_content is not a substring search", hit(4005, whole), False)
    report.check("json_content is case sensitive", hit(4006, whole), False)


def check_pass(report: Report) -> None:
    rules = [
        rule(4100, 'program: sshd; content:"ignore me"', action="pass"),
        rule(4101, 'program: sshd; content:"ignore"'),
    ]
    probe = "ignore me please"
    fired = sagan(rules, [event(probe)])
    report.check(
        "a pass rule emits its own alert", "4100" in fired.get(probe, set()), True
    )
    report.check(
        "and short-circuits what follows", "4101" in fired.get(probe, set()), False
    )


def check_country(report: Report) -> None:
    isnot = rule(
        4200,
        'program: sshd; content:"geo"; parse_src_ip: 1; '
        "country_code: track by_src, isnot $HOME_COUNTRY",
    )
    is_in = rule(
        4201,
        'program: sshd; content:"geo"; parse_src_ip: 1; '
        "country_code: track by_src, is RU,CN",
    )
    probes = {
        "private": "geo from 10.0.0.1 rfc1918",
        "absent": "geo from 198.51.100.7 notindb",
        "outside": "geo from 5.5.5.5 russia",
        "inside": "geo from 8.8.8.8 usa",
    }
    fired = sagan([isnot, is_in], [event(v) for v in probes.values()])

    def hit(sid: int, key: str) -> bool:
        return str(sid) in fired.get(probes[key], set())

    # $HOME_COUNTRY is US,CA in the lab config.
    report.check(
        "isnot is silent on an unplaceable private address", hit(4200, "private"), False
    )
    report.check(
        "isnot is silent on an address absent from the db", hit(4200, "absent"), False
    )
    report.check(
        "isnot fires on a resolved country outside the list", hit(4200, "outside"), True
    )
    report.check(
        "isnot is silent on a country inside the list", hit(4200, "inside"), False
    )

    report.check("is fires on a country in its list", hit(4201, "outside"), True)
    report.check("is is silent on a country outside it", hit(4201, "inside"), False)
    report.check("is is silent on an unplaceable address", hit(4201, "private"), False)


def main() -> bool:
    report = Report("enrichment: json_map, json_content, pass, country_code")
    check_json(report)
    check_pass(report)
    check_country(report)
    return report.done()


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
