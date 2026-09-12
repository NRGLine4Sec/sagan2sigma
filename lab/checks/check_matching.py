#!/usr/bin/env python3
"""Case sensitivity, modifier scope, negation, hex escapes, program selectors.

These decide what every emitted predicate looks like, so they are the checks
with the widest blast radius. Case handling alone shapes roughly 7,600 rules of
the upstream corpus: Sagan compares case-sensitively and `nocase` turns that
off, while Sigma is case-insensitive by default and `|cased` turns it on, so a
converter that copies the flag across instead of inverting it silently doubles
what every rule matches.

The scope question matters just as much and is easier to get wrong: `nocase`
applies only to the `content` it follows, not to the whole rule. The converter
relies on that when it decides which predicate gets `|cased`.
"""

from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from harness import Report, event, rule, sagan  # noqa: E402


def main() -> bool:
    report = Report("matching: case, nocase scope, negation, hex, program")

    rules = [
        rule(1001, 'program: sshd; content:"AAA"; content:"BBB"; nocase'),
        rule(1002, 'program: sshd; content:"AAA"; nocase; content:"BBB"'),
        rule(1003, 'program: sshd; meta_content:"%sagan%",AAA,CCC'),
        rule(1004, 'program: sshd; meta_content:"%sagan%",AAA,CCC; meta_nocase'),
        rule(1005, 'program: sshd; content:!"ZZZ"; content:"AAA"'),
        rule(1006, 'program: sshd; content:!"AAA"; content:"BBB"'),
        rule(1007, 'program: sshd; content:"Q|41|Q"'),
        rule(1008, 'program: sshd; pcre:"/Q|41|Q/"'),
        rule(1009, 'program: sshd|httpd; content:"progtest"'),
        rule(1010, 'program: ssh*; content:"globtest"'),
        rule(1011, 'program: SSHD; content:"casetest"'),
    ]
    probes = {
        "lowA": "aaa BBB one",
        "lowB": "AAA bbb two",
        "both": "AAA BBB three",
        "qaq": "xx QAQ yy",
        "raw41": "zz41zz nought",
        "prog": "progtest here",
        "glob": "globtest here",
        "case": "casetest here",
    }
    events = [
        event(probes["lowA"]),
        event(probes["lowB"]),
        event(probes["both"]),
        event(probes["qaq"]),
        event(probes["raw41"]),
        event(probes["prog"], program="httpd"),
        event(probes["glob"], program="sshd"),
        event(probes["case"], program="sshd"),
    ]
    fired = sagan(rules, events)

    def hit(sid: int, key: str) -> bool:
        return str(sid) in fired.get(probes[key], set())

    # nocase binds to the preceding content only. In 1001 it covers BBB, so AAA
    # must still match exactly; in 1002 it covers AAA instead.
    report.check(
        "nocase after both: lowercase AAA does not match", hit(1001, "lowA"), False
    )
    report.check("nocase after both: lowercase BBB matches", hit(1001, "lowB"), True)
    report.check("nocase in between: lowercase AAA matches", hit(1002, "lowA"), True)
    report.check("nocase in between: lowercase BBB does not", hit(1002, "lowB"), False)

    report.check("meta_content is case sensitive", hit(1003, "both"), True)
    report.check("meta_content misses lowercase", hit(1003, "lowA"), False)
    report.check("meta_nocase matches lowercase", hit(1004, "lowA"), True)

    report.check("negation passes when absent", hit(1005, "both"), True)
    report.check("negation blocks when present", hit(1006, "both"), False)

    # |41| is hex for 'A' in content, and plain regex alternation in pcre: the
    # engine never hex-decodes a pcre pattern.
    report.check("content decodes |41| to A", hit(1007, "qaq"), True)
    report.check("content does not match the literal 41", hit(1007, "raw41"), False)
    report.check("pcre treats |41| as alternation", hit(1008, "raw41"), True)

    report.check("program alternatives", hit(1009, "prog"), True)
    report.check("program glob", hit(1010, "glob"), True)
    report.check("program is case sensitive", hit(1011, "case"), False)

    return report.done()


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
