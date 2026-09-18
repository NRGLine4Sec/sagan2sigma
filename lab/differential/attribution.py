"""Which probe a Sagan alert belongs to.

Every differential in this directory sends a batch of probes to the engine and
has to tie each alert back to the probe that caused it. That sounds like a
dictionary lookup and is not: the engine rewrites what it logs, three times over,
and each rewrite was found by a run that reported a pile of disagreements which
turned out to be the tool's own.

The three, each measured rather than reasoned about:

``the program is part of the key``
    A rule's ``base`` and ``wrong_program`` probes carry the same text and differ
    only in the program. Keying on the message alone credits the second with the
    first's alert, so every rule carrying a ``program`` reads as disagreeing.

``append_program rewrites the message``
    The keyword makes the engine log the message with `` | <program>`` appended,
    so the text it writes is not the text that was sent. Measured: an event sent
    as ``%ASA-1-216001 ~ %ASA`` is logged as ``%ASA-1-216001 ~ %ASA | syslog``.
    75 corpus rules carry it.

``json_map "program" rewrites the program``
    The mapping replaces the syslog program with a value taken from the body,
    and Sagan logs that instead of the program that was sent. Measured both
    ways: a document carrying the wanted value fires whatever the syslog program
    says, one carrying another value stays silent even when the syslog program
    is right, and an absent key leaves the condition unsatisfiable. sid 5005158
    is sent as ``syslog`` and logged as ``SharePoint``. For those rules the
    message alone is the key, which loses nothing: no two probes of such a rule
    can be told apart by a program the body overrides anyway.

This module exists because the second tool to need all three rediscovered them
one failed run at a time, having not read the first. A shared index is the only
way the third will not.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any


class AlertIndex:
    """The alerts of one engine run, answering "did this rule fire on this probe".

    Built from the rows :func:`harness.alerts` returns, each a mapping with at
    least ``sid``, ``message`` and, where the engine reported one, ``program``.
    """

    __slots__ = ("_by_message", "_by_pair")

    def __init__(self, rows: Iterable[Mapping[str, str]]) -> None:
        self._by_pair: dict[tuple[str, str], set[str]] = defaultdict(set)
        self._by_message: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            self._by_pair[(row.get("program", ""), row["message"])].add(row["sid"])
            self._by_message[row["message"]].add(row["sid"])

    def fired(self, rule: Any, program: str, body: str) -> bool:
        """Whether ``rule`` alerted on the probe sent as ``program`` and ``body``.

        ``rule`` is a parsed Sagan rule, consulted for the two keywords that
        make the engine log something other than what was sent.
        """
        if _maps_program(rule):
            return rule.sid in self._by_message.get(body, set())
        if rule.sid in self._by_pair.get((program, body), set()):
            return True
        if rule.has("append_program"):
            return rule.sid in self._by_pair.get(
                (program, f"{body} | {program}"), set()
            )
        return False


def _maps_program(rule: Any) -> bool:
    """Whether the rule binds its program to a JSON key.

    Read from the rule rather than imported from the reference evaluator: this
    module is used by the tool that judges that evaluator, and a shared helper
    would let the two agree about a mapping neither had checked.
    """
    for option in rule.iter_options("json_map"):
        if option.value is None:
            continue
        name = option.value.split(",", 1)[0].strip().strip('"').lower()
        if name == "program":
            return True
    return False
