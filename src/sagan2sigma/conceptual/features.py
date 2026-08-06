"""Turning a rule into the terms and techniques it is about.

A rule's *concept fingerprint* is two things: the ATT&CK techniques it declares,
and a bag of distinctive tokens drawn from its title, its description and, most
importantly, the literal strings it actually searches for. The literals matter
more than the prose: a rule looking for ``sethc.exe`` or ``win32_shadowcopy``
tells you what it detects far more precisely than a title can, and two rules
that both look for the same rare artefact are very likely about the same thing.

Nothing here weights the tokens; that is left to :mod:`.similarity`, which needs
the whole corpus to know which tokens are distinctive. This module only decides
what counts as a token, and stopwords are pruned here so that a word too generic
to ever be evidence, such as "detection" or "windows", never becomes one.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

#: Matches an ATT&CK technique tag, capturing the technique id, including a
#: sub-technique when present: ``attack.t1059.001`` yields ``t1059.001``.
TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

#: A token: an alphanumeric run that may carry the inner dots, slashes and
#: hyphens of a file name, path or command, three characters or more. A token
#: must start alphanumeric, so leading punctuation is dropped (``/etc/passwd``
#: becomes ``etc/passwd``), but ``cmd.exe`` and ``set-psreadlineoption`` stay
#: whole. What matters is that both corpora are tokenised the same way.
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/\\-]{2,}")

#: Words too generic to ever distinguish one detection from another. Inverse
#: document frequency already discounts common words, but pruning these here
#: also stops them being used to pair rules for comparison in the first place,
#: which keeps the candidate set honest rather than merely re-ranked.
STOPWORDS = frozenset(
    [
        "the",
        "and",
        "for",
        "not",
        "with",
        "without",
        "this",
        "that",
        "will",
        "would",
        "can",
        "may",
        "your",
        "you",
        "our",
        "their",
        "its",
        "from",
        "was",
        "were",
        "are",
        "being",
        "been",
        "has",
        "have",
        "had",
        "which",
        "who",
        "whom",
        "whose",
        "what",
        "when",
        "where",
        "why",
        "how",
        "all",
        "any",
        "each",
        "via",
        "using",
        "use",
        "used",
        "into",
        "onto",
        "over",
        "under",
        "out",
        "off",
        "detects",
        "detection",
        "detected",
        "detect",
        "rule",
        "rules",
        "event",
        "events",
        "log",
        "logs",
        "logging",
        "activity",
        "alert",
        "alerts",
        "possible",
        "potential",
        "suspicious",
        "suspicious",
        "malicious",
        "generic",
        "unknown",
        "attempt",
        "attempts",
        "attempted",
        "access",
        "accessed",
        "accessing",
        "new",
        "old",
        "via",
        "based",
        "within",
        "across",
        "against",
        "between",
        "about",
        "during",
        "while",
        "after",
        "before",
        "then",
        "than",
        "only",
        "also",
        "more",
        "most",
        "less",
        "least",
        "very",
        "such",
        "other",
        "another",
        "same",
        "different",
        "windows",
        "linux",
        "system",
        "application",
        "applications",
        "service",
        "services",
        "process",
        "processes",
        "user",
        "users",
        "account",
        "accounts",
        "file",
        "files",
        "command",
        "commands",
        "line",
        "lines",
    ]
)


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """What a rule is about: its techniques and its distinctive tokens."""

    key: str
    origin: str
    title: str
    source: str
    sagan_sid: str
    techniques: frozenset[str]
    tokens: Counter[str]


def extract_techniques(document: dict[str, Any]) -> frozenset[str]:
    """Every ATT&CK technique id the rule declares, sub-techniques kept whole."""
    found: set[str] = set()
    for tag in document.get("tags") or []:
        match = TECHNIQUE_RE.match(str(tag))
        if match:
            found.add(match.group(1).lower())
    return frozenset(found)


def _string_values(node: Any, into: list[str]) -> None:
    """Collect every string leaf under a detection block, skipping conditions."""
    if isinstance(node, dict):
        for name, value in node.items():
            if name == "condition":
                continue
            _string_values(value, into)
    elif isinstance(node, list):
        for item in node:
            _string_values(item, into)
    elif isinstance(node, str):
        into.append(node)


def tokenise(text: str) -> list[str]:
    """Split text into distinctive lowercased tokens, stopwords removed."""
    tokens: list[str] = []
    for raw in _TOKEN_RE.findall(text.lower()):
        token = raw.strip("._/\\-")
        if len(token) < 3 or token.isdigit() or token in STOPWORDS:
            continue
        tokens.append(token)
    return tokens


def fingerprint(
    key: str,
    origin: str,
    title: str,
    source: str,
    sagan_sid: str,
    document: dict[str, Any],
) -> Fingerprint:
    """Build the concept fingerprint for one rule.

    Title and description are included for their wording, and the literal search
    strings for what the rule actually looks for. The description is not
    doubled: it is read once, since repeating it would let a verbose description
    outweigh the detection content it is meant only to explain.
    """
    literals: list[str] = []
    _string_values(document.get("detection", {}), literals)
    text = " ".join([title, str(document.get("description", "")), *literals])
    return Fingerprint(
        key=key,
        origin=origin,
        title=title,
        source=source,
        sagan_sid=sagan_sid,
        techniques=extract_techniques(document),
        tokens=Counter(tokenise(text)),
    )
