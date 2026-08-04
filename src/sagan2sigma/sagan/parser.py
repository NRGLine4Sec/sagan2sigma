"""Parser for Sagan ``.rules`` files.

The grammar is Snort's, which Sagan reuses verbatim::

    <action> <proto> <src> <sport> <direction> <dst> <dport> ( <options> )

The option block is a sequence of ``name: value;`` entries and bare ``name;``
flags.

**Tokenisation follows the engine, not intuition.** Sagan splits the option
block with a plain ``strtok_r(rulestring, ";", ...)`` (``src/rules.c``), with no
quote tracking at all, and only then applies ``Between_Quotes()`` to each token.
A literal semicolon therefore cannot appear inside a Sagan value: it has to be
hex-encoded as ``|3b|``, which is exactly why the upstream corpus contains none.

An earlier revision of this parser tracked quote state across the whole line,
which is *more* correct in the abstract but diverges from the engine in
practice: roughly 175 rules of the upstream corpus carry an odd number of double
quotes, usually a stray quote inside a JSON key such as
``json_meta_content:!".properties".deviceDetail",...``. Sagan parses those rules
without complaint because it never tracks quotes globally; a quote-aware lexer
desynchronises on them and loses the rest of the line. Matching the engine is
both simpler and more faithful.

The parser is deliberately forgiving: a malformed line yields a
:class:`~sagan2sigma.sagan.model.ParseFailure` instead of raising, so that one
damaged file does not abort conversion of the whole corpus.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from .model import Header, Option, ParseFailure, RuleFile, SaganRule

_HEADER = re.compile(
    r"^\s*(?P<action>alert|drop|pass)\s+"
    r"(?P<protocol>\S+)\s+"
    r"(?P<source>\S+)\s+(?P<source_port>\S+)\s+"
    r"(?P<direction><>|->|<-)\s+"
    r"(?P<destination>\S+)\s+(?P<destination_port>\S+)\s*"
    r"\(",
    re.IGNORECASE,
)

_DISABLED = re.compile(r"^\s*#\s*(alert|drop|pass)\s", re.IGNORECASE)


class LexError(ValueError):
    """The option block could not be split."""


def split_options(block: str) -> list[str]:
    """Split an option block on semicolons, exactly as the engine does.

    Sagan runs ``strtok_r`` on ``";"`` with no quote awareness, so this is a
    plain split. See the module docstring for why matching that behaviour is a
    deliberate choice rather than a shortcut.

    >>> split_options('msg:"hello"; sid:1;')
    ['msg:"hello"', 'sid:1']
    >>> split_options('nocase; content:"x"')
    ['nocase', 'content:"x"']
    >>> split_options('json_content:!".a".b","x"; sid:2;')
    ['json_content:!".a".b","x"', 'sid:2']
    """
    return [part.strip() for part in block.split(";") if part.strip()]


def find_options_block(line: str, open_paren: int) -> tuple[str, int]:
    """Return the option block body and the index of its closing parenthesis.

    The block runs from the first ``(`` of the header to the last ``)`` of the
    line, which is what Sagan itself uses. Parentheses inside values are
    therefore harmless.

    >>> line = 'alert any any any -> any any (msg:"a(b)"; sid:1;)'
    >>> find_options_block(line, line.index('('))[0]
    'msg:"a(b)"; sid:1;'
    """
    close_paren = line.rfind(")")
    if close_paren <= open_paren:
        raise LexError("missing closing parenthesis")
    return line[open_paren + 1 : close_paren], close_paren


def parse_option(text: str, index: int) -> Option:
    """Parse a single option.

    >>> parse_option('content:"x"', 0)
    Option(name='content', value='"x"', index=0)
    >>> parse_option('nocase', 3)
    Option(name='nocase', value=None, index=3)
    """
    if ":" not in text:
        return Option(name=text.strip().lower(), value=None, index=index)
    name, value = text.split(":", 1)
    return Option(name=name.strip().lower(), value=value.strip(), index=index)


def parse_rule(line: str, source_file: str, line_number: int) -> SaganRule:
    """Parse one complete rule line.

    Raises :class:`LexError` when the header or the option block is malformed.
    """
    match = _HEADER.match(line)
    if match is None:
        raise LexError("unrecognised rule header")

    open_paren = match.end() - 1
    block, _ = find_options_block(line, open_paren)

    options = tuple(
        parse_option(text, position)
        for position, text in enumerate(split_options(block))
    )
    if not options:
        raise LexError("empty option block")

    header = Header(
        action=match.group("action").lower(),
        protocol=match.group("protocol"),
        source=match.group("source"),
        source_port=match.group("source_port"),
        direction=match.group("direction"),
        destination=match.group("destination"),
        destination_port=match.group("destination_port"),
    )
    return SaganRule(
        header=header,
        options=options,
        source_file=source_file,
        line_number=line_number,
        raw=line.rstrip("\n"),
    )


def parse_lines(
    lines: Iterable[str], source_file: str
) -> tuple[list[SaganRule], list[ParseFailure], int]:
    """Parse a stream of lines, counting commented-out rules along the way."""
    rules: list[SaganRule] = []
    failures: list[ParseFailure] = []
    disabled = 0

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if _DISABLED.match(stripped):
            disabled += 1
            continue
        if stripped.startswith("#"):
            continue
        if not _HEADER.match(stripped):
            continue
        try:
            rules.append(parse_rule(stripped, source_file, line_number))
        except LexError as error:
            failures.append(
                ParseFailure(
                    source_file=source_file,
                    line_number=line_number,
                    raw=stripped,
                    reason=str(error),
                )
            )
    return rules, failures, disabled


def parse_file(path: Path) -> RuleFile:
    """Parse one ``.rules`` file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    rules, failures, disabled = parse_lines(text.splitlines(), path.name)
    return RuleFile(path=str(path), rules=rules, failures=failures, disabled=disabled)


def iter_rule_files(root: Path) -> Iterator[Path]:
    """Iterate ``.rules`` files under a path, in a stable order."""
    if root.is_file():
        yield root
        return
    yield from sorted(root.glob("*.rules"))
