"""Decoder for the hexadecimal escape sequences of the Sagan/Snort format.

Inside a ``content``, ``|22 3a 20|`` stands for the raw bytes 0x22 0x3a 0x20,
that is the string ``": "``. Sequences may repeat and be interleaved with
literal text: ``"a|3a| b |3b| c"``.

An unpaired ``|`` is left untouched: several rules in the corpus carry a
literal pipe inside a message.
"""

from __future__ import annotations

import re

_HEX_BLOCK = re.compile(r"\|([0-9A-Fa-f]{2}(?:[ \t]+[0-9A-Fa-f]{2})*)\|")


def decode_hex(value: str) -> str:
    """Replace every ``|xx xx|`` sequence with the matching characters.

    >>> decode_hex('User Agent|3a| Testing')
    'User Agent: Testing'
    >>> decode_hex('no sequence here')
    'no sequence here'
    >>> decode_hex('a|not hex|b')
    'a|not hex|b'
    >>> decode_hex('|22|mfaAuthenticated|22 3a 20 22|true|22|')
    '"mfaAuthenticated": "true"'
    """

    def _replace(match: re.Match[str]) -> str:
        return "".join(chr(int(byte, 16)) for byte in match.group(1).split())

    return _HEX_BLOCK.sub(_replace, value)


def has_hex(value: str) -> bool:
    """Report whether the value carries at least one hexadecimal sequence.

    >>> has_hex('a|3a|b'), has_hex('plain')
    (True, False)
    """
    return _HEX_BLOCK.search(value) is not None
