"""Registry of Sagan keyword handlers.

Each keyword is handled by an independent function registered through the
:func:`handler` decorator. Adding support for a keyword therefore means adding
one module and one test file, with no change to the rest of the chain.

Keywords fall into five families:

``HANDLED``
    a handler produces predicates or correlations;
``MODIFIERS``
    positional flags consumed by the handler of the preceding option
    (``nocase``, ``json_contains``), never processed on their own;
``IGNORED``
    metadata or engine-specific side effects with no bearing on whether the
    rule fires; they emit at most a degradation;
``BLOCKING``
    constructs with no Sigma equivalent, which trigger a refusal;
``UNKNOWN``
    everything else, refused with ``E_UNKNOWN_KEYWORD`` so that a new upstream
    keyword surfaces in the report instead of being silently swallowed.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ..errors import RefusalCode
from .positional import POSITIONAL_KEYWORDS

if TYPE_CHECKING:  # pragma: no cover
    from ..sagan.model import SaganRule
    from .context import Context
    from .fields import FieldResolver
    from .ir import RuleDraft
    from .values import CasePolicy

#: Handler signature: read the rule, enrich the draft.
Handler = Callable[
    ["SaganRule", "RuleDraft", "Context", "FieldResolver", "CasePolicy"], None
]

_HANDLERS: dict[str, Handler] = {}


def handler(*keywords: str) -> Callable[[Handler], Handler]:
    """Register a function as the handler for one or more keywords."""

    def decorator(function: Handler) -> Handler:
        for keyword in keywords:
            if keyword in _HANDLERS:
                raise RuntimeError(f"handler already registered for {keyword!r}")
            _HANDLERS[keyword] = function
        return function

    return decorator


def get_handler(keyword: str) -> Handler | None:
    """Handler bound to a keyword, ``None`` when there is none."""
    return _HANDLERS.get(keyword)


def registered_keywords() -> frozenset[str]:
    """Keywords covered by a handler."""
    return frozenset(_HANDLERS)


#: Positional flags, consumed by the handler of the preceding option.
MODIFIERS: frozenset[str] = frozenset(
    {
        "nocase",
        "meta_nocase",
        "json_nocase",
        "json_meta_nocase",
        "json_contains",
        "json_meta_contains",
        "json_strstr",
        "json_meta_strstr",
        "json_decode_base64",
        "json_base64_decode",
        "json_decode_base64_pcre",
        "json_base64_decode_pcre",
        "json_decode_base64_meta",
        "json_base64_decode_meta",
    }
)

#: Keywords with no bearing on detection. The boolean says whether to record a
#: degradation, that is whether Sagan does something the Sigma rule will not.
IGNORED: dict[str, bool] = {
    # Extraction and normalisation: they populate Sagan internal fields, never
    # the decision to fire.
    "normalize": False,
    "parse_src_ip": False,
    "parse_dst_ip": False,
    "parse_port": False,
    "parse_proto": False,
    "parse_proto_program": False,
    "parse_hash": False,
    "json_map": False,
    # Fallback values for the emitted alert, not filters on the input.
    "default_proto": False,
    "default_dst_port": False,
    "default_src_port": False,
    # Identifiers consumed elsewhere in the chain.
    "sid": False,
    "rev": False,
    # Engine-specific side effects.
    "external": True,
    "email": True,
    "dynamic_load": True,
    "offload": True,
    # Bit timers: they delay the state check, which Sigma cannot express.
    "xbits_pause": True,
    "xbits_upause": True,
    "flexbits_pause": True,
    "flexbits_upause": True,
}

#: Constructs with no Sigma equivalent, each with its refusal code, refused on
#: the keyword's mere presence. Positional keywords are not here: a zero-valued
#: positional is a no-op in the Sagan engine (see :mod:`.positional`), so the
#: refusal is decided on the effective value in the converter. Currently empty:
#: ``bluedot`` used to sit here but now has a handler that substitutes an
#: open-source feed for the closed API (see :mod:`.intel`).
BLOCKING: dict[str, RefusalCode] = {}


def classify(keyword: str) -> str:
    """Family of a keyword: handled, modifier, ignored, positional, blocking, unknown.

    ``positional`` keywords are inert at value zero and refused only when their
    value bites, so they are neither a plain modifier nor unconditionally
    blocking; the converter decides on the value.

    >>> classify('content'), classify('nocase'), classify('offset')
    ('handled', 'modifier', 'positional')
    >>> classify('bluedot'), classify('sid'), classify('made_up')
    ('handled', 'ignored', 'unknown')
    """
    if keyword in _HANDLERS:
        return "handled"
    if keyword in MODIFIERS:
        return "modifier"
    if keyword in IGNORED:
        return "ignored"
    if keyword in POSITIONAL_KEYWORDS:
        return "positional"
    if keyword in BLOCKING:
        return "blocking"
    return "unknown"
