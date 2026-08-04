"""Metadata handlers: ``msg``, ``classtype``, ``reference`` and ``metadata``.

These keywords do not affect firing, but they carry most of a rule's
documentary value: title, severity, references and ATT&CK mapping.
"""

from __future__ import annotations

import re

from ..errors import Refusal, RefusalCode
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import RuleDraft
from .registry import handler
from .values import CasePolicy, strip_quotes

_TECHNIQUE = re.compile(r"mitre_technique_id\s+(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_TACTIC = re.compile(r"mitre_tactic_id\s+(TA\d{4})", re.IGNORECASE)

#: Maximum Sigma title length mandated by the specification.
TITLE_MAX = 256


@handler("msg")
def handle_msg(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``msg: "Invalid Password";`` onto ``title``."""
    raw = rule.first("msg")
    if raw is None:
        raise Refusal(
            code=RefusalCode.PARSE,
            detail="rule has no msg, so there is no usable title",
            keywords=("msg",),
        )
    _, text = strip_quotes(raw)
    text = " ".join(text.split())
    if not text:
        raise Refusal(code=RefusalCode.PARSE, detail="empty msg", keywords=("msg",))
    draft.title = text[:TITLE_MAX]


@handler("classtype")
def handle_classtype(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``classtype: exploit-attempt;`` onto ``level`` plus a traceability tag.

    The mapping goes through ``classification.config``, which assigns a
    priority from 1 to 4 to each classtype. The classtype itself is kept as a
    tag: it is the only way to recover the original intent, ``level`` being far
    coarser.
    """
    classtype = rule.first("classtype")
    if classtype is None:
        return
    classtype = classtype.strip().lower()
    draft.set_level(context.config.level_for(classtype))
    draft.tags.add(f"sagan.classtype.{classtype}")


@handler("reference")
def handle_reference(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``reference: url,example.org/x;`` onto ``references``."""
    for option in rule.iter_options("reference"):
        if option.value is None:
            continue
        parts = option.value.split(",", 1)
        if len(parts) != 2:
            continue
        url = context.config.reference_url(parts[0], parts[1])
        if url and url not in draft.references:
            draft.references.append(url)


@handler("metadata")
def handle_metadata(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``metadata: mitre_technique_id T1059;`` onto ``tags: [attack.t1059]``.

    Only ATT&CK identifiers are promoted to tags: they are the sole Sagan
    metadata Sigma has a normalised representation for. The remaining keys
    (``created_at``, ``deployment``, ``affected_product``) are preserved
    verbatim in ``custom_attributes`` so that nothing is lost.
    """
    extras: list[str] = []
    for option in rule.iter_options("metadata"):
        if option.value is None:
            continue
        for technique in _TECHNIQUE.findall(option.value):
            draft.tags.add(f"attack.{technique.lower()}")
        for tactic in _TACTIC.findall(option.value):
            draft.tags.add(f"attack.{tactic.lower()}")
        cleaned = _TECHNIQUE.sub("", _TACTIC.sub("", option.value))
        for chunk in cleaned.split(","):
            chunk = " ".join(chunk.split())
            if not chunk or " " not in chunk:
                continue
            key, _, value = chunk.partition(" ")
            if value.strip().upper() not in ("", "NONE"):
                extras.append(f"{key}={value.strip()}")
    if extras:
        draft.custom_attributes["sagan.metadata"] = ",".join(dict.fromkeys(extras))
