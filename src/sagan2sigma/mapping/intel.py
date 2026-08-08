"""Threat-intelligence handlers: ``blacklist`` and ``zeek-intel``.

Both keywords fire when a parsed address is present in an external set of bad
addresses. ``blacklist`` (``src/processors/blacklist.c``) reads an IP/CIDR
denylist, for which the sample config recommends a public feed such as SANS
DShield. ``zeek-intel`` (``src/processors/zeek-intel.c``) reads a Zeek
Intelligence Framework feed; the original source it names, Critical Stack, has
closed, but a public equivalent, CriticalPathSecurity's Zeek-Intelligence-Feeds,
is maintained in the same format.

The rule keyword selects which address is tested (``src/processors/engine.c``):

* ``by_src`` / ``by_dst`` test the source or destination address;
* ``both`` tests the source or the destination (an OR);
* ``all`` tests every address parsed from the message.

Two details from the engine shape the conversion. First, ``zeek-intel``'s rule
keyword only ever tests IP indicators, even though the feed also carries domain,
hash and URL indicators, so only the address match is reproduced. Second, the
denylist processor matches IP addresses only, so a ``blacklist: by_username``
sets no flag and is inert; it is dropped and the rule converts, flagged with
``D_DENYLIST_USERNAME_INERT``.

The address forms need the feed, which is external data. Under the enriched
profile the bundled ``sagan-intel.vrl`` flags each parsed address that a feed
lists (``sagan_denylist_N`` / ``sagan_zeek_intel_N``), so the rule converts to a
match on that flag; under any other profile it is refused, recoverably.
"""

from __future__ import annotations

from ..errors import Degradation, DegradationCode, Refusal, RefusalCode
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver
from .ir import ConditionGroup, Predicate, RuleDraft
from .registry import handler
from .values import CasePolicy

#: Directions the processors act on, all address-based.
_ADDRESS_TRACKS = frozenset({"by_src", "by_dst", "both", "all"})

#: Positions sagan-parse-ip.vrl exposes, so ``all`` tests each of them.
_MAX_POSITIONS = 5


def _tracks(value: str) -> set[str]:
    """Tracking tokens declared on an option, lower-cased."""
    return {token.strip().lower() for token in value.split(",") if token.strip()}


def _positions(tracks: set[str], resolver: FieldResolver) -> list[int | None]:
    """Address positions a set of tracks selects, in a stable order.

    ``all`` selects every parsed position; the directional forms select the
    position ``parse_src_ip`` / ``parse_dst_ip`` declared, which is ``None`` when
    the rule did not parse that address.
    """
    if "all" in tracks:
        return list(range(1, _MAX_POSITIONS + 1))
    positions: list[int | None] = []
    if tracks & {"by_src", "both"}:
        positions.append(resolver.positions.get("src_ip"))
    if tracks & {"by_dst", "both"}:
        positions.append(resolver.positions.get("dest_ip"))
    return positions


def _emit_match(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    tracks: set[str],
    internal: str,
    keyword: str,
    degradation: DegradationCode,
    feed: str,
) -> None:
    """Emit the flag match for one intel option, refusing if unresolvable."""
    fields: list[str] = []
    for position in _positions(tracks, resolver):
        field = (
            context.profile.positional_field(internal, position)
            if position is not None
            else None
        )
        if field is None:
            raise Refusal(
                code=RefusalCode.EXTERNAL_ENRICHMENT,
                detail=(
                    f"{keyword} matches the address against an external feed "
                    f"({feed}); that needs the vector-enriched profile and the "
                    f"parsed address it tracks. Convert with --profile "
                    f"vector-enriched and build the feed into the enrichment table"
                ),
                keywords=(keyword,),
            )
        fields.append(field)

    fields = list(dict.fromkeys(fields))
    if len(fields) == 1:
        draft.add(
            Predicate(field=fields[0], modifiers=(), values=(True,), origin=keyword)
        )
    else:
        # `both` and `all` are a disjunction: any listed address fires.
        blocks = {
            f"{internal}_hit_{index}": {field: True}
            for index, field in enumerate(fields, 1)
        }
        draft.condition_groups.append(
            ConditionGroup(
                blocks=blocks,
                condition=" or ".join(blocks),
            )
        )

    draft.degrade(
        Degradation(
            code=degradation,
            detail=(
                f"{keyword} is matched against {', '.join(fields)}, set by the "
                f"bundled intel transform from a feed such as {feed}; it requires "
                f"that transform and its data to run in the pipeline"
            ),
        )
    )


@handler("blacklist")
def handle_blacklist(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``blacklist: by_src;`` matches an IP denylist; ``by_username`` is inert."""
    for option in rule.iter_options("blacklist"):
        if option.value is None:
            continue
        tracks = _tracks(option.value)
        if not tracks & _ADDRESS_TRACKS:
            # by_username, or tokens the engine does not act on: the denylist
            # processor matches IP addresses only, so this option changes nothing.
            draft.degrade(
                Degradation(
                    code=DegradationCode.DENYLIST_USERNAME_INERT,
                    detail=(
                        "blacklist tracked by_username, which the engine's "
                        "denylist processor ignores (it matches IP addresses "
                        "only); the inert option was dropped and the rest "
                        "converted"
                    ),
                )
            )
            continue
        _emit_match(
            rule,
            draft,
            context,
            resolver,
            tracks,
            "denylist",
            "blacklist",
            DegradationCode.DENYLIST_ENRICHMENT,
            "SANS DShield",
        )


@handler("zeek-intel", "bro-intel")
def handle_zeek_intel(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``zeek-intel: by_src;`` matches the address against a Zeek Intel feed."""
    for keyword in ("zeek-intel", "bro-intel"):
        for option in rule.iter_options(keyword):
            if option.value is None:
                continue
            tracks = _tracks(option.value) & _ADDRESS_TRACKS
            if not tracks:
                raise Refusal(
                    code=RefusalCode.EXTERNAL_ENRICHMENT,
                    detail=f"unrecognised {keyword} tracking: {option.value!r}",
                    keywords=(keyword,),
                )
            _emit_match(
                rule,
                draft,
                context,
                resolver,
                tracks,
                "zeek_intel",
                keyword,
                DegradationCode.ZEEK_INTEL_ENRICHMENT,
                "CriticalPathSecurity Zeek-Intelligence-Feeds",
            )
