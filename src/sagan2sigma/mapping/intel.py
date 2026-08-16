"""Threat-intelligence handlers: ``blacklist``, ``zeek-intel`` and ``bluedot``.

All three fire when a parsed address is present in an external set of bad
addresses. ``bluedot`` is the special case: it queries a closed commercial API,
so its conversion is the project's one deliberate break from fidelity, matching
the address against open-source feeds instead (see ``handle_bluedot`` and
``docs/DESIGN-DECISIONS.md``). The other two match a feed the user already
supplies, so they are faithful to the engine's "match whatever you loaded" model.

``blacklist`` (``src/processors/blacklist.c``) reads an IP/CIDR
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


#: Bluedot IP-reputation categories the corpus uses, onto the profile's
#: per-category positional fields. A category outside this set has no feed the
#: substitution can stand in for, so the rule is refused rather than guessed.
_BLUEDOT_CATEGORIES = {
    "tor": "bluedot_tor",
    "proxy": "bluedot_proxy",
    "malicious": "bluedot_malicious",
    "honeypot": "bluedot_honeypot",
}


def _parse_bluedot(value: str) -> tuple[str, set[str], list[str]]:
    """Split a bluedot option into (lookup type, tracks, category names).

    Grammar (``src/rules.c``): ``type <kind>, track <dir>, <freshness>, <cats>``
    where freshness is ``mdate_effective_period N unit`` / ``cdate...`` / ``none``
    and everything left is a category. The freshness filter is a Bluedot-only
    recency bound with no feed-agnostic equivalent, so it is dropped, folded into
    the substitution degradation rather than reproduced.
    """
    lookup_type = ""
    tracks: set[str] = set()
    categories: list[str] = []
    for raw in value.split(","):
        token = raw.strip()
        low = token.lower()
        if low.startswith("type"):
            parts = token.split(None, 1)
            lookup_type = parts[1].strip().lower() if len(parts) > 1 else ""
        elif low.startswith("track"):
            tracks |= {d for d in _ADDRESS_TRACKS if d in low}
        elif low == "none" or low.startswith(("mdate", "cdate")):
            continue
        elif token:
            categories.append(token)
    return lookup_type, tracks, categories


@handler("bluedot")
def handle_bluedot(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``bluedot: type ip_reputation, track by_src, none, Tor;`` onto a match.

    Bluedot is a closed commercial CTI source, so this is the project's one
    deliberate break from faithful conversion: the address is matched against
    open-source feeds the pipeline supplies, one per category, instead of against
    Bluedot. See ``docs/DESIGN-DECISIONS.md`` and ``D_BLUEDOT_SUBSTITUTION``. Only
    the ``ip_reputation`` lookup is reproduced; hash and URL lookups need a
    non-address enrichment table and stay refused.
    """
    for option in rule.iter_options("bluedot"):
        if option.value is None:
            continue
        lookup_type, tracks, categories = _parse_bluedot(option.value)

        if lookup_type != "ip_reputation":
            raise Refusal(
                code=RefusalCode.EXTERNAL_ENRICHMENT,
                detail=(
                    f"bluedot type {lookup_type or '(unset)'!r} looks up a "
                    "non-address indicator (hash, URL, filename or JA3); the "
                    "substitution reproduces only ip_reputation, which maps onto "
                    "the address enrichment tables"
                ),
                keywords=("bluedot",),
            )
        if not tracks:
            raise Refusal(
                code=RefusalCode.EXTERNAL_ENRICHMENT,
                detail=f"bluedot declares no by_src/by_dst/both/all: {option.value!r}",
                keywords=("bluedot",),
            )

        internals: list[str] = []
        for name in categories:
            internal = _BLUEDOT_CATEGORIES.get(name.lower())
            if internal is None:
                raise Refusal(
                    code=RefusalCode.EXTERNAL_ENRICHMENT,
                    detail=(
                        f"bluedot category {name!r} has no open-source feed the "
                        "substitution can stand in for; only Tor, Proxy, Malicious "
                        "and Honeypot are mapped"
                    ),
                    keywords=("bluedot",),
                )
            internals.append(internal)
        if not internals:
            raise Refusal(
                code=RefusalCode.EXTERNAL_ENRICHMENT,
                detail=f"bluedot lists no category: {option.value!r}",
                keywords=("bluedot",),
            )

        _emit_bluedot(draft, context, resolver, tracks, internals)


def _emit_bluedot(
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    tracks: set[str],
    internals: list[str],
) -> None:
    """Emit an OR over every (tracked position, category) flag, or refuse."""
    fields: list[str] = []
    for position in _positions(tracks, resolver):
        if position is None:
            raise Refusal(
                code=RefusalCode.EXTERNAL_ENRICHMENT,
                detail=(
                    "bluedot tracks an address the rule did not parse; the "
                    "substitution needs the vector-enriched profile and the parsed "
                    "address (parse_src_ip / parse_dst_ip)"
                ),
                keywords=("bluedot",),
            )
        for internal in internals:
            field = context.profile.positional_field(internal, position)
            if field is None:
                raise Refusal(
                    code=RefusalCode.EXTERNAL_ENRICHMENT,
                    detail=(
                        "bluedot substitution needs the vector-enriched profile, "
                        "which supplies the per-category address flags"
                    ),
                    keywords=("bluedot",),
                )
            fields.append(field)

    fields = list(dict.fromkeys(fields))
    if len(fields) == 1:
        draft.add(
            Predicate(field=fields[0], modifiers=(), values=(True,), origin="bluedot")
        )
    else:
        # Any listed category on any tracked address fires: a disjunction.
        blocks = {
            f"bluedot_hit_{index}": {field: True}
            for index, field in enumerate(fields, 1)
        }
        draft.condition_groups.append(
            ConditionGroup(blocks=blocks, condition=" or ".join(blocks))
        )

    draft.degrade(
        Degradation(
            code=DegradationCode.BLUEDOT_SUBSTITUTION,
            detail=(
                f"bluedot is matched against {', '.join(fields)}, set by the "
                "bundled sagan-bluedot.vrl from open-source feeds you supply, one "
                "per category, instead of Quadrant's closed Bluedot API. The rule "
                "fires on your feeds, not on Bluedot; Tor is near-authoritative, "
                "the other categories diverge. Bluedot's effective-period recency "
                "filter is not reproduced"
            ),
        )
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
