"""The ``country_code`` handler: GeoIP country matching through Vector.

Sagan's ``country_code`` looks up the country of an address in a MaxMind
database and fires on membership, or non-membership, of a user list. The engine
reference is ``src/geoip.c`` (``GeoIP2_Lookup_Country`` and the ``strcmp`` loop
over the user codes) and ``src/processors/engine.c`` around line 1055, which
sets the routing flag:

* ``track by_src`` / ``by_dst`` selects the source or destination address;
* ``is`` fires when the looked-up country is in the list, ``isnot`` when it is
  not; and, crucially, ``isnot`` requires only that the address be **present**.
  A private or unresolved address yields no country, which is "not in the list",
  so Sagan fires on it. The converted rule reproduces that by keying the
  presence test on the address field, not on the country field.

There is no field to match until an ingestion pipeline has both extracted the
address and enriched it with a country. That is exactly what the
``vector-enriched`` profile and the bundled ``sagan-geoip.vrl`` transform
provide, so the rule converts under that profile and is refused, recoverably,
under any other. The address it enriches is the one ``parse_src_ip`` /
``parse_dst_ip`` selected, so the country field follows the same position.
"""

from __future__ import annotations

import re

from ..errors import Degradation, DegradationCode, Refusal, RefusalCode
from ..sagan.model import SaganRule
from .context import Context
from .fields import FieldResolver, json_map
from .ir import Predicate, RuleDraft
from .registry import handler
from .values import CasePolicy


def _address_can_resolve(rule: SaganRule, internal: str) -> bool:
    """Whether the engine can ever mark this rule's tracked address valid.

    ``country_code`` only geo-locates an address the engine has marked valid
    (``src/processors/engine.c``: the lookup at the ``ip_src_is_valid`` /
    ``ip_dst_is_valid`` guard). That flag is set in exactly three places: the
    ``parse_src_ip`` / ``parse_dst_ip`` cache, a ``json_map`` binding of the
    address, and ``normalize`` (liblognorm). A rule carrying none of them for the
    tracked direction never validates the address, so the lookup is skipped,
    ``geoip2_isset`` stays false, and ``src/routing.c`` drops the rule: it can
    never fire. ``normalize`` may bind either direction, so its mere presence is
    enough to keep a rule off this path.
    """
    if rule.has("normalize"):
        return True
    position_keyword = "parse_src_ip" if internal == "src_ip" else "parse_dst_ip"
    if rule.has(position_keyword):
        return True
    return internal in json_map(rule)


#: ``country_code: track by_src, isnot US,CA;``. The codes run to the end,
#: variables included, and are resolved separately.
_COUNTRY_CODE = re.compile(
    r"\s*track\s+(?P<direction>by_src|by_dst)\s*,\s*"
    r"(?P<test>is|isnot)\s+(?P<codes>.+?)\s*$"
)

#: Tracking direction onto the internal address value and its country field.
_DIRECTION = {
    "by_src": ("src_ip", "src_country"),
    "by_dst": ("dest_ip", "dest_country"),
}


def _resolve_codes(raw: str, context: Context) -> tuple[str, ...]:
    """Resolve the country-code list, expanding a ``$VARIABLE`` if present.

    Codes are kept verbatim, not upper-cased: Sagan compares the MaxMind
    country (an upper-case ISO code) against the user list with ``strcmp``, so a
    list written in another case would not match under Sagan either.
    """
    codes: list[str] = []
    for token in (part.strip() for part in raw.split(",")):
        if not token:
            continue
        if token.startswith("$"):
            expanded = context.config.expand(token)
            if expanded is None:
                raise Refusal(
                    code=RefusalCode.VAR_UNRESOLVED,
                    detail=(
                        f"variable {token} in country_code is undefined; supply "
                        f"the sagan.yaml with --sagan-yaml"
                    ),
                    keywords=("country_code",),
                )
            codes.extend(expanded)
        else:
            codes.append(token)
    if not codes:
        raise Refusal(
            code=RefusalCode.PARSE,
            detail="country_code carries no country code",
            keywords=("country_code",),
        )
    return tuple(dict.fromkeys(codes))


@handler("country_code")
def handle_country_code(
    rule: SaganRule,
    draft: RuleDraft,
    context: Context,
    resolver: FieldResolver,
    policy: CasePolicy,
) -> None:
    """``country_code: track by_src, isnot $HOME_COUNTRY;`` onto a GeoIP field."""
    for option in rule.iter_options("country_code"):
        if option.value is None:
            continue
        match = _COUNTRY_CODE.match(option.value)
        if match is None:
            raise Refusal(
                code=RefusalCode.PARSE,
                detail=f"unrecognised country_code: {option.value!r}",
                keywords=("country_code",),
            )

        internal, country_internal = _DIRECTION[match.group("direction")]

        if not _address_can_resolve(rule, internal):
            direction = match.group("direction")
            valid_flag = f"ip_{'src' if internal == 'src_ip' else 'dst'}_is_valid"
            raise Refusal(
                code=RefusalCode.NO_DETECTION,
                detail=(
                    f"country_code tracks {direction} but the rule gives {internal} "
                    "no source the engine accepts (no parse_src_ip / parse_dst_ip, "
                    f"no json_map binding, no normalize), so {valid_flag} is never "
                    "set. Sagan then skips the GeoIP lookup and routing drops the "
                    "rule, so it never fires; there is nothing faithful to emit"
                ),
                keywords=("country_code",),
            )

        position = resolver.positions.get(internal)
        country_field = (
            context.profile.positional_field(country_internal, position)
            if position is not None
            else None
        )
        ip_field = resolver.positional(internal)

        if country_field is None or ip_field is None:
            raise Refusal(
                code=RefusalCode.EXTERNAL_ENRICHMENT,
                detail=(
                    "country_code needs a GeoIP country field, which only the "
                    "vector-enriched profile supplies. Convert with --profile "
                    "vector-enriched and deploy the bundled GeoIP transform; the "
                    f"tracked address must be extracted ({internal} via "
                    "parse_src_ip / parse_dst_ip)"
                ),
                keywords=("country_code",),
            )

        codes = _resolve_codes(match.group("codes"), context)

        if match.group("test") == "is":
            # Fires when the country is in the list, which requires it present.
            draft.add(
                Predicate(
                    field=country_field,
                    modifiers=(),
                    values=codes,
                    origin="country_code",
                )
            )
        else:
            # isnot: the address must be present and its country not in the list.
            # Keying presence on the address, not the country, reproduces Sagan
            # firing on a private or unresolved address, whose country is empty.
            draft.add(
                Predicate(
                    field=ip_field,
                    modifiers=("exists",),
                    values=(True,),
                    origin="country_code",
                )
            )
            draft.add(
                Predicate(
                    field=country_field,
                    modifiers=(),
                    values=codes,
                    negated=True,
                    origin="country_code",
                )
            )

        draft.degrade(
            Degradation(
                code=DegradationCode.GEOIP_COUNTRY_ENRICHMENT,
                detail=(
                    f"country_code is resolved against {country_field}, produced "
                    f"by the bundled GeoIP transform; it requires that transform "
                    f"and its MaxMind database to run in the pipeline"
                ),
            )
        )
