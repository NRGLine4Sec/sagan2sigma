"""The country of an address a rule binds by name, rather than of any address.

`json_map: "src_ip", ".ClientIP"` makes the engine resolve the country of that
key's value and of nothing else. Measured on the engine: with the key absent the
rule does not fire even when the message carries an address, and with the key
set it follows the key against a different address in the text.

A converted rule therefore has to test the country of that key. The pipeline
does not produce one for a bound key on its own, so the emitted configuration
carries a generated lookup; these tests pin the two halves to the same name.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_rule

from sagan2sigma.emit.vector import country_lookups, pipeline_transforms
from sagan2sigma.errors import Refusal
from sagan2sigma.mapping.geoip import country_field_for


def fields(raw: str, profile: str = "vector-enriched") -> set[str]:
    """Every detection field of a rule converted under ``profile``."""
    from tests.differential.test_differential import context

    from sagan2sigma.converter import Converter

    draft = Converter(context=context(profile)).convert_rule(make_rule(raw))
    return {predicate.field for predicate in draft.predicates}


BOUND = (
    'msg:"t"; program: p; json_content:".Operation","UserLoggedIn"; '
    'json_map: "src_ip", ".ClientIP"; country_code: track by_src, isnot US;'
)


class TestTheFieldTested:
    def test_the_country_of_the_bound_key(self) -> None:
        assert "ClientIP_country" in fields(f"{BOUND} sid:1;")

    def test_not_the_country_of_a_parsed_address(self) -> None:
        """Those describe whatever addresses the text carried, in order."""
        assert not {
            field
            for field in fields(f"{BOUND} sid:1;")
            if field.startswith("sagan_geoip_country_")
        }

    def test_a_positional_rule_still_uses_the_parsed_country(self) -> None:
        """The parsed country is named per position, not once.

        `parse_src_ip: 1` means the first address in the text, so the field is
        the one the profile gives that position.
        """
        raw = (
            'msg:"t"; program: p; content:"x"; parse_src_ip: 1; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        assert "sagan_geoip_country_1" in fields(raw)

    def test_a_bracketed_key_is_refused(self) -> None:
        """The engine stores `[]` as part of the name, so no document has it."""
        raw = (
            'msg:"t"; program: p; json_content:".Op","x"; '
            'json_map: "src_ip", ".Session.Connections[].Address"; '
            "country_code: track by_src, isnot US; sid:1;"
        )
        with pytest.raises(Refusal, match="array marker"):
            fields(raw)

    def test_the_plain_profile_still_refuses(self) -> None:
        """Only the enriched pipeline resolves a country at all."""
        with pytest.raises(Refusal, match="GeoIP country field"):
            fields(f"{BOUND} sid:1;", profile="rsigma-syslog")


class TestTheGeneratedLookup:
    def test_it_sets_the_field_the_rule_tests(self) -> None:
        text = country_lookups({"ClientIP"})
        assert f".{country_field_for('ClientIP')} = code" in text

    def test_a_nested_key_keeps_its_path(self) -> None:
        text = country_lookups({"client.ipAddress"})
        assert "string(.client.ipAddress)" in text
        assert ".client.ipAddress_country = code" in text

    def test_each_key_is_looked_up_once(self) -> None:
        text = country_lookups({"ClientIP", "srcip"})
        assert text.count("get_enrichment_table_record") == 2

    def test_no_keys_no_transform(self) -> None:
        names = [name for name, _ in pipeline_transforms({"geoip": True})]
        assert "sagan_geoip_keys" not in names

    def test_the_transform_runs_after_geoip_and_before_username(self) -> None:
        """It shares the geoip table, and username extraction stays last."""
        order = [
            name for name, _ in pipeline_transforms({"geoip": True}, geoip_keys=True)
        ]
        assert order.index("sagan_geoip") < order.index("sagan_geoip_keys")
        assert order[-1] == "sagan_username"
