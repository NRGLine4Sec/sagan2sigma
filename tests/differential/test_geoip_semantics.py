"""Does a converted ``country_code`` rule fire when Sagan's GeoIP lookup would?

Another family the main differential cannot reach. `sagan_reference.py` does not
model external enrichment, so `country_code` was only ever checked by asserting
the shape of the emitted predicates, against a belief about the engine. The
belief was wrong, in the direction that matters: the converted rule fired on
every RFC1918 address, where Sagan is silent, which on a rule reading "connection
from outside $HOME_COUNTRY" means firing on all internal traffic.

The engine's contract, from ``src/geoip.c`` and ``src/processors/engine.c``:

* ``GeoIP2_Lookup_Country`` returns ``GEOIP_SKIP`` from every path that cannot
  determine a country, which is a non-routable address, one in the configured
  ``skip_networks``, a lookup failure, and an address the database does not
  carry;
* ``GEOIP_HIT`` when the resolved country is in the rule's list, ``GEOIP_MISS``
  when it is not;
* ``engine.c`` compares only when the result is not ``GEOIP_SKIP``, so on a skip
  ``geoip2_isset`` stays false and ``routing.c`` drops the rule.

So both ``is`` and ``isnot`` require a country to have been resolved, and the
four cases below are the whole truth table. They are asserted against the real
engine on the document the converter actually emits, because that is the level
at which the defect existed: the predicates looked reasonable in isolation.

Skipped when ``rsigma`` is not on PATH; CI runs it in the differential job.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from sagan2sigma.converter import Converter
from sagan2sigma.emit.yaml_io import dump_collection
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.sagan.config import SaganConfig

RSIGMA = shutil.which("rsigma")

pytestmark = pytest.mark.skipif(
    RSIGMA is None,
    reason="build rsigma and put it on PATH to run the geoip semantics differential",
)

#: The address the rule parses, and the country field the transform fills for it.
IP_FIELD = "sagan_ip_1"
COUNTRY_FIELD = "sagan_geoip_country_1"


def converted(option: str) -> Path:
    """Convert one country_code rule and write the emitted document to disk."""
    context = Context(
        profile=load_profile("vector-enriched"),
        config=SaganConfig(variables={"HOME_COUNTRY": ["US", "CA"]}),
        catalog=load_catalog(),
    )
    line = (
        'alert any any any -> any any (msg:"[TEST] country"; program: sshd; '
        f'content:"x"; parse_src_ip: 1; {option}; '
        "classtype: suspicious-login; sid:9100001; rev:1;)"
    )
    directory = Path(tempfile.mkdtemp())
    source = directory / "t.rules"
    source.write_text(line + "\n", encoding="utf-8")
    result = Converter(context=context).convert_paths([source])
    assert result.documents, f"the rule did not convert: {result.refused}"
    rules = directory / "rule.yml"
    rules.write_text(dump_collection(result.documents), encoding="utf-8")
    return rules


def fires(rules: Path, event: dict[str, object]) -> bool:
    """Whether the real engine reports a match."""
    completed = subprocess.run(
        [
            str(RSIGMA),
            "engine",
            "eval",
            "--rules",
            str(rules),
            "--event",
            json.dumps({"appname": "sshd", "message": "x", **event}),
            "--output-format",
            "ndjson",
            "--no-stats",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return any(
        line.strip().startswith("{") and "rule_title" in line
        for line in completed.stdout.splitlines()
    )


#: (label, event, does Sagan fire). The country field is absent exactly when the
#: engine would have returned GEOIP_SKIP, which is what sagan-geoip.vrl produces:
#: it sets the field only on a successful lookup.
ISNOT_CASES = [
    ("private address, no country resolved (SKIP)", {IP_FIELD: "10.0.0.1"}, False),
    (
        "public address absent from the database (SKIP)",
        {IP_FIELD: "203.0.113.9"},
        False,
    ),
    (
        "public address outside the list (MISS)",
        {IP_FIELD: "5.5.5.5", COUNTRY_FIELD: "RU"},
        True,
    ),
    (
        "public address inside the list (HIT)",
        {IP_FIELD: "8.8.8.8", COUNTRY_FIELD: "US"},
        False,
    ),
]

IS_CASES = [
    ("private address, no country resolved (SKIP)", {IP_FIELD: "10.0.0.1"}, False),
    (
        "public address inside the list (HIT)",
        {IP_FIELD: "5.5.5.5", COUNTRY_FIELD: "RU"},
        True,
    ),
    (
        "public address outside the list (MISS)",
        {IP_FIELD: "8.8.8.8", COUNTRY_FIELD: "US"},
        False,
    ),
]


@pytest.mark.parametrize(("label", "event", "expected"), ISNOT_CASES)
def test_isnot_matches_the_engine(
    label: str, event: dict[str, object], expected: bool
) -> None:
    """Isnot fires only on a country that was resolved and is not listed."""
    rules = converted("country_code: track by_src, isnot $HOME_COUNTRY")
    assert fires(rules, event) is expected, label


@pytest.mark.parametrize(("label", "event", "expected"), IS_CASES)
def test_is_matches_the_engine(
    label: str, event: dict[str, object], expected: bool
) -> None:
    """Is fires only on a country that was resolved and is listed."""
    rules = converted("country_code: track by_src, is RU,CN")
    assert fires(rules, event) is expected, label


def test_an_unplaceable_address_is_silent_for_both_tests() -> None:
    """The regression this module exists for, stated once on its own.

    An address the pipeline could not place must fire neither form. Before the
    fix, isnot fired here, so every rule of the "connection from outside
    $HOME_COUNTRY" family alerted on all RFC1918 traffic.
    """
    internal = {IP_FIELD: "192.168.1.50"}
    isnot_rule = converted("country_code: track by_src, isnot $HOME_COUNTRY")
    is_rule = converted("country_code: track by_src, is RU,CN")
    assert not fires(isnot_rule, internal)
    assert not fires(is_rule, internal)
