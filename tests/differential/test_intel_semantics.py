"""Do converted threat-intel rules fire when the engine's lookups would?

The third and last family the main differential cannot reach.
``sagan_reference.py`` models no external enrichment, so ``blacklist``,
``zeek-intel`` and ``bluedot`` were checked only by asserting the shape of the
emitted predicates. That is precisely how the ``country_code`` defect survived:
predicates that look reasonable in isolation, resting on a belief about the
engine that nobody executed.

These three are structurally safer than ``country_code`` was, and the reason is
worth stating. They carry no negated form: a rule fires when an address is
*found* on a feed, so an address the pipeline could not enrich leaves the flag
unset and the rule silent, which is what the engine does too. There is no
"absence means match" trap of the kind that made every RFC1918 address fire.

What the engine does that a bare reading misses is ``both``. Every ``both``
branch in ``src/processors/engine.c`` is gated on
``ip_src_is_valid == true && ip_dst_is_valid == true``, so an event carrying
only one of the two addresses is not tested at all, even when that address is
listed. The converter used to emit a plain disjunction and would have fired.
No corpus rule uses ``both``, so nothing shipped wrong, but the tests below pin
the corrected behaviour rather than leaving it to be rediscovered.

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
    reason="build rsigma and put it on PATH to run the intel semantics differential",
)


def converted(options: str) -> Path:
    """Convert one rule carrying ``options`` and write the emitted document."""
    context = Context(
        profile=load_profile("vector-enriched"),
        config=SaganConfig(),
        catalog=load_catalog(),
    )
    line = (
        'alert any any any -> any any (msg:"[TEST] intel"; program: sshd; '
        f'content:"x"; {options}; classtype: trojan-activity; sid:9200001; rev:1;)'
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


#: keyword, the option that tracks the source address, and the flag the bundled
#: transform sets for the first parsed address.
FAMILIES = [
    ("blacklist", "parse_src_ip: 1; blacklist: by_src", "sagan_denylist_1"),
    ("zeek-intel", "parse_src_ip: 1; zeek-intel: by_src", "sagan_zeek_intel_1"),
    (
        "bluedot",
        "parse_src_ip: 1; bluedot: type ip_reputation, track by_src, none, Tor",
        "sagan_bluedot_tor_1",
    ),
]


@pytest.mark.parametrize(("name", "options", "flag"), FAMILIES)
def test_a_listed_address_fires(name: str, options: str, flag: str) -> None:
    rules = converted(options)
    assert fires(rules, {"sagan_ip_1": "203.0.113.7", flag: True}), name


@pytest.mark.parametrize(("name", "options", "flag"), FAMILIES)
def test_an_unlisted_address_is_silent(name: str, options: str, flag: str) -> None:
    """The feed said no, so the flag is unset and the rule must not fire."""
    rules = converted(options)
    assert not fires(rules, {"sagan_ip_1": "203.0.113.7"}), name


@pytest.mark.parametrize(("name", "options", "flag"), FAMILIES)
def test_an_absent_address_is_silent(name: str, options: str, flag: str) -> None:
    """No address parsed means the engine never runs the lookup either."""
    rules = converted(options)
    assert not fires(rules, {}), name


class TestBluedotCategories:
    """bluedot matches a set of categories, and only the ones the rule lists."""

    OPTIONS = (
        "parse_src_ip: 1; bluedot: type ip_reputation, track by_src, none, "
        "Malicious,Tor"
    )

    def test_either_listed_category_fires(self) -> None:
        rules = converted(self.OPTIONS)
        assert fires(rules, {"sagan_ip_1": "5.5.5.5", "sagan_bluedot_tor_1": True})
        assert fires(
            rules, {"sagan_ip_1": "5.5.5.5", "sagan_bluedot_malicious_1": True}
        )

    def test_an_unlisted_category_does_not_fire(self) -> None:
        """The engine compares the returned category against the rule's list."""
        rules = converted(self.OPTIONS)
        assert not fires(
            rules, {"sagan_ip_1": "5.5.5.5", "sagan_bluedot_proxy_1": True}
        )


class TestBothRequiresTwoAddresses:
    """``both`` is gated on both addresses being valid, not just either being listed."""

    OPTIONS = "parse_src_ip: 1; parse_dst_ip: 2; blacklist: both"

    def test_fires_when_both_are_present_and_one_is_listed(self) -> None:
        rules = converted(self.OPTIONS)
        event = {
            "sagan_ip_1": "203.0.113.7",
            "sagan_ip_2": "198.51.100.9",
            "sagan_denylist_1": True,
        }
        assert fires(rules, event)

    def test_silent_when_the_other_address_is_missing(self) -> None:
        """The regression this class exists for.

        Source listed, destination absent: the engine never reaches the lookup,
        so the converted rule must not fire either. A bare disjunction did.
        """
        rules = converted(self.OPTIONS)
        assert not fires(rules, {"sagan_ip_1": "203.0.113.7", "sagan_denylist_1": True})

    def test_silent_when_both_are_present_but_neither_is_listed(self) -> None:
        rules = converted(self.OPTIONS)
        assert not fires(
            rules, {"sagan_ip_1": "203.0.113.7", "sagan_ip_2": "198.51.100.9"}
        )
