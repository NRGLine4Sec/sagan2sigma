"""The variables the converted snapshots in this repository are built with.

`tools/reference-vars.yaml` exists so that a rule referencing `$RFC1918` is not
refused for want of a value nobody disagrees about. The tests that matter are
about what it must **not** contain: a variable whose value belongs to a site
rather than to the world would be published inside every converted rule, wrong
for everyone whose site differs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sagan2sigma.sagan.config import load_sagan_yaml

REFERENCE_VARS = Path(__file__).parents[2] / "tools" / "reference-vars.yaml"

#: Variables a published rule set may carry, and why each is defensible.
#:
#: `SAGAN_HOURS` and `SAGAN_DAYS` are the engine's own defaults for a working
#: week rather than facts about the world, and are here knowingly: 26 rules are
#: refused without them, the window they encode is visible in each converted
#: rule, and an operator passing their own sagan.yaml overrides it.
ALLOWED = {
    "RFC1918",
    "CREDIT_CARD_PREFIXES",
    "PSEXEC_MD5",
    "SAGAN_HOURS",
    "SAGAN_DAYS",
}

#: Variables whose value is a property of one site. Publishing a rule set built
#: with any of these would state somebody else's answer as fact.
FORBIDDEN = {"HOME_COUNTRY", "WINDOWS_DOMAINS", "HOME_NET", "EXTERNAL_NET"}


@pytest.fixture(scope="module")
def variables() -> dict[str, list[str]]:
    return load_sagan_yaml(REFERENCE_VARS)


def test_the_file_parses_as_a_sagan_yaml(variables: dict[str, list[str]]) -> None:
    """It has to be loadable by the same reader a real sagan.yaml goes through."""
    assert variables


def test_no_site_specific_variable_is_published(
    variables: dict[str, list[str]],
) -> None:
    assert not FORBIDDEN & set(variables), (
        "a variable whose value belongs to one site would be baked into every "
        "converted rule that reads it"
    )


def test_nothing_beyond_the_reviewed_set(variables: dict[str, list[str]]) -> None:
    """Adding a variable is a decision, so it has to be made here too."""
    assert set(variables) <= ALLOWED


def test_rfc1918_is_what_the_rfc_says(variables: dict[str, list[str]]) -> None:
    values = variables["RFC1918"]
    assert "10." in values
    assert "192.168." in values
    assert len([v for v in values if v.startswith("172.")]) == 16


def test_the_header_says_why_home_country_is_absent() -> None:
    """The reasoning is the file's point and has to travel with it."""
    text = REFERENCE_VARS.read_text(encoding="utf-8")
    assert "HOME_COUNTRY" in text
    assert "--sagan-yaml" in text
