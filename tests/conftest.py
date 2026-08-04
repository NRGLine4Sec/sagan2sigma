"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.mapping.fields import FieldResolver
from sagan2sigma.mapping.ir import RuleDraft
from sagan2sigma.mapping.values import CasePolicy
from sagan2sigma.sagan.config import SaganConfig
from sagan2sigma.sagan.model import SaganRule
from sagan2sigma.sagan.parser import parse_rule

FIXTURES = Path(__file__).parent / "fixtures"


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the golden-file refresh flag."""
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="rewrite the golden files instead of comparing against them",
    )


@pytest.fixture
def config() -> SaganConfig:
    """A configuration context with a representative sample of real data."""
    return SaganConfig(
        classtypes={
            "exploit-attempt": 1,
            "attempted-admin": 1,
            "correlated-attack": 1,
            "suspicious-traffic": 2,
            "user-activity": 3,
            "hardware-event": 4,
        },
        references={
            "cve": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
            "bugtraq": "https://www.securityfocus.com/bid/",
        },
        variables={"USERS": ["bob", "frank", "mary"], "HOME_COUNTRY": ["US"]},
    )


@pytest.fixture
def context(config: SaganConfig) -> Context:
    """Conversion context on the default RSigma syslog profile."""
    return Context(
        profile=load_profile("rsigma-syslog"),
        config=config,
        catalog=load_catalog(),
    )


@pytest.fixture
def vector_context(config: SaganConfig) -> Context:
    """Conversion context on the Vector JSON profile."""
    return Context(
        profile=load_profile("vector-json"),
        config=config,
        catalog=load_catalog(),
    )


@pytest.fixture
def draft() -> RuleDraft:
    """An empty draft."""
    return RuleDraft()


def make_rule(
    options: str, source_file: str = "test.rules", action: str = "alert"
) -> SaganRule:
    """Build a rule from its option block alone, for concise tests."""
    line = f"{action} any $EXTERNAL_NET any -> $HOME_NET any ({options})"
    return parse_rule(line, source_file, 1)


def resolver_for(rule: SaganRule, context: Context) -> FieldResolver:
    """Field resolver bound to a rule."""
    return FieldResolver.for_rule(rule, context)


def run(keyword_handler, rule, draft, context, policy=CasePolicy.FAITHFUL):
    """Invoke a handler with the standard argument order."""
    keyword_handler(rule, draft, context, resolver_for(rule, context), policy)


@pytest.fixture
def rule_factory():
    """Expose :func:`make_rule` as a fixture."""
    return make_rule
