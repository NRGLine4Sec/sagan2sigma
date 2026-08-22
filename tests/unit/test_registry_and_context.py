"""Tests for the handler registry, profiles and the logsource catalog."""

from __future__ import annotations

from pathlib import Path

import pytest

import sagan2sigma.mapping  # noqa: F401 - populates the registry
from sagan2sigma.mapping.context import (
    LogSourceCatalog,
    available_profiles,
    load_catalog,
    load_profile,
)
from sagan2sigma.mapping.registry import (
    BLOCKING,
    IGNORED,
    MODIFIERS,
    classify,
    get_handler,
    registered_keywords,
)


class TestRegistry:
    @pytest.mark.parametrize(
        "keyword",
        [
            "msg",
            "content",
            "meta_content",
            "pcre",
            "program",
            "event_id",
            "json_content",
            "json_meta_content",
            "json_pcre",
            "after",
            "threshold",
            "xbits",
            "flexbits",
            "classtype",
            "reference",
            "metadata",
            "priority",
        ],
    )
    def test_core_keywords_have_handlers(self, keyword: str) -> None:
        assert get_handler(keyword) is not None

    def test_the_registry_matches_the_engine_keyword_for_keyword(self) -> None:
        """The converter's tables are hand-copies of the engine's branches.

        Drift is silent in both directions and both have happened. Accepting a
        keyword Sagan rejects turns a rule that cannot load anywhere into
        working Sigma: `facility`, `level` and `tag` were accepted as bare
        aliases of the `syslog_` forms and are not keywords at all. Missing one
        Sagan accepts refuses a rule that works: `syslog_priority` is a real
        envelope selector that was reported as unknown.

        tests/data/engine-keywords.txt is the list from src/rules.c, checked
        against a locally built engine name by name.
        """
        from sagan2sigma.mapping.positional import POSITIONAL_KEYWORDS

        path = Path(__file__).resolve().parents[1] / "data" / "engine-keywords.txt"
        engine = {
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        known = (
            registered_keywords()
            | MODIFIERS
            | IGNORED.keys()
            | BLOCKING.keys()
            | POSITIONAL_KEYWORDS
        )
        assert not engine - known, "keywords Sagan accepts that we do not handle"
        # The converse, restricted to the envelope selectors this test was
        # written for. The full converse is not an invariant: the converter
        # deliberately knows names the parser reaches by other routes.
        invented = {"facility", "level", "tag"} & known
        assert not invented, "bare aliases the engine rejects"

    def test_families_are_disjoint(self) -> None:
        """A keyword in two families would be handled inconsistently."""
        from sagan2sigma.mapping.positional import POSITIONAL_KEYWORDS

        handled = registered_keywords()
        assert not handled & MODIFIERS
        assert not handled & BLOCKING.keys()
        assert not handled & IGNORED.keys()
        assert not MODIFIERS & BLOCKING.keys()
        assert not MODIFIERS & IGNORED.keys()
        assert not IGNORED.keys() & BLOCKING.keys()
        # Positional keywords are their own family, overlapping none of the rest.
        assert not POSITIONAL_KEYWORDS & handled
        assert not POSITIONAL_KEYWORDS & MODIFIERS
        assert not POSITIONAL_KEYWORDS & IGNORED.keys()
        assert not POSITIONAL_KEYWORDS & BLOCKING.keys()

    @pytest.mark.parametrize(
        ("keyword", "family"),
        [
            ("content", "handled"),
            ("nocase", "modifier"),
            ("sid", "ignored"),
            ("offset", "positional"),
            ("within", "positional"),
            ("bluedot", "handled"),
            ("never_seen_before", "unknown"),
        ],
    )
    def test_classify(self, keyword: str, family: str) -> None:
        assert classify(keyword) == family

    def test_duplicate_registration_is_rejected(self) -> None:
        from sagan2sigma.mapping.registry import handler

        with pytest.raises(RuntimeError, match="already registered"):

            @handler("content")
            def _duplicate(rule, draft, context, resolver, policy):  # pragma: no cover
                ...


class TestProfiles:
    def test_bundled_profiles_are_discoverable(self) -> None:
        assert set(available_profiles()) >= {"rsigma-syslog", "vector-json"}

    @pytest.mark.parametrize("name", ["rsigma-syslog", "vector-json"])
    def test_every_profile_defines_the_required_fields(self, name: str) -> None:
        profile = load_profile(name)
        for internal in ("message", "program", "syslog_host", "facility", "level"):
            assert profile.field(internal)

    def test_profiles_differ_only_on_the_message_field(self) -> None:
        rsigma = load_profile("rsigma-syslog").fields
        vector = load_profile("vector-json").fields
        differing = {k for k in rsigma if rsigma[k] != vector.get(k)}
        assert differing == {"message"}

    def test_unknown_internal_value_raises(self) -> None:
        with pytest.raises(KeyError):
            load_profile("rsigma-syslog").field("not_a_field")

    def test_external_profile_file(self, tmp_path) -> None:
        path = tmp_path / "custom.yml"
        path.write_text(
            "name: custom\ndescription: d\nfields:\n  message: body\n", encoding="utf-8"
        )
        assert load_profile(str(path)).field("message") == "body"


class TestLogSourceCatalog:
    def test_exact_match_wins(self) -> None:
        assert load_catalog().resolve("ssh.rules").logsource["service"] == "sshd"

    def test_longest_prefix_wins(self) -> None:
        catalog = load_catalog()
        assert catalog.resolve("azureEventHub_windows-security.rules").logsource == {
            "product": "windows"
        }
        assert catalog.resolve("azureEventHub_other.rules").logsource == {
            "product": "azure"
        }

    def test_fallback_is_flagged(self) -> None:
        entry = load_catalog().resolve("totally-unknown-vendor.rules")
        assert entry.is_fallback
        assert entry.logsource == {"product": "syslog"}

    def test_report_category(self) -> None:
        assert (
            load_catalog().resolve("cisco-asa.rules").category
            == "Network and firewalls"
        )

    def test_unmatched_category(self) -> None:
        assert load_catalog().resolve("zzz-unknown.rules").category == "Unclassified"

    def test_empty_catalog_still_resolves(self) -> None:
        entry = LogSourceCatalog(fallback={"product": "syslog"}).resolve("a.rules")
        assert entry.is_fallback
