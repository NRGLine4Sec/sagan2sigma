"""Tests for the Sagan configuration loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from sagan2sigma.sagan.config import (
    DEFAULT_LEVEL,
    SaganConfig,
    load_classification,
    load_config,
    load_references,
    load_sagan_yaml,
)


class TestLoadClassification:
    def test_parses_real_syntax(self, tmp_path: Path) -> None:
        path = tmp_path / "classification.config"
        path.write_text(
            "# comment\n"
            "config classification: exploit-attempt,Attempted Exploit,1\n"
            "config classification: user-activity,User Activity,3\n"
            "garbage line\n",
            encoding="utf-8",
        )
        assert load_classification(path) == {"exploit-attempt": 1, "user-activity": 3}

    def test_returns_empty_on_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "classification.config"
        path.write_text("", encoding="utf-8")
        assert load_classification(path) == {}


class TestLoadReferences:
    def test_parses_real_syntax(self, tmp_path: Path) -> None:
        path = tmp_path / "reference.config"
        path.write_text(
            "config reference: cve https://cve.mitre.org/x?name=\n"
            "config reference: url http://\n",
            encoding="utf-8",
        )
        assert load_references(path) == {
            "cve": "https://cve.mitre.org/x?name=",
            "url": "http://",
        }


class TestLevelFor:
    @pytest.mark.parametrize(
        ("classtype", "expected"),
        [
            ("exploit-attempt", "high"),
            ("suspicious-traffic", "medium"),
            ("user-activity", "low"),
            ("hardware-event", "informational"),
        ],
    )
    def test_maps_priority_to_level(
        self, config: SaganConfig, classtype: str, expected: str
    ) -> None:
        assert config.level_for(classtype) == expected

    def test_unknown_classtype_falls_back(self, config: SaganConfig) -> None:
        assert config.level_for("never-heard-of-it") == DEFAULT_LEVEL

    def test_none_falls_back(self, config: SaganConfig) -> None:
        assert config.level_for(None) == DEFAULT_LEVEL

    def test_is_case_insensitive(self, config: SaganConfig) -> None:
        assert config.level_for("  Exploit-Attempt ") == "high"


class TestReferenceUrl:
    def test_url_gets_https_when_bare(self, config: SaganConfig) -> None:
        assert config.reference_url("url", "example.org/x") == "https://example.org/x"

    def test_url_is_left_alone_when_absolute(self, config: SaganConfig) -> None:
        assert config.reference_url("url", "http://a/b") == "http://a/b"

    def test_known_prefix_is_applied(self, config: SaganConfig) -> None:
        assert config.reference_url("cve", "1999-0531").endswith("name=1999-0531")

    def test_unknown_kind_returns_the_target(self, config: SaganConfig) -> None:
        assert config.reference_url("mystery", "42") == "42"


class TestVariables:
    def test_expand_known(self, config: SaganConfig) -> None:
        assert config.expand("$USERS") == ["bob", "frank", "mary"]

    def test_expand_is_case_insensitive(self, config: SaganConfig) -> None:
        assert config.expand("$users") == ["bob", "frank", "mary"]

    def test_expand_unknown_is_none(self, config: SaganConfig) -> None:
        assert config.expand("$NOPE") is None

    def test_unresolved_variables(self, config: SaganConfig) -> None:
        assert config.unresolved_variables("$USERS and $NOPE") == ["NOPE"]


class TestLoadSaganYaml:
    def test_flattens_nested_var_groups(self, tmp_path: Path) -> None:
        path = tmp_path / "sagan.yaml"
        path.write_text(
            "vars:\n"
            "  address-groups:\n"
            "    HOME_NET: 'any'\n"
            "  sagan-groups:\n"
            "    USERS: '[bob, frank]'\n"
            "  port-groups:\n"
            "    SSH_PORT: 22\n",
            encoding="utf-8",
        )
        variables = load_sagan_yaml(path)
        assert variables["USERS"] == ["bob", "frank"]
        assert variables["HOME_NET"] == ["any"]
        assert variables["SSH_PORT"] == ["22"]

    def test_accepts_native_yaml_lists(self, tmp_path: Path) -> None:
        path = tmp_path / "sagan.yaml"
        path.write_text("vars:\n  g:\n    USERS: [bob, mary]\n", encoding="utf-8")
        assert load_sagan_yaml(path)["USERS"] == ["bob", "mary"]

    def test_tolerates_missing_vars_section(self, tmp_path: Path) -> None:
        path = tmp_path / "sagan.yaml"
        path.write_text("other: 1\n", encoding="utf-8")
        assert load_sagan_yaml(path) == {}


class TestLoadConfig:
    def test_every_file_is_optional(self, tmp_path: Path) -> None:
        config = load_config(rules_dir=tmp_path, sagan_yaml=tmp_path / "absent.yaml")
        assert config.classtypes == {}
        assert config.variables == {}

    def test_reads_files_next_to_the_rules(self, tmp_path: Path) -> None:
        (tmp_path / "classification.config").write_text(
            "config classification: a,A,1\n", encoding="utf-8"
        )
        assert load_config(rules_dir=tmp_path).classtypes == {"a": 1}
