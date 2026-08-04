"""Tests for the command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from tests.conftest import FIXTURES

from sagan2sigma.cli import (
    EXIT_RATE_BELOW_THRESHOLD,
    EXIT_VALIDATION_FAILED,
    build_parser,
    main,
)

RULES = str(FIXTURES / "rules" / "synthetic.rules")


class TestParser:
    def test_defaults(self) -> None:
        args = build_parser().parse_args([RULES])
        assert args.profile == "rsigma-syslog"
        assert args.case_policy == "faithful"
        assert args.split == "per-source"

    def test_rejects_an_unknown_case_policy(self) -> None:
        with pytest.raises(SystemExit):
            build_parser().parse_args([RULES, "--case-policy", "nonsense"])


class TestRun:
    def test_writes_every_artefact(self, tmp_path: Path) -> None:
        assert main([RULES, "-o", str(tmp_path)]) == 0
        assert (tmp_path / "CONVERSION-REPORT.md").is_file()
        assert (tmp_path / "conversion-report.json").is_file()
        assert (tmp_path / "rules" / "synthetic.yml").is_file()

    def test_emitted_rules_are_valid_yaml(self, tmp_path: Path) -> None:
        main([RULES, "-o", str(tmp_path)])
        text = (tmp_path / "rules" / "synthetic.yml").read_text(encoding="utf-8")
        documents = list(yaml.safe_load_all(text))
        assert len(documents) > 10

    def test_single_file_split(self, tmp_path: Path) -> None:
        main([RULES, "-o", str(tmp_path), "--split", "single"])
        assert (tmp_path / "rules" / "rules.yml").is_file()

    def test_json_report_is_parseable(self, tmp_path: Path) -> None:
        main([RULES, "-o", str(tmp_path)])
        payload = json.loads((tmp_path / "conversion-report.json").read_text("utf-8"))
        assert payload["summary"]["rules_converted"] > 0
        assert payload["settings"]["profile"] == "rsigma-syslog"

    def test_missing_path_is_reported(self, tmp_path: Path) -> None:
        assert main([str(tmp_path / "absent.rules"), "-o", str(tmp_path)]) == 1

    def test_min_rate_gate(self, tmp_path: Path) -> None:
        code = main([RULES, "-o", str(tmp_path), "--min-rate", "99.9"])
        assert code == EXIT_RATE_BELOW_THRESHOLD

    def test_min_rate_gate_passes_when_met(self, tmp_path: Path) -> None:
        assert main([RULES, "-o", str(tmp_path), "--min-rate", "10"]) == 0

    def test_no_validate_still_produces_rules(self, tmp_path: Path) -> None:
        assert main([RULES, "-o", str(tmp_path), "--no-validate"]) == 0
        assert (tmp_path / "rules" / "synthetic.yml").is_file()

    def test_relaxed_policy_removes_cased(self, tmp_path: Path) -> None:
        main([RULES, "-o", str(tmp_path), "--case-policy", "relaxed"])
        text = (tmp_path / "rules" / "synthetic.yml").read_text(encoding="utf-8")
        assert "|cased" not in text

    def test_vector_profile(self, tmp_path: Path) -> None:
        main([RULES, "-o", str(tmp_path), "-p", "vector-json"])
        text = (tmp_path / "rules" / "synthetic.yml").read_text(encoding="utf-8")
        assert "message|contains" in text
        assert "_raw" not in text

    def test_output_is_byte_identical_across_runs(self, tmp_path: Path) -> None:
        first, second = tmp_path / "a", tmp_path / "b"
        main([RULES, "-o", str(first)])
        main([RULES, "-o", str(second)])
        assert (first / "rules" / "synthetic.yml").read_bytes() == (
            second / "rules" / "synthetic.yml"
        ).read_bytes()


class TestExitCodes:
    def test_success(self, tmp_path: Path) -> None:
        assert main([RULES, "-o", str(tmp_path)]) == 0

    def test_codes_are_distinct(self) -> None:
        assert EXIT_VALIDATION_FAILED != EXIT_RATE_BELOW_THRESHOLD


class TestSyntheticRuleFile:
    def test_aggregates_get_their_own_file(self, tmp_path: Path) -> None:
        """Aggregate rules span every source file, so they need a real name."""
        main([RULES, "-o", str(tmp_path)])
        names = {path.name for path in (tmp_path / "rules").iterdir()}
        assert "_xbit-aggregates.yml" in names
        assert not any(name.startswith("(") for name in names)
