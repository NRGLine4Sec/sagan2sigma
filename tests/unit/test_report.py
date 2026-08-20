"""Tests for the Markdown and JSON conversion reports."""

from __future__ import annotations

import json

from sagan2sigma.converter import ConversionResult, ConvertedRule, RefusedRule
from sagan2sigma.errors import Degradation, DegradationCode, RefusalCode
from sagan2sigma.report import json_report, markdown


def sample_result() -> ConversionResult:
    result = ConversionResult(files_processed=2, disabled_rules=7)
    result.converted.append(
        ConvertedRule(
            sid="5000116",
            title="Disk full",
            source_file="syslog.rules",
            category="Unix and Linux",
            documents=[{"title": "Disk full", "id": "abc"}],
            degradations=[
                Degradation(DegradationCode.RAW_TEXT_MATCH, "raw body match")
            ],
        )
    )
    result.refused.append(
        RefusedRule(
            sid="5000200",
            title="Needs GeoIP",
            source_file="cisco-asa.rules",
            line_number=12,
            category="Network and firewalls",
            code=RefusalCode.EXTERNAL_ENRICHMENT,
            detail="keywords with no Sigma equivalent: country_code",
            keywords=("country_code",),
        )
    )
    result.unknown_keywords["brand_new_keyword"] = 3
    return result


class TestMarkdownReport:
    def test_contains_every_section(self) -> None:
        text = markdown.render(sample_result(), "rsigma-syslog", "faithful")
        for heading in (
            "# Conversion report",
            "## Summary",
            "## Outcome by product family",
            "## Refusals by code",
            "## Converted with semantic loss",
            "## Unknown keywords",
            "## pySigma validation",
            "## Refused rules",
        ):
            assert heading in text

    def test_reports_the_refused_rule(self) -> None:
        text = markdown.render(sample_result(), "p", "faithful")
        assert "5000200" in text
        assert "E_EXTERNAL_ENRICHMENT" in text
        assert "country_code" in text

    def test_reports_degradations(self) -> None:
        text = markdown.render(sample_result(), "p", "faithful")
        assert "D_RAW_TEXT_MATCH" in text

    def test_refused_rules_are_behind_a_disclosure_block(self) -> None:
        """The per-rule listing runs to hundreds of rows, so it folds away.

        The heading and the explanation stay outside the block: a reader
        scanning the report must see which refusals dominate, and why, without
        clicking anything.
        """
        text = markdown.render(sample_result(), "p", "faithful")
        refused = text.split("## Refused rules", 1)[1]
        assert "<details>" in refused and "</details>" in refused
        heading, block = refused.split("<details>", 1)
        assert "E_EXTERNAL_ENRICHMENT" in heading
        assert "| SID | Source file |" in block

    def test_disclosure_block_keeps_a_blank_line_after_the_summary(self) -> None:
        """Without it GitHub renders the table as literal pipes rather than a.

        table, which is the one way this markup silently degrades.
        """
        text = markdown.render(sample_result(), "p", "faithful")
        after = text.split("</summary>", 1)[1]
        assert after.startswith("\n\n")

    def test_records_the_settings(self) -> None:
        text = markdown.render(sample_result(), "vector-json", "relaxed")
        assert "vector-json" in text and "relaxed" in text

    def test_escapes_pipes_in_cells(self) -> None:
        result = sample_result()
        result.refused[0].title = "a | b"
        assert "a \\| b" in markdown.render(result, "p", "faithful")

    def test_handles_an_empty_result(self) -> None:
        text = markdown.render(ConversionResult(), "p", "faithful")
        assert "# Conversion report" in text


class TestJsonReport:
    def test_is_valid_json(self) -> None:
        payload = json.loads(json_report.render(sample_result(), "p", "faithful"))
        assert payload["schema_version"] == 1

    def test_summary_counts(self) -> None:
        payload = json.loads(json_report.render(sample_result(), "p", "faithful"))
        assert payload["summary"]["rules_converted"] == 1
        assert payload["summary"]["rules_refused"] == 1
        assert payload["summary"]["conversion_rate"] == 50.0

    def test_lists_every_refusal_without_truncation(self) -> None:
        result = ConversionResult()
        for index in range(1000):
            result.refused.append(
                RefusedRule(
                    sid=str(index),
                    title="t",
                    source_file="f.rules",
                    line_number=index,
                    category="c",
                    code=RefusalCode.POSITIONAL,
                    detail="d",
                    keywords=(),
                )
            )
        payload = json.loads(json_report.render(result, "p", "faithful"))
        assert len(payload["refused"]) == 1000

    def test_is_deterministic(self) -> None:
        first = json_report.render(sample_result(), "p", "faithful")
        second = json_report.render(sample_result(), "p", "faithful")
        assert first == second
