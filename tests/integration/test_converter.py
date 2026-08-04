"""End-to-end conversion tests over the hand-written fixture corpus."""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURES

from sagan2sigma.converter import ConversionResult, Converter
from sagan2sigma.errors import DegradationCode, RefusalCode
from sagan2sigma.mapping.context import Context

RULES = FIXTURES / "rules" / "synthetic.rules"


@pytest.fixture(scope="module")
def result_factory():
    def build(context: Context) -> ConversionResult:
        return Converter(context=context).convert_paths([RULES])

    return build


@pytest.fixture
def result(context: Context, result_factory) -> ConversionResult:
    return result_factory(context)


def sids(items) -> set[str]:
    return {item.sid for item in items}


def refusal_for(result: ConversionResult, sid: str) -> RefusalCode:
    return next(item.code for item in result.refused if item.sid == sid)


def document_for(result: ConversionResult, sid: str) -> dict:
    return next(item.documents[0] for item in result.converted if item.sid == sid)


class TestCorpusLevelOutcome:
    def test_counts_disabled_rules(self, result: ConversionResult) -> None:
        assert result.disabled_rules == 1

    def test_no_parse_failures(self, result: ConversionResult) -> None:
        assert result.parse_failures == []

    def test_no_validation_issues(self, result: ConversionResult) -> None:
        assert result.validation_issues == []

    def test_no_unknown_keywords(self, result: ConversionResult) -> None:
        assert result.unknown_keywords == {}

    def test_every_expected_rule_converted(self, result: ConversionResult) -> None:
        converted = sids(result.converted)
        assert {f"90000{n:02d}" for n in range(1, 14)} <= converted


class TestRefusals:
    @pytest.mark.parametrize(
        ("sid", "code"),
        [
            ("9000014", RefusalCode.POSITIONAL),
            ("9000015", RefusalCode.EXTERNAL_ENRICHMENT),
            ("9000016", RefusalCode.TIME_WINDOW),
            ("9000017", RefusalCode.STATE_ABSENCE),
            ("9000018", RefusalCode.GROUPBY_UNRESOLVED),
            ("9000019", RefusalCode.BASE64_FIELD_DECODE),
            ("9000020", RefusalCode.PASS_RULE),
            ("9000022", RefusalCode.RAW_TEXT_ON_JSON_EVENT),
        ],
    )
    def test_refusal_codes(self, result: ConversionResult, sid: str, code) -> None:
        assert refusal_for(result, sid) is code

    def test_refusals_keep_their_source_location(
        self, result: ConversionResult
    ) -> None:
        refused = next(item for item in result.refused if item.sid == "9000014")
        assert refused.source_file == "synthetic.rules"
        assert refused.line_number > 0


class TestConvertedContent:
    def test_json_rules_target_the_prefixed_envelope(
        self, result: ConversionResult
    ) -> None:
        """The envelope is renamed once the body is JSON.

        A rule mixing program with json_content has to follow, or it can never
        fire.
        """
        keys = {
            key
            for block in document_for(result, "9000005")["detection"].values()
            if isinstance(block, dict)
            for key in block
        }
        assert "syslog_appname|cased" in keys
        assert "appname|cased" not in keys

    def test_text_rules_keep_the_plain_envelope(self, result: ConversionResult) -> None:
        keys = {
            key
            for block in document_for(result, "9000001")["detection"].values()
            if isinstance(block, dict)
            for key in block
        }
        assert "appname|cased" in keys

    def test_program_alternatives_and_case(self, result: ConversionResult) -> None:
        detection = document_for(result, "9000001")["detection"]
        blocks = [v for k, v in detection.items() if k != "condition"]
        assert {"appname|cased": ["sshd", "openssh"]} in blocks

    def test_negation_appears_in_the_condition(self, result: ConversionResult) -> None:
        condition = document_for(result, "9000001")["detection"]["condition"]
        assert "not filter_" in condition

    def test_hex_escape_and_wildcard_escape(self, result: ConversionResult) -> None:
        detection = document_for(result, "9000002")["detection"]
        values = [
            next(iter(v.values())) for k, v in detection.items() if k != "condition"
        ]
        assert "User Agent: scanner" in values
        assert "100\\*" in values

    def test_meta_content_expands_to_a_list(self, result: ConversionResult) -> None:
        detection = document_for(result, "9000003")["detection"]
        assert {"_raw|contains": ["USER=root", "USER=admin"]} in [
            v for k, v in detection.items() if k != "condition"
        ]

    def test_pcre_modifiers(self, result: ConversionResult) -> None:
        detection = document_for(result, "9000004")["detection"]
        assert any(
            "_raw|re|i" in block
            for block in detection.values()
            if isinstance(block, dict)
        )

    def test_json_rule_targets_real_fields(self, result: ConversionResult) -> None:
        document = document_for(result, "9000005")
        keys = {
            key
            for block in document["detection"].values()
            if isinstance(block, dict)
            for key in block
        }
        assert "eventName|cased" in keys
        assert "awsRegion|cased" in keys

    def test_attack_tags(self, result: ConversionResult) -> None:
        """ATT&CK ids become Sigma tags; the classtype is kept alongside them.

        so the original Sagan intent stays recoverable.
        """
        assert document_for(result, "9000005")["tags"] == [
            "attack.t1078",
            "attack.ta0005",
            "sagan.classtype.user-activity",
        ]

    def test_json_map_redirects_the_content_search(
        self, result: ConversionResult
    ) -> None:
        keys = {
            key
            for block in document_for(result, "9000006")["detection"].values()
            if isinstance(block, dict)
            for key in block
        }
        assert "RenderedDescription|contains" in keys
        assert "EventID" in keys
        assert not any(key.startswith("_raw") for key in keys)

    def test_numeric_json_value_has_no_cased(self, result: ConversionResult) -> None:
        keys = {
            key
            for block in document_for(result, "9000007")["detection"].values()
            if isinstance(block, dict)
            for key in block
        }
        assert "resultType" in keys

    def test_priority_beats_classtype(self, result: ConversionResult) -> None:
        assert document_for(result, "9000012")["level"] == "high"

    def test_drop_action_is_reported(self, result: ConversionResult) -> None:
        converted = next(item for item in result.converted if item.sid == "9000013")
        assert any(
            d.code is DegradationCode.DROP_ACTION for d in converted.degradations
        )


class TestCorrelations:
    def test_after_emits_a_second_document(self, result: ConversionResult) -> None:
        converted = next(item for item in result.converted if item.sid == "9000008")
        assert len(converted.documents) == 2
        correlation = converted.documents[1]["correlation"]
        assert correlation["type"] == "event_count"
        assert correlation["group-by"] == ["sourceIPAddress"]
        assert correlation["condition"] == {"gte": 5}
        assert correlation["timespan"] == "5m"

    def test_base_rule_gets_a_name(self, result: ConversionResult) -> None:
        assert document_for(result, "9000008")["name"] == "sagan_9000008"

    def test_syslog_host_fallback(self, result: ConversionResult) -> None:
        converted = next(item for item in result.converted if item.sid == "9000009")
        assert converted.documents[1]["correlation"]["group-by"] == ["hostname"]
        assert any(
            d.code is DegradationCode.GROUPBY_SYSLOG_HOST
            for d in converted.degradations
        )

    def test_threshold_suppress_is_metadata_not_correlation(
        self, result: ConversionResult
    ) -> None:
        document = document_for(result, "9000009")
        assert document["custom_attributes"]["rsigma.suppress"] == "15m"

    def test_xbit_aggregate_is_emitted(self, result: ConversionResult) -> None:
        aggregates = [
            item for item in result.converted if item.sid == "xbit:brute_force"
        ]
        assert len(aggregates) == 1
        assert aggregates[0].documents[0]["name"] == "sagan_xbit_brute_force"

    def test_state_correlation_references_the_aggregate(
        self, result: ConversionResult
    ) -> None:
        converted = next(item for item in result.converted if item.sid == "9000011")
        correlation = converted.documents[1]["correlation"]
        assert correlation["type"] == "temporal_ordered"
        assert correlation["rules"] == ["sagan_xbit_brute_force", "sagan_9000011"]
        assert correlation["timespan"] == "6h"

    def test_state_window_comes_from_the_setter_expiry(
        self, result: ConversionResult
    ) -> None:
        """Sagan attaches expire to `set`, never to `isset`."""
        converted = next(item for item in result.converted if item.sid == "9000011")
        assert converted.documents[1]["correlation"]["timespan"] == "6h"


class TestDeterminismAndProfiles:
    def test_two_runs_are_identical(self, context: Context) -> None:
        first = Converter(context=context).convert_paths([RULES]).documents
        second = Converter(context=context).convert_paths([RULES]).documents
        assert first == second

    def test_identifiers_are_stable_across_profiles(
        self, context: Context, vector_context: Context
    ) -> None:
        rsigma = {
            d["id"] for d in Converter(context=context).convert_paths([RULES]).documents
        }
        vector = {
            d["id"]
            for d in Converter(context=vector_context).convert_paths([RULES]).documents
        }
        assert rsigma == vector

    def test_vector_profile_uses_the_message_field(
        self, vector_context: Context
    ) -> None:
        result = Converter(context=vector_context).convert_paths([RULES])
        keys = {
            key
            for block in document_for(result, "9000001")["detection"].values()
            if isinstance(block, dict)
            for key in block
        }
        assert any(key.startswith("message|") for key in keys)
        assert not any(key.startswith("_raw") for key in keys)
