"""A `json_map` binding names where a value would be, not a condition.

Measured on the engine before any of this was written. Three rules differing
only in their binding, one plain syslog line and one JSON document:

    program: sshd; json_map: "src_ip", ".ip"; content:"needle"   plain and JSON
    program: sshd; content:"needle"                              plain and JSON
    program: sshd; json_map: "src_ip", ".ip"; json_content:...   JSON only

The binding changes nothing about which events match. Only a keyword that reads
a key out of a parsed document does, and `json_map` is not one: it leaves the
internal value empty when there is no document.

The converter used to read any `json_map` as "this rule is JSON-bodied", and an
ingestion chain renames the syslog envelope once the body is a document, so the
41 corpus rules in that state were emitted against `syslog_appname` alone and
could not match the plain syslog lines the original matches. `openssh.rules`
sid 5000411 is the case that makes it concrete: a binding for a JSON variant of
the source, on a rule whose ordinary event is a plain sshd line.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_rule
from tests.differential.test_differential import context

from sagan2sigma.converter import Converter
from sagan2sigma.emit.sigma import build_detection
from sagan2sigma.errors import DegradationCode, Refusal, RefusalCode
from sagan2sigma.mapping.ir import RuleDraft

#: Binds an address and searches text, which is the shape of most of the 41.
EITHER_SHAPE = 'msg:"t"; program: sshd; json_map: "src_ip", ".ip"; content:"needle";'

#: The same rule with a condition no plain line can satisfy.
JSON_ONLY = (
    'msg:"t"; program: sshd; json_map: "src_ip", ".ip"; json_content:".user","bob";'
)


def convert(raw: str, profile: str) -> RuleDraft:
    return Converter(context=context(profile)).convert_rule(make_rule(raw))


def detection(raw: str, profile: str) -> dict[str, object]:
    blocks, _ = build_detection(convert(raw, profile).predicates)
    return blocks


def block_for(raw: str, profile: str, value: object) -> object:
    """The detection block carrying ``value``, whatever its generated name."""
    for block in detection(raw, profile).values():
        rendered = block if isinstance(block, list) else [block]
        if any(value in entry.values() for entry in rendered):
            return block
    raise AssertionError(f"no block carries {value!r}")


def codes(raw: str, profile: str) -> set[DegradationCode]:
    return {degradation.code for degradation in convert(raw, profile).degradations}


class TestTheEnvelopeAcceptsEitherName:
    """Both names, because the event may arrive under either."""

    def test_the_program_selector_lists_both(self) -> None:
        assert block_for(f"{EITHER_SHAPE} sid:1;", "vector-enriched", "sshd") == [
            {"syslog_appname|cased": "sshd"},
            {"appname|cased": "sshd"},
        ]

    def test_so_does_a_facility_selector(self) -> None:
        raw = f"{EITHER_SHAPE} syslog_facility: kern; sid:1;"
        assert block_for(raw, "vector-enriched", "kern") == [
            {"syslog_facility": "kern"},
            {"facility": "kern"},
        ]

    def test_the_text_search_runs_on_the_field_both_shapes_carry(self) -> None:
        """`sagan-json.vrl` sets `sagan_raw` on every event, document or not."""
        assert block_for(f"{EITHER_SHAPE} sid:1;", "vector-enriched", "needle") == {
            "sagan_raw|contains|cased": "needle"
        }

    def test_a_rule_requiring_a_document_names_one_shape(self) -> None:
        assert block_for(f"{JSON_ONLY} sid:1;", "vector-enriched", "sshd") == {
            "syslog_appname|cased": "sshd"
        }

    @pytest.mark.parametrize("profile", ["rsigma-syslog", "vector-enriched"])
    def test_a_rule_naming_no_json_at_all_is_untouched(self, profile: str) -> None:
        raw = 'msg:"t"; program: sshd; content:"needle"; sid:1;'
        assert block_for(raw, profile, "sshd") == {"appname|cased": "sshd"}


class TestOnAProfileThatKeepsNoRawBody:
    """RSigma hands over the parsed object alone, so half the rule is out."""

    def test_the_plain_half_converts_and_the_loss_is_declared(self) -> None:
        assert DegradationCode.JSON_BODY_ARM_LOST in codes(
            f"{EITHER_SHAPE} sid:1;", "rsigma-syslog"
        )

    def test_the_text_search_runs_against_the_plain_body(self) -> None:
        assert block_for(f"{EITHER_SHAPE} sid:1;", "rsigma-syslog", "needle") == {
            "_raw|contains|cased": "needle"
        }

    def test_nothing_is_declared_where_the_pipeline_keeps_the_body(self) -> None:
        assert DegradationCode.JSON_BODY_ARM_LOST not in codes(
            f"{EITHER_SHAPE} sid:1;", "vector-enriched"
        )

    def test_a_rule_with_no_text_search_loses_nothing(self) -> None:
        """Nothing to lose: an envelope selector reads both shapes."""
        raw = 'msg:"t"; program: p; json_map: "src_ip", ".ip"; event_id: 4624; sid:1;'
        assert DegradationCode.JSON_BODY_ARM_LOST not in codes(raw, "rsigma-syslog")

    def test_a_rule_that_requires_a_document_is_still_refused(self) -> None:
        with pytest.raises(Refusal) as raised:
            convert(f'{JSON_ONLY} content:"needle"; sid:1;', "rsigma-syslog")
        assert raised.value.code is RefusalCode.RAW_TEXT_ON_JSON_EVENT

    def test_a_search_redirected_into_a_key_reads_one_shape(self) -> None:
        """`json_map: "message"` reads a key, which only a document has.

        Nothing is refused here: RSigma parses the body, so the key is a field
        it exposes. What matters is that the rule is not treated as matching
        both shapes, since its text search cannot run on a plain line.
        """
        raw = (
            'msg:"t"; program: sshd; json_map: "message", ".Description"; '
            'content:"needle"; sid:1;'
        )
        assert block_for(raw, "rsigma-syslog", "needle") == {
            "Description|contains|cased": "needle"
        }
        assert block_for(raw, "rsigma-syslog", "sshd") == {
            "syslog_appname|cased": "sshd"
        }
