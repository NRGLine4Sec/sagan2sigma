"""Invariant tests against the real upstream corpus.

These are opt-in: they need a checkout of ``quadrantsec/sagan-rules`` and are
skipped when ``SAGAN_RULES_DIR`` is unset. They exist because the synthetic
fixtures only cover constructs we already understand, and every serious defect
found in this converter so far came from running it over the real 10,000-rule
corpus, not from the fixtures. In CI they run as a separate job that clones the
upstream repository.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest
import yaml

from sagan2sigma.converter import Converter
from sagan2sigma.emit.yaml_io import dump_collection
from sagan2sigma.errors import RefusalCode
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.sagan.config import load_config
from sagan2sigma.validate.pysigma import validate_all

CORPUS = os.environ.get("SAGAN_RULES_DIR")

pytestmark = pytest.mark.skipif(
    not CORPUS or not Path(CORPUS).is_dir(),
    reason="set SAGAN_RULES_DIR to a sagan-rules checkout to run corpus tests",
)

#: Floor for the conversion rate. Lowering it must be a deliberate, reviewed
#: act, which is the whole point of pinning it in a test.
MIN_CONVERSION_RATE = 78.0


@pytest.fixture(scope="module")
def corpus_result():
    root = Path(CORPUS)
    context = Context(
        profile=load_profile("rsigma-syslog"),
        config=load_config(rules_dir=root),
        catalog=load_catalog(),
    )
    return Converter(context=context).convert_paths([root])


class TestCorpusHealth:
    def test_every_line_parses(self, corpus_result) -> None:
        """A parse failure means the lexer diverged from the engine."""
        assert corpus_result.parse_failures == [], (
            f"{len(corpus_result.parse_failures)} lines failed to parse, "
            f"first: {corpus_result.parse_failures[:1]}"
        )

    def test_conversion_rate_floor(self, corpus_result) -> None:
        assert corpus_result.conversion_rate >= MIN_CONVERSION_RATE

    def test_no_unknown_keywords(self, corpus_result) -> None:
        """A new upstream keyword must be handled, not silently refused."""
        assert corpus_result.unknown_keywords == {}, (
            "unhandled keywords appeared upstream: "
            f"{sorted(corpus_result.unknown_keywords)}"
        )

    def test_a_meaningful_number_of_rules_is_seen(self, corpus_result) -> None:
        assert corpus_result.total_rules > 5000


class TestEmittedDocuments:
    def test_every_document_is_valid_sigma(self, corpus_result) -> None:
        issues = validate_all(corpus_result.documents)
        assert issues == [], f"{len(issues)} invalid documents, first: {issues[:1]}"

    def test_no_validation_issues_recorded(self, corpus_result) -> None:
        assert corpus_result.validation_issues == []

    def test_identifiers_are_unique(self, corpus_result) -> None:
        counts = Counter(document["id"] for document in corpus_result.documents)
        duplicates = [key for key, count in counts.items() if count > 1]
        assert duplicates == []

    def test_names_are_unique(self, corpus_result) -> None:
        names = [d["name"] for d in corpus_result.documents if "name" in d]
        assert len(names) == len(set(names))

    def test_every_document_has_the_mandatory_fields(self, corpus_result) -> None:
        for document in corpus_result.documents:
            assert document.get("title")
            assert document.get("id")
            assert "correlation" in document or "detection" in document

    def test_serialised_output_round_trips(self, corpus_result) -> None:
        text = dump_collection(corpus_result.documents[:500])
        assert len(list(yaml.safe_load_all(text))) == 500


class TestDeterminism:
    def test_two_runs_are_byte_identical(self, corpus_result) -> None:
        root = Path(CORPUS)
        context = Context(
            profile=load_profile("rsigma-syslog"),
            config=load_config(rules_dir=root),
            catalog=load_catalog(),
        )
        again = Converter(context=context).convert_paths([root])
        assert dump_collection(again.documents) == dump_collection(
            corpus_result.documents
        )


class TestRefusalTaxonomy:
    def test_every_refusal_uses_a_known_code(self, corpus_result) -> None:
        codes = {refused.code for refused in corpus_result.refused}
        assert codes <= set(RefusalCode)

    def test_no_converter_defects(self, corpus_result) -> None:
        """E_SIGMA_INVALID means we emitted something pySigma rejects."""
        defects = [
            refused
            for refused in corpus_result.refused
            if refused.code is RefusalCode.SIGMA_INVALID
        ]
        assert defects == [], f"{len(defects)} converter defects, first: {defects[:1]}"

    def test_every_refusal_carries_a_detail(self, corpus_result) -> None:
        assert all(refused.detail for refused in corpus_result.refused)

    def test_pass_rules_are_all_refused(self, corpus_result) -> None:
        """Converting a pass rule into an alert would invert its meaning."""
        assert any(
            refused.code is RefusalCode.PASS_RULE for refused in corpus_result.refused
        )
