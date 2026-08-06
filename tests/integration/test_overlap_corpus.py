"""Self-validation of the overlap analysis against the real corpora.

Opt-in and heavy: it needs a ``sagan-rules`` checkout (``SAGAN_RULES_DIR``), a
SigmaHQ checkout (``SAGAN2SIGMA_SIGMAHQ_DIR``) and the ``rsigma`` binary on
PATH, and it runs the full analysis, so it is skipped unless all three are
present. In CI it belongs in the same job that already clones the corpora and
builds the engine.

The unit invariants in ``tests/overlap/test_invariants.py`` prove the analysis
behaves on hand-built rules. This proves the same properties hold on the real
report, where the interesting cases actually live. The central check replays
every covering verdict's witness event against each rule on its own and requires
both to fire, which is the promise the whole tool is built to keep: a claim of
coverage always comes with an event that demonstrates it.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from sagan2sigma.converter import Converter
from sagan2sigma.emit.yaml_io import dump_collection
from sagan2sigma.mapping.context import Context, load_catalog, load_profile
from sagan2sigma.overlap.analysis import (
    Relation,
    _logsource_compatible,
    analyse,
    load_converted,
    load_sigmahq,
)
from sagan2sigma.overlap.cache import SynthesisCache
from sagan2sigma.overlap.engine import RsigmaBatch
from sagan2sigma.sagan.config import load_config

CORPUS = os.environ.get("SAGAN_RULES_DIR")
SIGMAHQ = os.environ.get("SAGAN2SIGMA_SIGMAHQ_DIR")
CACHE = os.environ.get("SAGAN2SIGMA_OVERLAP_CACHE")
RSIGMA = shutil.which("rsigma")

#: Floor for the share of rules the engine confirms a test event for. Synthesis
#: sits far above this in practice; the floor is a regression tripwire, so a
#: change that quietly stops satisfying a class of rules fails here.
MIN_SYNTHESIS_RATE = 0.90

pytestmark = pytest.mark.skipif(
    not (CORPUS and Path(CORPUS).is_dir() and SIGMAHQ and Path(SIGMAHQ).is_dir())
    or RSIGMA is None,
    reason=(
        "set SAGAN_RULES_DIR, SAGAN2SIGMA_SIGMAHQ_DIR and put rsigma on PATH "
        "to run the overlap corpus self-validation"
    ),
)


@pytest.fixture(scope="module")
def analysis(tmp_path_factory: pytest.TempPathFactory) -> Any:
    """Convert the corpus, then run the full overlap analysis over both."""
    root = Path(CORPUS)  # type: ignore[arg-type]
    context = Context(
        profile=load_profile("rsigma-syslog"),
        config=load_config(rules_dir=root),
        catalog=load_catalog(),
    )
    converted = Converter(context=context).convert_paths([root])

    workdir = tmp_path_factory.mktemp("overlap-corpus")
    rules_dir = workdir / "rules"
    rules_dir.mkdir()
    (rules_dir / "all.yml").write_text(
        dump_collection(converted.documents), encoding="utf-8"
    )

    sagan = load_converted(rules_dir)
    sigmahq = load_sigmahq(
        Path(SIGMAHQ),  # type: ignore[arg-type]
        skip_dirs=frozenset({"rules-placeholder"}),
    )
    cache = SynthesisCache(Path(CACHE)) if CACHE else None
    result = analyse(sagan, sigmahq, workdir=workdir / "engine", cache=cache)
    documents = {record.key: record.document for record in sagan + sigmahq}
    return result, documents, workdir


def _covering(result: Any) -> list[Any]:
    return [
        verdict
        for verdict in result.verdicts
        if verdict.relation in (Relation.EQUIVALENT, Relation.SAGAN_REDUNDANT)
    ]


def test_synthesis_rate_floor(analysis: Any) -> None:
    result, _, _ = analysis
    rate = result.sagan_usable / max(result.sagan_total, 1)
    assert rate >= MIN_SYNTHESIS_RATE, (
        f"only {rate:.1%} of converted rules got a confirmed event; "
        "synthesis may have regressed"
    )


def test_no_absence_matcher_reaches_a_verdict(analysis: Any) -> None:
    result, _, _ = analysis
    blanket = set(result.sagan_blanket) | set(result.sigmahq_blanket)
    in_verdicts: set[str] = set()
    for verdict in result.verdicts:
        in_verdicts.add(verdict.sagan_key)
        in_verdicts.add(verdict.sigmahq_key)
    assert not (blanket & in_verdicts), (
        "an absence matcher reached a verdict; the negative-control screen leaked"
    )


def test_coverage_flag_matches_the_documents(analysis: Any) -> None:
    """The stored compatibility flag agrees with the rules' own logsources."""
    result, documents, _ = analysis
    for verdict in result.verdicts:
        expected = _logsource_compatible(
            documents[verdict.sagan_key], documents[verdict.sigmahq_key]
        )
        assert verdict.logsource_compatible is expected


def test_actionable_coverage_is_all_log_source_compatible(analysis: Any) -> None:
    result, _, _ = analysis
    # The actionable set is exactly the converted rules with a compatible
    # covering verdict, nothing snuck in via an incompatible one.
    compatible_covered = {
        verdict.sagan_key
        for verdict in _covering(result)
        if verdict.logsource_compatible
    }
    assert result.redundant_sagan_keys == compatible_covered
    # And the gate is doing real work: some covering co-firings were rejected
    # for crossing log sources.
    assert result.cross_logsource_covered > 0


def test_every_covering_witness_fires_both_rules(analysis: Any) -> None:
    """The promise: each coverage witness fires both rules, replayed on its own.

    Every covering verdict, compatible or not, is checked. The witness is put
    through the engine against each rule alone, so a witness picked by a
    segmentation or containment bug would fail here rather than be trusted.
    """
    result, documents, workdir = analysis
    covering = _covering(result)
    assert covering, "expected covering verdicts on the real corpus"

    probe = workdir / "witness-probe"
    for index, verdict in enumerate(covering):
        witness: dict[str, Any] = verdict.witness
        sagan_doc = documents[verdict.sagan_key]
        sigmahq_doc = documents[verdict.sigmahq_key]

        sagan_hit = RsigmaBatch([sagan_doc], workdir=probe / f"s{index}").evaluate(
            [witness]
        )[0]
        sigmahq_hit = RsigmaBatch([sigmahq_doc], workdir=probe / f"h{index}").evaluate(
            [witness]
        )[0]

        assert str(sagan_doc["id"]) in sagan_hit, (
            f"witness for SID {verdict.sagan_sid} does not fire the converted rule"
        )
        assert str(sigmahq_doc["id"]) in sigmahq_hit, (
            f"witness for SID {verdict.sagan_sid} does not fire "
            f"{verdict.sigmahq_title!r}"
        )
