"""Golden-file tests.

The unit tests assert on individual fields. These assert on the exact bytes of the
emitted YAML, which is what a reviewer actually reads and what a downstream Git
diff actually sees. Any change in formatting, key order or identifier generation
shows up here first. Refresh the expected files with:: pytest
tests/integration/test_golden.py --update-golden
"""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURES

from sagan2sigma.converter import Converter
from sagan2sigma.emit.yaml_io import dump_collection
from sagan2sigma.mapping.context import Context
from sagan2sigma.mapping.values import CasePolicy

RULES = FIXTURES / "rules" / "synthetic.rules"
GOLDEN = FIXTURES / "golden"


CASES = {
    "rsigma-faithful": ("rsigma-syslog", CasePolicy.FAITHFUL),
    "rsigma-relaxed": ("rsigma-syslog", CasePolicy.RELAXED),
    "vector-faithful": ("vector-json", CasePolicy.FAITHFUL),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_output_matches_golden(
    case: str, context: Context, vector_context: Context, request
) -> None:
    profile_name, policy = CASES[case]
    active = vector_context if profile_name == "vector-json" else context
    result = Converter(context=active, case_policy=policy).convert_paths([RULES])
    rendered = dump_collection(result.documents)

    expected = GOLDEN / f"{case}.yml"
    if request.config.getoption("--update-golden", default=False):
        expected.parent.mkdir(parents=True, exist_ok=True)
        expected.write_text(rendered, encoding="utf-8")
        pytest.skip(f"golden file refreshed: {expected.name}")

    assert expected.is_file(), (
        f"missing golden file {expected}; run pytest --update-golden"
    )
    assert rendered == expected.read_text(encoding="utf-8")


def test_golden_files_are_valid_yaml() -> None:
    import yaml

    for path in sorted(GOLDEN.glob("*.yml")):
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        assert documents, f"{path.name} is empty"
        assert all(isinstance(document, dict) for document in documents)


def test_faithful_and_relaxed_differ_only_on_case() -> None:
    """The relaxed policy must change nothing but the |cased modifier."""
    faithful = (GOLDEN / "rsigma-faithful.yml").read_text(encoding="utf-8")
    relaxed = (GOLDEN / "rsigma-relaxed.yml").read_text(encoding="utf-8")
    assert faithful.replace("|cased", "") == relaxed
