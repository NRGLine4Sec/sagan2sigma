# Contributing

## Adding support for a Sagan keyword

The conversion layer is a registry of independent handlers, so adding a keyword
touches exactly two files.

1. Write the handler in the module matching its family, or a new module under
   `src/sagan2sigma/mapping/`:

   ```python
   @handler("my_keyword")
   def handle_my_keyword(rule, draft, context, resolver, policy):
       """One line on what the keyword does in Sagan, then how it maps."""
   ```

2. Register the module in `src/sagan2sigma/mapping/__init__.py` if it is new.
3. Write `tests/unit/test_<module>.py` covering the keyword's behaviour,
   including its failure modes.
4. Add a row to the table in `docs/MAPPING.md`.
5. Add a fixture rule to `tests/fixtures/rules/synthetic.rules` and refresh the
   golden files with `pytest --update-golden`.

If a keyword has no faithful Sigma equivalent, do not approximate it. Add a
`RefusalCode` and refuse. A missing rule is recoverable; a rule that looks
right and matches the wrong thing is not.

## Ground rules

- **Match the engine, not the documentation.** Where the two disagree, the C
  source in `quadrantsec/sagan` wins, and the divergence goes in a comment.
  `docs/DESIGN-DECISIONS.md` lists the cases found so far.
- **Never silently drop a keyword.** Anything the converter does not handle
  must surface as a refusal or a degradation in the report.
- **Every semantic loss gets a `DegradationCode`.** If the converted rule does
  not do exactly what Sagan did, the report has to say so.
- **Determinism is a feature.** Output must be byte-identical between runs.
  No timestamps, no iteration over unordered sets, no random identifiers.

## Running the checks

```sh
pip install -e ".[dev]"

pytest                      # unit, property, golden and integration tests
pytest --update-golden      # refresh golden files after an intended change
ruff check src tests
ruff format src tests
mypy
```

The corpus invariant tests need a checkout of the upstream rules:

```sh
git clone --depth 1 https://github.com/quadrantsec/sagan-rules.git /tmp/sagan-rules
SAGAN_RULES_DIR=/tmp/sagan-rules pytest tests/integration/test_corpus.py -v
```

Those tests are where every serious defect in this converter has been found so
far. Run them before opening a pull request.

## Licence

By contributing you agree that your work is licensed under GPL-2.0-only, the
same terms as the project.
