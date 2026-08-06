# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `sagan2sigma-overlap`, a behavioural comparison between the converted rules
  and the SigmaHQ corpus that establishes coverage by testing rather than by
  textual similarity: every rule from both sets is turned into events that
  satisfy it, and the RSigma engine decides which rules each event fires in a
  single pass. It reports, for each converted rule, whether a SigmaHQ rule
  already covers it, with a witness event attached to every verdict. Two
  safeguards keep the verdicts honest against the engine not enforcing
  logsource: a negative-control screen removes rules that fire on the empty
  event, since they match on absence rather than on shared detection, and a
  log-source-compatibility gate keeps a SigmaHQ keyword rule from being counted
  as covering a rule from another product whose raw text merely shares a word.
  On the upstream corpora this is the difference between a spurious 7,879
  "covered" and the 58 deployable ones. Installed with the `overlap` extra
  (`pip install "sagan2sigma[overlap]"`), which adds `hypothesis` and `exrex`.
  The method, taxonomy and results are documented in `docs/SIGMAHQ-OVERLAP.md`.
  Synthesised events are cached (`--cache`), keyed by a hash of the detection
  block, so re-runs against a moved corpus are cheap. The analysis carries its
  own invariant tests, including a self-validation that replays every covering
  verdict's witness event against each rule on its own and requires both to
  fire, run both on hand-built pairs and, opt-in, over the real corpora.
- `sagan2sigma-conceptual`, a separate lexical analysis that proposes review
  candidates: converted rules that look like they detect the same thing as a
  SigmaHQ rule, from the distinctive terms they search for (IDF-weighted) and
  their shared ATT&CK techniques, which the behavioural analysis cannot reach
  because raw-text and structured-field rules never fire the same event. It is
  explicitly not tested equivalence and never grounds for retiring a rule; the
  two analyses are almost disjoint on the upstream corpora (11 of 1,346
  conceptual candidates also appear behaviourally). Pure standard library, no
  engine, deterministic. Documented in `docs/CONCEPTUAL-OVERLAP.md`.
- `sagan2sigma-inventory`, which merges the behavioural and conceptual reports
  into one confidence-tiered list of overlapping rule pairs, each placed in the
  single strongest tier its evidence earns, from "confirmed by both analyses"
  down to "conceptual candidate, weaker match". Every inventory is pinned to the
  exact commit of each rule corpus it was built from, since both change daily
  and an unpinned list rots silently. A generated snapshot is committed at
  `docs/OVERLAP-INVENTORY.md`.

### Fixed

- Regular expressions using lookahead, lookbehind or backreferences, and
  character classes containing an escaped hyphen, were emitted despite the Rust
  `regex` engine behind RSigma refusing all of them. Because one uncompilable
  rule aborts the entire rule load, the 34 affected rules made the whole
  converted ruleset undeployable. `validate_regex` now rejects them, and the
  full corpus loads with zero refusals.
- The README opened with `pip install sagan2sigma`, which fails because the
  project is not published. Replaced with the install-from-source instructions
  that work today, and added `RELEASING.md` covering publication.
- The declared `pyyaml` floor was 6.0, which no resolver can satisfy alongside
  pysigma's own `pyyaml>=6.0.3`. Corrected to 6.0.3.

## [0.1.0]

First public release.

### Added

- Sagan rule parser matching the engine's own tokenisation, including the
  quote-agnostic option splitting that lets it read the roughly 175 upstream
  rules carrying an unbalanced double quote.
- Handlers for 25 Sagan keywords across five families, registered individually
  so that adding one keyword means adding one module and one test file.
- Two output profiles, `rsigma-syslog` and `vector-json`, parameterising every
  field name so the same corpus can target either ingestion chain.
- `json_map` aware field resolution: `content` and `pcre` follow a
  `json_map: "message", ".key"` redirection instead of searching the raw body.
- Correlation support: `after` becomes a Sigma `event_count` correlation, and
  `xbits`/`flexbits` state machines are rebuilt through synthetic aggregate
  rules with a `temporal_ordered` correlation.
- Logsource catalog mapping rule file names onto a Sigma logsource and a report
  category.
- Markdown and JSON conversion reports covering every refusal, every semantic
  loss and every unknown keyword.
- pySigma validation of every emitted document, on by default.
- Deterministic output: stable UUIDs derived from the Sagan SID and
  insertion-ordered YAML, so consecutive runs produce reviewable diffs.
- `--case-policy` to choose between reproducing Sagan case sensitivity exactly
  and trading it for recall.
- A `vector-enriched` profile and a bundled VRL library. `sagan-parse-ip.vrl`
  is a faithful port of the engine's `Parse_IP()`, including the both-sides
  separator handling that makes Cisco ASA lines resolve, and it preserves
  address position so `parse_src_ip: 2` converts against the second address
  rather than any address. This takes `E_GROUPBY_UNRESOLVED` from 313 rules to
  14 and the conversion rate from 81.8% to 84.8%.
- `--emit-vector-config`, implied by the enriched profile, writing a runnable
  Vector pipeline so the rules and the transforms they depend on ship together.
- A differential test suite comparing converted-rule behaviour against an
  independent reference evaluator of Sagan semantics and the real rsigma
  engine, over generated events rather than hand-written expectations.

### Not yet verified

- The bundled VRL is executed against Vector in CI, but the emitted Sigma has
  not been executed against a running RSigma instance.
  pySigma validation proves the output is valid Sigma; it does not prove the
  rules match the same events the Sagan originals matched.
- There is no differential test comparing converted-rule behaviour against the
  Sagan engine.

### Known limitations

- Sagan `pass` rules are refused rather than converted; see
  `docs/DESIGN-DECISIONS.md`.
- Positional keywords (`offset`, `depth`, `distance`, `within`) have no Sigma
  equivalent and are refused.
- External enrichment lookups (Bluedot, GeoIP, blacklists, Zeek Intel) are out
  of scope for a detection-rule converter.
