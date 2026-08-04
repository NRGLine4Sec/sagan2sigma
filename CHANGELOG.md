# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
