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
  two analyses are almost disjoint on the upstream corpora (11 of 1,794
  conceptual candidates also appear behaviourally). Pure standard library, no
  engine, deterministic. Documented in `docs/CONCEPTUAL-OVERLAP.md`.
- `sagan2sigma-inventory`, which merges the behavioural and conceptual reports
  into one confidence-tiered list of overlapping rule pairs, each placed in the
  single strongest tier its evidence earns, from "confirmed by both analyses"
  down to "conceptual candidate, weaker match". Every inventory is pinned to the
  exact commit of each rule corpus it was built from, since both change daily
  and an unpinned list rots silently. A generated snapshot is committed at
  `docs/OVERLAP-INVENTORY.md`.
- The upstream corpus, already converted with the default `rsigma-syslog`
  profile, is committed under `converted/`, so the rules can be used without
  installing the project. `converted/VERSIONS.md` records each iteration by a
  version id (the short hash of the `sagan-rules` and `sagan2sigma` commits it
  was built from) with that corpus commit's date, so a reader sees how old the
  rules are. A scheduled workflow, `.github/workflows/convert-rules.yml`, and
  the `tools/refresh_converted_rules.py` script it runs, reconvert the whole
  corpus whenever it moves and commit only when the output changes, so rules
  modified or removed upstream are reflected, not only new ones.

### Added

- `blacklist` and `zeek-intel` rules now convert under `--profile vector-enriched`
  instead of being refused. Both fire when a parsed address is on an external
  feed: `blacklist` an IP denylist (`src/processors/blacklist.c`), `zeek-intel` a
  Zeek Intelligence Framework feed (`src/processors/zeek-intel.c`). The bundled
  `sagan-denylist.vrl` and `sagan-zeek-intel.vrl` flag each parsed address a feed
  lists, and the rule matches that flag; `by_src`/`by_dst`/`both`/`all` map to the
  positions the engine tests, `all` and `both` as a disjunction through a new
  `ConditionGroup`. The feeds are external and change constantly, so nothing is
  bundled: the enrichment tables are Vector's `mmdb` type, and
  `tools/fetch_cti.py` downloads the recommended public feeds and builds both
  MMDBs, with `tools/build_denylist_mmdb.py` doing the feed-to-MMDB step for a
  feed of your own, feed-agnostic like GeoIP. The Sagan docs' own public feeds
  still work, SANS DShield for the denylist and, since Critical Stack closed,
  CriticalPathSecurity's Zeek-Intelligence-Feeds for zeek-intel, plus a CC0
  alternative (abuse.ch Feodo Tracker); CI builds a database with the tool and
  runs the transforms against real Vector. A `blacklist: by_username` sets no flag
  in the engine and is inert, so it is dropped (`D_DENYLIST_USERNAME_INERT`); the
  address forms carry `D_DENYLIST_ENRICHMENT` / `D_ZEEK_INTEL_ENRICHMENT`. See
  `docs/DESIGN-DECISIONS.md` and `docs/PIPELINE.md`.
- `alert_time` rules now convert under `--profile vector-enriched` instead of
  being refused. The bundled `sagan-time.vrl` transform derives the weekday and
  the HHMM-integer time from the event timestamp, exactly the two values Sagan's
  `Check_Time` compares (`src/aetas.c`), and the window becomes a match on them.
  The engine compares HHMM as an integer, so the hour range is reproduced exactly,
  minute boundaries included. A window crossing midnight fires in the evening on
  the alert days and in the morning on those days and the day after each, which a
  flat conjunction cannot express, so a new `ConditionGroup` in the IR carries the
  disjunction and the emitter folds it into the condition. The clock is the one
  loss: Sagan reads the wall clock at processing time in local time, so the
  converted rule carries `D_ALERT_TIME_EVENT_CLOCK`. Verified case by case against
  the RSigma engine, boundaries and the midnight rollover included.
- `country_code` (GeoIP) rules now convert under `--profile vector-enriched`
  instead of being refused. The bundled `sagan-geoip.vrl` transform enriches each
  parsed address with its country (`sagan_geoip_country_N`), and the rule becomes
  a match on that field. `isnot` keys its presence test on the address, not the
  country, so it still fires on a private or unresolved address whose country is
  empty, matching `src/geoip.c`. The enrichment is provider-agnostic: the emitted
  `vector.yaml` uses Vector's `mmdb` enrichment type, which reads any database in
  the MaxMind file format, so DB-IP IP-to-Country Lite (the documented default,
  CC BY 4.0, no licence key), MaxMind GeoLite2-Country and IPLocate all drop in by
  path alone. The transform reads the ISO code from either the nested
  `country.iso_code` (MaxMind, DB-IP) or the top-level `country_code` (IPLocate).
  The database is not bundled; the config points at a placeholder path, and the
  transform is emitted only when the corpus uses `country_code`. This adds 134
  rules under the enriched profile (89.4% to 90.8%) once a `$HOME_COUNTRY` value
  and the database are supplied, and the converted rules carry the new
  `D_GEOIP_COUNTRY_ENRICHMENT` degradation. CI runs the transform through real
  Vector against both DB-IP and IPLocate data, and the emitted Sigma is checked
  against the RSigma engine directly. See `docs/DESIGN-DECISIONS.md`.

### Changed

- `pass` rules are now converted as ordinary `alert` rules instead of being
  refused with `E_PASS_RULE`. The previous refusal assumed `pass` was a silent
  whitelist, the Snort and Suricata reading. The Sagan engine disagrees: the
  detection loop in `src/processors/engine.c` calls `Send_Alert` for a matching
  rule and only afterwards checks the action, and `Send_Alert` (`src/send-alert.c`)
  never consults the rule type, so a matching `pass` rule emits an alert and then
  short-circuits the rules that follow it for that event. Its detection is
  therefore faithful; only the short-circuit, the suppression of other rules on
  the same event, cannot be reproduced under RSigma's independent evaluation, and
  it is recorded as the new `D_PASS_SHORT_CIRCUIT` degradation. This recovers 515
  rules, the single largest block the tool used to drop, and lifts the upstream
  conversion rate from 81.5% to 86.6% (89.5% with `vector-enriched`). The
  differential harness covers the recovered rules and reports no disagreement.
  `E_PASS_RULE` is retained in the taxonomy for compatibility but is no longer
  emitted. See `docs/DESIGN-DECISIONS.md`.
- Rules whose only positional constraints are zero-valued are now converted
  rather than refused. The Sagan engine guards every `offset`, `depth`,
  `distance` and `within` with `if (value != 0)` (`src/content.c`,
  `src/meta-content.c`), so `distance:0` and its kin are no-ops: the search runs
  over the whole message, exactly as a bare `content` does, and `within` is inert
  without a non-zero `distance`. Reading `distance:0` as an ordering constraint,
  which the inherited Snort documentation suggests, would emit a rule that misses
  events the original matches, so a rule with only inert positionals is converted
  faithfully as independent `|contains` predicates. Only a non-zero `offset`,
  `depth` or `distance`, a real byte position Sigma cannot express, is still
  refused. This clears 245 positional refusals and lifts the upstream conversion
  rate from 79.0% to 81.4% (8,135 of 9,997 rules; a handful of the un-blocked
  rules then meet a different, genuine refusal). The differential harness now
  covers them and reports zero disagreements. See `mapping/positional.py` and
  `docs/DESIGN-DECISIONS.md`.

### Fixed

- Regular expressions using lookahead, lookbehind or backreferences were emitted
  despite the Rust `regex` engine behind RSigma refusing all of them. Because one
  uncompilable rule aborts the entire rule load, the affected rules made the
  whole converted ruleset undeployable. `validate_regex` now rejects them, and
  the full corpus loads with zero refusals.
- An escaped hyphen inside a character class, `[\!\-\%]`, was refused as
  non-portable, but the RSigma versions this targets compile it and match it
  exactly as Python does. The over-cautious check was removed, recovering the
  rules it had refused. `validate_regex` was verified against the engine over
  every `pcre` in the corpus: it now refuses exactly the regexes RSigma rejects,
  no more and no fewer.
- A `pcre` containing a `{` that is not a counted repetition, such as `{\d}`,
  was emitted verbatim: Python's `re` reads it as a literal brace, but the Rust
  `regex` engine rejects it and aborts the whole rule load. Two such rules were
  exposed once the positional un-blocking let them convert. `has_unsupported_brace`
  now refuses them; the check was verified against the engine over every `pcre`
  in the corpus, catching all 19 it rejects with no false positives.
- `meta_content` is now split the way the engine splits it (`src/rules.c`),
  taking the first comma-delimited token as the helper and stripping its quotes
  with the engine's `Between_Quotes`, rather than with a regex that assumed the
  comma sat outside the quotes. This recovers 3 rules that were refused with
  `E_PARSE` because they wrote their values inside the quotes, and, more
  importantly, corrects 72 Cisco ASA/FWSM rules whose `""%sagan%"` helper made
  the regex emit a search for `"%ASA`, a leading quote no real ASA log carries,
  so they matched nothing. Values are now kept verbatim, since the engine does
  not trim them either. All are covered by the differential harness with no
  disagreement.
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

- Positional keywords (`offset`, `depth`, `distance`, `within`) have no Sigma
  equivalent and are refused.
- External enrichment lookups (Bluedot, GeoIP, blacklists, Zeek Intel) are out
  of scope for a detection-rule converter.
