# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `flexbits` correlations grouped on the source address whatever direction the
  rule named. `flexbits` states its direction as a bare token where `xbits`
  writes `track ip_src`, so the pattern that reads the tracking key never
  matched a `flexbits` option and every one of them fell through to the
  `ip_src` default. On the upstream corpus that put nine correlations on an
  address where Sagan keys on the user: a different detection, not a narrower
  one. `by_dst`, `both` and `username` now resolve to the field they name.
- `flexbits` directions that Sigma cannot state are refused instead of being
  grouped on the source address. `none` sets a global bit with no key at all,
  `reverse` compares one event's source against another's destination, and the
  `_p` forms add the port to the key. One corpus rule is affected, and it now
  refuses with `E_GROUPBY_UNRESOLVED` rather than converting into something
  that correlates on the wrong thing.
- The list of `flexbits` tracking keys held six of the fourteen tokens
  `Flexbit_Type()` accepts. An unrecognised one is silently taken for the bit
  name, so the correlation would be rebuilt around a bit no rule ever sets. No
  corpus rule uses the missing eight, but the corpus is an input, not a
  specification. Verified against the engine: all fourteen load and anything
  else is rejected.
- `--sagan-yaml` aborted on Sagan's own `etc/sagan.yaml`. That file separates
  values from inline comments with tabs and ends one line with a tab, which
  libyaml accepts and PyYAML refuses to scan, so the flag whose documented use
  is to point at a stock install failed on one, and failed with a traceback
  rather than a message. Tabs outside quoted scalars are now normalised, tabs
  inside them are preserved, an indentation tab is still an error, and a
  malformed file names itself.

### Changed

- `docs/DESIGN-DECISIONS.md` records an engine defect that makes converted
  `flexbits` correlations fire where Sagan is silent. The address directions
  compare the printable address buffer rather than the binary form the struct
  also carries, sixteen bytes of it, so the result depends on the bytes
  following the address in the message rather than on the address. Reproducing
  it is not an option; it is documented instead.

## [0.2.0] - 2026-08-21

### Added

- Two verification layers for the regular expressions the converter emits, which
  were until now the one keyword family never checked against the engine at
  runtime. `tests/integration/test_engine_load.py` hands RSigma each committed
  rule set whole and requires a clean compile: the engine aborts the entire load
  on one bad rule, so a single non-portable pattern takes the whole detection set
  offline rather than costing one rule, and nothing checked that before (the
  corpus job validates with pySigma, a different and more permissive parser).
  `tests/differential/test_regex_semantics.py` then extracts every distinct `|re`
  pattern from the committed sets, 233 today, generates probes for each (matches
  via `exrex`, near misses by mutation, noise from the pattern's own literals)
  and requires Python's `re` and the real `rsigma` binary to agree on every
  pattern/event pair, about 2.8 million of them in under a second by feeding the
  engine NDJSON on stdin. Both carry a test proving they can fail. Running the
  differential over unrestricted input surfaced a genuine engine difference, now
  documented: Sagan compiles PCRE in byte mode (`PCRE_UTF8` is commented out in
  `src/rules.c`) so its `\w` is ASCII, while the Rust engine is Unicode-aware, so
  the two disagree on non-ASCII content. See `docs/DESIGN-DECISIONS.md`.
- `bluedot` rules now convert under `--profile vector-enriched`, the project's one
  deliberate break from faithful conversion. Bluedot is Quadrant's closed
  commercial threat-intelligence API, which cannot be integrated legally and has
  no faithful reproduction; a bluedot rule left refused can never fire under
  RSigma at all. So its `ip_reputation` lookup is SUBSTITUTED: each parsed address
  is matched against open-source feeds you supply, one MMDB per Bluedot category
  (Tor, Proxy, Malicious, Honeypot), via the new `sagan-bluedot.vrl` transform,
  and the rule becomes a disjunction over every (tracked position, category) flag.
  The rule fires on your feeds, not on Bluedot: Tor is near-authoritative (the Tor
  Project exit list is the same public ground truth Bluedot derives from), the
  other categories diverge, and every converted rule carries the loud
  `D_BLUEDOT_SUBSTITUTION` degradation saying so. This recovers 134 rules of the
  upstream corpus (the address-tracking ones with a parsed position); hash and URL
  lookups need a non-address enrichment table and stay refused, as do bluedot
  rules whose address the converter cannot position. The four category tables are
  emitted only when the corpus uses bluedot, built with
  `tools/build_denylist_mmdb.py` like the denylist. This is an assumed compromise
  and explicitly not a precedent; the reasoning and its engine basis are in
  `docs/DESIGN-DECISIONS.md`.
- `pcre` (and `json_pcre`) patterns the Rust engine spells differently are now
  rewritten into the equivalent accepted form instead of being refused with
  `E_PCRE_UNSUPPORTED`: a numbered subroutine `(?N)` is inlined as `(?:...)`, a
  literal `{` that is not a counted repetition is escaped, the whole-string
  `^((?!X).)*$` idiom becomes a negated search for `X`, and a flag Sagan silently
  ignores (no default case in its flag switch, e.g. the inert `H`) is dropped
  rather than refused. Each rewrite was fuzzed against a PCRE oracle with zero
  divergence and its output confirmed to load in RSigma; together they recover 9
  rules of the upstream corpus and change no other rule's output. Constructs with
  no faithful rewrite (recursion, look-around used as an embedded assertion,
  back-references, control verbs, and the IP-range look-around negations that only
  a lossy enrichment approximation could reach) stay refused on purpose; the
  reasoning is documented in `docs/DESIGN-DECISIONS.md`. A latent hang is fixed in
  passing: a recursive subroutine would have grown without bound during
  expansion, now detected and refused.
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
- The upstream corpus converted with the `vector-enriched` profile is now
  committed under `converted-vector-enriched/`, alongside the default
  `rsigma-syslog` snapshot in `converted/`, and refreshed by the same workflow.
  It carries the rules, the conversion report and the runnable Vector pipeline the
  enriched rules depend on. `converted/VERSIONS.md` now records the rate for both
  profiles in one table. Because `country_code` and most `alert_time` rules need
  site-specific variables (`$HOME_COUNTRY`, `$SAGAN_DAYS`), they are refused with
  `E_VAR_UNRESOLVED` in the committed snapshot; regenerate with your `sagan.yaml`
  to include them. See `converted-vector-enriched/README.md`.
- Rules that search the raw body with `content`, `pcre` or `meta_content` while
  also using JSON operators now convert under `--profile vector-enriched` instead
  of being refused with `E_RAW_TEXT_ON_JSON_EVENT`. RSigma keeps no raw string
  once it has parsed a JSON body, so the raw search had nothing to run against;
  the new first transform, `data/vrl/sagan-json.vrl`, copies the body into
  `sagan_raw` verbatim and lifts the JSON object's keys to the top level, so
  `json_content` targets the lifted key and the raw search targets `sagan_raw`,
  the exact string Sagan itself searched. A profile opts in by naming the field
  in a new `json_raw` key, so the default `rsigma-syslog` profile is unchanged and
  still refuses. This clears all 386 `E_RAW_TEXT_ON_JSON_EVENT` refusals; 255
  convert outright and 131 surface a different pre-existing blocker the refusal was
  masking, lifting the enriched rate by 255, from 90.1% to 92.7% (9,010 to 9,265
  rules). Because the raw body is preserved byte for byte, the match is
  faithful to the serialization Sagan saw, including serialization-specific
  patterns such as CloudTrail's `"mfaAuthenticated": "true"`; the converted rule
  carries `D_RAW_TEXT_MATCH` to record that the match is format-bound. Proven end
  to end, a JSON event through real Vector then the converted rule in the RSigma
  engine, and the transform is executed against a real Vector binary in CI. See
  `docs/DESIGN-DECISIONS.md` and `docs/PIPELINE.md`.
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

- The per-rule listings under "Refused rules" in `CONVERSION-REPORT.md` are now
  behind click-to-open blocks, one per refusal code. The section runs to
  thousands of rows on the upstream corpus, which buried the part a reader
  actually scans first. The heading and its explanation stay outside the block,
  so the counts and the reason for each refusal are still visible at a glance,
  and only the listing folds away. This uses HTML `<details>`, since Markdown has
  no such construct: renderers that pass inline HTML through (GitHub, GitLab, the
  common editors) show a real disclosure widget, and one that strips HTML shows
  the table as before, so nothing is ever hidden from a reader whose viewer does
  not support it.
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

- `docs/DESIGN-DECISIONS.md` and `docs/PIPELINE.md` quoted stale and mutually
  inconsistent counts for the normalization trade-off: 88 and 78 rules carrying
  `D_NORMALIZE_PRECEDENCE` against 80 in the shipped report, and 14 refused
  against 9. Both now match `converted-vector-enriched/CONVERSION-REPORT.md`.
  The precedence itself, that liblognorm overrides `parse_src_ip` when it
  resolves an address and positional parsing only fills what it left unset, is
  now established by running a real Sagan engine on messages where the two
  mechanisms name different hosts, rather than by reading the guard in
  `engine.c`.
- `after: count N` now emits a Sigma threshold of `N+1`, because that is when
  Sagan alerts. `src/after.c` seeds its tracking entry with `count = 1` on the
  first match and alerts only while `after2_count < count`, a strictly-greater
  comparison: N events pass in silence and the next one alerts. A Sigma
  `event_count` with `gte: N` fires as soon as the window holds N, one event
  early, so all 970 corpus correlations were slightly more trigger-happy than
  the rules they came from. The title keeps the rule's own number. This document
  had asserted "alert from N+1" since the beginning while the code emitted
  `gte: N`. Settled by running both engines on the same six events, repeatedly
  and from a clean state: Sagan alerts from the N+1th for every N tested, and
  rsigma reproduces it exactly once the threshold is raised.
- `track by_string` in an `after` correlation no longer refuses the rule, and
  does not group on the username either: it is inert there. The two correlation
  parsers disagree, and only the C shows it. `threshold` tests the intact option
  token, so there `by_string` really is a synonym for `by_username`, while
  `after` calls `strtok_r` first and then tests a token already truncated to
  `"track"` (`src/rules.c`), so its `by_string` branch can never fire. `after`
  therefore drops the key, recording `D_AFTER_BY_STRING_INERT`, and refuses a
  rule whose only key is `by_string`, because Sagan rejects that at load. Five
  corpus rules are recovered under `--profile vector-enriched`, grouping on the
  source alone. Settled by building the engine and running it, after an earlier
  reading had mapped `by_string` to the username for both keywords.
- `blacklist`, `zeek-intel` and `bluedot` tracking `both` now require both
  addresses to be present, not just either one to be listed. Every `both` branch
  in `src/processors/engine.c` is gated on
  `ip_src_is_valid == true && ip_dst_is_valid == true`, so an event carrying only
  one of the two is never tested, even when that address is on the feed; the
  converter emitted a bare disjunction and would have fired. No corpus rule uses
  `both`, so nothing shipped wrong. Found while extending the engine-backed
  checks to the remaining enrichment families, and pinned by
  `tests/differential/test_intel_semantics.py`, which covers all three against
  the real engine: a listed address fires, an unlisted or absent one stays
  silent, and bluedot matches only the categories its rule lists.
- `country_code: ... isnot` no longer fires on an address the pipeline could not
  place, which it did for every RFC1918 one. The converted rule required the
  *address* field to exist and then negated the country list, on the reading that
  "no country" satisfies "not in this list". The engine disagrees:
  `GeoIP2_Lookup_Country` returns `GEOIP_SKIP` from every path that cannot
  determine a country (non-routable, `skip_networks`, lookup failure, absent from
  the database), `engine.c` compares only when the result is not `GEOIP_SKIP`, and
  `routing.c` then drops the rule. Both `is` and `isnot` therefore require a
  resolved country, and the emitted rule now requires the **country** field to
  exist. 138 corpus rules are convertible with `isnot`, all of the "connection
  from outside $HOME_COUNTRY" kind, so before this they alerted on all internal
  traffic. The committed snapshots never showed it, since those rules need
  `$HOME_COUNTRY` from a site `sagan.yaml` and are otherwise refused with
  `E_VAR_UNRESOLVED`: only users converting with their own configuration were
  affected. `tests/differential/test_geoip_semantics.py` pins the full truth
  table against the real engine.
- The declared `pysigma` floor moves from 1.0 to 1.1.0. Up to 1.0.2 pySigma's
  rule-condition parser calls pyparsing's `parseString`, which current pyparsing
  deprecates; 1.1.0 switched to `parse_string`. This is a genuine floor problem
  rather than a test artefact, since the old spelling will eventually be removed
  from pyparsing and take pySigma 1.0.x with it. The minimum-versions CI job,
  which pins the declared floor and is what surfaced this, is pinned to match.
- `country_code` rules that track an address the engine can never resolve (no
  `parse_src_ip` / `parse_dst_ip`, no `json_map` binding of the address, no
  `normalize`) are now refused as `E_NO_DETECTION` instead of the misleading
  `E_EXTERNAL_ENRICHMENT`. The engine only geo-locates an address it marked valid
  (`src/processors/engine.c`), and with no source that flag is never set, so the
  lookup is skipped and `src/routing.c` drops the rule: it can never fire, so no
  enrichment could recover it. Two upstream rules are reclassified; the honest
  reason replaces one that implied they were recoverable. The wider analysis of
  why the `country_code by_src` family (which geo-locates a per-rule `json_map`
  JSON field, is gated on `$HOME_COUNTRY`, and depends on engine behaviours Vector
  cannot reproduce) stays an architectural refusal is documented in
  `docs/DESIGN-DECISIONS.md`.
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
