# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `sagan-parse-ip.vrl` and `username-extraction.vrl` read the raw body from
  `sagan_raw` rather than `message`, so a JSON-bodied event keeps its parsed
  addresses and username. Dropping `.message` from a JSON event, which the
  envelope fix below does, left both transforms reading a field that was no
  longer there: they produced nothing at all, and 37 corpus rules that match on
  or group by a derived field could not fire under `vector-enriched`. Found by
  the corpus differential once the denylist and Zeek intel feeds were enabled,
  12 rules disagreeing on the same shape. The chain is now tested as a chain:
  testing each transform alone is what let one transform's output stop being
  the next one's input.
- The `vector-enriched` pipeline no longer lets the syslog envelope overwrite a
  JSON body's own fields. `data/vrl/sagan-json.vrl` lifts a JSON body's keys to
  the top level, where the envelope already sat, and the envelope won every
  collision: measured with Vector 0.39, a Netskope event carrying
  `"severity": "Low"` came out of the transform holding the syslog severity
  instead. 131 corpus rules match on a shadowed `severity` and one on
  `hostname`, so they could never fire, and nothing said so because both the
  converted rule and the pipeline were valid. The transform now renames the
  envelope to `syslog_appname` / `syslog_hostname` / `syslog_facility` /
  `syslog_severity` before merging the body in, and drops `.message`, whose
  content `sagan_raw` holds byte for byte. The profile's `json_envelope` names
  the same fields, which also makes a JSON-bodied rule select the same envelope
  under `vector-enriched` as under `rsigma-syslog`.

  A pipeline built from an earlier version of the VRL must be updated together
  with the rules, `sagan2sigma --emit-vector-config` writing both.
- The reference evaluator now clips JSON keys as the engine's key table does,
  30 characters, instead of walking the document. Upstream has started
  rewriting rules whose key path exceeds the limit and recording the original
  above them, and against such a corpus the evaluator reported a rule as dead
  that the engine matches. The corpus differential also excludes rules that are
  dead upstream, the same three defect codes the engine differential excludes,
  which is where a rule naming a path the engine never stores now belongs.

### Added
- `U_PARTIAL_MATCH`, an upstream defect for a rule that loads, fires, and lists
  a value that can never match, so it detects less than it names.
- A detector for a comma inside a quoted `meta_content` template. `rules.c`
  cuts the option with `strtok_r(arg, ",")` and only then unquotes the first
  piece, so the template ends at that comma and everything after it, closing
  quote included, is pushed into the value list. Measured in all three of its
  consequences: the template silently loses its tail; the first listed value
  inherits the stray quote and can never match, which costs
  `windows-sysmon.rules` its `\powershell` alternative in two rules while
  `\pwsh.exe` still fires; and with a `$variable` among the values nothing
  matches at all, which kills two more. Found by the corpus differential once
  the engine's own `sagan.yaml` was loaded, sid 5009779 firing on the converted
  side and never on Sagan's.
- A golden file for `vector-enriched`, the only profile whose JSON-bodied rules
  name a different envelope from its plain ones.
- `U_INERT_CONDITION`, an upstream defect for a rule that loads, fires, and
  carries a condition the engine can never satisfy, so it fires more widely
  than it reads. The first case is a value list whose items are wrapped in
  quotes: `meta_content` and `json_meta_content` compare each item verbatim,
  quotes included, unlike `content` and `json_content` whose quotes delimit the
  argument. Measured both ways on the engine. One corpus rule is affected, sid
  5014486 of `fortinet-json.rules`, whose negated `"analytics"` excludes a
  value no producer emits, so the exclusion never fires. A list whose items are
  all quoted and *not* negated is reported as `U_CANNOT_MATCH` instead, the
  condition then being required rather than excluded.

## [0.4.0] - 2026-09-07

### Added
- A report section listing upstream rules that do not work in Sagan, and the
  `sagan2sigma.upstream` module behind it. Every other part of this tool asks
  whether the conversion is faithful; this asks whether the rule it started
  from ever worked, which no comparison against a running Sagan can reveal,
  because a dead rule and its faithful conversion agree by staying silent.
  On the upstream corpus: 752 rules that load and can never fire, 1 that makes
  the engine refuse to start, and 4 that fire while grouping on fewer keys than
  they name. Each detector rests on an engine behaviour measured by execution,
  and the module says which. Judging whether a working rule detects anything
  useful is out of reach and stated as such.
- A detector for a `|` that opens a hex sequence and never closes it, in the
  four options Sagan expands with `Content_Pipe`. What that produces is not
  guessable from the syntax: `alpha|` matches, `|alpha` makes the engine refuse
  the ruleset, and `alpha|4` loads and searches for a trailing 0x04 that no
  message carries. Four upstream rules take the third path, all in
  `crowdstrike.rules`, where `content:"|7c|DetectionSummaryEvent|4"` means to
  search for `|DetectionSummaryEvent|4`. The corpus figure above includes them.
- Four more upstream detectors, each resting on a behaviour measured against a
  running engine rather than read from it, and each found by following a
  disagreement the engine differential reported.
  - A `content` or `program` option missing its `;`. The argument runs to the
    next semicolon, so the following option is swallowed into it and the rule
    matches nothing at all, not even its own literal. 15 corpus rules, twelve
    of them consecutive in `web-attack.rules`.
  - A header protocol a syslog event cannot satisfy. Measured: `any`, `udp` and
    `syslog` match, `tcp` and `icmp` do not, and `default_proto` is what
    supplies the protocol otherwise.
  - A header destination port with no `default_dst_port`. The header ports are
    a matching condition; the addresses, measured in all four combinations, are
    not. An address variable left in the port slot is not a port either, which
    is why the detector recognises port shapes instead of testing for `any`.
  - A `program` whose value contains a space, which no event can satisfy.
  - `pcre:!` under a new `U_INVERTED_CONDITION` code. Sagan has no negation for
    `pcre`: the parser never looks for the `!` and `PcreS` has no flag to
    invert, so the condition asserts what it means to forbid. Measured both
    ways: absent pattern stays silent, present pattern alerts.

### Fixed
- Every rebuilt `xbits` correlation was inert. RSigma 0.21.0 resolves a
  `rules:` entry by name for `event_count` only; for `temporal` and
  `temporal_ordered` it records each hit under the rule id, so a name reference
  matches nothing and the correlation never fires, without a warning. The Sigma
  spec allows either form, so the temporal correlations now reference ids. This
  is a workaround for an engine defect, kept to the one place that needs it and
  marked for reversal; it is reported upstream in
  `rsigma-issues/01-temporal-correlation-rule-names`. Measured on a hand-written
  pair of rules where only the reference style changes, then on the corpus: 9 of
  the 14 judgeable correlations go from never firing to firing.
- A correlation falling back to the syslog sender grouped on `hostname` even
  when the rule targets JSON events, for which RSigma exposes the envelope as
  `syslog_hostname` and no unprefixed `hostname` exists at all. No two events
  ever shared a group key, so the correlation could not pair them. The fallback
  now goes through the field resolver, which already knows the event shape.
  4 correlations were affected.
- Converted rules named a JSON field that no producer emits. Sagan stores a
  dotted key path clipped to 31 characters and compares it with an exact
  `strcmp`, so upstream now writes the clipped name in the rule and records the
  original above it in a comment (`quadrantsec/sagan-rules@6211ab5`). Sigma has
  no such limit and the log carries the full name, so the conversion has to put
  it back; emitting the clipped one produced a rule matching nothing outside
  Sagan. Measured with RSigma on sid 5005921: the clipped
  `data.authorizationInfo.operati` does not match an event carrying
  `data.authorizationInfo.operation`, which is what Confluent emits. The parser
  reads those comments and the conversion restores the real name, reported as
  `D_JSON_KEY_RESTORED`, in `json_content`, `json_meta_content`, `json_pcre`
  and `json_map` alike. 15 rules carry a restored search key and 13 `json_map`
  bindings are corrected, the latter deciding field names and correlation
  group-by keys.

  The comments are the only usable signal: key length says nothing, since
  `data.authorizationInfo.granted` is exactly 30 characters and is a real field
  name sitting in the same rules. The engine differential could not have found
  this either, because the probe generator builds its event from the rule's own
  key, so both sides agree on a name no log carries.
- A `json_content` or `json_meta_content` value is cut by the engine at its
  first colon or comma, the value being taken with `strtok` and never put back
  together, and the converted rule demanded the whole string. Measured:
  `json_content:".K","c:\temp"` matches an event whose key holds exactly `c`
  and not one holding `c:\temp`, and `"TCP NULL, FIN, or XMAS Scan"` searches
  for `TCP NULL`. The truncation is now reproduced and reported as
  `D_VALUE_TRUNCATED`, which makes the converted rule agree with the engine and
  broader than the rule reads. The truncation runs on the raw text, before hex
  escapes are expanded, so a colon written `|3a|` survives it as it does in the
  engine; doing it the other way round would have undone the escape that PR 3
  adds upstream.
- `resolve_references` checked correlation references against `name:` only, so
  the id references above would have been reported as pointing outside the
  batch. It accepts either form now, as the spec does.
- A negated `json_content` or `json_meta_content` fired on events that do not
  carry the key at all. Sagan walks the event's keys and can only satisfy a
  condition on a key it finds, so a missing key fails the rule; Sigma reads
  `not field: value` as satisfied when the field is absent, which is the
  broader reading. Measured against a running engine on
  `json_content:".action","x"; json_content:!".type","pdf"`: no `.type` does
  not fire, `.type` holding something else fires, `.type` holding the forbidden
  value does not. An `exists` guard beside the negation reproduces all three.
  200 upstream rules carry such a condition, and 35 converted files change.
- `tests/differential/sagan_reference.py` modelled the same wrong belief, which
  is why the existing harness reported agreement on those rules. It now
  requires the key to be present, as the engine does.
- `flexbits` setters lost their expiry. The two keywords write it differently
  and only the `xbits` form, `expire N`, was read; `flexbits` puts a bare number
  third, `flexbits: set, name, 532800`, and the engine rejects the rule without
  it. Every `flexbits` setter therefore fell back to the one-day default, so 13
  rebuilt correlations were measured over the wrong window: eight over a day
  instead of eight hours, one instead of six days, and two over a day instead
  of ten and thirty seconds. The window decides whether two events are seen as
  related at all, so the short ones fired far more often than the rule they
  came from.
- `flexbits: set_srcport`, `set_dstport` and `set_ports` were ignored. All
  three set a bit a later `isset` sees, checked against the engine, so
  ignoring them dropped the setter: a correlation rebuilt from an `isset` would
  omit those rules and fire less often, or not at all when every setter uses
  one.
- `xbits: toggle` converted into a rule without the bit. Sagan rejects it at
  load: the branch is commented out in `src/rules.c`, with a 2019 note saying
  the semantics were never settled, so `xbit_type` stays zero and the ruleset
  aborts. The engine's own error message lists the action as valid, and so does
  the upstream rule validator, which is why this looked supported. It now
  refuses.

### Changed
- The README no longer presents the Python differential harness as the whole of
  the behavioural checking. That harness states its own limit, a misreading
  shared between the model and the converter, and the limit was reached: the
  `after` off-by-one across 970 correlations survived it. The engine-backed
  differential that replaced the model is now described alongside it, with what
  each covers.
- `docs/DESIGN-DECISIONS.md` records the engine limits that make a rule search
  for something other than what it says, all found by running the corpus
  through Sagan and RSigma side by side, and says which are reproduced and why.
  A colon truncates a `meta_content` value, so `c:\program files\AVAST\`
  searches for `c`, affecting 734 rules; that one is not reproduced, since
  matching every message containing a `c` is a flood. The same truncation in
  `json_content` and `json_meta_content` is reproduced, the search there being
  scoped to a field rather than the whole message. And a JSON key path over 31
  characters is clipped by the engine, which upstream now works around in the
  rules themselves, so the conversion restores the real name from the comment
  they leave behind.

## [0.3.0] - 2026-08-23

### Added

- `D_JSON_PCRE_ABSENT_KEY`, recording that Sagan treats a key the event does
  not carry as a *match* for `json_pcre`. `JSON_Pcre()` tests only keys that
  exist and returns false only on a failed match, so an absent key falls
  through to `return(true)`. Sigma has the opposite convention, so the
  converted rule is narrower and stays silent on those events. Two corpus rules
  carry it. Reproducing the engine here would mean a disjunction firing on
  every event without the field, which inverts what the rule is written to
  detect, so the divergence is documented rather than mirrored.
  `json_content` and `json_meta_content` do not share the behaviour, which was
  checked at the same time.
- `tests/data/engine-keywords.txt`, the list of rule options Sagan's parser
  recognises, and a test asserting the converter's tables match it. The
  converter's keyword tables are hand-copies of branches in `src/rules.c`, and
  every defect below is one of them having drifted: the drift is silent, the
  corpus does not reveal it, and nothing else in the suite was watching. The
  test fails in both directions and was checked to fail by reintroducing each
  defect.

### Changed

- `meta_content` splitting is now pinned against a running engine. All three
  claims in `docs/DESIGN-DECISIONS.md` hold: the first comma separates helper
  from values wherever it sits, `Between_Quotes` drops every quote it meets so
  a doubled opening quote yields the helper `%sagan%`, and a value keeps the
  stray closing quote a rule leaves on it. The 72 Cisco rules search for `%ASA`
  and match a real `%ASA-2-...` line.
- Correct one imprecise sentence in that section. It said values are kept
  verbatim "because the engine does not trim them either". Whitespace is the
  exception: 156 corpus options write `, value` rather than `,value`, and that
  space does not reach the search, which is what the converter emits too.
  Deeper whitespace cases behave inconsistently in the engine and are now
  explicitly not claimed rather than covered by a sentence that reads as
  though they were.
- `alert_time` is now verified against a running engine rather than read.
  `Aetas()` calls `time(NULL)` and `localtime()`, and both halves of
  `D_ALERT_TIME_EVENT_CLOCK` were measured under a faked clock: an event
  stamped Sunday 03:00 fires a Tuesday-afternoon window when the machine
  believes it is Tuesday afternoon and stays silent on a window matching its
  own stamp, and one fixed instant falls inside a 1400-1500 window in UTC and
  outside it in Tokyo. The degradation text was accurate as written. The
  midnight-crossing branches were checked case by case on `days 2, hours
  1800-0800`, and the emitted condition agrees with the engine on all five
  boundary cases, including the morning half firing on the alert day itself.
- The refusal for an `alert_time` missing its `days` or `hours` called the
  value unrecognised. Sagan recognises an hours-only window, loads it, and can
  never fire it, because the parser only ORs day bits in so the mask stays
  empty. The message now says that. Nothing changes in what converts.
- `docs/DESIGN-DECISIONS.md` records an engine defect that makes converted
  `flexbits` correlations fire where Sagan is silent. The address directions
  compare the printable address buffer rather than the binary form the struct
  also carries, sixteen bytes of it, so the result depends on the bytes
  following the address in the message rather than on the address. Reproducing
  it is not an option; it is documented instead.

### Fixed

- `blacklist: all` and `zeek-intel: all` converted into a match over every
  address position even when the rule declared none. The engine scans the
  address cache `Parse_IP` fills, and it fills that cache only for a rule that
  declares a position, so with none the lookup finds nothing, routing rejects
  the event and the rule cannot alert at all. The converted rule fired where
  Sagan is silent. Both now refuse with `E_NO_DETECTION`. This is the opposite
  of the `by_username` case, where the direction is unrecognised, the flag
  stays clear and routing skips the denylist entirely so the rule fires on its
  other conditions: that one is still dropped as inert. Both behaviours were
  measured against a running engine, and confusing them is what made the first
  attempt at this fix wrong in the noisier direction.
- The refusal for a `zeek-intel` tracking the converter cannot reproduce called
  the value unrecognised. The engine accepts `domain`, `file_hash`, `url`,
  `software`, `email`, `user_name`, `file_name` and `cert_hash`, and each sets
  the flag, so such a rule really is filtered on that indicator type rather
  than left inert: a rule tracking `domain` loads and does not fire on an
  address the feed lists. The message now says the bundled enrichment carries
  address indicators only.
- The keyword list the completeness test compares against was scraped from the
  `strcmp()` calls in `src/rules.c` and missed four entries. Sagan validates
  every option against a single whitelist, `VALID_RULE_OPTIONS` in
  `src/rules.h`, which is now the source. Two of the four, `json_strstr` and
  `json_meta_strstr`, are whitelisted but have *no parsing branch at all*.
- `json_strstr` and `json_meta_strstr` were treated as synonyms of
  `json_contains` and `json_meta_contains`, so a rule using one emitted
  `|contains` where Sagan compares whole values, which is broader than the rule
  it came from. Only the `contains` spellings set the substring flag; the other
  two load and do nothing, confirmed against the engine. They are now
  classified as inert.
- `json_base64_decode`, `json_base64_decode_pcre` and `json_base64_decode_meta`
  were accepted. The word order is not interchangeable: none is in
  `VALID_RULE_OPTIONS` and Sagan aborts the ruleset on one, so accepting them
  converted rules that cannot load anywhere.
- The converse half of the completeness test checked three hardcoded names,
  which is why those five invented spellings survived the previous pass. It now
  compares the whole set, in both directions.
- `json_pcre` applied its own `flag in ("i", "m", "s")` filter instead of the
  shared flag handling, so the `A` and `x` refusals added for `pcre` never
  reached it and both flags were still dropped silently. Both keywords now go
  through `pcre_modifiers()`.
- `event_id` degradation text said Sagan searches the first 10 bytes of the
  message. `strlcpy(alter_message, message, 10)` copies **nine** characters,
  and the searched string is `" <id>: "` including both spaces, so an ID at
  offset 0 never matches. Measured by padding: `xx 4624: ` is found and
  `xxx 4624: ` is not. Sagan's own comment above that code says `depth: 8`,
  agreeing with neither.
- `after` honoured tracking keys the engine ignores. Its parser compares each
  `&`-separated token with `strcmp`, so `by_user` is not `by_username`,
  `byusername` is an upstream typo, and neither `by_tag` nor `by_hostname` has
  a branch at all. All four set no method and contribute nothing to the counter
  key. The converter mapped `by_user` onto the username and `by_tag` onto the
  syslog tag, so four upstream correlations grouped *more finely* than Sagan
  groups them and therefore fired less often than the rules they came from.
  They now drop the inert key with `D_TRACK_KEY_INERT`. Verified against a
  running engine: two events differing only in the inert key share a counter.
  Inertness is decided the way the engine decides it, by absence from the list
  of five recognised branches, rather than by a second list of known-bad
  tokens. An unrecognised key was previously refused outright, which made the
  converter stricter than the engine on a rule Sagan loads and runs.
- A rule whose only tracking key is inert now refuses. Sagan needs a validity
  count of four, made of `track`, a *recognised* key, `count` and `seconds`, so
  it rejects such a rule at load. One corpus rule tracks `by_tag` alone.
- `by_srcport` and `by_dstport` were missing from the tracking table. Both are
  real branches, and an unknown key was refused outright, so a rule using
  either was rejected for a reason that was not true.
- `facility`, `level` and `tag` were accepted as bare aliases of the `syslog_`
  forms. They are not aliases: Sagan has no such options and aborts the whole
  ruleset on one. Accepting them turned a rule that cannot load anywhere into
  working Sigma, so an operator could deploy a detection that never existed
  upstream. They now fall through to `E_UNKNOWN_KEYWORD`.
- The PCRE flags `A` and `x` were dropped silently although both change what
  matches. On a message reading `zzab tail`, `/ab/` matches and `/ab/A` does
  not, because an anchored match may not start at offset 2: dropping the flag
  made the converted rule fire where Sagan stays silent. `/z z a b/` does not
  match and `/z z a b/x` does, because extended mode ignores the whitespace in
  the pattern: dropping it made the rule look for something the original never
  looked for. Neither is expressible in Sigma, so both now refuse. Measured
  against a running engine; no upstream rule uses either, which is why the gap
  survived.
- The PCRE flag `G` was refused although the engine accepts it. It sets
  `PCRE_UNGREEDY`, which decides how much text a match consumes rather than
  whether one exists, so it is now dropped like the other inert letters.
- `syslog_priority` was reported as an unknown keyword. It is a real envelope
  selector, distinct from `priority`/`pri` which set the alert's own severity
  through `atoi`, and distinct from `syslog_level`: an event carrying
  `priority=warning` and `level=notice` matches each keyword only on its own
  value. It is now refused explicitly, because decoded syslog carries no such
  third field, rather than being mapped onto the severity.
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
