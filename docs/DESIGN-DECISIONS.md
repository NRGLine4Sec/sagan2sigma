# Design decisions

This document records the choices that are not obvious from the code, and the
evidence behind them. Every entry here was either a bug that shipped and got
caught, or a bug that was avoided because someone read the engine source
instead of the documentation.

## The three traps

These are the mistakes a straightforward Sagan-to-Sigma converter makes. All
three produce output that parses cleanly, validates against pySigma, and is
wrong.

### 1. Case sensitivity is inverted between the two formats

Sagan compares `content` **case-sensitively** by default; `nocase` turns that
off. Sigma is **case-insensitive** by default; `|cased` turns sensitivity on.

A converter that copies the flag across without inverting it flips the meaning
of every rule that does not carry `nocase`. In the upstream corpus that is
about 7,600 rules. Nothing downstream catches it: the rules parse, they
validate, and they match more than they should.

Handled in `mapping/values.py::case_modifiers`, with a dedicated test class in
`tests/unit/test_content.py::TestContentCaseInversion`.

The `--case-policy relaxed` flag drops `|cased` everywhere. That is a
deliberate, documented trade of fidelity for recall, not the default.

### 2. `threshold` is not a correlation

Three Sagan keywords look like thresholds. Only one is.

| Keyword | What it actually does |
| --- | --- |
| `after` | genuine correlation: suppress the first N events, alert from N+1 |
| `threshold type limit` | alert volume cap: alert on the first N per window, then stay silent |
| `threshold type suppress` | alert volume cap with a timer that resets on every event |

Only `after` changes *whether* something is a detection. The other two change
*how often you are told*. Converting `threshold` into a Sigma `event_count`
correlation turns a noisy detection into one that requires N occurrences, which
is a different rule.

`type suppress` is carried over as `custom_attributes['rsigma.suppress']`,
where a downstream deduplicator can honour it. `type limit` has no equivalent
and is dropped with `D_THRESHOLD_LIMIT`.

The corpus has 1,143 `suppress` and 146 `limit` uses, against 970 real `after`
correlations.

### 3. Group-by keys need not exist as fields

Sagan reasons over internal values (`src_ip`, `username`) that are populated
after matching, not fields present in the event. `after: track by_src` groups
on whatever Sagan decided `src_ip` was. Three cases arise:

1. a `json_map` binds the internal value to a JSON key, so that key is the
   group-by field;
2. `parse_src_ip` or `normalize` is present, meaning Sagan extracts the address
   by regex from the raw text. No field exists anywhere, so the rule is refused
   with `E_GROUPBY_UNRESOLVED` and the report says the field has to be produced
   upstream;
3. neither applies, in which case Sagan falls back to the syslog sender. The
   rule converts, grouping on the profile's hostname field, and carries
   `D_GROUPBY_SYSLOG_HOST` because the grouping is now per emitting host rather
   than per attacker.

Case 3 covers 387 corpus rules. Emitting `group-by: [src_ip]` for any of these
would produce a correlation that never fires, because no event has that field.

A fourth branch sits ahead of case 2 when the active profile declares
positional enrichment. See the next section.

## Recreating what Sagan derived from raw text

Case 2 above refuses 313 rules, and the refusal is correct only for as long as
nothing produces the field. The `vector-enriched` profile plus the bundled VRL
library change that, taking the category from 313 rules to 14.

### The port is faithful, and that is the whole point

`data/vrl/sagan-parse-ip.vrl` reproduces `Parse_IP()` from `src/parsers/ip.c`
rather than approximating it with a convenient regular expression. The engine
does something specific: it rewrites a fixed delimiter set to spaces, splits on
whitespace, and validates each whole token with `inet_pton()`.

Two branches would be lost by anyone reaching for `\d+\.\d+\.\d+\.\d+`:

* **Both sides of a separator are validated** (`ip.c:476` and `556`). Sagan
  calls `strtok_r` and tries the left half, then the right. This is what makes
  `outside:203.0.113.7` resolve, where the address sits *after* the colon,
  while `1.2.3.4:8080` resolves with the address *before* it. Cisco ASA is 118
  of the affected rules, so getting this wrong would have quietly discarded the
  largest product family in the set.
* **The dot-count envelope** (`ip.c:255`) rejects tokens with fewer than three
  or more than four dots, which is what stops `1.2.3` and `4.5.6.7.8` from
  being read as addresses. A greedy regex matches `4.5.6.7` inside the latter.

Validation uses VRL's `ip_to_ipv6()`, whose accept and reject behaviour matches
`inet_pton()` for both families, including rejecting leading zeros such as
`01.2.3.4`. That was verified by execution, not assumed.

### Position is preserved because it is meaning

`parse_src_ip: 2` does not mean "a source address", it means the second address
in the message. In the corpus, 94% of `parse_src_ip` uses ask for position 1
and 91% of `parse_dst_ip` for position 2, but positions 2 and 3 appear in 480
rules between them.

So the transform exposes `sagan_ip_1` through `sagan_ip_5`, and each converted
rule targets the index it declared. `src_ip` and `dest_ip` exist as aliases for
positions 1 and 2, for humans reading the events; the converter never uses them
where a rule asked for something else.

### Where the port stops, and why it says so

`data/vrl/username-extraction.vrl` is explicitly **not** a port. Sagan resolves
usernames through liblognorm rulebases, which are per-format data files, not an
algorithm. There is nothing to reproduce faithfully, so the file opens by
saying so and ships a starter kit of patterns for the formats the corpus groups
by user.

The same honesty applies to precedence. `engine.c:797` shows that liblognorm
wins when it resolves an address and positional parsing is only the fallback.
88 corpus rules carry both. They convert against the fallback and carry
`D_NORMALIZE_PRECEDENCE`, because reproducing half a mechanism and calling it
whole is exactly the kind of silent divergence this document exists to prevent.

The 14 rules that still refuse are the honest residue: they group on a value
only liblognorm produced, with no positional fallback to inherit.

### The rules and the transforms are one deliverable

A rule grouped on `sagan_ip_2` is valid Sigma that never fires if nothing
produces `sagan_ip_2`. Shipping the profile without the transform would create
precisely the failure this project refuses everywhere else, so
`--emit-vector-config` is implied by the enriched profile rather than left as
an option, and CI executes the transforms against a real Vector binary.

### GeoIP `country_code` rides on the same enrichment

`country_code: track by_src, isnot $HOME_COUNTRY;` looks the source address up
in an IP-to-country database and fires when its country is not in the list. The
lookup is external, so under the default profile the rule is refused, recoverably,
with `E_EXTERNAL_ENRICHMENT`. But it is exactly the kind of derived field the
enriched profile exists to supply: the bundled `sagan-geoip.vrl` enriches each
parsed address with its country (`sagan_geoip_country_N`), so under
`--profile vector-enriched` the rule converts to a match on that field. Since
`country_code` tracks the same address `parse_src_ip` selected, the country
follows the same position.

Two details from `src/geoip.c` and `src/processors/engine.c` decide the exact
Sigma. First, and this is the one worth reading the C for, **both `is` and
`isnot` require a country to have actually been resolved**. The obvious reading
of `isnot` is "anything except these countries", which would make an address
with no country satisfy it. The engine does not do that.
`GeoIP2_Lookup_Country` returns `GEOIP_SKIP` from *every* path that fails to
determine a country: a non-routable address, one inside the configured
`skip_networks`, a lookup failure, and an address the database does not carry.
`engine.c` runs the `is` / `isnot` comparison only when the result is not
`GEOIP_SKIP`, so on a skip `geoip2_isset` stays false and `routing.c` drops the
rule. Sagan is silent on any address it could not place. The converted rule
therefore requires the **country** field to exist
(`sagan_geoip_country_N|exists: true`) and negates the country list.

This was wrong in the first implementation, in the direction that hurts. Keying
the presence test on the address instead meant that any address the pipeline
could not place still satisfied `isnot`, so every rule of the "connection from
outside $HOME_COUNTRY" family, 138 of them convertible in the corpus, fired on
all RFC1918 traffic. The committed snapshots never showed it, because those
rules need `$HOME_COUNTRY` from a site `sagan.yaml` and are refused with
`E_VAR_UNRESOLVED` without one: the defect only reached users converting with
their own configuration, which is the documented way to use the tool.
`tests/differential/test_geoip_semantics.py` now pins the full truth table
against the real engine.

Second, the database is not bundled, and the enrichment is deliberately
**provider-agnostic**. GeoIP databases carry a licence, and MaxMind's GeoLite2
in particular needs a signed-up licence key, which is friction and a single point
of failure for anyone deploying the rules. So the emitted `vector.yaml` declares
the enrichment table as Vector's `mmdb` type, not its `geoip` type: `geoip`
hard-codes the MaxMind schema and rejects any other provider's database, whereas
`mmdb` returns the raw record of any database in the MaxMind file format, whatever
its `database_type`. The default the docs lead with is **DB-IP IP-to-Country
Lite** (CC BY 4.0, a plain monthly download, no key), but MaxMind GeoLite2-Country
and IPLocate drop in with no code change. The one wrinkle is that the providers
disagree on where the ISO code sits: MaxMind and DB-IP nest it at
`country.iso_code` (the GeoIP2 schema), while IPLocate puts it top-level at
`country_code`. `sagan-geoip.vrl` reads `country_code` and overrides it with
`country.iso_code` when the record carries a nested `country` object, so all three
resolve without the pipeline knowing which is loaded. (It cannot use VRL's `??`
for this: `??` coalesces on error, and a missing path yields null, not an error.)
The country therefore reflects the database loaded at ingestion time, which is
recorded as the `D_GEOIP_COUNTRY_ENRICHMENT` degradation. Because these databases
are freely downloadable, CI can and does run the transform against real Vector
with real DB-IP and IPLocate data, so the provider-agnostic claim is tested, not
asserted.

### `alert_time` becomes a match on derived time fields

`alert_time: days 12345, hours 1800-0800;` fires only on a recurring weekday and
hour window (`src/aetas.c`, `Check_Time`). Sigma has no recurring-time operator,
so under the default profile the rule is refused with `E_TIME_WINDOW`. Under the
enriched profile the bundled `sagan-time.vrl` derives the two values `Check_Time`
actually compares, the weekday (0=Sunday, matching the engine's day bitmask) and
the time as an HHMM integer, and the window becomes a match on them.

The engine reads the time with `atoi("HHMM")` and compares it as an integer, so
`sagan_event_hhmm|gte: 1800` and `|lte: 800` reproduce the window **exactly**,
minute boundaries and all: there is no precision loss here, only the clock
divergence below. What needs care is the midnight crossing. When the start is
after the end, `Check_Time` fires in the evening on the alert days and in the
morning on the alert days **and the day after each** (its `next_day` roll: a
window that opened last night is still open this morning even if today is an off
day). That is a disjunction of conjunctions a flat predicate list cannot express,
so the handler emits a `ConditionGroup`, the one construct in the IR that carries
its own sub-condition: `(days and evening) or (days-and-the-morning-after and
morning)`. The emitter folds it into the rule's condition with `and (...)`.

Two things do not follow, both recorded as `D_ALERT_TIME_EVENT_CLOCK`. Sagan
evaluates the window against the wall clock at the moment it processes the line,
not against the event's own timestamp; the transform uses the event timestamp,
which is what "activity at a suspicious time" usually means and coincides with
Sagan's value under near-real-time ingestion. And `Check_Time` uses `localtime()`,
so the pipeline must format timestamps in the Sagan host's timezone for the window
to line up.

### `blacklist` and `zeek-intel` become a threat-intel flag

`blacklist` fires when a parsed address is on a denylist of bad IPs or networks
(`src/processors/blacklist.c`); `zeek-intel` fires when it is in a Zeek
Intelligence Framework feed (`src/processors/zeek-intel.c`). Both are external
data, so under the default profile they are refused with `E_EXTERNAL_ENRICHMENT`.
Under the enriched profile the bundled `sagan-denylist.vrl` and
`sagan-zeek-intel.vrl` flag each parsed address a feed lists
(`sagan_denylist_N` / `sagan_zeek_intel_N`), and the rule becomes a match on that
flag. The engine (`src/processors/engine.c`) decides which address: `by_src` and
`by_dst` test one position, `both` tests the source or the destination, and `all`
tests every parsed address, which the converter renders as a disjunction over the
flags through a `ConditionGroup`.

Three engine details shape this. First, `zeek-intel`'s rule keyword only ever
tests IP indicators, so the domain, hash and URL indicators a Zeek feed also
carries are not reproduced. Second, the denylist processor matches IP addresses
only, so `blacklist: by_username` sets no flag and is inert: it is dropped and the
rest of the rule converts, flagged with `D_DENYLIST_USERNAME_INERT`, exactly as
the engine evaluates it. Third, the feeds are external and change constantly, so
nothing is bundled and the enrichment is feed-agnostic in the same way GeoIP is:
the tables are declared as Vector's `mmdb` type, and `tools/build_denylist_mmdb.py`
turns a feed into the MMDB Vector reads. An MMDB is the right shape because the
lookup is a longest-prefix network match, so DShield's `/24` blocks match every
host inside them, which a plain exact-match table could not do.

The public feeds matter here. Sagan's own sample config recommends SANS DShield's
`block.txt` for the denylist, and it is still live. For `zeek-intel` the source
the config names, Critical Stack, closed its free feed, but CriticalPathSecurity
publishes a maintained public equivalent in the same Zeek Intel format, so the
capability survives. Because these feeds are freely downloadable, CI builds a
database with the tool and runs the transforms against real Vector, so the intel
path is tested end to end rather than asserted. The match reflects the feed loaded
at ingestion time, recorded as `D_DENYLIST_ENRICHMENT` / `D_ZEEK_INTEL_ENRICHMENT`.

### `bluedot`: the one deliberate break from fidelity

Everything else in this project earns its conversion by being faithful to the
Sagan engine, and refuses when it cannot. `bluedot` is the single, deliberate
exception, and it is worth being explicit about why.

`bluedot` queries Quadrant's Bluedot API (`src/processors/bluedot.c`), a **closed
commercial** threat-intelligence source. Its data cannot be redistributed, so it
is impossible to integrate legally, and no faithful reproduction exists: a
converted rule simply cannot ask Bluedot anything. The corpus depends on it
heavily, though. It is 310 rules, 62% of everything the enriched profile refuses,
and they are ordinary, useful detections ("this source address is a Tor exit / an
open proxy / known malicious / a honeypot talker"). Reading the engine shows the
dependency is only ever on standard indicator types and a tiny, standard
taxonomy: five lookup types (`bluedot.h`: IP, hash, URL, filename, JA3), of which
the corpus uses IP, URL and hash, and for IP just four categories, Tor, Proxy,
Malicious and Honeypot. The match is a plain set membership: the API returns one
category for the address and the rule fires if it is in the rule's list
(`Sagan_Bluedot_Cat_Compare`).

Here the fidelity rule and usefulness pull apart, and the resolution is purely
logical. A `bluedot` rule left refused can **never** fire under RSigma, so
keeping it "faithful" by refusing it guarantees the one outcome nobody wants: the
detection is silently lost. Substituting an open-source feed changes *which*
addresses fire it, but keeps the detection alive. Between a rule that is
guaranteed dead and one that is alive against a different-but-related feed, the
second is the better engineering outcome, and it is taken **as an assumed
compromise**. This is the project's only such compromise; it is not a precedent,
and nothing else here trades fidelity for coverage.

The mechanism mirrors `blacklist`/`zeek-intel` exactly, extended by the category
dimension. `sagan-bluedot.vrl` flags each parsed address in one enrichment table
per category (`sagan_bluedot_tor_N` and so on), and a rule converts to a
disjunction over every (tracked position, category) flag. Only the
`ip_reputation` lookup is reproduced, because hash and URL indicators need a
different, non-address enrichment table; those rules stay refused. The fidelity of
the substitution is honestly uneven, and the degradation says so:

* **Tor is near-authoritative.** Who is a Tor exit node is a public fact, and the
  Tor Project's own exit list is the same ground truth Bluedot derives from, so
  the Tor category is close to faithful.
* **Malicious, Proxy and Honeypot diverge.** They depend entirely on the feed you
  point each table at; different providers list different addresses, so the rule
  will fire on a different population than Bluedot would.

Every converted `bluedot` rule carries `D_BLUEDOT_SUBSTITUTION`, which spells out
that it matches your feeds rather than Bluedot, that Tor is the trustworthy
category and the rest approximate, and that Bluedot's effective-period recency
filter is not reproduced. It is the loudest degradation in the taxonomy on
purpose.

## Where the documentation and the engine disagree

The rule-keywords documentation is the best available description of the
format, but it is not the specification. Where it and the C source disagree,
this converter follows the source and says so in a comment.

### `json_map` accepts three undocumented internal values

The documentation lists fifteen internal values. The `strcmp(json_map_type, …)`
chain in `src/rules.c` accepts eighteen: it also takes `username`, `flow_id`
and `ja3`.

`username` alone appears in 1,182 corpus rules. Following the documentation
here would have silently dropped the binding, which in turn would have refused
or misgrouped every user-based correlation.

Encoded in `mapping/fields.py::INTERNAL_VALUES`.

### `json_map: "message"` redirects the message search

The documentation does mention this, in one sentence, and it is easy to miss:

> `message`: Replaces existing "syslog" message with the value within the
> specified key.

The consequence is large. In a rule carrying
`json_map: "message", ".RenderedDescription";`, a `content:` search runs
against the `RenderedDescription` JSON key, **not** against the raw body.
1,020 corpus rules are in that situation. Emitting `_raw|contains` for them
produces rules that never match, because the engine sees a JSON object rather
than the original line.

Handled by `mapping/fields.py::FieldResolver`, which every message-searching
handler consults instead of hardcoding a field name.

### `track by_string` is a synonym for `by_username`

The documentation presents `by_string` as tracking on an application string,
which reads like a value with no field equivalent, and refusing it on that basis
is tempting. The engine says otherwise: in `src/rules.c` the `after` and
`threshold` parsers set the **same** flag for both keys,

    if (Sagan_strstr(tmptoken, "by_username") || Sagan_strstr(tmptoken, "by_string"))
        rulestruct[...].method_username = true;

and the correlation hash in `src/after.c` is then built from the username value.
So `by_string` groups on exactly the field `by_username` does. Treating it as its
own unresolvable key refused rules the engine tracks like any other user
correlation; mapping it to `username` recovers them, under `--profile
vector-enriched` where the VRL supplies `sagan_username`, and carries the same
best-effort-username degradation. Encoded in
`mapping/correlation.py::TRACK_TO_INTERNAL`.

### Sagan's option tokenisation ignores quotes

Sagan splits the option block with a plain `strtok_r(rulestring, ";", …)`,
with no quote tracking whatsoever, then applies `Between_Quotes()` per token.
A literal semicolon therefore cannot appear inside a Sagan value; it has to be
hex-encoded as `|3b|`.

An earlier revision of this parser tracked quote state across the line, which
is more correct in the abstract and wrong in practice: roughly 175 upstream
rules carry an odd number of double quotes, usually a stray quote inside a JSON
key such as `json_meta_content:!".properties".deviceDetail",…`. Sagan reads
those rules without complaint; a quote-aware lexer desynchronises and loses the
rest of the line.

Matching the engine took parse failures from 175 to zero.

### `meta_content` without `%sagan%` is a load-time error

`src/rules.c` logs `lacks the meta_content 'helper' (%sagan%)` and aborts. Such
a rule cannot run under Sagan at all, so the converter refuses it rather than
guessing what was meant. The upstream corpus contains none.

### `program` matching is a case-sensitive full-string glob

`Wildcard()` in `src/util.c` supports `*` and `?` with the same semantics as a
Sigma plain value, anchored on the whole string, and compares case-sensitively.
Wildcards therefore pass through unescaped, and `|cased` applies.

That is the opposite of `content`, where `*` and `?` are literal characters and
must be escaped. The two are handled by different code paths for exactly this
reason.

### A zero-valued `offset`, `depth`, `distance` or `within` is a no-op

The Snort syntax Sagan inherits describes `offset`, `depth`, `distance` and
`within` as byte constraints on where a `content` match may sit. The engine
implements them, in `src/content.c` (`Content()`) and `src/meta-content.c`,
guarding every one with `if (value != 0)`:

```c
if ( rulestruct[rule_position].s_offset[z]   != 0 ) { ... }
if ( rulestruct[rule_position].s_depth[z]    != 0 ) { ... }
if ( rulestruct[rule_position].s_distance[z] != 0 ) { ...  /* within lives here */ }
```

So `offset:0`, `depth:0`, `distance:0` and `within:0` change nothing: the search
runs over the whole message, exactly as a bare `content` does. And `within` is
applied only inside the `distance != 0` block, so it is inert unless the same
content also carries a non-zero `distance`.

The consequence matters, because the documentation would mislead. A rule
`content:"A"; content:"B"; distance:0` does **not** require B to follow A: with
`distance` at zero the positional block is skipped and both are independent
substring searches. Reading `distance:0` as "B after A", as the Snort
documentation suggests, and emitting an ordered regex `A.*B` would produce a
rule that misses events the original matches. A rule whose positional keywords
are all inert is therefore converted faithfully as plain `|contains` predicates,
and only a non-zero `offset`, `depth` or `distance`, a real byte position Sigma
cannot express, is refused. This recovers 245 rules of the upstream corpus that
were previously refused wholesale. See `mapping/positional.py`.

One consequence to guard: un-blocking these rules exposes their `content` and
`pcre` to the engine for the first time. Some carried a `pcre` with a `{` that is
not a counted repetition, for example `{\d}`, which Python's `re` reads as a
literal brace and the Rust `regex` crate rejects, taking the whole ruleset down
at load. Those are now rewritten rather than refused (see the next section);
`has_unsupported_brace` in `mapping/regexes.py` still detects the raw form, and
the property that the full converted corpus loads into RSigma with zero refusals
holds. It was verified against the engine over every `pcre` in the corpus.

### PCRE the Rust engine rejects: rewrite the provably-equal subset, refuse the rest

RSigma compiles Sigma regular expressions with the Rust `regex` crate, which
guarantees linear-time matching and therefore rejects several PCRE constructs
Sagan's libpcre accepts. The whole rule is refused with `E_PCRE_UNSUPPORTED`, and
because RSigma aborts the entire load on one bad pattern, that strictness is not
optional. Of the corpus's refused patterns, a well-defined minority are not
really "unsupported" so much as *written in a form the Rust engine spells
differently*. For those, and only those, the handler rewrites the pattern into
the equivalent Rust-accepted form before validating:

- **Numbered subroutine `(?N)`** is inlined as the non-capturing group `(?:...)`
  carrying group N's subpattern. A non-recursive subroutine call is pure macro
  expansion, so the matches are identical. A call that reaches itself is
  recursive, cannot be flattened, and is left in place to be refused (inlining it
  would grow without bound; `expand_subroutines` detects the self-reference and
  stops).
- **A literal `{`** that does not open `{m,n}` is escaped to `\{`. Python reads it
  as a literal, the Rust engine rejects it, and escaping means a literal brace to
  both. Only the `{` is touched: the Rust engine already accepts a literal `}`,
  so escaping that too would needlessly change the output of rules that were
  never broken.
- **The whole-string idiom `^((?!X).)*$`** ("the line contains no `X`") becomes a
  negated search for `X`. On the single-line events Sagan matches, the two are
  exactly equivalent; the caller emits `X` as a negated predicate and XORs any
  outer negation.
- **A flag Sagan silently ignores** is dropped, not refused. Sagan's flag switch
  (`src/rules.c`) has no default case, so any letter outside `i s m x A E G` is a
  no-op at load. Refusing a rule the engine runs, over a letter it ignores, would
  make the converter stricter than its target. The corpus carries one such flag,
  `H` (a Suricata `http_header` buffer modifier Sagan never implemented).

Each rewrite was fuzzed against a PCRE oracle over thousands of inputs with zero
divergence, and its output confirmed to load in RSigma, before being committed;
`tests/unit/test_regexes.py` pins the behaviour. Together they recover 9 rules of
the upstream corpus and change no other rule's output.

**Where this deliberately stops, and why.** The recovered set is exactly the
constructs whose rewrite is *provably equal to what the engine did*. Everything
else stays an honest refusal, because the only way to convert it is to change
what the rule matches:

- **Look-around used as an embedded assertion** (`A(?!B)`, `(?<!B)A`) is not the
  whole-string idiom and does not decompose safely. Rewriting `A(?!B)` as "matches
  `A` and not `AB`" changes the meaning as soon as a line contains both an `A`
  followed by `B` and another `A` that is not: the assertion is about one
  position, the decomposition is about the whole line. Approximating here would
  produce rules that fire where Sagan does not.
- **Back-references** (`\1`, `\k<name>`) make the language non-regular; no
  finite-automaton regex, and so no Rust `regex` pattern, can express "the same
  captured text again". There is nothing to rewrite to.
- **Recursion, conditionals and control verbs** (`(?R)`, `(?(1)..)`, `(*SKIP)`)
  are beyond regular languages by construction.
- **A large family of look-around negations tests whether an extracted
  `src`/`dst` IP is public** (not in RFC1918). These *could* be recovered by
  classifying each parsed address in a Vector transform and matching a flag, the
  way GeoIP and the denylists already work. It is left out on purpose: the flag
  tests "the N-th parsed address is private", while the regex tests "the address
  at this exact spot in the text is private", and the two coincide only under an
  assumption about the log's shape that cannot be guaranteed per rule. That is an
  enrichment approximation, not a faithful conversion, so it would have to ship
  behind a degradation and a per-rule differential rather than as a clean rewrite.
  The project's bar is to refuse rather than approximate, so these stay refused
  until each can be shown equivalent, not merely plausible.

The distinction throughout is fidelity: a rewrite is applied only when it
provably preserves the match the engine performs. A transformation that is only
usually right is worse than an honest `E_PCRE_UNSUPPORTED`, because it hides in
the conversion rate as a rule that looks converted and quietly disagrees with
Sagan.

### `meta_content` is split the way the engine splits it, not by a tidy regex

`meta_content:"HELPER", value1, value2` searches for HELPER once per value, with
`%sagan%` in HELPER replaced by each. The obvious way to parse it is a regex that
reads a quoted helper, then a comma, then the values. The engine does something
less tidy, in `src/rules.c`: it takes the first comma-delimited token as the
helper, strips its quotes with `Between_Quotes` (`src/util.c`), and takes
everything after that first comma as the values. Two consequences follow that
the regex gets wrong.

First, the first comma is the separator wherever it sits, even inside the
quotes. A rule that writes its values inside the closing quote,
`meta_content:"eventName|22 3a 20 22|%sagan%,AttachRolePolicy,PutBucketPolicy"`,
is parsed by the engine as helper `eventName": "%sagan%` and values
`AttachRolePolicy` and `PutBucketPolicy"`, the trailing quote included. The regex
could not parse it at all and the rule was refused with `E_PARSE`. Three corpus
rules were in this position.

Second, `Between_Quotes` is not a balanced-quote parser: it keeps everything
after the first quote and drops every quote it meets. So `meta_content:""%sagan%",
%ASA,%FWSM`, with a doubled opening quote, has helper `%sagan%`, not `"%sagan%`.
The regex, matching non-greedily, kept the stray quote and emitted a search for
`"%ASA`, a string no real Cisco ASA log carries, so 72 Cisco rules silently
matched nothing. Parsing the way the engine does fixes them: the search becomes
`%ASA`, which a `%ASA-2-...` line does contain.

Values are kept verbatim, quotes and all, because the engine does not trim them
either; the stray closing quote a rule leaves on its last value is part of what
the engine searches for. All of this is validated by the differential harness,
which now judges these rules and reports no disagreement.

## `pass` rules alert first, then short-circuit

The rule-syntax documentation says only this about the `pass` action:

> When using the `pass` option and the signature's conditions are met, no other
> signatures are processed.

Read on its own, that sentence invites the Snort and Suricata reading, where
`pass` means "accept the packet, do not alert, stop." On that reading a `pass`
rule is a silent whitelist, and emitting it as a Sigma `alert` would invert its
meaning, turning suppression into detection. This project refused `pass` rules on
exactly that reasoning, and it was wrong. The engine does not behave that way.

The detection loop in `src/processors/engine.c` sends the alert for a matching
rule **before** it consults the action:

```c
if ( rulestruct[b].type == NORMAL_RULE )
{
    Send_Alert(...);                                    /* the alert is emitted */

    /* If this is a "pass" signature, we can stop processing now */
    if ( rulestruct[b].rule_type == RULE_TYPE_PASS )
        break;                                          /* stop the remaining rules */
}
```

`Send_Alert` (`src/send-alert.c`) builds a `_Sagan_Event` and hands it to
`Output(...)`; it never looks at `rule_type`, so nothing suppresses the alert for
a `pass` rule. A matching `pass` rule therefore **alerts, and only then stops the
engine from evaluating the rules that come after it for that same event.** It is
not a silent whitelist. It is a normal detection with a first-match-wins
short-circuit: an optimisation (do not scan the rest of the ruleset once a
definitive match is in hand) and a precedence device (make this classification
win over any broader rule that would also match). The 515 corpus `pass` rules are
re-ingested, already-classified ExtraHop alerts (`program: exabeam-api_data`, a
specific `.alert_name`); the intent is plainly to surface them, not to hide them.

So a `pass` rule converts as an ordinary `alert` rule, faithful to its detection.
The one behaviour that cannot follow is the short-circuit, the suppression of
*other* rules on the same event, because RSigma evaluates every rule
independently. That loss is recorded as the `D_PASS_SHORT_CIRCUIT` degradation
rather than a refusal. For these rules the loss is close to theoretical: another
rule would have to match the same `exabeam-api_data` event for the suppression to
have changed anything. Converting them lifts the conversion rate by about five
points and recovers the single largest block of rules the tool used to drop.

This is the clearest case in the project of the "match the engine, not the
documentation" rule earning its place: the documentation was accurate but
incomplete, and only the C source settled what `pass` actually does.

## Refusals that are architectural, not gaps

### Base64 field decoding

Sigma has a `base64` modifier, so this looks convertible. It is not. Sagan's
`json_decode_base64` decodes the **field value** and then compares. Sigma's
`base64` encodes the **searched pattern** and then compares. The two agree only
when the encoding aligns on byte boundaries, which is not guaranteed.

Refused with `E_BASE64_FIELD_DECODE`.

### `xbits isnotset`

Requires that an earlier event did **not** occur. Sigma correlations can only
express conjunction and ordering, never absence. Eight corpus rules, refused
with `E_STATE_ABSENCE`.

### `country_code` on an address the engine never resolves

Around 142 corpus rules run `country_code: track by_src, isnot $HOME_COUNTRY`
without a `parse_src_ip`. They look like the single largest recoverable family:
GeoIP already converts under `vector-enriched`, so surely these just need the
country of the source address. Reading the engine says otherwise, and the detail
is worth recording because it is a trap.

`country_code` only geo-locates an address the engine has **marked valid**. In
`src/processors/engine.c` the lookup is guarded by `ip_src_is_valid` /
`ip_dst_is_valid`; when the address is not valid the lookup is skipped,
`geoip2_isset` stays false, and `src/routing.c` (`geoip2_flag && !geoip2_isset`)
drops the rule. That valid flag is set in exactly three places: the
`parse_src_ip` / `parse_dst_ip` cache, a `json_map` binding of the address, and
`normalize` (liblognorm). So the behaviour of a `by_src` rule with none of them
depends entirely on what actually feeds the address, and splits the 142 in two:

* **139 carry a `json_map` binding** such as `json_map:"src_ip",".ClientIP"`, so
  on JSON input the address is valid and the rule geo-locates that JSON field
  (124 use `.ClientIP`, the rest a scatter of `.sourceIPAddress`,
  `.callerIpAddress`, `.properties.client_ip`, ...). Recovering them is not the
  clean win it appears to be. The source field differs per rule, so a faithful
  pipeline would have to geo-locate each one into its own country field; the
  comparison is against `$HOME_COUNTRY`, so without the site's `sagan.yaml` they
  are `E_VAR_UNRESOLVED` regardless and the committed snapshot gains nothing; and
  two engine behaviours cannot be reproduced from Vector. When the bound field is
  **absent**, Sagan does not skip: it copies `config->sagan_host`, the sensor's
  own address, and geo-locates *that* (`engine.c`, the empty-value branch of the
  `json_map` src-ip handling), which a converted rule has no way to know. When
  the address is **private or non-routable**, `GeoIP2_Lookup_Country` returns
  `GEOIP_SKIP` (`src/geoip.c`), the `is`/`isnot` block is skipped, and the rule
  does **not** fire, even for `isnot`. Converting these into rules that do fire
  would invent detections Sagan never makes, so they stay refused rather than
  approximated.

* **A remaining 2 carry no source at all** (no `parse_src_ip`, no `json_map`, no
  `normalize`). For them `ip_src_is_valid` can never be set, so the rule can
  never fire in Sagan. These are refused as `E_NO_DETECTION`, not
  `E_EXTERNAL_ENRICHMENT`: the honest reason is that the rule is inert, not that
  it is waiting for enrichment. `mapping/geoip.py::_address_can_resolve` encodes
  the liveness check, and `tests/unit/test_geoip.py` pins the exact boundary.

The lesson is the same one the whole converter is built on: a family that looks
recoverable at the level of the rule text can be, at the level of the engine,
either faithful only under assumptions the target cannot guarantee or dead on
arrival. Refusing both is what keeps the conversion rate honest.

## Rebuilding `xbits` state machines

Sigma cannot express a disjunction between the rules a correlation references:
`rules: [a, b]` in a `temporal_ordered` requires **both** to occur. Sagan's
`xbits` are a many-to-many state machine, so a direct translation is
impossible.

The corpus makes the scale clear:

| Bit | Rules that set it | Rules that test it |
| --- | ---: | ---: |
| `exploit_attempt` | 178 | 31 |
| `brute_force` | 122 | 44 |
| `recon` | 58 | 30 |

Emitting one correlation per setter–tester pair would produce 5,518
correlations for `exploit_attempt` alone.

Instead, one **synthetic aggregate rule** is emitted per bit, whose detection
is the disjunction of every setter's detection, each branch keeping its own
negations:

```yaml
condition: (s1_selection_1 and not s1_filter_2) or (s2_selection_1) or ...
```

Each tester then gets a two-rule `temporal_ordered` correlation referencing the
aggregate and itself. The correlation window comes from the `expire` declared
by the **setters**, because Sagan attaches bit lifetime to `set` and not to
`isset`. When setters disagree, the longest expiry wins, the only choice that
cannot lose a correlation the original would have made.

Aggregates are capped at `--max-xbit-branches` (default 250), with
`D_XBIT_AGGREGATE_TRUNCATED` when the cap bites.

Note that the corpus carries both `brute_force` and `brute-force` as distinct
bits that never correlate with each other. The identifier slug preserves the
difference, and a deterministic suffix guards against any remaining collision.
This was caught by the corpus invariant test, not by the fixtures.

## The event shape decides the field names

RSigma does not expose one set of fields. It exposes two, and which one you get
depends on whether the syslog body parsed as JSON
(`crates/rsigma-runtime/src/input/syslog.rs`):

| Body | Envelope fields | Message body |
| --- | --- | --- |
| plain text | `appname`, `hostname`, `facility`, `severity` | `_raw` |
| JSON | `syslog_appname`, `syslog_hostname`, `syslog_facility`, `syslog_severity` | the parsed keys, and **no `_raw` at all** |

Both were confirmed by running the engine, not merely read from the source.

Two consequences, and both were live defects until the differential harness
found them.

### A JSON rule must select the prefixed envelope

2,564 corpus rules, a quarter of the whole set, combine a JSON operator with an
envelope selector such as `program`. Emitting `appname` for those produces a
rule that parses, validates against pySigma, and can never fire, because a
JSON-bodied event has no field by that name.

Profiles therefore carry a `json_envelope` table alongside `fields`, and the
converter picks between them from the rule itself: any of `json_content`,
`json_meta_content`, `json_pcre` or `json_map` means the rule targets JSON
events. The fix corrected 1,673 predicates.

Vector-based profiles declare an empty `json_envelope`, because Vector emits
one flat object either way and the names do not change.

### A raw-text search on a JSON event is refused, not emitted

250 corpus rules search the raw body with `content` or `pcre` while also using
JSON operators, without a `json_map` binding `message` to a key. Under Sagan
that works: `content` searches the syslog message, which for those events is
the JSON text itself. Under RSigma there is no raw field on a JSON event, so
the predicate has nothing to run against.

Emitting it anyway would have been the worst available outcome: a rule that
looks converted, counts towards the conversion rate, and silently contributes
nothing. On the default profiles they are refused with
`E_RAW_TEXT_ON_JSON_EVENT`.

This is why the headline conversion rate went **down** from 81.8% to 79.4% when
the defect was fixed. The 2.4 points it lost were never real.

The refusal is a property of the *pipeline*, not the rule: it holds only because
RSigma keeps no raw field once it has parsed a JSON body. Give the pipeline one,
and the search has somewhere to run. The `vector-enriched` profile does exactly
that. Its first transform, `data/vrl/sagan-json.vrl`, runs before any field
parsing and copies the original body into `sagan_raw` verbatim, then lifts the
JSON object's keys to the top level. Both search families then resolve:
`json_content` targets the lifted key, and the raw `content` / `pcre` /
`meta_content` search targets `sagan_raw`, the exact string Sagan itself
searched. A profile advertises the capability by naming the field in a `json_raw`
key; the resolver falls back to it for the message search only when the profile
sets it, so the default profiles are unchanged and still refuse. This clears all
386 `E_RAW_TEXT_ON_JSON_EVENT` refusals in the upstream corpus. 255 of those
rules convert outright; the other 131 turn out to have a second, pre-existing
blocker that the raw-text refusal was masking (a positional field, an unresolved
site variable), so they stay refused under a different code. The enriched rate
therefore rises by 255, from 90.1% to 92.7% (9,010 to 9,265 rules).

The match stays faithful precisely because the raw body is preserved *byte for
byte*: Sagan's `content` searches the raw JSON as received, so patterns that
depend on the serialization, such as CloudTrail's `"mfaAuthenticated": "true"`
with its colon-space, match under Vector exactly when they matched under Sagan,
and not otherwise. That format dependence is real, so the converted rule still
carries the `D_RAW_TEXT_MATCH` portability degradation: faithful to this source's
serialization, not portable to a re-serialized copy of the same event.

## Determinism

Two runs over the same corpus produce byte-identical output. This is not
cosmetic: without it, the Git diff between two conversions is unreadable and
regressions are invisible in review.

- Rule identifiers are UUID5 values derived from the Sagan SID under a fixed
  namespace, so a rule keeps its id forever and across profiles.
- YAML keys are serialised in insertion order, never alphabetically.
- Anchors and aliases are disabled.
- Rule files and bits are iterated in sorted order.

Enforced by `tests/integration/test_corpus.py::TestDeterminism` and by the
golden files.

## We do not re-validate the upstream Sagan rules

This project does not check that the rules in `quadrantsec/sagan-rules` are valid
Sagan, and deliberately so: the upstream repository already validates them in its
own CI, with
[`validate_sagan_rules.py`](https://github.com/quadrantsec/sagan-rules/blob/main/.github/scripts/validate_sagan_rules.py),
which is run on every change there. Re-implementing that check here would only
duplicate it, and would drift from the authoritative version.

So the corpus is treated as valid Sagan input, and the effort goes into
converting it faithfully rather than re-auditing it. The parser is still
defensive, a malformed line is recorded as a parse failure in the report rather
than crashing the run, but that is a guard against a genuinely broken line or a
syntax this converter does not yet read, not a validation pass on the upstream
rules. What this project is responsible for is the fidelity of the conversion,
which is what the differential harness below tests.

## Proving behaviour, not just shape

Every other test in this repository checks that the converter produces the
output we expect. That cannot catch a mistaken belief about what Sagan does,
because the same belief shapes the code and the expectation alike.

`tests/differential/` asks the harder question: given an event, does the
converted rule fire exactly when the original would have? Both answers are
computed independently:

* the Sagan side by `sagan_reference.py`, an evaluator written from the engine
  C source that imports nothing from `sagan2sigma.mapping`;
* the Sigma side by the real `rsigma` binary evaluating the emitted document.

Events are generated from each rule rather than hand-written, so no expectation
is baked in anywhere. Each rule gets a battery: a base event satisfying every
positive condition, a case-flipped copy, one copy per positive literal removed,
one per negation reintroduced, a wrong program, and a literal-asterisk probe.

The harness carries a test that deliberately mis-converts a rule by dropping
`|cased`, and asserts the disagreement is detected. Without it, a harness that
silently compared nothing would pass.

Coverage: the reference evaluator can judge 4,310 of the 10,000 corpus rules,
the ones built only from constructs it implements, including rules whose
positional keywords are inert. `pcre`, correlation and effective (non-zero)
positional keywords are out of scope and are skipped rather than judged
approximately.

**What this catches**: case-sensitivity inversion, negation grouping, wildcard
escaping, hex decoding, `json_map` redirection, numeric versus string
comparison, envelope field naming, alternative handling in `program`.

**What it cannot catch**: a misreading of the Sagan source that the reference
evaluator and the converter happen to share. That limitation is exactly why the
reference is written from the C rather than from the converter, and why the two
are kept in separate packages.

### The rule set has to load before any of this matters

`tests/integration/test_engine_load.py` asks the cruder question that comes
first: will RSigma accept the ruleset at all. The failure mode is unusually
harsh, and it is the reason `mapping/regexes.py` refuses non-portable PCRE
rather than emitting it hopefully. RSigma compiles every rule up front, and one
rule it cannot compile aborts the **whole** load: no rules are registered, so a
single bad regular expression takes the entire detection set offline instead of
costing one rule. The test asserts exactly that by building a directory with one
good rule and one bad one, and checking that the good rule stays silent.

Nothing checked this before. The corpus job validates emitted documents with
pySigma, a different and more permissive parser, and the differential feeds the
engine rule by rule from generated documents, never the shipped set. So the two
committed rule sets are now handed to the engine whole, and required to compile.

### Regular expressions, the family the differential cannot reach

`sagan_reference.py` puts `pcre` out of scope on purpose: generating events for
an arbitrary regular expression is a different problem from evaluating
`content`. That left a real gap, because regular expressions were checked only
two weaker ways, neither of which involves the engine at runtime: the converter
refuses non-portable constructs at conversion time, and the rewrites are fuzzed
against a PCRE oracle in Python.

`tests/differential/test_regex_semantics.py` closes it. It extracts every
distinct `|re` pattern from the committed rule sets, 233 of them today,
generates probes for each (strings the pattern accepts via `exrex`, near misses
by mutation, and noise drawn from the pattern's own literals), and requires
Python's `re` and the real `rsigma` binary to agree on every pattern/event pair.
The engine reads NDJSON from stdin and evaluates the whole rule set per event, so
a cross product of roughly 2.8 million pairs costs one process and under a
second.

The fidelity argument closes in two links, each tested somewhere. First, the
original Sagan pattern is equivalent to the emitted one: for the large majority
they are byte-identical, and for the four rewrites `tests/unit/test_regexes.py`
fuzzes the rewrite against a PCRE oracle. Second, the emitted pattern behaves
the same under a mainstream engine and under RSigma, which is this module.
Together they say the shipped rule matches what Sagan matched.

### Where Sagan and RSigma genuinely disagree: non-ASCII

Running that harness over unrestricted input is what surfaced this, and it is
worth stating plainly because it is not fixable in the converter.

Sagan compiles every pattern in **byte mode**. The `PCRE_UTF8` case in
`src/rules.c` sits inside the block commented "PCRE options that aren't really
used?", so it is never set, and libpcre's `\w`, `\d` and `.` are therefore
ASCII. The Rust engine behind RSigma is Unicode-aware by default, so its `\w`
also matches `é`, and its `.` is a character rather than a byte. On non-ASCII log
content the two engines will disagree, and a converted rule can fire where Sagan
would not.

This is a property of the two engines, not of the conversion, and nothing the
converter emits changes it. It is left as a documented limitation rather than
papered over: forcing ASCII semantics would mean emitting Rust-specific
`(?-u:...)` syntax into rules that are meant to stay portable Sigma. The
regex differential therefore probes printable ASCII, the domain where libpcre,
Python and Rust agree, so that it measures the conversion instead of
re-deriving this difference on every run.

## Honest metadata

Every emitted rule carries:

```yaml
falsepositives:
  - "Unassessed: automatically converted, not yet tuned"
status: experimental
```

Claiming a converted rule has no false positives would be a lie, and `status:
stable` on a machine translation nobody has reviewed would be worse.
