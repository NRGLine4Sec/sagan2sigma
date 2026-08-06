# Behavioural overlap with SigmaHQ

This document describes how `sagan2sigma-overlap` decides which converted Sagan
rules already have an equivalent in [SigmaHQ](https://github.com/SigmaHQ/sigma),
what its verdicts mean, what it found, and where its answers stop. It is written
so that a reader could reimplement the method from it, and so that a SOC could
act on the results without taking any claim on trust.

## 1. What it answers, and what it does not

The question is practical. If you are moving from Sagan to a Sigma engine, some
of the converted rules will duplicate detections SigmaHQ already ships. You want
to deploy SigmaHQ for those and keep the converted rules only where they add
coverage SigmaHQ lacks. So: **which converted rules does SigmaHQ already cover?**

The honest framing matters, because it is easy to claim more than the method
supports.

- This establishes **behavioural containment on synthesised events**, not
  conceptual similarity. Two rules are related here because an event was found
  that fires both, not because their titles or ATT&CK tags match.
- It is **not a proof over all possible events.** A verdict is a statement about
  the events this tool could build for a rule. More events make a verdict
  stronger; none of them make it universal.
- It only compares rules that **share a field vocabulary.** A converted rule
  matching the raw syslog body and a SigmaHQ rule matching a structured Windows
  field may describe the same attack, but they cannot fire on one event, so they
  are correctly reported as unrelated. That is a statement about event shape,
  not about intent.

Everything below is built to make those boundaries visible rather than to paper
over them.

## 2. Method

### 2.1 One engine pass, both directions at once

Every rule from both corpora is turned into events that satisfy it. Those events
are evaluated by the real RSigma engine against **both rule sets at once, in a
single pass**. That one pass yields, for every event, the complete set of rules
it fires, which gives both directions of containment simultaneously:

- an event built from converted rule *A* that also fires SigmaHQ rule *B* proves
  the two can fire together;
- if **every** event built from *A* fires *B*, then on the available evidence
  *B* covers *A*, and deploying *B* makes *A* redundant;
- running the same test starting from *B*'s events separates equivalence from
  one-directional containment.

Using the real engine rather than a reimplementation of Sigma matching is
deliberate: the engine is the thing that will actually run in production, and
its quirks (regex dialect, case handling, field vocabulary) are exactly what a
textual or reimplemented comparison would get wrong.

### 2.2 The sentinel technique

RSigma's `engine eval` reports which rules matched, but **not which event
produced each match**, and loading a large rule set costs far more than
evaluating one event. Running one process per event would spend almost all its
time reloading rules; evaluating all events in one process loses the mapping
from match back to event.

The way around both is a **sentinel event**. A rule matching
`__sagan2sigma_sentinel__|exists: true` is appended to the rule set, and after
each real event a sentinel event carrying that event's index is interleaved into
the stream. Because RSigma emits matches in event order, the sentinel matches
segment the output: every match between two sentinels belongs to the event the
first sentinel indexes. One invocation then yields an exact per-event match set
for tens of thousands of events against thousands of rules. The technique relies
only on documented output and on results being emitted as events are processed,
not on any internal ordering guarantee beyond that.

### 2.3 Event synthesis

Comparing two rules behaviourally needs events, and hand-writing them would only
test what the author already believed. They are derived from the rule instead.

pySigma does most of the work: by the time a rule is parsed, modifiers are
folded into values, so `CommandLine|contains: admin` arrives as the string
`*admin*` and `|all` has already become a conjunction. What remains is a small
satisfiability problem over a boolean tree of field constraints. The condition
AST is walked, satisfying branch choices are enumerated (bounded, so a rule with
many alternatives does not explode), and for each branch one concrete value is
built per field that meets every constraint on it at once.

Four fixes were needed to make this work on real rules, each worth stating
because each corrects a wrong reading that silently weakens conclusions:

1. **Keyword semantics.** An unbound Sigma keyword matches anywhere in the
   event, so it is a substring requirement, not an exact value. Reading it as an
   exact value makes `all of selection_*` over two keyword lists look
   unsatisfiable when it is not.
2. **Negations are not enumerated.** Modern SigmaHQ rules are mostly
   `selection and not 1 of filter_*` with many filters; expanding that by
   De Morgan multiplies into hundreds of mostly unsatisfiable branches, and the
   branch cap then discards the one that would have worked. Instead the positive
   part drives construction and the negated subtree is evaluated against the
   finished event, with targeted repairs: a `field: null` or
   `field|exists: false` filter is disarmed by adding the field; an equality
   filter on an otherwise unconstrained field is disarmed by changing the value.
   A repair is kept only when it breaks no positive constraint; a branch that
   cannot be repaired is dropped rather than emitted wrong.
3. **Two regex generators.** `hypothesis.find(st.from_regex)` handles lazy
   quantifiers and nested groups that `exrex` mangles, while `exrex` produces
   more literal output for simple alternations. Whatever comes out is verified
   with `re.search` before use. An anchored pattern (`^...$`) owns the whole
   field value; an unanchored one is folded in as a `contains` fragment, which
   is what lets several constraints coexist on one `CommandLine`.
4. **Per-field repair values.** Several rules filter on two fields being equal,
   so repair values are unique per field: repairing both to one value would
   satisfy exactly the filter being disarmed.

Nothing here is trusted on its own. **Every synthesised event is put through the
engine, and a rule whose events the engine will not confirm is excluded from the
analysis rather than compared.** A wrong event never becomes evidence; it only
costs a rule its place in the comparison, which the report counts.

### 2.4 Compile screening

RSigma compiles a rule set as a whole, and **a single rule it cannot compile
aborts the entire load** with no rules loaded at all. pySigma does not catch
these, and neither does `rsigma rule validate`: the rejection happens at engine
compile time, on constructs the Rust `regex` crate refuses but Python's `re`
accepts (lookarounds, backreferences, an escaped hyphen forming an invalid
character-class range). So before any analysis, each corpus is screened by
**bisection**: a batch that compiles is accepted wholesale, one that does not is
split until the offenders are isolated. That costs O(k log n) engine invocations
for k bad rules and is exact. The refused rules are removed and reported, never
silently dropped.

### 2.5 The negative control, and why it is essential

RSigma's `engine eval` does not enforce a rule's `logsource`, which is what makes
single-event synthesis workable at all: an event need not carry fabricated
product metadata to be judged. The same permissiveness has a sharp edge. A rule
whose condition is `not selection`, such as the SigmaHQ rule "Publicly
Accessible RDP Service" (`condition: not selection` over a private-address CIDR
list), fires on **every event that lacks the field it negates**. Left unchecked,
one such rule co-fires with almost every synthesised event and is reported as
covering thousands of unrelated converted rules. In an early run, a single Zeek
RDP rule "covered" all 7,879 testable converted rules.

The fix is a negative control: the **empty event** `{}`. Every rule is evaluated
against it once. A discriminating rule, one that needs some field to be present,
does not fire on the empty event; a rule that matches on absence does. Any rule
the empty event fires is an "absence matcher" and is excluded from containment
entirely, in both directions, and reported separately. This also removes the
only rules that would otherwise contaminate the sentinel segments, since those
near-empty marker events are exactly what an absence matcher fires on.

### 2.6 Log-source compatibility

Because logsource is not enforced, a SigmaHQ **keyword** rule, which searches the
whole event for an unbound term, co-fires with any converted rule whose raw body
happens to contain that term. The SigmaHQ rule "Cisco File Deletion"
(`keywords: [erase, delete, format]`, scoped to `cisco/aaa`) fires on a converted
FTP, CloudTrail or Exchange rule whose message contains the word "delete", and
"Suspicious SQL Query" (`keywords: [drop, truncate, dump, ...]`, `category:
database`) fires on any rule mentioning a dropped file. These co-firings are
real, but they are **not deployable coverage**: in production the Cisco rule runs
only on Cisco AAA logs, so it will never see an Exchange event.

So each covering verdict is annotated with whether the two rules could run on the
same log stream. They are compatible only when they **positively agree on at
least one of `product`, `category` or `service`** and disagree on none they both
specify. Converted rules always carry a product, so in practice a covering
SigmaHQ rule must target the same product. A covering co-firing across
incompatible log sources is still recorded in the JSON report, flagged
`logsource_compatible: false`, but it is kept out of the actionable "covered"
count, because acting on it would be a mistake. This gate alone took the covered
count in the run below from 484 co-firings to 58 deployable ones.

## 3. The taxonomy

Each reported pair carries one of four relations. Disjoint pairs, which fire on
no common event, are the default state of unrelated rules and are not recorded.

| Relation | Meaning | What a SOC does with it |
| --- | --- | --- |
| `EQUIVALENT` | Each rule fires on every event built from the other. | Deploy either; drop the converted one. |
| `SAGAN_REDUNDANT` | Every event from the converted rule also fires the SigmaHQ rule, not the reverse. SigmaHQ is broader. | Drop the converted rule if you deploy SigmaHQ; it adds nothing on the evidence. |
| `SAGAN_BROADER` | Every event from the SigmaHQ rule also fires the converted rule, not the reverse. | Keep the converted rule; it widens coverage beyond SigmaHQ. |
| `OVERLAP` | They fire together on at least one event, but neither covers the other. | Related, not interchangeable; review both before dropping either. |

`EQUIVALENT` and `SAGAN_REDUNDANT`, **restricted to log-source-compatible
pairs**, together form the actionable "already covered" list. Several guards keep
those verdicts honest: no rule enters the analysis until the engine confirms at
least one of its events fires it; absence matchers are screened out; every
verdict carries the number of events behind it and a witness event, so a
conclusion resting on a single event is visible as exactly that; and a
`coverage_breadth` figure accompanies each SigmaHQ rule, counting how many
converted rules it covers, which flags a rule broad enough that a match may mean
less than it looks.

## 4. Results

Run against the upstream `quadrantsec/sagan-rules` corpus converted with the
`rsigma-syslog` profile, and SigmaHQ at the same date with `rules-placeholder/`
excluded, using RSigma 0.21.0.

| Metric | Converted (Sagan) | SigmaHQ |
| --- | ---: | ---: |
| Rules with a detection block | 7,911 | 4,013 |
| With an engine-confirmed test event | 7,879 | 3,866 |
| Refused by the engine (uncompilable) | 0 | 0 |
| Absence matchers, excluded | 0 | 1 |
| Synthesised no candidate event at all | 1 | 61 |

21,051 events were evaluated in one engine pass, producing 561 recorded verdicts:

| Relation | Pairs |
| --- | ---: |
| `EQUIVALENT` | 6 |
| `SAGAN_REDUNDANT` | 478 |
| `SAGAN_BROADER` | 19 |
| `OVERLAP` | 58 |

**Headline: 58 converted rules are fully covered by a log-source-compatible
SigmaHQ rule**, roughly 0.7% of those testable. Deploying SigmaHQ makes those 58
redundant. They concentrate where the two corpora genuinely share structured
telemetry: Windows AppLocker (Sagan `windows-applocker` covered by the SigmaHQ
AppLocker event rules on `EventID` 8003/8004), Windows Security (SID history,
DSRM password change, security-group modification, Mimikatz keywords), Windows
Defender, and a handful of Cisco AAA rules.

That the number is small is itself the finding: Sagan's strength is network
appliances and Unix daemons, terrain SigmaHQ barely covers, while SigmaHQ is
overwhelmingly Windows endpoint telemetry. The two libraries are largely
complementary rather than redundant.

A further **420 covering co-firings were found across incompatible log sources**
and deliberately kept out of that count. Almost all are a SigmaHQ keyword rule
matching a common English word in the raw body of a rule from another product:
"Cisco File Deletion" firing on any message containing "delete", "Suspicious SQL
Query" firing on any message containing "dump". They are recorded in the JSON
report with `logsource_compatible: false` so they can be inspected, but treating
them as coverage would be a mistake, since the SigmaHQ rule would never run on
the other product's logs. This category is a useful map of where titles and
keywords coincide, not a deployment list.

## 5. Evidence

Every verdict in `overlap-report.json` carries its `witness_event`: an event the
engine confirmed fires both rules. The Markdown report inlines the witness for
the best-supported covered verdicts. Any verdict can be replayed directly
against the engine:

```sh
rsigma engine eval --rules <ruleset.yml> \
  --event '<witness_event from the JSON report>' \
  --output-format ndjson --no-stats --quiet
```

A worked example from the run. The converted rule "[WINDOWS-APPLOCKER] Allowed
program to execute" is reported as covered by the SigmaHQ rule "AppLocker
Application Would Have Been Blocked". The witness is:

```json
{"EventID": 8003, "appname": "AppLocker"}
```

Replaying it against the SigmaHQ rule confirms the match on the structured field,
not on any coincidence of wording:

```sh
rsigma engine eval \
  --rules rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml \
  --event '{"EventID": 8003, "appname": "AppLocker"}' \
  --output-format ndjson --no-stats --quiet
# -> matches, matched_fields: [{"field": "EventID", "value": 8003}]
```

Both rules key on AppLocker event ID 8003, so this is genuine shared detection,
and the same event was synthesised from the converted rule and confirmed to fire
it. This is the point of the whole design: when the tool says SigmaHQ covers a
converted rule, it hands you the event that demonstrates it, rather than asking
you to believe a similarity score.

## 6. Limits, stated plainly

- **Coverage of the corpora.** A rule that yields no engine-confirmed event
  takes no part in the comparison, and a rule the engine refuses to compile is
  removed before the run. Both counts are in the report; they are the
  denominator any "covered" percentage should be read against.
- **Absence matchers are excluded.** A rule that fires on the empty event
  matches on the absence of a field rather than on anything an event carries, so
  it cannot be evidence of shared detection and takes no part in the comparison.
  This is a soundness choice, not a coverage gap: including such a rule would
  manufacture thousands of spurious verdicts, as an early run showed.
- **Coverage requires log-source compatibility, judged from metadata.** The
  engine does not enforce logsource, so the tool applies it afterwards as a gate
  on the declared `product`, `category` and `service`. This depends on both
  rules carrying accurate logsource metadata; it is a coarse product-level check,
  not a guarantee that two same-product rules truly see the same events. Its
  purpose is to stop keyword co-firings across unrelated products from being
  counted, which it does, at the cost of possibly excluding a genuine overlap
  between a product-scoped and a category-scoped rule. Those survive as
  `logsource_compatible: false` entries for manual review.
- **Field vocabulary.** Two rules can only fire on one event if they agree on
  field names. Of the 7,911 converted rules carrying a detection block, 2,250
  match only named fields and 5,570 search the raw syslog body; SigmaHQ, by
  contrast, is overwhelmingly structured Windows telemetry. The two corpora
  share just 23 field names, dominated by `EventID` (1,811 converted rules,
  355 SigmaHQ), then a long tail of `category`, `action`, `status`,
  `operationName` (Azure) and `eventName` (CloudTrail). Overlap therefore
  concentrates in that shared vocabulary; a converted rule matching the raw body
  and a SigmaHQ rule matching a structured field are reported as unrelated,
  which is correct for single-event evaluation but is not a statement that no
  conceptual overlap exists.
- **Correlations are out of scope.** Rules needing a sequence of events, which
  is every converted `after` and `xbits` rule, cannot be judged by single-event
  evaluation and are excluded.
- **`rules-placeholder/` is excluded by default.** Its rules carry unresolved
  `%placeholder%` values that no event can satisfy; include them with
  `--include-placeholder` if you have substituted the placeholders.

A second analysis of the raw-text rules, based on shared ATT&CK technique tags
and title similarity, would say something useful about the rules this method
cannot reach, but it would be conceptual overlap rather than tested equivalence
and must never be presented as the same thing. It is deliberately not built here.

## 7. Reproducing this

```sh
# 1. the two corpora
git clone --depth 1 https://github.com/quadrantsec/sagan-rules.git sagan-rules
git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigmahq

# 2. the engine, with the daemon feature (needed for syslog input); build from
#    the workspace root, not with -p rsigma-cli
git clone https://github.com/timescale/rsigma.git
cargo build --release --bin rsigma --features daemon --manifest-path rsigma/Cargo.toml
export PATH="$PWD/rsigma/target/release:$PATH"

# 3. convert, then compare
pip install "sagan2sigma[overlap]"
sagan2sigma sagan-rules -o converted
sagan2sigma-overlap \
  --converted converted/rules \
  --sigmahq sigmahq \
  --output overlap --cache .overlap-cache
```

The run is deterministic: synthesis depends only on the detection block, and the
`--cache` directory makes a re-run against a newer SigmaHQ cheap, rebuilding
events only for the rules that changed. `OVERLAP-REPORT.md` is the actionable
list; `overlap-report.json` carries every verdict with its witness event.
