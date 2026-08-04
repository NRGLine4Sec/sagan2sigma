# Architecture

## The pipeline

```
.rules file
    │
    ├─ sagan/parser.py ──────► SaganRule            immutable AST
    │                          (Header, Option[])
    │
    ├─ mapping/fields.py ────► FieldResolver        which Sigma field does
    │                                               this rule's message
    │                                               search actually target?
    │
    ├─ mapping/registry.py ──► handlers             one function per keyword
    │      ├─ selectors.py                          program, event_id, facility
    │      ├─ content.py                            content, meta_content
    │      ├─ regexes.py                            pcre
    │      ├─ json_ops.py                           json_content and friends
    │      ├─ correlation.py                        after, threshold, xbits
    │      └─ metadata.py                           msg, classtype, reference
    │                             │
    │                             ▼
    │                          RuleDraft            Predicate[], tags,
    │                                               correlations, degradations
    │
    ├─ emit/sigma.py ────────► dict documents       Sigma rule + correlations
    ├─ validate/pysigma.py ──► ValidationIssue[]    reference implementation
    ├─ emit/yaml_io.py ──────► deterministic YAML
    └─ report/ ──────────────► Markdown + JSON
```

`converter.py` orchestrates this in **two passes**, which is the one piece of
non-obvious control flow.

## Why two passes

Pass one converts each rule in isolation and records which `xbits` it sets or
tests. Pass two builds the state correlations.

A rule that tests a bit cannot be correlated until every rule that *sets* that
bit is known, because the correlation references a synthetic aggregate rule
built from all of them. There is no way to do that rule-by-rule, so the
converter cannot be a plain `map` over the corpus.

## The intermediate representation

Handlers never emit YAML. They emit `Predicate` objects:

```python
Predicate(
    field="_raw",                      # already profile- and json_map-resolved
    modifiers=("contains", "cased"),   # renders as _raw|contains|cased
    values=("authentication failure",),
    negated=False,
)
```

Three consequences worth stating:

- a handler can be tested without touching serialisation;
- the emitter can change its block-naming scheme without touching handlers;
- field resolution happens once, in `FieldResolver`, rather than being
  reimplemented in every handler that searches the message.

`RuleDraft` accumulates predicates plus everything else a rule carries: tags,
references, correlation specs, custom attributes and the list of degradations.

## The registry

```python
@handler("content")
def handle_content(rule, draft, context, resolver, policy):
    ...
```

Adding keyword support is one module plus one test file. Nothing else changes.
The five keyword families (`handled`, `modifier`, `ignored`, `blocking`,
`unknown`) are declared alongside the registry, and `classify()` is the single
place that answers "what happens to this keyword?".

A keyword appearing in two families would be handled inconsistently, so
`tests/unit/test_registry_and_context.py` asserts the families are disjoint.

## Detection block layout

One Sigma block per predicate:

```yaml
detection:
  selection_1: {appname|cased: [sshd, openssh]}
  selection_2: {_raw|contains: authentication failure}
  filter_3:    {_raw|contains|cased: frank}
  condition: selection_1 and selection_2 and not filter_3
```

Merging predicates into a shared `selection` breaks the moment two of them
target the same key, because a YAML mapping cannot carry `_raw|contains`
twice. One block each removes the failure mode entirely and makes the condition
explicit.

## Profiles

A profile is a table from Sagan internal value names to concrete field names:

```yaml
name: rsigma-syslog
fields:
  message: _raw
  program: appname
  syslog_host: hostname
```

Deliberately, the profiles define only the internal values that have a
syslog-level equivalent. `src_ip` and `event_id` have none, and their absence is
exactly what makes the converter refuse a correlation grouped on a field that
exists nowhere, rather than emitting one that never fires.

Adding an ingestion chain means adding a YAML file, not writing code.

## Test layers

| Layer | What it protects |
| --- | --- |
| `tests/unit/` | one behaviour per test, including every failure mode |
| `tests/property/` | invariants over generated input: the lexer never loses a segment, escaping neutralises every wildcard, the decoder is total |
| `tests/integration/test_converter.py` | end-to-end over hand-written fixtures |
| `tests/integration/test_golden.py` | exact emitted bytes, so formatting and identifier changes surface in review |
| `tests/integration/test_cli.py` | flags, exit codes, artefacts |
| `tests/integration/test_vector_vrl.py` | the bundled VRL executed by a real Vector binary |
| `tests/integration/test_corpus.py` | invariants against the real 10,000-rule corpus |
| `tests/differential/` | does a converted rule *behave* like the original, judged by a reference evaluator and the real rsigma engine |

The corpus and differential layers are opt-in, via `SAGAN_RULES_DIR` and the
presence of an `rsigma` binary, and each runs as its own CI job. Between them
they have found every serious defect in this converter: the parser divergence
on unbalanced quotes, the incomplete `json_map` key list, `|cased` on numeric
values, the `brute_force` / `brute-force` name collision, and the envelope
field naming that silently broke a quarter of the corpus. The fixtures only
cover constructs already understood; these layers cover the ones that were not.

`tests/differential/` deliberately does not import `sagan2sigma.mapping`. Its
reference evaluator is written from the engine C source so that a shared
misunderstanding cannot make both sides agree for the wrong reason.

A golden test asserts that faithful and relaxed output differ **only** by the
`|cased` modifier, which pins the case-policy contract to something mechanical.
