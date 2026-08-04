# Keyword mapping

Every Sagan keyword falls into one of five families. The family determines what
happens to it, and `mapping/registry.py` is the single source of truth.

| Family | Behaviour |
| --- | --- |
| **handled** | a handler emits predicates or correlations |
| **modifier** | a positional flag consumed by the preceding option's handler |
| **ignored** | no bearing on firing; emits a degradation when Sagan does something the Sigma rule will not |
| **blocking** | no Sigma equivalent; the rule is refused |
| **unknown** | anything else, refused with `E_UNKNOWN_KEYWORD` so new upstream keywords surface |

The last row matters. An unrecognised keyword is never dropped silently,
because dropping a keyword usually widens a rule rather than narrowing it.

## Handled keywords

### Message body

| Sagan | Sigma | Notes |
| --- | --- | --- |
| `content:"x"` | `<message>\|contains\|cased: x` | `\|cased` is emitted when `nocase` is **absent**; `*` and `?` are escaped because they are literal in Sagan |
| `content:!"x"` | `not filter_n` | negations are grouped: `... and not (filter_1 or filter_2)` |
| `nocase` | drops `\|cased` | binds to the preceding `content` only |
| `meta_content:"a %sagan% b",x,y` | `<message>\|contains: [a x b, a y b]` | the pattern is instantiated once per value, producing an OR |
| `meta_content:"…",$USERS` | same, variable expanded | needs `--sagan-yaml`, else `E_VAR_UNRESOLVED` |
| `meta_nocase` | drops `\|cased` | |
| `pcre:"/x/i"` | `<message>\|re\|i: x` | flags `i`, `m`, `s` map across; `g`, `x` and friends are no-ops |

`<message>` is `_raw` under the `rsigma-syslog` profile and `message` under
`vector-json`, **unless** the rule carries `json_map: "message", ".key"`, in
which case it is that key. See `docs/DESIGN-DECISIONS.md`.

### JSON

| Sagan | Sigma | Notes |
| --- | --- | --- |
| `json_content:".k","v"` | `k\|cased: v` | exact match; numeric values become integers and never carry `\|cased` |
| `json_contains` / `json_strstr` | adds `\|contains` | switches to substring matching |
| `json_nocase` | drops `\|cased` | |
| `json_meta_content:".k",a,b` | `k\|cased: [a, b]` | value list is an OR |
| `json_meta_contains` / `json_meta_strstr` | adds `\|contains` | |
| `json_pcre:".k","/x/i"` | `k\|re\|i: x` | |
| `json_decode_base64` and variants | refused | `E_BASE64_FIELD_DECODE`, see design decisions |
| `json_map` | field resolution | not a predicate; rebinds internal values to JSON keys |

JSON rules are the only ones that produce portable Sigma: they name a key,
therefore a field. Everything matching the raw body carries
`D_RAW_TEXT_MATCH`.

### Envelope

The field names below are the plain-text ones. When the rule uses any JSON
operator, RSigma exposes the `syslog_` prefixed variants instead, and the
converter follows. See `docs/DESIGN-DECISIONS.md`.

| Sagan | Sigma | Notes |
| --- | --- | --- |
| `program: a\|b` | `<program>\|cased: [a, b]` | `\|` is always an OR; `*` and `?` are wildcards here and pass through unescaped |
| `event_type` | same as `program` | documented alias |
| `event_id: 4624,4625` | `EventID: [4624, 4625]` | uses the `json_map` key when bound, else `D_EVENT_ID_HEURISTIC` |
| `syslog_facility` / `facility` | `<facility>` | case-insensitive |
| `syslog_level` / `level` | `<level>` | case-insensitive |
| `syslog_tag` / `tag` | `syslog_tag` | no profile exposes this; `D_SIDE_EFFECT_DROPPED` |
| `append_program` | nothing | `D_APPEND_PROGRAM`: Sagan searches `message \| program`, Sigma cannot concatenate fields |

Without a `json_map` for `event_id`, Sagan looks for `" <id>: "` in the first
10 bytes of the message. That heuristic exists to compensate for missing
structure and has no Sigma equivalent, so the converter emits a structured
`EventID` predicate and records the divergence.

### Correlation

| Sagan | Sigma | Notes |
| --- | --- | --- |
| `after: track by_src, count N, seconds T` | `event_count` correlation, `condition: {gte: N}` | base rule gets a `name:` and stays silent |
| `threshold: type suppress, …` | `custom_attributes['rsigma.suppress']` | volume control, not detection |
| `threshold: type limit, …` | dropped | `D_THRESHOLD_LIMIT` |
| `xbits: set,<bit>,track ip_src[, expire N]` | feeds a synthetic aggregate rule | |
| `xbits: isset,<bit>,…` | `temporal_ordered` correlation | window comes from the setters' `expire` |
| `xbits: isnotset,…` | refused | `E_STATE_ABSENCE` |
| `xbits: unset,…` | dropped | `D_SIDE_EFFECT_DROPPED` |
| `flexbits` | same as `xbits` | different argument order on the test forms |

Group-by resolution has four branches; see `docs/DESIGN-DECISIONS.md`. Under
`--profile vector-enriched` a rule declaring `parse_src_ip: N` groups on
`sagan_ip_N`, produced by the bundled VRL transform, instead of being refused.

### Metadata

| Sagan | Sigma |
| --- | --- |
| `msg:"…"` | `title`, truncated to 256 characters |
| `classtype: x` | `level` via `classification.config`, plus tag `sagan.classtype.x` |
| `priority: N` | `level`, overriding `classtype` regardless of option order |
| `reference: url,x` | `references`, prefixed via `reference.config` |
| `metadata: mitre_technique_id T1059` | tag `attack.t1059` |
| `metadata: mitre_tactic_id TA0002` | tag `attack.ta0002` |
| other `metadata` keys | `custom_attributes['sagan.metadata']` |
| `sid`, `rev` | `custom_attributes`, and the seed for the rule's UUID |

## Ignored keywords

These populate Sagan's internal state or shape the emitted alert, but never
decide whether the rule fires:

`normalize`, `parse_src_ip`, `parse_dst_ip`, `parse_port`, `parse_proto`,
`parse_proto_program`, `parse_hash`, `json_map`, `default_proto`,
`default_dst_port`, `default_src_port`, `sid`, `rev`.

`parse_src_ip` and `parse_dst_ip` are ignored as predicates but are read for
their position argument, which is what the enriched profile groups on.

These are engine-side effects with no Sigma equivalent, and each emits
`D_SIDE_EFFECT_DROPPED`:

`external`, `email`, `dynamic_load`, `offload`, `xbits_pause`, `xbits_upause`,
`flexbits_pause`, `flexbits_upause`.

Note that `parse_src_ip` and `normalize` are ignored as *predicates* but are
load-bearing for correlation group-by resolution: their presence is what makes
`after: track by_src` unresolvable.

## Blocking keywords

| Keyword | Refusal code |
| --- | --- |
| `offset`, `depth`, `distance`, `within` | `E_POSITIONAL` |
| `meta_offset`, `meta_depth`, `meta_distance`, `meta_within` | `E_POSITIONAL` |
| `bluedot`, `blacklist`, `zeek-intel`, `bro-intel`, `country_code` | `E_EXTERNAL_ENRICHMENT` |
| `alert_time` | `E_TIME_WINDOW` |

The rule header's `pass` action is also blocking, with `E_PASS_RULE`.

## Refusal and degradation codes

Both taxonomies live in `src/sagan2sigma/errors.py` with a one-line explanation
each, which the report renders verbatim. The values are a stable contract:
existing codes never change, new ones may be added.

Run `sagan2sigma <rules> -o out` and read `out/CONVERSION-REPORT.md` for the
counts on your own corpus.
