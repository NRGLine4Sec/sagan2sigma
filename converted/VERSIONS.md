# Converted rule set versions

This table records each iteration of the converted rule sets, newest first,
produced from
[`quadrantsec/sagan-rules`](https://github.com/quadrantsec/sagan-rules) so they
can be used without installing this project. Both profiles are refreshed
together whenever the upstream corpus changes; see
`.github/workflows/convert-rules.yml`. The default `rsigma-syslog` snapshot is
under [`converted/`](rules); the `vector-enriched` one, which recovers more,
is [`converted-vector-enriched/`](../converted-vector-enriched).

The **version** is the short hash of the `sagan-rules` commit and the
`sagan2sigma` commit the rules were produced from, so it is reproducible. The
**sagan-rules date** is that commit's date, which is how old the rules are.

| Version | sagan-rules commit | sagan-rules date | sagan2sigma | Generated | Default | Enriched |
| --- | --- | --- | --- | --- | ---: | ---: |
| `3b2179a2c273` | [`9dc7b1f7603b`](https://github.com/quadrantsec/sagan-rules/commit/9dc7b1f7603b92ac260205a1ac951bea6297f10d) | 2026-08-14 | `d3d9c543a98d` | 2026-08-15 | 8671 / 10019 (86.5%) | 9280 / 10019 (92.6%) |
| `554db0e28946` | [`44d11446d16c`](https://github.com/quadrantsec/sagan-rules/commit/44d11446d16c1430d125c81a23ca4a3f0f5080c9) | 2026-08-07 | `2c13d4316bce` | 2026-08-14 | 8659 / 9997 (86.6%) | 9265 / 9997 (92.7%) |
| `8e0b793f259d` | [`44d11446d16c`](https://github.com/quadrantsec/sagan-rules/commit/44d11446d16c1430d125c81a23ca4a3f0f5080c9) | 2026-08-07 | `295f05c0d2d2` | 2026-08-10 | 8659 / 9997 (86.6%) | 9010 / 9997 (90.1%) |
