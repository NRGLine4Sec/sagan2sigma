# Converted rule set versions

This table records each iteration of the converted rule set under
[`converted/`](rules), newest first. The rules there are produced from
[`quadrantsec/sagan-rules`](https://github.com/quadrantsec/sagan-rules) with
the default `rsigma-syslog` profile, so they can be used without installing
this project. They are regenerated whenever the upstream corpus changes; see
`.github/workflows/convert-rules.yml`.

The **version** is the short hash of the `sagan-rules` commit and the
`sagan2sigma` commit the rules were produced from, so it is reproducible. The
**sagan-rules date** is that commit's date, which is how old the rules are.

| Version | sagan-rules commit | sagan-rules date | sagan2sigma | Generated | Rules |
| --- | --- | --- | --- | --- | ---: |
| `604e66bf31e4` | [`44d11446d16c`](https://github.com/quadrantsec/sagan-rules/commit/44d11446d16c1430d125c81a23ca4a3f0f5080c9) | 2026-08-07 | `74b38b490cf8` | 2026-08-08 | 8655 / 9997 (86.6%) |
