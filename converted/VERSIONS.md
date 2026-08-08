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
| `pending` | [`a6dfb7d7f865`](https://github.com/quadrantsec/sagan-rules/commit/a6dfb7d7f865c01c0cfc7f10bfa0bda8d1c05f55) | 2026-08-06 | `pending` | 2026-08-07 | 8659 / 9997 (86.6%) |
