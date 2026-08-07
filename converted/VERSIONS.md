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
| `pending` | [`142303c74980`](https://github.com/quadrantsec/sagan-rules/commit/142303c749801b4882b73a36e94e8d76f79e7500) | 2026-08-05 | `pending` | 2026-08-07 | 8656 / 9997 (86.6%) |
