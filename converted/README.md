# Converted rules

This directory holds the [`quadrantsec/sagan-rules`](https://github.com/quadrantsec/sagan-rules)
corpus already converted to Sigma with the default `rsigma-syslog` profile, so
you can take the rules without installing or running anything. The same corpus
converted with the `vector-enriched` profile, which recovers more of it, is in
[`converted-vector-enriched/`](../converted-vector-enriched).

- [`rules/`](rules) is the converted Sigma rules, one file per Sagan source
  file, ready to load into RSigma.
- [`CONVERSION-REPORT.md`](CONVERSION-REPORT.md) explains everything that did
  **not** convert, with a stable code and reasoning for each refusal, so the
  gap in coverage is explicit rather than silent.
- [`VERSIONS.md`](VERSIONS.md) records which snapshot of the upstream corpus
  these rules were built from, and how old it is.

The rules are marked `status: experimental` and are a starting point for tuning,
not a drop-in production ruleset. Read `CONVERSION-REPORT.md`, and the top-level
[`README.md`](../README.md) under "Status and what has not been verified",
before trusting them.

## How this stays current

A scheduled GitHub Actions workflow, `.github/workflows/convert-rules.yml`,
reconverts the **whole** corpus whenever the upstream repository moves, so rules
that were modified or removed upstream are reflected here too, not only new
ones. To reproduce a version by hand, or to bootstrap the first `VERSIONS.md`
entry:

```sh
git clone --depth 1 https://github.com/quadrantsec/sagan-rules.git /tmp/sagan-rules
python tools/refresh_converted_rules.py --sagan-rules /tmp/sagan-rules
```

That regenerates both snapshots, `converted/` and `converted-vector-enriched/`,
and the shared `VERSIONS.md` row for the current pair of commits. It needs only
the package installed (`pip install .`), not the RSigma engine, since conversion
is pure Python.
