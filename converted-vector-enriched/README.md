# Converted rules: `vector-enriched` profile

The same upstream Sagan corpus as [`converted/`](../converted), converted with the
`vector-enriched` profile instead of the default `rsigma-syslog` one. It is
committed alongside the default snapshot because the enriched profile has become
the one that recovers most of the corpus, so having it ready to use without
running the tool is worth it.

It is produced and refreshed by the same job as the default snapshot
(`tools/refresh_converted_rules.py`, run from `.github/workflows/convert-rules.yml`),
from the exact commits recorded in [`converted/VERSIONS.md`](../converted/VERSIONS.md);
there is no separate version file, because it is always the same version as the
default snapshot, only a different profile.

## What the enriched profile adds

The enriched profile recovers constructs the default profile refuses, because it
assumes a Vector pipeline recreates the fields Sagan derived from the raw message:

- **Positional IP correlations** (`after`, `xbits` grouped on `src_ip` / `dest_ip`),
  which the default profile refuses with `E_GROUPBY_UNRESOLVED`.
- **`blacklist` and `zeek-intel`** IP matches, against denylist and Zeek-intel
  enrichment tables.
- **`alert_time`** windows and **`country_code`** GeoIP matches (see the caveat
  below).

On this snapshot that is about **90%** of the corpus, against **86.6%** for the
default profile. The exact figures are in the table in `converted/VERSIONS.md` and
the full breakdown in [`CONVERSION-REPORT.md`](CONVERSION-REPORT.md).

## What it does not include without your configuration

Two constructs need site-specific values, so they are **not** in this snapshot and
are reported as `E_VAR_UNRESOLVED`:

- **`country_code`** rules use `$HOME_COUNTRY`, the countries you consider home.
- Most **`alert_time`** rules use `$SAGAN_DAYS` / `$SAGAN_HOURS`, your out-of-hours
  window.

To include them, regenerate with your `sagan.yaml`:

```sh
sagan2sigma sagan-rules -o converted-vector-enriched \
  --profile vector-enriched --sagan-yaml /etc/sagan/sagan.yaml
```

## Using it

Unlike the default snapshot, these rules only fire once the fields they match are
produced. The runnable Vector pipeline that creates them is in
[`vector/`](vector); see [`docs/PIPELINE.md`](../docs/PIPELINE.md) for setting its
placeholders, and for fetching the GeoIP database and the threat-intel feeds the
enrichment tables read (`tools/fetch_cti.py`).
