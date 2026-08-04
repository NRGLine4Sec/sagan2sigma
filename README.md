# sagan2sigma

Convert [Sagan](https://sagan.quadrantsec.com/) rules into
[Sigma](https://sigmahq.io/) rules.

Sagan's rule corpus is large, actively maintained and covers a lot of ground
that SigmaHQ does not, particularly network appliances and Unix daemons. The
Sagan engine itself has seen little movement in years. This tool moves the
rules to a format other engines can run, notably
[RSigma](https://github.com/timescale/rsigma).

On the upstream corpus (10,000 active rules across 337 files) it converts
**79.4%** into 8,750 Sigma documents, with zero parse failures and zero
documents rejected by pySigma. With `--profile vector-enriched`, which ships
the transforms needed to recreate the fields Sagan derived from raw text, the
rate rises to **82.3%**.

Everything it does not convert is reported with a stable code and the reasoning
behind it, so the gap in your coverage is explicit rather than silent.

## Install

```sh
pip install sagan2sigma
```

## Use

```sh
git clone --depth 1 https://github.com/quadrantsec/sagan-rules.git

sagan2sigma sagan-rules --output converted
```

You get three things:

| Path | What it is |
| --- | --- |
| `converted/rules/*.yml` | Sigma rules, one file per Sagan source file |
| `converted/CONVERSION-REPORT.md` | every refusal and every semantic loss, grouped by product family |
| `converted/conversion-report.json` | the same data, untruncated, for CI |
| `converted/vector/` | with `vector-enriched`, a runnable Vector pipeline carrying the VRL transforms those rules depend on |

Useful flags:

```sh
# recover the correlations Sagan grouped on src_ip or username, and get a
# runnable Vector pipeline that recreates those fields
sagan2sigma sagan-rules -o converted --profile vector-enriched

# target a pipeline where Vector parses syslog into JSON, without enrichment
sagan2sigma sagan-rules -o converted --profile vector-json

# resolve $USERS and friends from your own configuration
sagan2sigma sagan-rules -o converted --sagan-yaml /etc/sagan/sagan.yaml

# trade exact case fidelity for recall
sagan2sigma sagan-rules -o converted --case-policy relaxed

# fail the build if conversion regresses
sagan2sigma sagan-rules -o converted --min-rate 80 --fail-on-validation
```

`sagan2sigma --help` lists the rest.

## What it will not do

The converter refuses rather than approximates. A missing rule is recoverable;
a rule that looks right and matches the wrong thing is not. It will not convert:

- **`pass` rules**, which abort evaluation of every remaining signature. Sigma
  has no equivalent short-circuit, and emitting them as alerts would invert
  their meaning.
- **positional matching** (`offset`, `depth`, `distance`, `within`), which
  Sigma string modifiers cannot express.
- **external enrichment** (Bluedot, GeoIP, blacklists, Zeek Intel), which
  belongs in an ingestion pipeline.
- **negative correlations** (`xbits isnotset`), which Sigma cannot express.
- **group-by keys that only liblognorm produced**, since its rulebases are
  per-format data files with no algorithm to reproduce. The regex-extracted
  ones are recovered by `--profile vector-enriched`, which takes this category
  from 313 rules down to 14.

Each of these carries a stable code in the report, with the reasoning attached.

## Status and what has not been verified

This is a 0.1.0 release and the rules it emits are marked `status:
experimental` for a reason.

**What is verified.** Every emitted document is parsed by
[pySigma](https://github.com/SigmaHQ/pySigma), the reference implementation, so
the output is valid Sigma rather than YAML that resembles it. The full upstream
corpus converts with zero parse failures and zero rejected documents, and the
conversion is deterministic: two runs are byte-identical.

Beyond shape, behaviour is checked too. A differential harness runs every
corpus rule it can judge, 4,083 of them, through two independent evaluators: a
reference implementation of Sagan semantics written from the engine C source,
and the real [rsigma](https://github.com/timescale/rsigma) engine evaluating
the converted rule. Roughly 24,000 event evaluations, no disagreements. This is
what caught the field-naming defect that silently broke a quarter of the corpus
before release.

The bundled VRL transforms are executed against a real Vector binary in CI, and
their address extraction is checked case by case against the branches of
Sagan's own `Parse_IP()`.

**What is not verified.** The differential harness covers detection semantics
only. Correlation rules, `pcre` and positional constructs are outside what the
reference evaluator can judge, and are skipped rather than approximated. No
test replays real production traffic. Treat the first deployment as a tuning
exercise, not a migration, and read the conversion report before trusting any
of it.

If you run the output through another Sigma engine, or against traffic the
harness does not model, reports of divergence are the most useful contribution
this project can receive.

## Credits

The rule corpus this tool reads is the work of
[Quadrant Information Security](https://github.com/quadrantsec) and the
contributors to [`sagan-rules`](https://github.com/quadrantsec/sagan-rules),
maintained continuously for well over a decade. This project only translates
it; the detection engineering is theirs.

## Read next

- [`docs/PIPELINE.md`](docs/PIPELINE.md) to get the output running under RSigma
- [`docs/MAPPING.md`](docs/MAPPING.md) for the keyword-by-keyword mapping
- [`docs/DESIGN-DECISIONS.md`](docs/DESIGN-DECISIONS.md) for the traps this
  converter avoids, and why
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) to work on the code

## Licence

GPL-2.0-only, matching `quadrantsec/sagan-rules`.

**The rules this tool produces are derivative works of the Sagan corpus and
inherit its licence.** If you redistribute converted rules, they are GPL-2.0
too. Running them in your own SOC is unaffected.
