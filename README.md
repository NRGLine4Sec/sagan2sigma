# sagan2sigma

Convert [Sagan](https://sagan.quadrantsec.com/) rules into
[Sigma](https://sigmahq.io/) rules.

Sagan's rule corpus is large, actively maintained and covers a lot of ground
that SigmaHQ does not, particularly network appliances and Unix daemons. The
Sagan engine itself has seen little movement in years. This tool moves the
rules to a format other engines can run, notably
[RSigma](https://github.com/timescale/rsigma).

On the upstream corpus (10,000 active rules across 337 files) it converts
**86.6%** into 9,466 Sigma documents, with zero parse failures, zero documents
rejected by pySigma, and zero rules the RSigma engine refuses to load. With
`--profile vector-enriched`, which ships the transforms needed to recreate the
fields Sagan derived from raw text, the rate rises to **89.5%**.

Everything it does not convert is reported with a stable code and the reasoning
behind it, so the gap in your coverage is explicit rather than silent.

## Just want the rules?

The upstream corpus, already converted with the default profile, is committed
under [`converted/`](converted). Take the Sigma rules from
[`converted/rules/`](converted/rules) without installing anything. A scheduled
job keeps them in step with the upstream corpus, reconverting the whole set on
each change, and [`converted/VERSIONS.md`](converted/VERSIONS.md) records which
snapshot they were built from and how old it is.

## Install

Not published to PyPI yet, so install from source:

```sh
git clone https://github.com/NRGLine4Sec/sagan2sigma.git
cd sagan2sigma
pip install .
```

Or in one line, without keeping the checkout:

```sh
pip install "git+https://github.com/NRGLine4Sec/sagan2sigma.git"
```

Either way you get a `sagan2sigma` command on your PATH. Python 3.10 or newer.

Once the project is released, `pip install sagan2sigma` will work as well; see
[`RELEASING.md`](RELEASING.md).

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

## Finding what SigmaHQ already covers

A companion command answers a question a migration always raises: which of the
converted rules already have an equivalent in [SigmaHQ](https://github.com/SigmaHQ/sigma),
so you can deploy SigmaHQ for those and keep the converted rules only where they
add coverage. It answers it by running, not by comparing text: every rule from
both sets is turned into events that satisfy it, and the RSigma engine decides
which rules each event fires. When it reports that SigmaHQ covers a converted
rule, a test event that fires both is attached.

```sh
pip install "sagan2sigma[overlap]"   # pulls in the two extra dependencies

sagan2sigma-overlap \
  --converted converted/rules \
  --sigmahq /path/to/sigmahq \
  --output overlap --cache .overlap-cache
```

It needs the `rsigma` binary on your PATH, and writes `OVERLAP-REPORT.md` (the
actionable list) and `overlap-report.json` (every verdict, with its witness
event). The method, the taxonomy and the results are in
[`docs/SIGMAHQ-OVERLAP.md`](docs/SIGMAHQ-OVERLAP.md).

A second, separate command answers a softer question the behavioural one cannot:
which converted rules *look like* they detect the same thing as a SigmaHQ rule,
even when they can never fire the same event because one matches raw text and the
other a structured field. It compares the distinctive terms rules search for and
their ATT&CK techniques, and produces review candidates, never verdicts:

```sh
sagan2sigma-conceptual \
  --converted converted/rules \
  --sigmahq /path/to/sigmahq \
  --output conceptual
```

It needs no engine and no extra dependency. It is a triage aid, not grounds for
retiring a rule, and the two analyses are almost disjoint by design; see
[`docs/CONCEPTUAL-OVERLAP.md`](docs/CONCEPTUAL-OVERLAP.md).

## What it will not do

The converter refuses rather than approximates. A missing rule is recoverable;
a rule that looks right and matches the wrong thing is not. It will not convert:

- **effective positional matching**, a non-zero `offset`, `depth` or `distance`,
  which pins a pattern to a byte position Sigma string modifiers cannot express.
  A zero-valued positional is a no-op in the Sagan engine and is converted.
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
corpus rule it can judge, 4,310 of them, through two independent evaluators: a
reference implementation of Sagan semantics written from the engine C source,
and the real [rsigma](https://github.com/timescale/rsigma) engine evaluating
the converted rule. Tens of thousands of event evaluations, no disagreements.
This is what caught the field-naming defect that silently broke a quarter of the
corpus
before release.

The bundled VRL transforms are executed against a real Vector binary in CI, and
their address extraction is checked case by case against the branches of
Sagan's own `Parse_IP()`.

**What is not verified.** The differential harness covers detection semantics
only. Correlation rules, `pcre` and effective (non-zero) positional constructs
are outside what the reference evaluator can judge, and are skipped rather than
approximated. No
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

- [`docs/SIGMAHQ-OVERLAP.md`](docs/SIGMAHQ-OVERLAP.md) to see which converted
  rules SigmaHQ already covers, and how that is established by testing
- [`docs/CONCEPTUAL-OVERLAP.md`](docs/CONCEPTUAL-OVERLAP.md) for the separate,
  lexical review-candidate analysis that covers the rules testing cannot reach
- [`docs/OVERLAP-INVENTORY.md`](docs/OVERLAP-INVENTORY.md) for the merged,
  confidence-tiered list of overlapping rules, pinned to a commit of each corpus
  (a point-in-time snapshot; regenerate with `sagan2sigma-inventory`)
- [`converted/`](converted) for the pre-converted rules and how they are kept
  current
- [`docs/PIPELINE.md`](docs/PIPELINE.md) to get the output running under RSigma
- [`docs/MAPPING.md`](docs/MAPPING.md) for the keyword-by-keyword mapping
- [`docs/DESIGN-DECISIONS.md`](docs/DESIGN-DECISIONS.md) for the traps this
  converter avoids, and why
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) to work on the code
- [`CONTRIBUTING.md`](CONTRIBUTING.md) to add a keyword handler

## Licence

GPL-2.0-only, matching `quadrantsec/sagan-rules`.

**The rules this tool produces are derivative works of the Sagan corpus and
inherit its licence.** If you redistribute converted rules, they are GPL-2.0
too. Running them in your own SOC is unaffected.
