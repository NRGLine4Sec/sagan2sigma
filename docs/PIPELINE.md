# Running the output

The converter targets [RSigma](https://github.com/timescale/rsigma), a Rust
Sigma engine. Two ingestion shapes are supported, and the choice determines
which `--profile` you convert with.

## Option A: RSigma parses syslog directly

```
appliances ──syslog──► rsigma engine daemon ──► alerts
```

```sh
sagan2sigma sagan-rules -o converted --profile rsigma-syslog
```

RSigma parses RFC 3164 and RFC 5424 itself. The message body is exposed as
`_raw` and the envelope as `appname`, `hostname`, `facility`, `severity`.

Fewer moving parts, and no transformation between the wire format and the
rules. The drawback is that raw-body rules are pinned to RSigma: `_raw` is not
a portable Sigma field.

## Option B: Vector normalises and enriches first

```
appliances ──syslog──► vector ──JSON──► rsigma ──► alerts
                         │
                         └─ bundled VRL transforms recreate src_ip, dest_ip
                            and username from the raw message
```

```sh
sagan2sigma sagan-rules -o converted --profile vector-enriched
```

This is the profile to use if you want the correlations. It converts **89.4%**
of the corpus against 86.6% for the plain profiles, because the 313 rules
refused with `E_GROUPBY_UNRESOLVED` drop to 14. With a `$HOME_COUNTRY` value and
the GeoIP database in place, the `country_code` rules convert too and the rate
reaches **90.8%**.

It also writes `converted/vector/`, a runnable pipeline carrying the transforms
those rules depend on. Two placeholders in `vector.yaml` need your values, the
listen address and the RSigma endpoint; a third, the IP-to-country database path,
appears only when the corpus has `country_code` rules. Everything else is ready:

```sh
cd converted/vector
$EDITOR vector.yaml          # set sources.appliances.address and sinks.rsigma.uri
                             # and, if present, enrichment_tables.sagan_geoip.path
vector validate --no-environment vector.yaml
vector --config vector.yaml
```

### Choosing an IP-to-country database

The database is not bundled: every provider carries a licence, and MaxMind's in
particular needs a signed-up licence key. So the enrichment table is declared as
Vector's provider-agnostic `mmdb` type, and any of these MMDB databases drops in
by setting `enrichment_tables.sagan_geoip.path`. No code changes between them.

| Provider | Licence | Update | Download | Notes |
| --- | --- | --- | --- | --- |
| **DB-IP IP-to-Country Lite** (default) | CC BY 4.0 | monthly | direct `.mmdb.gz`, no signup | recommended: cleanest licence, simplest download |
| MaxMind GeoLite2-Country | MaxMind EULA | weekly | signup + licence key | the original, if you already run it |
| IPLocate ip-to-country | CC BY-SA 4.0 | daily | GitHub LFS mirror, no signup | freshest; share-alike licence |

Trade-offs: DB-IP is the least friction to obtain and its CC BY licence carries no
share-alike obligation, which is why it is the default; monthly is ample for
country-level geolocation. IPLocate updates daily and is the pick if freshness
matters, at the cost of a Git-LFS download and a share-alike licence. MaxMind is
supported for those already licensed to it. All three attach an attribution
requirement when you display results; check each provider's terms.

Getting the default, DB-IP:

```sh
# Current month; DB-IP publishes a new file at the start of each month.
month=$(date +%Y-%m)
curl -sL "https://download.db-ip.com/free/dbip-country-lite-${month}.mmdb.gz" \
  | gunzip > /etc/vector/ip-to-country.mmdb
```

IPLocate, if you prefer daily updates (needs a Git-LFS-aware fetch):

```sh
curl -sL "https://media.githubusercontent.com/media/iplocate/ip-address-databases/main/ip-to-country/ip-to-country.mmdb" \
  -o /etc/vector/ip-to-country.mmdb
```

Whichever you choose, point `enrichment_tables.sagan_geoip.path` at it. Without a
database Vector refuses to start when `country_code` rules are present, which is
why the transform is emitted only then. The providers disagree on the record
schema, MaxMind and DB-IP nesting the ISO code at `country.iso_code` and IPLocate
exposing it at the top level as `country_code`; `sagan-geoip.vrl` reads both, so
the swap really is code-free.

**The rules and the transforms are one deliverable.** A rule grouped on
`sagan_ip_2` is valid Sigma that never fires if nothing produces
`sagan_ip_2`. That is why the pipeline is emitted automatically with this
profile rather than left as an option.

### What the transforms do

`sagan-parse-ip.vrl` is a **faithful port** of `Parse_IP()` from
`src/parsers/ip.c`. Sagan does not use a regular expression: it rewrites a
fixed delimiter set to spaces, splits on whitespace, and validates each token
with `inet_pton()`. The port reproduces every branch, including the ones that
are easy to miss:

| Log fragment | Extracted | Why |
| --- | --- | --- |
| `from 192.168.1.50 port 22` | `192.168.1.50` | plain IPv4 |
| `srcip="10.0.0.1"` | `10.0.0.1` | `"` and `=` are delimiters |
| `src outside:203.0.113.7/51234` | `203.0.113.7` | both sides of a separator are validated, which is what makes Cisco ASA resolve |
| `client 198.51.100.9#41234` | `198.51.100.9` | BIND host#port form |
| `blocked from 172.16.0.9.` | `172.16.0.9` | trailing dot |
| `version 1.2.3`, `4.5.6.7.8` | nothing | the dot-count envelope rejects both |
| `999.1.1.1`, `01.2.3.4` | nothing | `inet_pton` rejects out-of-range octets and leading zeros |

Position matters and is preserved. `parse_src_ip: 2` means the second address
in the message, so the transform exposes `sagan_ip_1` through `sagan_ip_5` and
each converted rule targets the index it actually declared. `src_ip` and
`dest_ip` are aliases for positions 1 and 2, matching the 94% and 91%
conventions in the corpus, and are never used where a rule asked for something
else.

`sagan-geoip.vrl` enriches each parsed address with its country. For every
`sagan_ip_N` it looks the address up in the `sagan_geoip` enrichment table (type
`geoip`, pointing at the MaxMind database) and sets `sagan_geoip_country_N` to
the ISO code. A private or unresolved address has no country, which is left
unset, matching how `country_code: ... isnot` still fires on it. It is emitted
only when the corpus has `country_code` rules, so a pipeline that does not need a
GeoIP database is not made to require one.

`sagan-time.vrl` derives the weekday (`sagan_event_weekday`, 0=Sunday) and the
time as an HHMM integer (`sagan_event_hhmm`) from the event timestamp, the two
values `alert_time` rules match a recurring window on. It is emitted only when
the corpus has `alert_time` rules. Note the timestamp is read in the timezone
Vector formats in, which must match the Sagan host's local time for the window
to align; see `D_ALERT_TIME_EVENT_CLOCK` in the report.

`username-extraction.vrl` is **not** a port and says so at the top of the file.
Sagan derives usernames through liblognorm rulebases, which are per-format data
files with no algorithm to reproduce. It is a starter kit of patterns for the
formats the corpus groups by user: FortiGate and similar `user="..."`, Windows
Security `Account Name:`, OpenSSH, sudo and IBM i. Validate them against your
own logs before relying on them.

All four transforms are executed against a real Vector binary in CI, so the
behaviour above is tested rather than asserted. `sagan-geoip.vrl` is exercised end
to end too: CI downloads the free DB-IP and IPLocate databases and runs the
transform through Vector against both, which is what proves the provider-agnostic
schema handling works and not merely that it compiles. Choosing databases with a
permissive, key-free licence is what makes that test possible. The Sigma the
`country_code` handler produces is additionally checked against the RSigma engine
directly.

### What it still does not recover

14 rules remain refused, and they are the honest residue: they group on a value
that only liblognorm produced, with no `parse_src_ip` fallback to fall back to.
78 more convert but carry `D_NORMALIZE_PRECEDENCE`, because Sagan would have
let liblognorm resolve the address first and only the positional fallback is
reproduced.

## Option C: Vector normalises first, without enrichment

```
appliances ──syslog──► vector ──JSON──► rsigma ──► alerts
```

```sh
sagan2sigma sagan-rules -o converted --profile vector-json
```

A minimal Vector configuration:

```toml
[sources.appliances]
type = "syslog"
address = "0.0.0.0:514"
mode = "tcp"

[sinks.rsigma]
type = "http"
inputs = ["appliances"]
uri = "http://rsigma:8080/ingest"
encoding.codec = "json"
```

Vector's syslog source emits `message`, `appname`, `hostname`, `facility`,
`severity`, which is what the `vector-json` profile targets.

Worth the extra hop when you want enrichment before detection. Which brings us
to the main reason to consider it.

## Inspecting what is left

Whichever profile you pick, the JSON report is the place to look:

```sh
# rules still refused for a missing group-by field
jq '.refused[] | select(.code == "E_GROUPBY_UNRESOLVED") | {sid, title, detail}' \
  converted/conversion-report.json

# rules that converted but depend on the VRL transforms running
jq -r '.degradations[] | select(.codes | index("D_POSITIONAL_IP_FIELD")) | .sid' \
  converted/conversion-report.json
```

`D_GROUPBY_SYSLOG_HOST` (387 rules) deserves its own pass. Those converted
under every profile, but they group on the emitting host rather than on an
attacker address, which is rarely what you want from a brute-force rule. They
are rules where Sagan itself fell back to the syslog sender, so the conversion
is faithful; it is the original that is coarse.

## Deployment order

1. **Convert and read the report before deploying anything.** The refusals tell
   you what your coverage does not include; the degradations tell you which
   rules will behave differently from Sagan.

2. **Start with the JSON rules.** Filter for rules whose detection targets
   named fields rather than `_raw`. They are portable, precise and the least
   likely to be noisy.

3. **Triage `falsepositives` before promoting anything.** Every rule ships with
   `status: experimental` and an explicit "not yet tuned" marker, which is the
   truth about a machine translation nobody has reviewed.

4. **Pin the conversion in CI.** Re-run against upstream on a schedule and gate
   on the rate:

   ```sh
   sagan2sigma sagan-rules -o converted --min-rate 80 --fail-on-validation
   ```

   Because identifiers are deterministic, the diff between two runs shows
   exactly which rules changed upstream.

## Portability beyond RSigma

`D_RAW_TEXT_MATCH` covers 5,828 rules, and it is the honest warning that these
work under RSigma but do not translate well elsewhere. `_raw|contains` becomes
`index=* "pattern"` under a Splunk backend and a leading-wildcard full-text
search under Elasticsearch. Both are correct and both are unusable at volume.

The rules without that degradation, chiefly the JSON ones, translate cleanly
through `sigma convert` to any pySigma backend.

If portability matters more than coverage, filter on the degradation list in
the JSON report and deploy only the clean subset:

```sh
jq -r '.degradations[] | select(.codes | index("D_RAW_TEXT_MATCH") | not) | .sid' \
  converted/conversion-report.json
```
