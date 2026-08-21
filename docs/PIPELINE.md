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

### Choosing threat-intel feeds

`blacklist` and `zeek-intel` rules need a denylist and a Zeek Intel feed, in the
same `mmdb` form. The feeds change constantly and carry their own licences, so
none is bundled with this project. Instead, `tools/fetch_cti.py` downloads the
recommended public feeds and builds both MMDBs in one step, run before you start
the pipeline (it needs the `cti` extra, `pip install "sagan2sigma[cti]"`):

```sh
pip install "sagan2sigma[cti]"
# DShield -> denylist.mmdb, CriticalPathSecurity ThreatFox -> zeek-intel.mmdb
python tools/fetch_cti.py --output-dir /etc/vector
python tools/fetch_cti.py --list      # every known feed, its role and licence
```

The feeds it knows are the ones the Sagan docs point at, still public, plus a CC0
alternative:

| Feed | Role | Licence | Notes |
| --- | --- | --- | --- |
| SANS DShield `block.txt` | denylist | CC BY-NC-SA | Sagan's own recommendation; CIDR blocks |
| abuse.ch Feodo Tracker | denylist | CC0 | botnet C2 IPs; unrestricted use |
| [CriticalPathSecurity/Zeek-Intelligence-Feeds](https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds) | zeek | MIT code, mixed data | maintained public replacement for the closed Critical Stack, same Zeek Intel format |

Pick feeds with `--denylist-feed` / `--zeek-feed`; for example
`--denylist-feed feodotracker` uses only the CC0 feed. Point
`enrichment_tables.sagan_denylist.path` and `.sagan_zeek_intel.path` at the
results. For an air-gapped install, run the fetch on a connected host and copy the
two MMDBs across; re-run it on a schedule to keep the feeds current.

The lower-level `tools/build_denylist_mmdb.py` builds one MMDB from a feed file you
already have (`--format dshield|zeek|cidr`), which is what `fetch_cti.py` calls and
how you load a feed of your own. The `cidr` format is a plain IP or CIDR list, so a
private-range allowlist or any other IP list drops in the same way. Every lookup is
a longest-prefix network match, so CIDR entries cover every host inside them.

A note on why nothing is shipped in-repo: bundling a feed means redistributing it,
and the licences do not allow it. DShield's `block.txt` is CC BY-NC-SA, whose
non-commercial clause is incompatible with a repository that may be used
commercially; the CriticalPathSecurity aggregation is MIT for its code but collects
feeds under mixed, sometimes undefined terms. Fetching a feed for your own use, as
`fetch_cti.py` does, is not redistribution, so it is unaffected.

**The rules and the transforms are one deliverable.** A rule grouped on
`sagan_ip_2` is valid Sigma that never fires if nothing produces
`sagan_ip_2`. That is why the pipeline is emitted automatically with this
profile rather than left as an option.

### What the transforms do

`sagan-json.vrl` runs first, before any field parsing looks at the body. When
the syslog body is a JSON document, RSigma parses it into fields but keeps no
raw string, so a `content` / `pcre` / `meta_content` search on the raw body,
which Sagan runs against the raw JSON text, has nothing to run against. This
transform gives it one: it copies the body into `sagan_raw` **verbatim**, then,
when the body is JSON, lifts the object's keys to the top level. Both search
families then resolve, `json_content` against the lifted key and the raw search
against `sagan_raw`, so the 386 rules that combine the two are no longer refused
with `E_RAW_TEXT_ON_JSON_EVENT`. 255 of them convert outright and the rest
surface a different pre-existing blocker (a positional field, an unresolved
variable), which is why the enriched rate rises by 255, not 386. The syslog envelope and
`sagan_raw` win any name clash with a body key, so `appname` and `hostname` are
never clobbered from inside the payload. A non-JSON body is left untouched with
`sagan_raw` set to the message, so the transform is harmless on plain events.
Because the raw body is preserved byte for byte, the match is faithful to the
exact serialization Sagan saw; the converted rule carries `D_RAW_TEXT_MATCH` to
say the match is format-bound and not portable to a re-serialized event.

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

Five positions is a deliberate ceiling, and the one place it shows is
`blacklist: all` / `zeek-intel: all` / `bluedot: ... track all`, where the engine
walks its whole lookup cache of up to `MAX_PARSE_IP` (30) addresses. A message
carrying more than five addresses can hold a listed one the converted rule never
looks at. The error is always an under-match, never a false alarm, and a few
dozen corpus rules use `all`, so the limit is exercised rather than theoretical.
Raising the ceiling is a matter of widening the transform and the profile
together, should a deployment need it.

Worth knowing alongside it: in the engine that cache is filled only for a rule
that declares `parse_src_ip` or `parse_dst_ip`, so an `all` rule declaring
neither scans nothing at all and never fires. Every corpus rule using `all`
declares a position, so this does not bite today, but it is why `all` cannot be
read as "every address in the message" on its own.

`sagan-geoip.vrl` enriches each parsed address with its country. For every
`sagan_ip_N` it looks the address up in the `sagan_geoip` enrichment table (type
`geoip`, pointing at the MaxMind database) and sets `sagan_geoip_country_N` to
the ISO code. An address with no country, whether private, non-routable or just
absent from the database, leaves the field unset. That matches the engine, which
reports those as `GEOIP_SKIP` and then runs no `is` / `isnot` comparison at all,
so the rule stays silent rather than treating "no country" as "not in the list".
It is emitted only when the corpus has `country_code` rules, so a pipeline that
does not need a GeoIP database is not made to require one.

`sagan-time.vrl` derives the weekday (`sagan_event_weekday`, 0=Sunday) and the
time as an HHMM integer (`sagan_event_hhmm`) from the event timestamp, the two
values `alert_time` rules match a recurring window on. It is emitted only when
the corpus has `alert_time` rules. Note the timestamp is read in the timezone
Vector formats in, which must match the Sagan host's local time for the window
to align; see `D_ALERT_TIME_EVENT_CLOCK` in the report.

`sagan-denylist.vrl` and `sagan-zeek-intel.vrl` flag each parsed address a threat
feed lists (`sagan_denylist_N`, `sagan_zeek_intel_N`), which is what `blacklist`
and `zeek-intel` rules match on. Each reads its own `mmdb` enrichment table, so
they are emitted, with the table, only when the corpus has those rules. See
"Choosing threat-intel feeds" below for building the databases.

`sagan-bluedot.vrl` is the substitute for `bluedot`, Sagan's closed commercial
threat-intel lookup. Because that source cannot be integrated, this transform
matches each parsed address against **open-source feeds you supply, one MMDB per
Bluedot category** (`sagan_bluedot_tor_N`, `_proxy_N`, `_malicious_N`,
`_honeypot_N`), and the converted rule fires on your feeds rather than on Bluedot.
This is a deliberate, degraded substitution, not a faithful reproduction (see
`docs/DESIGN-DECISIONS.md` and `D_BLUEDOT_SUBSTITUTION`). Point each table's path
at a feed: for the Tor category use the Tor Project exit-node list, which is the
authoritative source and makes that category near-faithful; the others are your
choice and will diverge from Bluedot. Build each MMDB with
`tools/build_denylist_mmdb.py`, exactly as for the denylist. The transform and its
four tables are emitted only when the corpus has `bluedot` rules.

`username-extraction.vrl` is **not** a port and says so at the top of the file.
Sagan derives usernames through liblognorm rulebases, which are per-format data
files with no algorithm to reproduce. It is a starter kit of patterns for the
formats the corpus groups by user: FortiGate and similar `user="..."`, Windows
Security `Account Name:`, OpenSSH, sudo and IBM i. Validate them against your
own logs before relying on them.

All these transforms are executed against a real Vector binary in CI, so the
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
