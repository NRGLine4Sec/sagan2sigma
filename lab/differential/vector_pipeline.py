"""Build the RSigma side of an enriched probe with the shipped Vector transforms.

Why this exists
---------------
`tests/differential/events.py` knows how to render an event the way a pipeline
would, and that is a model of the pipeline written by the same hand as the
converter. It is exactly the kind of shared belief the engine differential was
built to remove: `sagan-json.vrl` let the syslog envelope overwrite a JSON
body's own fields for months, the model reproduced the same rule, and the two
agreed while 131 corpus rules could not fire.

So under a profile that declares a pipeline, the probe is no longer rendered.
The syslog line handed to Sagan is handed to a real Vector running the very
transforms `sagan2sigma --emit-vector-config` writes, in the order that emitter
puts them in, and whatever comes out is what RSigma is asked about. The
differential then judges the deliverable the documentation claims, rules and
transforms together, rather than the rules alone.

What it does not do
-------------------
Nothing here supplies an enrichment table that is not on this machine. GeoIP
runs because the lab ships `config/country.mmdb`; the denylist, Zeek intel and
Bluedot substitutes need feeds this repository cannot redistribute, so their
transforms stay off and the rules that read their fields stay excluded, counted
by name.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LAB = Path(__file__).resolve().parent.parent
FEEDS = LAB / "config" / "rules"

#: Where the lab keeps the databases the optional transforms read.
DATABASES: dict[str, Path] = {
    "geoip": LAB / "config" / "country.mmdb",
    "denylist": FEEDS / "diff-blacklist.txt",
    "zeek": FEEDS / "diff-zeek-intel.dat",
}

#: The enrichment table each optional transform looks its addresses up in, and
#: how the lab's copy of the feed is read.
#:
#: Built as an `mmdb` by `tools/build_denylist_mmdb.py`, the script the
#: documentation tells an operator to run, so the differential exercises the
#: lookup the shipped configuration declares. That matters for what these feeds
#: mostly contain: a DShield block list is networks rather than hosts, and an
#: exact-match table would leave prefix matching untested on both sides while
#: the engine's own blacklist resolves it. A run without the MMDB writer falls
#: back to a CSV table, which matches an address exactly, and says so.
#:
#: Keyed by the emitter's flag; the values are the Vector table name and the
#: processor name `sagan.yaml` uses, which are not the same word in either case.
TABLES: dict[str, tuple[str, str]] = {
    "denylist": ("sagan_denylist", "blacklist"),
    "zeek": ("sagan_zeek_intel", "zeek-intel"),
}


def _feed_addresses(flag: str) -> list[str]:
    """The addresses a lab feed lists, read from the file Sagan is given.

    One file, two consumers. Keeping a separate copy for the Vector side is how
    the two would drift, and a differential whose two sides disagree about what
    is on the denylist measures its own fixtures.
    """
    out: list[str] = []
    for line in DATABASES[flag].read_text(encoding="utf-8").splitlines():
        if not line or line[0] in "#; ":
            continue
        # blacklist.c takes the whole line; zeek-intel.c takes the first of
        # three tab-separated columns.
        out.append(line.split("\t")[0].strip())
    return out


#: Vector's own bookkeeping, which a syslog source would not produce and no
#: rule reads. Removed so the event RSigma sees is the pipeline's output and
#: not the harness's.
_SOURCE_ARTEFACTS = ("source_type", "host")

#: Field carrying the caller's index through the pipeline, so an output can be
#: tied to the probe that produced it without relying on Vector preserving
#: order. Removed before the event is handed on.
_INDEX = "sagan_probe_index"

#: Which optional transform produces each internal value a profile can name.
#: `None` means the transform is always in the chain. This is what lets the
#: differential say *why* a rule is set aside rather than skipping it silently.
PRODUCED_BY: dict[str, str | None] = {
    "src_ip": None,
    "dest_ip": None,
    "username": None,
    "src_country": "geoip",
    "dest_country": "geoip",
    "denylist": "denylist",
    "zeek_intel": "zeek",
    "bluedot_tor": "bluedot",
    "bluedot_proxy": "bluedot",
    "bluedot_malicious": "bluedot",
    "bluedot_honeypot": "bluedot",
    "event_weekday": "time",
    "event_hhmm": "time",
}


@dataclass
class VectorPipeline:
    """A running configuration of the shipped transforms.

    ``flags`` selects the optional transforms, using the same names the emitter
    uses. A flag whose database is missing is refused rather than quietly
    dropped: a transform that runs without its table produces no field, and a
    rule reading that field would then be judged against an event nobody
    promised.
    """

    binary: str = "vector"
    flags: dict[str, bool] = field(default_factory=dict)
    #: JSON keys whose country the converted rules read. The shipped transforms
    #: resolve the addresses they parse out of the text; a rule binding an
    #: address by name needs that key looked up too, and the emitter generates
    #: exactly that. Leaving it out here made 138 rules fire on Sagan and stay
    #: silent on RSigma, which is the pipeline being wrong and not the rules.
    geoip_keys: frozenset[str] = frozenset()
    config: Path = field(init=False)

    def __post_init__(self) -> None:
        for flag, enabled in self.flags.items():
            database = DATABASES.get(flag)
            if enabled and database is not None and not database.is_file():
                raise FileNotFoundError(
                    f"the {flag} transform needs {database}, which is not here"
                )
        self.config = _write_config(self.flags, self.geoip_keys)

    def run(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Every event, transformed, in the order they were given."""
        if not events:
            return []
        payload = "\n".join(
            json.dumps({**event, _INDEX: index}, sort_keys=True)
            for index, event in enumerate(events)
        )
        completed = subprocess.run(
            [self.binary, "--config", str(self.config), "--quiet"],
            input=payload + "\n",
            capture_output=True,
            text=True,
            timeout=300,
        )
        out: dict[int, dict[str, Any]] = {}
        for line in completed.stdout.splitlines():
            if not line.strip().startswith("{"):
                continue
            row = json.loads(line)
            index = row.pop(_INDEX, None)
            for artefact in _SOURCE_ARTEFACTS:
                row.pop(artefact, None)
            if isinstance(index, int):
                out[index] = row
        if len(out) != len(events):
            raise RuntimeError(
                f"the pipeline returned {len(out)} of {len(events)} events; "
                f"vector said: {completed.stderr[-400:]}"
            )
        return [out[index] for index in range(len(events))]


def _write_config(
    flags: dict[str, bool], geoip_keys: frozenset[str] = frozenset()
) -> Path:
    """A stdin-to-console pipeline carrying the emitter's transform chain."""
    # Imported here so this module can be read without the repository on the
    # path, and so the chain is always the emitted one rather than a copy.
    from sagan2sigma.emit.vector import (
        GENERATED_GEOIP_KEYS,
        country_lookups,
        pipeline_transforms,
        read_transform,
    )

    work = Path(tempfile.mkdtemp(prefix="vector-pipeline-"))
    blocks: list[str] = []
    previous = "in"
    for name, filename in pipeline_transforms(flags, geoip_keys=bool(geoip_keys)):
        text = (
            country_lookups(geoip_keys)
            if filename == GENERATED_GEOIP_KEYS
            else read_transform(filename)
        )
        (work / filename).write_text(text, encoding="utf-8")
        blocks.append(
            f"  {name}:\n"
            f"    type: remap\n"
            f"    inputs: [{previous}]\n"
            f"    file: {work / filename}\n"
            f"    drop_on_error: false\n"
        )
        previous = name

    tables = ""
    if flags.get("geoip"):
        tables += f"  sagan_geoip:\n    type: mmdb\n    path: {DATABASES['geoip']}\n"
    for flag, (name, _) in TABLES.items():
        if not flags.get(flag):
            continue
        database = _build_mmdb(flag, name, work)
        if database is not None:
            tables += f"  {name}:\n    type: mmdb\n    path: {database}\n"
            continue
        listing = work / f"{name}.csv"
        listing.write_text(
            "ip\n" + "\n".join(_feed_addresses(flag)) + "\n", encoding="utf-8"
        )
        tables += (
            f"  {name}:\n"
            f"    type: file\n"
            f"    file:\n"
            f"      path: {listing}\n"
            f"      encoding:\n"
            f"        type: csv\n"
            f"    schema:\n"
            f"      ip: string\n"
        )
    config = work / "pipeline.yaml"
    config.write_text(
        (f"enrichment_tables:\n{tables}" if tables else "")
        + "sources:\n  in:\n    type: stdin\n    decoding:\n      codec: json\n"
        + "transforms:\n"
        + "".join(blocks)
        + f"sinks:\n  out: {{type: console, inputs: [{previous}], "
        + "encoding: {codec: json}}\n",
        encoding="utf-8",
    )
    return config


#: How each lab feed is spelled, for the builder that turns it into an mmdb.
_FEED_FORMAT = {"denylist": "cidr", "zeek": "zeek"}


def _build_mmdb(flag: str, name: str, work: Path) -> Path | None:
    """The feed as an MMDB, or None when the writer is not installed.

    Run as a subprocess rather than imported, because that is how an operator
    runs it: a differential that exercises the shipped script end to end also
    notices when its command line stops working.
    """
    builder = LAB.parent / "tools" / "build_denylist_mmdb.py"
    database = work / f"{name}.mmdb"
    completed = subprocess.run(
        [
            sys.executable,
            str(builder),
            "--format",
            _FEED_FORMAT[flag],
            "--feed",
            str(DATABASES[flag]),
            "--output",
            str(database),
        ],
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0 and database.is_file():
        return database
    reason = (completed.stderr.strip().splitlines() or [""])[-1]
    print(f"  [pipeline] {name}: exact-match table, no MMDB written ({reason})")
    return None


def feed_files(flags: dict[str, bool]) -> dict[str, Path]:
    """The Sagan processors to enable, and the feed each one reads.

    Keyed by the name `sagan.yaml` uses, so the result goes straight to
    `harness.config_with_processors`. Both engines then consult the same file,
    which is what makes a disagreement about a listed address mean something.
    """
    return {
        processor: DATABASES[flag]
        for flag, (_, processor) in TABLES.items()
        if flags.get(flag)
    }


def listed_addresses(flag: str, limit: int = 5) -> list[str]:
    """Concrete addresses the lab's feed for ``flag`` covers.

    A feed entry may be a network, and a probe cannot plant one: `Parse_IP`
    would read `203.0.113.0/24` as the bare address `203.0.113.0`, which is
    inside the network by luck rather than by construction. Each network is
    therefore expanded into hosts, so what the probe carries is what an event
    would carry and the lookup that resolves it is the prefix match the shipped
    configuration declares.
    """
    out: list[str] = []
    for entry in _feed_addresses(flag):
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if network.num_addresses == 1:
            out.append(str(network.network_address))
            continue
        # Skip the network address itself, which a producer would not emit.
        hosts = network.hosts()
        out.extend(str(next(hosts)) for _ in range(min(limit, 4)))
    return out[:limit]


def source_event(
    body: str,
    program: str,
    facility: str,
    level: str,
    host: str = "sensor01",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """What Vector's syslog source produces for one line, before any transform.

    Field names from Vector's `syslog` source: the body in `message`, the
    envelope in `appname`, `hostname`, `facility` and `severity`. Everything the
    profile promises is derived from these by the transforms.

    ``timestamp`` sets the instant `sagan-time.vrl` derives the weekday and the
    hour from. Left out, the source stamps its own arrival time, which is fine
    for everything except an `alert_time` rule, where the differential has to
    put both engines at the same moment.
    """
    event: dict[str, Any] = {
        "message": body,
        "appname": program,
        "hostname": host,
        "facility": facility,
        "severity": level,
    }
    if timestamp is not None:
        event["timestamp"] = timestamp
    return event
