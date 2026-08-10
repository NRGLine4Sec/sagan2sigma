"""Tests that execute the bundled VRL against a real Vector binary.

Everything else in this suite checks that the converter produces plausible
output. These check that the enrichment the ``vector-enriched`` profile depends
on actually behaves like the Sagan engine, by running it.

They are skipped when ``vector`` is not on PATH. In CI a dedicated job installs
it, because a profile that promises fields nobody produces is exactly the
failure mode this project refuses elsewhere.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar

import pytest

from sagan2sigma import __version__
from sagan2sigma.emit.vector import TRANSFORMS, write_pipeline

VECTOR = shutil.which("vector")

pytestmark = pytest.mark.skipif(
    VECTOR is None, reason="install Vector to run the VRL tests"
)

VRL_DIR = Path(__file__).parents[2] / "src" / "sagan2sigma" / "data" / "vrl"
PARSE_IP = VRL_DIR / "sagan-parse-ip.vrl"
USERNAME = VRL_DIR / "username-extraction.vrl"
TIME = VRL_DIR / "sagan-time.vrl"
GEOIP = VRL_DIR / "sagan-geoip.vrl"
DENYLIST = VRL_DIR / "sagan-denylist.vrl"
ZEEK_INTEL = VRL_DIR / "sagan-zeek-intel.vrl"

_BUILDER_PATH = Path(__file__).parents[2] / "tools" / "build_denylist_mmdb.py"


def _load_builder():
    """Load the denylist MMDB builder script as a module."""
    spec = importlib.util.spec_from_file_location("build_denylist_mmdb", _BUILDER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: IP-to-country databases CI downloads and points these variables at, one per
#: provider so the provider-agnostic transform is proven against each real schema
#: (DB-IP nests the code at country.iso_code, IPLocate exposes it at top level).
GEOIP_DATABASES = {
    name: path
    for name, env in (
        ("dbip", "SAGAN2SIGMA_GEOIP_MMDB_DBIP"),
        ("iplocate", "SAGAN2SIGMA_GEOIP_MMDB_IPLOCATE"),
    )
    if (path := os.environ.get(env)) and Path(path).is_file()
}


def run_vrl(program: Path, events: list[dict], tmp_path: Path) -> list[dict]:
    """Run a VRL program over events and return the transformed events."""
    source = tmp_path / "events.json"
    source.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8"
    )
    completed = subprocess.run(
        [str(VECTOR), "vrl", "-i", str(source), "-p", str(program), "-o"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [
        json.loads(line)
        for line in completed.stdout.splitlines()
        if line.strip().startswith("{")
    ]


def ips(event: dict) -> list[str]:
    """Ordered positional addresses extracted from one event."""
    return [event[f"sagan_ip_{n}"] for n in range(1, 6) if f"sagan_ip_{n}" in event]


class TestParseIpMatchesSaganSemantics:
    """Each case mirrors a branch of Parse_IP() in src/parsers/ip.c."""

    CASES: ClassVar[list[tuple[str, list[str]]]] = [
        # Plain IPv4, the overwhelmingly common case.
        (
            "Failed password for admin from 192.168.1.50 port 44231 ssh2",
            ["192.168.1.50"],
        ),
        # Delimiters rewritten to spaces, so key=value and quotes both work.
        ('srcip="10.0.0.1" dstip="10.0.0.2" action=deny', ["10.0.0.1", "10.0.0.2"]),
        # Both sides of a separator are validated, which is what makes Cisco
        # ASA lines resolve: the address sits after the colon.
        (
            "%ASA-4-106023: Deny tcp src outside:203.0.113.7/51234 "
            "dst inside:10.1.1.5/443",
            ["203.0.113.7", "10.1.1.5"],
        ),
        # BIND style host#port.
        ("client 198.51.100.9#41234: query: example.com IN A", ["198.51.100.9"]),
        # IPv6.
        ("connection closed by 2001:db8::dead:beef port 22", ["2001:db8::dead:beef"]),
        # Trailing dot at the end of a sentence.
        ("blocked traffic from 172.16.0.9. see policy", ["172.16.0.9"]),
        # Version strings must not be mistaken for addresses.
        ("agent version 1.2.3 build 4.5.6.7.8 started", []),
        # inet_pton rejects out-of-range octets and leading zeros.
        ("invalid 999.1.1.1 and padded 01.2.3.4 present", []),
        ("no address at all in this line", []),
    ]

    @pytest.mark.parametrize(("message", "expected"), CASES)
    def test_extraction(
        self, message: str, expected: list[str], tmp_path: Path
    ) -> None:
        events = run_vrl(PARSE_IP, [{"message": message}], tmp_path)
        assert ips(events[0]) == expected

    def test_positions_are_ordered_and_one_based(self, tmp_path: Path) -> None:
        """parse_src_ip: 2 means the second address, so order is the contract."""
        message = "flow 10.0.0.1 -> 10.0.0.2 via 10.0.0.3"
        event = run_vrl(PARSE_IP, [{"message": message}], tmp_path)[0]
        assert event["sagan_ip_1"] == "10.0.0.1"
        assert event["sagan_ip_2"] == "10.0.0.2"
        assert event["sagan_ip_3"] == "10.0.0.3"

    def test_convenience_aliases_follow_the_corpus_convention(
        self, tmp_path: Path
    ) -> None:
        message = "session from 10.0.0.1 to 10.0.0.2"
        event = run_vrl(PARSE_IP, [{"message": message}], tmp_path)[0]
        assert event["src_ip"] == "10.0.0.1"
        assert event["dest_ip"] == "10.0.0.2"

    def test_protocol_keywords_are_not_addresses(self, tmp_path: Path) -> None:
        event = run_vrl(PARSE_IP, [{"message": "tcp udp icmp 10.0.0.1"}], tmp_path)[0]
        assert ips(event) == ["10.0.0.1"]

    def test_missing_message_does_not_fail(self, tmp_path: Path) -> None:
        event = run_vrl(PARSE_IP, [{"other": "field"}], tmp_path)[0]
        assert ips(event) == []


class TestUsernameExtraction:
    CASES: ClassVar[list[tuple[str, str | None]]] = [
        ('devname=fw user="jdoe" action=login', "jdoe"),
        ("srcip=10.0.0.1 user=bob action=deny", "bob"),
        ("Failed password for invalid user admin from 192.168.1.50 port 22", "admin"),
        ("Accepted publickey for carol from 10.0.0.5 port 22 ssh2", "carol"),
        ("    dave : TTY=pts/0 ; PWD=/home/dave ; COMMAND=/bin/ls", "dave"),
        ("AUTFAIL USER(QSECOFR) an incorrect password was entered", "QSECOFR"),
        ("nothing identifying here at all", None),
    ]

    @pytest.mark.parametrize(("message", "expected"), CASES)
    def test_extraction(
        self, message: str, expected: str | None, tmp_path: Path
    ) -> None:
        event = run_vrl(USERNAME, [{"message": message}], tmp_path)[0]
        assert event.get("sagan_username") == expected

    def test_windows_skips_machine_and_placeholder_accounts(
        self, tmp_path: Path
    ) -> None:
        message = (
            "An account failed to log on. Subject: Account Name: WKS01$ "
            "Account For Which Logon Failed: Account Name: alice"
        )
        event = run_vrl(USERNAME, [{"message": message}], tmp_path)[0]
        assert event["sagan_username"] == "alice"

    def test_quoted_form_wins_over_the_loose_fallback(self, tmp_path: Path) -> None:
        message = 'for user decoy and user="real"'
        event = run_vrl(USERNAME, [{"message": message}], tmp_path)[0]
        assert event["sagan_username"] == "real"


def run_geoip_pipeline(
    database: str, messages: list[str], tmp_path: Path
) -> list[dict]:
    """Run stdin -> parse-ip -> geoip -> console through Vector with a database.

    The whole enrichment path is exercised, not the VRL alone, because the geoip
    transform depends on the ``mmdb`` enrichment table that only a full pipeline
    provides.
    """
    config = tmp_path / "geoip.yaml"
    config.write_text(
        "enrichment_tables:\n"
        "  sagan_geoip:\n"
        "    type: mmdb\n"
        f"    path: {database}\n"
        "sources:\n"
        "  in: {type: stdin}\n"
        "transforms:\n"
        "  sagan_parse_ip:\n"
        "    type: remap\n"
        "    inputs: [in]\n"
        f"    file: {PARSE_IP}\n"
        "    drop_on_error: false\n"
        "  sagan_geoip:\n"
        "    type: remap\n"
        "    inputs: [sagan_parse_ip]\n"
        f"    file: {GEOIP}\n"
        "    drop_on_error: false\n"
        "sinks:\n"
        "  out: {type: console, inputs: [sagan_geoip], encoding: {codec: json}}\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [str(VECTOR), "--config", str(config), "--quiet"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        out, _ = process.communicate(input="\n".join(messages) + "\n", timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        out, _ = process.communicate()
    return [
        json.loads(line) for line in out.splitlines() if line.strip().startswith("{")
    ]


@pytest.mark.skipif(
    not GEOIP_DATABASES,
    reason="set SAGAN2SIGMA_GEOIP_MMDB_DBIP / _IPLOCATE to an .mmdb to run",
)
class TestGeoipEnrichment:
    """The same transform must resolve every provider's schema, run for real."""

    @pytest.mark.parametrize("provider", sorted(GEOIP_DATABASES))
    def test_country_is_resolved_for_public_addresses(
        self, provider: str, tmp_path: Path
    ) -> None:
        database = GEOIP_DATABASES[provider]
        events = run_geoip_pipeline(
            database,
            [
                "Accepted publickey for admin from 8.8.8.8 port 44231 ssh2",
                "login attempt from 5.255.255.5 rejected",
                "internal service on 10.0.0.1 restarted",
            ],
            tmp_path,
        )
        by_ip = {e.get("sagan_ip_1"): e for e in events}
        # A US and a RU public address resolve regardless of the record schema.
        assert by_ip["8.8.8.8"].get("sagan_geoip_country_1") == "US"
        assert by_ip["5.255.255.5"].get("sagan_geoip_country_1") == "RU"
        # A private address has no country, so the field stays unset, which is
        # what lets an `isnot` rule fire on it.
        assert "sagan_geoip_country_1" not in by_ip["10.0.0.1"]


def run_intel_pipeline(
    vrl: Path, table: str, database: str, messages: list[str], tmp_path: Path
) -> list[dict]:
    """Run stdin -> parse-ip -> intel flag transform -> console through Vector."""
    config = tmp_path / f"{table}.yaml"
    config.write_text(
        "enrichment_tables:\n"
        f"  {table}:\n"
        "    type: mmdb\n"
        f"    path: {database}\n"
        "sources:\n"
        "  in: {type: stdin}\n"
        "transforms:\n"
        "  sagan_parse_ip:\n"
        "    type: remap\n"
        "    inputs: [in]\n"
        f"    file: {PARSE_IP}\n"
        "    drop_on_error: false\n"
        f"  {table}:\n"
        "    type: remap\n"
        "    inputs: [sagan_parse_ip]\n"
        f"    file: {vrl}\n"
        "    drop_on_error: false\n"
        "sinks:\n"
        f"  out: {{type: console, inputs: [{table}], encoding: {{codec: json}}}}\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [str(VECTOR), "--config", str(config), "--quiet"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        out, _ = process.communicate(input="\n".join(messages) + "\n", timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        out, _ = process.communicate()
    return [
        json.loads(line) for line in out.splitlines() if line.strip().startswith("{")
    ]


@pytest.mark.skipif(
    importlib.util.find_spec("mmdb_writer") is None,
    reason="pip install mmdb-writer to run the intel enrichment test",
)
class TestIntelEnrichment:
    """A denylist or Zeek-intel MMDB, built by our own tool, flags a listed IP.

    Self-contained: the database is built from fixed CIDRs, so a listed address
    is known ahead of time and the test does not depend on a live feed.
    """

    @pytest.mark.parametrize(
        ("vrl", "table", "flag"),
        [
            (DENYLIST, "sagan_denylist", "sagan_denylist_1"),
            (ZEEK_INTEL, "sagan_zeek_intel", "sagan_zeek_intel_1"),
        ],
    )
    def test_listed_address_sets_the_flag(
        self, vrl: Path, table: str, flag: str, tmp_path: Path
    ) -> None:
        builder = _load_builder()
        database = tmp_path / f"{table}.mmdb"
        builder.build_mmdb(
            [("203.0.113.0/24", "test"), ("198.51.100.7/32", "test")],
            database,
            f"{table}-test",
        )
        events = run_intel_pipeline(
            vrl,
            table,
            str(database),
            [
                "connection from 203.0.113.42 blocked",  # inside the listed /24
                "internal service on 10.0.0.1 restarted",  # not listed
            ],
            tmp_path,
        )
        by_ip = {e.get("sagan_ip_1"): e for e in events}
        assert by_ip["203.0.113.42"].get(flag) is True
        assert flag not in by_ip["10.0.0.1"]


class TestTimeDerivation:
    """sagan-time.vrl derives the two values aetas.c's Check_Time compares."""

    def test_weekday_and_hhmm_from_the_timestamp(self, tmp_path: Path) -> None:
        # 2026-08-05 is a Wednesday; %w numbers Sunday 0 .. Saturday 6.
        events = run_vrl(TIME, [{"timestamp": "2026-08-05T22:30:00Z"}], tmp_path)
        assert events[0]["sagan_event_weekday"] == 3
        assert events[0]["sagan_event_hhmm"] == 2230

    def test_midnight_is_zero_not_2400(self, tmp_path: Path) -> None:
        events = run_vrl(TIME, [{"timestamp": "2026-08-09T00:05:00Z"}], tmp_path)
        assert events[0]["sagan_event_weekday"] == 0  # Sunday
        assert events[0]["sagan_event_hhmm"] == 5

    def test_missing_timestamp_leaves_the_fields_unset(self, tmp_path: Path) -> None:
        """Rather than fire on a guessed clock, an event with no time is silent."""
        events = run_vrl(TIME, [{"message": "no timestamp here"}], tmp_path)
        assert "sagan_event_weekday" not in events[0]
        assert "sagan_event_hhmm" not in events[0]


class TestGeneratedPipeline:
    def test_vector_accepts_the_generated_configuration(self, tmp_path: Path) -> None:
        """Vector compiles VRL at validate time, so this checks both."""
        write_pipeline(tmp_path, __version__)
        completed = subprocess.run(
            [str(VECTOR), "validate", "--no-environment", "vector.yaml"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr

    def test_configuration_with_the_time_transform_validates(
        self, tmp_path: Path
    ) -> None:
        """The time transform has no external dependency, so it validates alone."""
        write_pipeline(tmp_path, __version__, time=True)
        completed = subprocess.run(
            [str(VECTOR), "validate", "--no-environment", "vector.yaml"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr

    def test_every_declared_transform_is_written(self, tmp_path: Path) -> None:
        write_pipeline(tmp_path, __version__)
        for _, filename in TRANSFORMS:
            assert (tmp_path / "transforms" / filename).is_file()
