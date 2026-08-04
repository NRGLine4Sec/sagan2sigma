"""Tests that execute the bundled VRL against a real Vector binary.

Everything else in this suite checks that the converter produces plausible
output. These check that the enrichment the ``vector-enriched`` profile depends
on actually behaves like the Sagan engine, by running it.

They are skipped when ``vector`` is not on PATH. In CI a dedicated job installs
it, because a profile that promises fields nobody produces is exactly the
failure mode this project refuses elsewhere.
"""

from __future__ import annotations

import json
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

    def test_every_declared_transform_is_written(self, tmp_path: Path) -> None:
        write_pipeline(tmp_path, __version__)
        for _, filename in TRANSFORMS:
            assert (tmp_path / "transforms" / filename).is_file()
