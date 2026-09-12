#!/usr/bin/env python3
"""Run rules and events through a real, locally built Sagan engine.

This is the measuring instrument the checks in ``checks/`` are written against.
It exists because reading Sagan's C is not the same as knowing what Sagan does:
three converter bugs, one of them affecting 970 rules, were found only by
running the engine and comparing.

This is not part of the test suite and CI never runs it: it needs a compiled
Sagan, which takes a toolchain and minutes rather than seconds. It lives in the
repository all the same, because the claims it produced are all over the
converter's comments and documentation, and a claim nobody else can re-measure
is a claim on trust. ``docs/LAB.md`` is the entry point.

Usage
-----
    from harness import sagan, event, alerts

    fired = sagan(rules=[rule_text, ...], events=[event(...), ...])
    # fired maps each event's message text to the set of SIDs that alerted

Give every probe a distinct message: attribution is by message text.

**Never run two checks at the same time.** Every run wipes the shared
correlation state in ``/dev/shm`` and rebuilds ``work/``, so two concurrent
checks erase each other's state mid-flight and produce a clean-looking result in
which nothing fires at all. ``run-all.sh`` is deliberately sequential.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

#: How long to wait for another run before assuming its process died.
LOCK_TIMEOUT_SECONDS = 900

LAB = Path(__file__).resolve().parent
CONFIG = LAB / "config"
WORK = LAB / "work"

#: Where the engine binaries live. ``build/build-sagan.sh`` writes them here and
#: the directory is not committed, binaries being build output. Override with
#: ``SAGAN2SIGMA_LAB_BIN`` to point at a build kept elsewhere.
BIN = Path(os.environ.get("SAGAN2SIGMA_LAB_BIN") or (LAB / "bin"))

#: Sagan built from upstream sources, unmodified. Every check that does not
#: involve the `after` correlation path uses this one.
UPSTREAM = BIN / "sagan-upstream"

#: Upstream plus one local patch to the `after` path, which a plain build cannot
#: exercise: see :class:`MissingBinary` and ``docs/LAB.md`` for why this binary
#: may be absent.
PATCHED = BIN / "sagan-patched"

#: Upstream plus both local patches. This is the binary to use when measuring
#: what a rule *means*, because without them a rule carrying only `content` and
#: `program` can be silently turned into a correlation and then fires only from
#: the N+1th event, which would attribute engine behaviour to the converter.
SANE = BIN / "sagan-sane"


class MissingBinary(RuntimeError):
    """An engine build this measurement needs is not present.

    Two of the three binaries need local patches to the engine that this
    repository does not carry. They are held back deliberately: they fix
    defects that are not public, and the maintainers have been told privately.
    Publishing them here would amount to disclosing those defects, which is not
    this repository's call to make.

    Everything that does not touch the `after` correlation path runs on the
    plain upstream build. ``docs/LAB.md`` lists what runs and what does not.
    """

    def __init__(self, binary: Path) -> None:
        local = binary.name in ("sagan-patched", "sagan-sane")
        detail = (
            "this build carries local patches that are not published with the "
            "repository, so this measurement cannot run here"
            if local
            else f"build it with {LAB / 'build' / 'build-sagan.sh'}"
        )
        super().__init__(f"{binary} is missing: {detail}")
        self.binary = binary


def require_binary(binary: Path) -> Path:
    """Fail with an explanation rather than an exec error."""
    if not binary.exists():
        raise MissingBinary(binary)
    return binary


def available(*binaries: Path) -> bool:
    """Whether every one of these builds is present."""
    return all(binary.exists() for binary in binaries)


#: Libraries the binaries were linked against, needed on every invocation.
NIX_PKGS = (
    "pcre",
    "libyaml",
    "libmaxminddb",
    "libfastjson",
    "libestr",
    "liblognorm",
    "zlib",
)

#: Sagan's traditional pipe format, from src/input-pipe.c.
PIPE_FIELDS = "host|facility|priority|level|tag|date|time|program|message"


def event(
    message: str,
    program: str = "sshd",
    host: str = "192.168.2.1",
    facility: str = "auth",
    priority: str = "info",
    level: str = "info",
    tag: str = "sagan",
    date: str = "08/21/2026",
    time: str = "11:00:00",
) -> str:
    """One input line in the pipe format ``--file`` reads."""
    return "|".join(
        [host, facility, priority, level, tag, date, time, program, message]
    )


def _reset_state() -> Path:
    """Clear everything Sagan carries between runs.

    Two stores matter and only one is obvious. The lock directory is local, but
    the correlation state (xbits, flexbits, threshold, after) lives in
    ``/dev/shm/sagan-*.shared`` and **outlives the process**. A harness that
    does not wipe it inherits the previous run's counters, so a rule already
    over threshold alerts on the very first event. That mistake produced a
    confidently wrong conclusion once; hence this function.
    """
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "log").mkdir(parents=True)
    (WORK / "run").mkdir(parents=True)
    for stale in Path("/dev/shm").glob("sagan-*.shared"):
        stale.unlink(missing_ok=True)
    return WORK


#: Held for the duration of every engine run. See :func:`_engine_lock`.
LOCKFILE = Path(tempfile.gettempdir()) / "sagan-engine-lab.lock"


@contextlib.contextmanager
def _engine_lock() -> Iterator[None]:
    """Serialise engine runs across every process using this harness.

    Two runs at once destroy each other: each wipes ``work/`` and the shared
    correlation state in ``/dev/shm``, so one overwrites the rules file the
    other is about to read. The result is not an error but a *plausible* one,
    typically a load failure naming a keyword the check never used, or a file
    in which nothing fires at all.

    The README warned about this and it still happened three times, twice
    costing a wrong conclusion, because the warning only binds whoever reads
    it: a check file run directly, or a throwaway probe in a scratch script,
    ignores it just as easily as a second ``run-all.sh``. A lock in the one
    function every path goes through cannot be forgotten. Waiting is better
    than refusing here, since the second caller usually wants the answer
    rather than an error.
    """
    LOCKFILE.touch(exist_ok=True)
    with LOCKFILE.open("r+") as handle:
        waited = 0
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if waited == 0:
                    print(
                        "  [harness] another engine run is in progress, waiting",
                        flush=True,
                    )
                if waited >= LOCK_TIMEOUT_SECONDS:
                    raise RuntimeError(
                        f"engine still locked after {LOCK_TIMEOUT_SECONDS}s; "
                        f"a previous run may have been killed, remove {LOCKFILE}"
                    ) from None
                time.sleep(2)
                waited += 2
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def config_template() -> str:
    """The shipped configuration, with this checkout's own paths filled in.

    Sagan's configuration has no notion of a variable for a path, so the file
    carries ``@LAB@`` where the lab's directory belongs and every reader goes
    through here. That is what lets the lab be cloned anywhere instead of
    working only where it was written.
    """
    return (
        (CONFIG / "sagan.yaml").read_text(encoding="utf-8").replace("@LAB@", str(LAB))
    )


def base_config() -> Path:
    """The shipped configuration, materialised and ready for the engine."""
    return _write_config(config_template())


def config_with_rulebase(rulebase: Path) -> Path:
    """Derive a config that normalizes with ``rulebase`` instead of the default.

    Only the ``normalize_rulebase`` line changes; ``LOG_PATH`` still points at
    the lab's ``work/log``, which is where the readers below look. The derived
    file lives in its own temporary directory because ``_reset_state`` wipes
    ``work/`` on every run.
    """
    text = re.sub(
        r"normalize_rulebase: .*",
        f'normalize_rulebase: "{rulebase}"',
        config_template(),
        count=1,
    )
    return _write_config(text)


def _write_config(text: str) -> Path:
    """Park a derived config outside ``work/``, which every run wipes."""
    out = Path(tempfile.mkdtemp()) / "sagan.yaml"
    out.write_text(text, encoding="utf-8")
    return out


def config_with_processor(name: str, filename: Path) -> Path:
    """Enable a disabled processor and point it at a local fixture.

    ``blacklist`` and ``zeek-intel`` ship disabled and expect feeds that are
    not on this machine, so their behaviour cannot be observed at all until
    both are rewritten. ``name`` is the key as it appears in ``sagan.yaml``
    (``blacklist``, ``zeek-intel``).
    """
    return config_with_processors({name: filename})


def config_with_processors(feeds: dict[str, Path]) -> Path:
    """The same for several processors at once, in one derived config.

    The corpus differential needs both feeds enabled in a single run, and
    calling the one-processor form twice does not compose: each call starts
    again from the shipped config, so the second silently discards the first.

    Only the block belonging to each name is touched: the ``enabled`` and
    ``filename`` lines that follow it, and nothing further, since several
    processors share those two key names.
    """
    lines = config_template().splitlines()
    out: list[str] = []
    current: str | None = None
    for line in lines:
        opened = re.match(r"\s*-\s*([a-z0-9-]+)\s*:", line)
        if opened is not None:
            current = opened.group(1)
        if current in feeds:
            if re.match(r"\s*enabled\s*:", line):
                line = re.sub(r"(enabled\s*:).*", r"\1 yes", line)
            elif re.match(r"\s*filename\s*:", line):
                line = re.sub(r"(filename\s*:).*", rf'\1 "{feeds[current]}"', line)
        out.append(line)
    return _write_config("\n".join(out) + "\n")


def run_sagan(
    rules: list[str],
    events: list[str],
    *,
    binary: Path = UPSTREAM,
    config: Path | None = None,
    at_time: str | None = None,
    timezone: str | None = None,
) -> Path:
    """Execute one batch and return the directory holding the logs.

    Single-threaded with a batch size of one, because Sagan's default of fifty
    threads makes which event "wins" a race: the same input produced different
    alerts run to run until this was pinned down.

    ``at_time`` runs the engine under ``faketime``, which intercepts ``time()``
    through ``LD_PRELOAD``. That is what makes ``alert_time`` observable, since
    it evaluates its window against the wall clock rather than the event's own
    timestamp. Faking the clock rather than setting the machine's avoids
    disturbing anything else on the host, and lets one run pretend to be
    Tuesday and the next Sunday. Accepts anything libfaketime parses, such as
    ``"2026-08-18 14:30:00"``.

    ``timezone`` sets ``TZ`` for the run, because the engine reads the window
    through ``localtime()``.
    """
    require_binary(binary)
    config = config or base_config()
    with _engine_lock():
        return _run_locked(rules, events, binary, config, at_time, timezone)


def _run_locked(
    rules: list[str],
    events: list[str],
    binary: Path,
    config: Path,
    at_time: str | None,
    timezone: str | None,
) -> Path:
    """The body of :func:`run_sagan`, with the engine lock already held."""
    work = _reset_state()
    rules_file = work / "harness.rules"
    rules_file.write_text("\n".join(rules) + "\n", encoding="utf-8")
    events_file = work / "harness.events"
    events_file.write_text("\n".join(events) + "\n", encoding="utf-8")

    launch = f"timeout 120 {binary}"
    packages = list(NIX_PKGS)
    if at_time is not None:
        packages.append("libfaketime")
        launch = f'timeout 120 faketime "{at_time}" {binary}'
    prefix = f"export TZ={timezone}; " if timezone else ""

    inner = (
        f"{prefix}{launch} -f {config} -r {rules_file} "
        f"-l {work}/log/sagan.log -F {events_file} -u $(whoami) -t 1 -b 1 -Q"
    )
    completed = subprocess.run(
        ["nix-shell", "-p", *packages, "--run", inner],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        log = work / "log" / "sagan.log"
        tail = log.read_text(errors="replace").splitlines()[-8:] if log.exists() else []
        raise RuntimeError(
            f"sagan exited {completed.returncode}\n"
            + "\n".join(tail)
            + "\n"
            + completed.stderr[-400:]
        )
    return work


def _logged_message(line: str) -> str:
    """The message text from an ``Message: ...`` line, whitespace intact.

    Only the single space Sagan writes after the colon is removed. Stripping
    the result instead, which this did at first, silently loses a leading or
    trailing space in the message, and since attribution is by message text the
    alert then matches no probe and reads as "did not fire". That turned a
    correct ``event_id`` result into a convincing failure: the engine had
    alerted on ``" 4624: logon"`` and the harness could not see it.
    """
    text = line[len("Message:") :]
    return text[1:] if text.startswith(" ") else text


def sagan(
    rules: list[str],
    events: list[str],
    *,
    binary: Path = UPSTREAM,
    config: Path | None = None,
    at_time: str | None = None,
    timezone: str | None = None,
) -> dict[str, set[str]]:
    """Message text -> the set of SIDs that alerted on it.

    Keys keep whatever whitespace the message carried, so a probe with a
    leading space is found under that exact text.
    """
    work = run_sagan(
        rules,
        events,
        binary=binary,
        config=config,
        at_time=at_time,
        timezone=timezone,
    )
    fired: dict[str, set[str]] = {}
    alert = work / "log" / "alert.log"
    if not alert.exists():
        return fired
    sid = None
    for line in alert.read_text(errors="replace").splitlines():
        header = re.match(r"\[\*\*\] \[\d+:(\d+):\d+\]", line)
        if header:
            sid = header.group(1)
        elif line.startswith("Message:") and sid:
            fired.setdefault(_logged_message(line), set()).add(sid)
    return fired


def alerts(
    rules: list[str],
    events: list[str],
    *,
    binary: Path = UPSTREAM,
    config: Path | None = None,
    at_time: str | None = None,
    timezone: str | None = None,
) -> list[dict[str, str]]:
    """Each alert as ``{sid, src, dst, message}``.

    The addresses are what makes ``Parse_IP`` observable: ``parse_src_ip: N``
    selects the Nth address and the alert line shows which one that was. They
    also make ``normalize`` observable, since liblognorm's ``src-ip`` and
    ``dst-ip`` land in the same two fields.

    ``at_time`` and ``timezone`` run the engine under ``faketime``, which is the
    only way to observe ``alert_time``: the window is compared against the wall
    clock at processing time, not against the event's own stamp.
    """
    work = run_sagan(
        rules,
        events,
        binary=binary,
        config=config,
        at_time=at_time,
        timezone=timezone,
    )
    out: list[dict[str, str]] = []
    alert = work / "log" / "alert.log"
    if not alert.exists():
        return out
    current: dict[str, str] = {}
    for line in alert.read_text(errors="replace").splitlines():
        header = re.match(r"\[\*\*\] \[\d+:(\d+):\d+\]", line)
        flow = re.match(
            r"\S+ \S+ (\S+):(\d+)\s+-> (\S+):(\d+)"
            r"(?:\s+(\S+)\s+(\S+)\s+(\S+))?",
            line,
        )
        if header:
            current = {"sid": header.group(1)}
        elif flow and current:
            current["src"], current["dst"] = flow.group(1), flow.group(3)
            # The envelope trails the flow: facility, level, program. The
            # program is what distinguishes two probes of the same rule that
            # carry the same message text, which message-only attribution
            # cannot tell apart.
            current["facility"] = flow.group(5) or ""
            current["level"] = flow.group(6) or ""
            current["program"] = flow.group(7) or ""
        elif line.startswith("Message:") and current:
            current["message"] = _logged_message(line)
            out.append(current)
            current = {}
    return out


def loads(rules: list[str], *, binary: Path = UPSTREAM) -> bool:
    """Whether Sagan accepts these rules at load time.

    A load check answers questions an alert count cannot. ``after: track
    by_string`` is rejected outright, which is only possible if the key
    contributes nothing to the parser's validity count; that is how the
    by_string asymmetry was settled.
    """
    require_binary(binary)
    config = base_config()
    work = _reset_state()
    rules_file = work / "harness.rules"
    rules_file.write_text("\n".join(rules) + "\n", encoding="utf-8")
    inner = (
        f"timeout 60 {binary} -f {config} -r {rules_file} -l {work}/log/sagan.log -T"
    )
    subprocess.run(
        ["nix-shell", "-p", *NIX_PKGS, "--run", inner],
        capture_output=True,
        text=True,
    )
    log = work / "log" / "sagan.log"
    return log.exists() and "everything passed" in log.read_text(errors="replace")


def rule(sid: int | str, options: str, action: str = "alert") -> str:
    """Assemble a Sagan rule from its option block."""
    return (
        f'{action} any any any -> any any (msg:"[LAB] {sid}"; {options}; '
        f"classtype: misc-activity; sid:{sid}; rev:1;)"
    )


class Report:
    """Collects comparisons and prints a readable pass/fail summary."""

    def __init__(self, title: str) -> None:
        self.title = title
        self.failures: list[str] = []
        self.skipped: list[str] = []
        self.total = 0
        print(f"\n=== {title} ===")

    def check(self, label: str, got: object, expected: object) -> bool:
        self.total += 1
        ok = got == expected
        mark = "ok  " if ok else "FAIL"
        print(f"  [{mark}] {label:58} expected={expected!s:12} got={got!s}")
        if not ok:
            self.failures.append(label)
        return ok

    def skip(self, label: str, reason: str) -> None:
        """Record a measurement this environment cannot make.

        A skip is not a pass. It is printed and counted separately so that a
        run missing half its measurements cannot read as a clean one.
        """
        self.skipped.append(label)
        print(f"  [skip] {label:58} {reason}")

    def measure(self, step: Callable[[Report], None]) -> None:
        """Run one group of checks, turning a missing build into a skip.

        Every check file goes through here so that an absent engine build stops
        one group rather than the file, and says which one.
        """
        try:
            step(self)
        except MissingBinary as missing:
            self.skip(step.__name__, str(missing))

    def done(self) -> bool:
        if self.failures:
            print(f"  {len(self.failures)}/{self.total} FAILED in {self.title}")
        elif self.total:
            print(f"  all {self.total} checks passed")
        else:
            # "all 0 checks passed" reads as a success and is the one summary a
            # skipped file must not print.
            print("  nothing was measured in this file")
        if self.skipped:
            print(f"  {len(self.skipped)} group(s) skipped: {', '.join(self.skipped)}")
        return not self.failures


def skip_unless_available(report: Report, *binaries: Path) -> bool:
    """True when the run can proceed, otherwise record one skip and say why.

    For a check file whose every case needs the same build. Files made of
    independent groups use :meth:`Report.measure` instead, which skips the
    group rather than the file.
    """
    missing = [binary for binary in binaries if not binary.exists()]
    if not missing:
        return True
    report.skip(
        "every case in this file",
        "; ".join(str(MissingBinary(binary)) for binary in missing),
    )
    return False


def json_dumps(value: object) -> str:
    """Convenience for building JSON message bodies in checks."""
    return json.dumps(value, separators=(",", ":"))


def temp_rules(text: str) -> Path:
    """Write a rules file outside the lab, for one-off experiments."""
    path = Path(tempfile.mkdtemp()) / "adhoc.rules"
    path.write_text(text, encoding="utf-8")
    return path
