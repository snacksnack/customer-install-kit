"""Evidence sources for the diagnostic bundle (RC1-642, ADR 0008).

Every source runs on the operator workstation, outside ESP, under the
customer's own Fly identity (an app deploy token is enough) and the install
workspace's files. None of them needs ESP to be running: the platform API,
the platform log buffer and the install's local files answer while the app
crash-loops. The file sink needs a reachable machine and is reported
unavailable when there is none.

A source returns a SourceResult: either data (already projected through the
allowlist, or validated events) or an explicit `unavailable` reason. A
source never raises into the collector.
"""

import json
import re
import subprocess
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kit import report as preflight_report
from kit.bundle import events
from kit.bundle.allowlist import Allowlist, project
from kit.install.fly import Fly, Result

SINK_PATH = "/data/esp-error-events.jsonl"
TRACEBACK = "Traceback (most recent call last):"
_EXC_LINE = re.compile(r"^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*){0,6})(?::|$)")


@dataclass
class SourceResult:
    name: str
    data: Any = None
    unavailable: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    dropped: dict[str, int] = field(default_factory=dict)
    seconds: float = 0.0


def timed_runner(timeout_s: int) -> Callable[[list[str], str | None], Result]:
    def run(args: list[str], stdin: str | None) -> Result:
        proc = subprocess.run(["flyctl", *args], input=stdin, capture_output=True,
                              text=True, timeout=timeout_s)
        return Result(proc.returncode, proc.stdout, proc.stderr)
    return run


def _guard(name: str, fn: Callable[[], SourceResult]) -> SourceResult:
    start = time.monotonic()
    try:
        result = fn()
    except subprocess.TimeoutExpired:
        result = SourceResult(name, unavailable="timeout")
    except FileNotFoundError:
        result = SourceResult(name, unavailable="not_found")
    except Exception as exc:  # noqa: BLE001 - recorded as unavailable, by class only
        result = SourceResult(name, unavailable=f"error:{type(exc).__name__}")
    result.seconds = round(time.monotonic() - start, 2)
    return result


def _fly_json(fly: Fly, *args: str) -> Any:
    result = fly.run(*args, "--json", check=False)
    if result.code != 0:
        raise RuntimeError("fly command failed")
    return json.loads(result.stdout or "null")


def _projected(name: str, allow: Allowlist, data: Any) -> SourceResult:
    return SourceResult(name, data=project(data, allow.sources[name].paths))


# -- Fly platform ---------------------------------------------------------


def fly_status(fly: Fly, app: str, allow: Allowlist) -> SourceResult:
    return _guard("fly_status", lambda: _projected(
        "fly_status", allow, _fly_json(fly, "status", "-a", app)))


def fly_machines(fly: Fly, app: str, allow: Allowlist) -> SourceResult:
    return _guard("fly_machines", lambda: _projected(
        "fly_machines", allow, _fly_json(fly, "machines", "list", "-a", app) or []))


def fly_releases(fly: Fly, app: str, allow: Allowlist) -> SourceResult:
    def run() -> SourceResult:
        rows = (_fly_json(fly, "releases", "-a", app) or [])[:20]
        return _projected("fly_releases", allow, rows)
    return _guard("fly_releases", run)


def fly_secrets(fly: Fly, app: str, allow: Allowlist) -> SourceResult:
    return _guard("fly_secrets", lambda: _projected(
        "fly_secrets", allow, _fly_json(fly, "secrets", "list", "-a", app) or []))


def _log_rows(text: str) -> list[dict]:
    """`fly logs --json` prints concatenated objects, not JSON lines."""
    decoder, i, rows = json.JSONDecoder(), 0, []
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = decoder.raw_decode(text, i)
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def startup_exceptions(messages: list[str]) -> Counter:
    """Exception TYPES that ended a traceback, counted. The message after
    the colon is never kept: it is free text (ESP's own config errors name
    environment variables; a driver error names hosts and roles)."""
    found: Counter = Counter()
    in_tb = False
    for msg in messages:
        if msg.startswith(TRACEBACK):
            in_tb = True
            continue
        if in_tb and msg and not msg[0].isspace():
            match = _EXC_LINE.match(msg)
            if match:
                found[match.group(1)] += 1
            in_tb = False
    return found


def platform_log(fly: Fly, app: str, allow: Allowlist) -> SourceResult:
    """ESP's stderr sink as the platform buffers it (about the last 100
    lines: short-lived, so the file sink is the durable copy)."""
    def run() -> SourceResult:
        result = fly.run("logs", "-a", app, "--no-tail", "--json", check=False)
        if result.code != 0:
            return SourceResult("platform_log", unavailable="fly_logs_failed")
        rows = _log_rows(result.stdout)
        messages = [str(r.get("message", "")) for r in rows]
        kept, drops = events.from_lines(messages, allow.bounds.max_events)
        stamps = sorted(str(r.get("timestamp")) for r in rows if r.get("timestamp"))
        data = {
            "buffer": {"lines": len(rows), "oldest": stamps[0] if stamps else None,
                       "newest": stamps[-1] if stamps else None},
            "error_events": kept,
            "error_event_summary": events.summarize(kept),
            "startup_exception_types": dict(startup_exceptions(messages)),
        }
        return SourceResult("platform_log", data=data, counts={"events": len(kept)},
                            dropped=dict(drops))
    return _guard("platform_log", run)


def file_sink(fly: Fly, app: str, allow: Allowlist) -> SourceResult:
    """The tail of ESP's file sink on the volume, read over `fly ssh`."""
    def run() -> SourceResult:
        n = allow.bounds.max_sink_read_bytes
        cmd = (f"sh -c 'if [ -f {SINK_PATH} ]; then echo CIK-SINK-PRESENT; "
               f"tail -c {n} {SINK_PATH}; else echo CIK-SINK-ABSENT; fi'")
        result = fly.run("ssh", "console", "-a", app, "-C", cmd, check=False)
        if "CIK-SINK-ABSENT" in result.stdout:
            return SourceResult("file_sink", unavailable="sink_file_absent")
        if "CIK-SINK-PRESENT" not in result.stdout:
            return SourceResult("file_sink", unavailable="machine_unreachable")
        body = result.stdout.split("CIK-SINK-PRESENT", 1)[1]
        lines = body.splitlines()
        if len(body.encode()) >= n and lines:
            lines = lines[1:]  # the first line may be cut mid-record by tail -c
        kept, drops = events.from_lines(lines, allow.bounds.max_events)
        data = {"path": SINK_PATH, "error_events": kept,
                "error_event_summary": events.summarize(kept)}
        return SourceResult("file_sink", data=data, counts={"events": len(kept)},
                            dropped=dict(drops))
    return _guard("file_sink", run)


# -- live probe -------------------------------------------------------------


def health(http_status: Callable[[str], int], url: str) -> SourceResult:
    def run() -> SourceResult:
        start = time.monotonic()
        status = http_status(url)
        return SourceResult("health", data={
            "healthz_status": status, "seconds": round(time.monotonic() - start, 2),
            "note": "liveness only: a 200 says the web process answers, nothing more"})
    return _guard("health", run)


# -- local install workspace --------------------------------------------------


def install_record(path: Path, allow: Allowlist) -> SourceResult:
    return _guard("install_record", lambda: _projected(
        "install_record", allow, json.loads(path.read_text())))


def preflight(path: Path, name: str, registry) -> SourceResult:
    """A preflight report, re-validated: its schema and registry version must
    be ones this kit reads, every check ID known, every evidence field
    declared (kit.report.parse refuses anything else)."""
    def run() -> SourceResult:
        return SourceResult(name, data=preflight_report.parse(
            json.loads(path.read_text()), registry))
    return _guard(name, run)


def conformance(workdir: Path, allow: Allowlist) -> SourceResult:
    def run() -> SourceResult:
        runs = sorted((workdir / "conformance").glob("*/report.json"))
        if not runs:
            return SourceResult("conformance", unavailable="no_conformance_run")
        return _projected("conformance", allow, json.loads(runs[-1].read_text()))
    return _guard("conformance", run)
