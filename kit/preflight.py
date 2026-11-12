"""Run the registry's checks for one context and build the report.

Probes are bounded: each runs on a daemon thread and is abandoned at its
registry timeout, so a hung DNS lookup or TCP connect yields "unknown:
timeout" rather than a hung install.
"""

import platform
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from kit import __version__
from kit.model import ALLOWED_REASONS, Check, Context, Observation, Outcome, Reason, Severity
from kit.probes import PROBES, ProbeEnv
from kit.probes.base import Probe
from kit.registry import Registry, validate_evidence
from kit.report import SCHEMA

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNKNOWN = 2
EXIT_KIT_ERROR = 3

# Variables whose values must never appear in any output. Matched by prefix
# or exact name; URL-shaped values are also split so the password alone is
# caught.
SECRET_PREFIXES = ("ESP_", "CIK_")
SECRET_NAMES = frozenset({"DATABASE_URL", "PGPASSWORD"})
MIN_SECRET_LENGTH = 8


class KitError(Exception):
    """A bug or contract breach in the kit itself, never a customer finding."""


@dataclass(frozen=True)
class Run:
    report: dict[str, Any]
    observations: tuple[Observation, ...]
    exit_status: int


def _run_bounded(fn: Probe, check: Check, env: ProbeEnv) -> tuple[str, Any]:
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = fn(check, env)
        except Exception as exc:  # noqa: BLE001 - any probe crash is "unknown"
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True, name=f"probe-{check.id}")
    thread.start()
    thread.join(check.timeout_s)
    if thread.is_alive():
        return "timeout", None
    if "error" in box:
        return "error", box["error"]
    return "ok", box["result"]


def run_check(check: Check, env: ProbeEnv, probes: dict[str, Probe]) -> Observation:
    started = time.monotonic()
    status, value = _run_bounded(probes[check.id], check, env)
    elapsed = int((time.monotonic() - started) * 1000)
    if status == "timeout":
        return Observation(check.id, Outcome.UNKNOWN, Reason.TIMEOUT, {}, elapsed)
    if status == "error":
        # The class name goes to the operator's terminal, not the report.
        print(f"[{check.id}] probe error: {type(value).__name__}", file=sys.stderr)
        return Observation(check.id, Outcome.UNKNOWN, Reason.PROBE_ERROR, {}, elapsed)
    if value.reason not in ALLOWED_REASONS[value.outcome]:
        raise KitError(f"{check.id}: reason {value.reason} is not valid for {value.outcome}")
    problems = validate_evidence(check, value.evidence)
    if problems:
        raise KitError("; ".join(problems))
    return Observation(check.id, value.outcome, value.reason, value.evidence, elapsed)


def exit_status(registry: Registry, observations: list[Observation]) -> int:
    checks = registry.by_id()
    required = [o for o in observations if checks[o.check_id].severity is Severity.REQUIRED]
    if any(o.outcome is Outcome.FAIL for o in required):
        return EXIT_FAILED
    if any(o.outcome is Outcome.UNKNOWN for o in required):
        return EXIT_UNKNOWN
    return EXIT_OK


def secret_values(environ: dict[str, str]) -> set[str]:
    values: set[str] = set()
    for name, value in environ.items():
        if not (name.startswith(SECRET_PREFIXES) or name in SECRET_NAMES):
            continue
        values.add(value)
        if "://" in value:
            password = urlsplit(value).password
            if password:
                values.add(password)
    return {v for v in values if len(v) >= MIN_SECRET_LENGTH}


def assert_no_secrets(text: str, environ: dict[str, str]) -> None:
    """Last line of defense behind the evidence allowlist: refuse to emit
    output that contains any secret value from the environment."""
    if any(s in text for s in secret_values(environ)):
        raise KitError("output contains a secret value from the environment; refusing to emit it")


def run(
    registry: Registry,
    context: Context,
    profile: str = "v1",
    env: ProbeEnv | None = None,
    probes: dict[str, Probe] | None = None,
) -> Run:
    env = env or ProbeEnv()
    probes = PROBES if probes is None else probes
    started_at = datetime.now(UTC)
    results: dict[str, Observation] = {}
    for check in registry.checks:
        if check.context is not context:
            continue
        if profile not in check.profiles:
            results[check.id] = Observation(
                check.id, Outcome.NOT_APPLICABLE, Reason.NOT_IN_PROFILE, {}, 0
            )
            continue
        blockers = tuple(d for d in check.depends_on if results[d].outcome is not Outcome.PASS)
        if blockers:
            results[check.id] = Observation(
                check.id, Outcome.UNKNOWN, Reason.BLOCKED, {}, 0, blocked_by=blockers
            )
            continue
        results[check.id] = run_check(check, env, probes)

    observations = list(results.values())
    status = exit_status(registry, observations)
    summary = {o.value: 0 for o in Outcome}
    for obs in observations:
        summary[obs.outcome.value] += 1
    report = {
        "schema": SCHEMA,
        "registry_version": registry.version,
        "kit_version": __version__,
        "profile": profile,
        "context": context.value,
        "run_id": uuid.uuid4().hex,
        "started_at": started_at.isoformat(timespec="seconds"),
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "host": {"machine": platform.machine(), "python": platform.python_version()},
        "observations": [o.to_json() for o in observations],
        "summary": summary,
        "exit_status": status,
    }
    return Run(report, tuple(observations), status)
