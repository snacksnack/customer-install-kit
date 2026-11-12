"""Machine probes: architecture, memory, and writable storage."""

import os
import uuid
from pathlib import Path

from kit.model import Check, Outcome, ProbeResult, Reason
from kit.probes.base import ProbeEnv, probe

# cgroup reports "no limit" as the string "max" (v2) or a near-2^63 number
# (v1); either means "ask the next source".
UNLIMITED_FLOOR = 1 << 60


@probe("RT-001")
def architecture(check: Check, env: ProbeEnv) -> ProbeResult:
    machine = env.machine()
    if machine in check.params["accepted"]:
        return ProbeResult(Outcome.PASS, Reason.OK, {"machine": machine})
    return ProbeResult(Outcome.FAIL, Reason.UNSUPPORTED, {"machine": machine})


def _memory_bytes(env: ProbeEnv) -> tuple[int, str] | None:
    for path, source in (
        ("/sys/fs/cgroup/memory.max", "cgroup_v2"),
        ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "cgroup_v1"),
    ):
        text = env.read_text(path)
        if text is None:
            continue
        text = text.strip()
        if text.isdigit() and int(text) < UNLIMITED_FLOOR:
            return int(text), source
    meminfo = env.read_text("/proc/meminfo")
    if meminfo:
        for line in meminfo.splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024, "proc_meminfo"
    return None


@probe("RT-002")
def memory(check: Check, env: ProbeEnv) -> ProbeResult:
    found = _memory_bytes(env)
    if found is None:
        # No cgroup limit and no /proc: not Linux, or a locked-down sandbox.
        return ProbeResult(Outcome.UNKNOWN, Reason.PROBE_UNAVAILABLE)
    amount, source = found
    minimum = check.params["minimum_bytes"]
    evidence = {"memory_bytes": amount, "source": source, "minimum_bytes": minimum}
    if amount < minimum:
        return ProbeResult(Outcome.FAIL, Reason.BELOW_MINIMUM, evidence)
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)


def write_test(path: Path, minimum_free: int) -> ProbeResult:
    """Write, flush, fsync, close, delete. ENOSPC on a nearly full disk often
    surfaces only at flush or close (Phase 0B), so every step is checked."""
    evidence = {
        "path": str(path),
        "exists": path.is_dir(),
        "writable": None,
        "errno": None,
        "free_bytes": None,
        "minimum_free_bytes": minimum_free,
    }
    if not evidence["exists"]:
        return ProbeResult(Outcome.FAIL, Reason.MISSING, evidence)
    probe_file = path / f".cik-preflight-{uuid.uuid4().hex}"
    try:
        with probe_file.open("wb") as fh:
            fh.write(b"\0" * 4096)
            fh.flush()
            os.fsync(fh.fileno())
        evidence["writable"] = True
    except OSError as exc:
        evidence["writable"] = False
        evidence["errno"] = exc.errno
    finally:
        probe_file.unlink(missing_ok=True)
    stats = os.statvfs(path)
    evidence["free_bytes"] = stats.f_bavail * stats.f_frsize
    if not evidence["writable"]:
        return ProbeResult(Outcome.FAIL, Reason.REFUSED, evidence)
    if evidence["free_bytes"] < minimum_free:
        return ProbeResult(Outcome.FAIL, Reason.BELOW_MINIMUM, evidence)
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)


@probe("RT-003")
def data_volume(check: Check, env: ProbeEnv) -> ProbeResult:
    return write_test(Path(check.params["path"]), check.params["minimum_free_bytes"])


@probe("RT-004")
def error_event_sink(check: Check, env: ProbeEnv) -> ProbeResult:
    target = env.environ.get(check.params["path_var"], "").strip()
    if not target:
        return ProbeResult(Outcome.NOT_APPLICABLE, Reason.NOT_CONFIGURED)
    return write_test(Path(target).parent, check.params["minimum_free_bytes"])
