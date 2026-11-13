"""Conformance checks: observations in, outcomes out (RC1-641, ADR 0007).

Pure functions over what the runner collected. Three outcomes:

- pass: the evidence shows the behavior.
- fail: the evidence shows the behavior is broken.
- insufficient_evidence: the check could not be judged (a prerequisite did
  not pass, a dependency was unreachable, or the output was not what a pass
  or a fail looks like). It is never a pass: a refused write or an
  unavailable dependency can only make a run fail or come up short.

A check listed in `requires` that did not pass makes this one
insufficient_evidence, whatever its own inputs say.
"""

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Outcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INSUFFICIENT = "insufficient_evidence"


@dataclass(frozen=True)
class Check:
    id: str
    name: str
    requires: tuple[str, ...] = ()


CHECKS = (
    Check("CNF-001", "release_deployed"),
    Check("CNF-002", "health_endpoint"),
    Check("CNF-010", "anonymous_write_refused"),
    Check("CNF-011", "wrong_password_refused"),
    Check("CNF-012", "approver_sign_in"),
    Check("CNF-013", "audit_append", ("CNF-012",)),
    Check("CNF-020", "fixture_built"),
    Check("CNF-021", "gate_refuses_draft", ("CNF-020",)),
    Check("CNF-023", "approval_recorded", ("CNF-020",)),
    Check("CNF-022", "gate_refuses_tampered", ("CNF-023",)),
    Check("CNF-030", "migration_executed", ("CNF-021", "CNF-022", "CNF-023")),
    Check("CNF-031", "destination_state", ("CNF-030",)),
    Check("CNF-032", "suppression_integrity", ("CNF-030",)),
    Check("CNF-040", "fixture_cleanup", ("CNF-020",)),
)
CHECK_VERSION = 1


@dataclass
class Observation:
    check_id: str
    name: str
    outcome: Outcome
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {"check_id": self.check_id, "name": self.name, "outcome": self.outcome.value,
                "reason": self.reason, "evidence": self.evidence}


Result = tuple[Outcome, str, dict[str, Any]]


def _step(machine: dict | None, name: str) -> dict | None:
    return None if machine is None else machine.get("steps", {}).get(name)


def _ran(step: dict | None) -> bool:
    return step is not None and step.get("exit") is not None


def _text(step: dict, key: str) -> str:
    return "\n".join(step.get(key) or [])


def _jsonl(text: str | None) -> list[dict]:
    return [json.loads(line) for line in (text or "").splitlines() if line.strip()]


def _expected(machine: dict | None) -> dict | None:
    text = (machine or {}).get("files", {}).get("expected.json")
    return json.loads(text) if text else None


# -- individual checks ------------------------------------------------------


def release_deployed(obs: dict) -> Result:
    want, running = obs["release"].get("record_digest"), obs["release"].get("running_digests")
    ev = {"record_digest": want, "running_digests": running}
    if not want or running is None:
        return Outcome.INSUFFICIENT, "machines_unreadable", ev
    if running and all(d == want for d in running):
        return Outcome.PASS, "running_verified_digest", ev
    return Outcome.FAIL, "digest_mismatch" if running else "no_machine", ev


def health_endpoint(obs: dict) -> Result:
    status = obs["health"]["status"]
    ev = {"status": status, "note": "liveness only; never sufficient for conformance"}
    if status == 200:
        return Outcome.PASS, "healthz_200", ev
    return (Outcome.INSUFFICIENT, "unreachable", ev) if status == 0 else \
        (Outcome.FAIL, "healthz_not_200", ev)


def _refused(status: int | None) -> Result:
    ev = {"status": status}
    if status == 401:
        return Outcome.PASS, "refused_401", ev
    if status is not None and 200 <= status < 300:
        return Outcome.FAIL, "accepted", ev
    return Outcome.INSUFFICIENT, "unexpected_status", ev


def anonymous_write_refused(obs: dict) -> Result:
    return _refused(obs["identity"].get("anonymous_write_status"))


def wrong_password_refused(obs: dict) -> Result:
    return _refused(obs["identity"].get("wrong_password_status"))


def approver_sign_in(obs: dict) -> Result:
    ident = obs["identity"]
    status, me = ident.get("login_status"), ident.get("me") or {}
    who = (me.get("identity") or {})
    ev = {"login_status": status, "authenticated": me.get("authenticated"),
          "method": who.get("method"), "verified": who.get("verified")}
    if status is None:
        return Outcome.INSUFFICIENT, "no_password_configured", ev
    if status == 200 and me.get("authenticated") and who.get("method") == "password":
        return Outcome.PASS, "signed_in_password_unverified", ev
    if status == 0:
        return Outcome.INSUFFICIENT, "unreachable", ev
    return Outcome.FAIL, "sign_in_failed", ev


def audit_append(obs: dict) -> Result:
    ident = obs["identity"]
    before, records = ident.get("audit_seq_before"), ident.get("audit_after")
    if records is None:
        return Outcome.INSUFFICIENT, "audit_unreadable", {}
    new = [r for r in records if r.get("seq", 0) > (before or 0) and r.get("event") == "sign_in"]
    ev = {"seq_before": before, "new_sign_in_seqs": sorted(r["seq"] for r in new)}
    if new:
        return Outcome.PASS, "sign_in_recorded", ev
    return Outcome.FAIL, "sign_in_not_recorded", ev


def fixture_built(obs: dict) -> Result:
    machine = obs.get("machine")
    if machine is None:
        return Outcome.INSUFFICIENT, "machine_run_failed", {"error": obs.get("machine_error")}
    step, expected = _step(machine, "fixture"), _expected(machine)
    if _ran(step) and step["exit"] == 0 and expected:
        return Outcome.PASS, "fixture_built", {
            "exported_total": expected["exported_total"],
            "suppressed": len(expected["suppressed_emails"]),
            "list_name": expected["list_name"],
            "source_fingerprint": expected["source_fingerprint"],
        }
    return Outcome.FAIL, "fixture_failed", {"exit": (step or {}).get("exit")}


def gate_refuses_draft(obs: dict) -> Result:
    step = _step(obs.get("machine"), "gate_draft")
    if not _ran(step):
        return Outcome.INSUFFICIENT, "not_run", {}
    ev = {"exit": step["exit"]}
    if step["exit"] == 0:
        return Outcome.FAIL, "draft_accepted", ev
    if "not approved" in _text(step, "stderr_tail"):
        return Outcome.PASS, "draft_refused", ev
    return Outcome.INSUFFICIENT, "failed_for_another_reason", ev


def approval_recorded(obs: dict) -> Result:
    machine = obs.get("machine")
    step = _step(machine, "approve")
    if not _ran(step):
        return Outcome.INSUFFICIENT, "not_run", {}
    sha = next((line.split(":", 1)[1].strip() for line in step.get("stdout_tail") or []
                if line.startswith("content sha256:")), None)
    ev = {"exit": step["exit"], "content_sha256": sha}
    if step["exit"] == 0 and sha and "spec.approved.yaml" in machine.get("files", {}):
        return Outcome.PASS, "approved_through_gate", ev
    return Outcome.FAIL, "approval_failed", ev


def gate_refuses_tampered(obs: dict) -> Result:
    machine = obs.get("machine")
    step = _step(machine, "gate_tampered")
    if not _ran(step) or not machine.get("steps", {}).get("tamper_applied"):
        return Outcome.INSUFFICIENT, "not_run", {}
    ev = {"exit": step["exit"]}
    if step["exit"] == 0:
        return Outcome.FAIL, "tampered_accepted", ev
    if "modified after approval" in _text(step, "stderr_tail"):
        return Outcome.PASS, "tampered_refused", ev
    return Outcome.INSUFFICIENT, "failed_for_another_reason", ev


def migration_executed(obs: dict) -> Result:
    machine = obs.get("machine")
    step, expected = _step(machine, "execute"), _expected(machine)
    if not _ran(step) or not expected:
        return Outcome.INSUFFICIENT, "not_run", {}
    events = _jsonl(machine.get("files", {}).get("journal.jsonl"))
    done = next((e for e in events if e.get("event") == "run_complete"), None)
    conv = next((e for e in events if e.get("event") == "convergence"), None)
    failed = next((e for e in events if e.get("event") == "run_failed"), None)
    written = (done or {}).get("written") or {}
    total = sum(written.values()) + (done or {}).get("skipped_unchanged", 0)
    want = expected["exported_total"] + 1  # every contact plus the one campaign
    ev = {"exit": step["exit"], "written": written, "expected_writes": want,
          "converged": (conv or {}).get("converged"), "run_failed": failed is not None,
          "conflicts": (done or {}).get("conflicts")}
    if step["exit"] != 0 or failed or done is None:
        return Outcome.FAIL, "execute_failed", ev
    if total != want or (done or {}).get("skipped_unchanged"):
        return Outcome.FAIL, "write_count_mismatch", ev
    if not (conv or {}).get("converged"):
        return Outcome.FAIL, "not_converged", ev
    return Outcome.PASS, "executed_and_converged", ev


def _history(machine: dict) -> dict | None:
    rows = _jsonl(machine.get("files", {}).get("reconcile-history.jsonl"))
    return rows[-1] if rows else None


def destination_state(obs: dict) -> Result:
    machine = obs.get("machine")
    step, expected = _step(machine, "reconcile"), _expected(machine)
    if not _ran(step) or not expected:
        return Outcome.INSUFFICIENT, "not_run", {}
    hist = _history(machine)
    cleanup = json.loads(machine["files"]["cleanup.json"]) \
        if "cleanup.json" in machine.get("files", {}) else None
    found = cleanup["deleted"]["contacts"] if cleanup else None
    ev = {"reconcile_exit": step["exit"], "passed": (hist or {}).get("passed"),
          "failing": (hist or {}).get("failing"), "expected_contacts": expected["exported_total"],
          "contacts_read_back": found}
    if step["exit"] == 2 or hist is None:
        return Outcome.INSUFFICIENT, "reconcile_could_not_run", ev
    if step["exit"] != 0 or not hist.get("passed"):
        return Outcome.FAIL, "reconcile_failed", ev
    if found is None:
        return Outcome.INSUFFICIENT, "no_independent_read", ev
    if found != expected["exported_total"]:
        return Outcome.FAIL, "read_back_count_mismatch", ev
    return Outcome.PASS, "reconciled_and_read_back", ev


def suppression_integrity(obs: dict) -> Result:
    machine = obs.get("machine")
    expected = _expected(machine)
    hist = _history(machine) if machine else None
    if not expected or hist is None:
        return Outcome.INSUFFICIENT, "no_reconcile_record", {}
    n = len(expected["suppressed_emails"])
    ev = {"suppression_pct": hist.get("suppression_pct"), "suppressed_in_fixture": n}
    if n == 0:
        return Outcome.INSUFFICIENT, "vacuous_no_suppressed_records", ev
    if hist.get("suppression_pct") == 100.0:
        return Outcome.PASS, "all_suppressed_non_subscribable", ev
    return Outcome.FAIL, "suppressed_address_subscribable", ev


def fixture_cleanup(obs: dict) -> Result:
    machine = obs.get("machine")
    step = _step(machine, "cleanup")
    if not _ran(step):
        return Outcome.INSUFFICIENT, "not_run", {}
    text = machine.get("files", {}).get("cleanup.json")
    result = json.loads(text) if text else None
    ev = {"exit": step["exit"], "deleted": (result or {}).get("deleted"),
          "remaining": (result or {}).get("remaining")}
    if step["exit"] == 0 and result and result.get("clean"):
        return Outcome.PASS, "nothing_remains", ev
    if step["exit"] == 1:
        return Outcome.FAIL, "resources_remain", ev
    return Outcome.INSUFFICIENT, "cleanup_could_not_run", ev


EVALUATORS = {
    "CNF-001": release_deployed, "CNF-002": health_endpoint,
    "CNF-010": anonymous_write_refused, "CNF-011": wrong_password_refused,
    "CNF-012": approver_sign_in, "CNF-013": audit_append,
    "CNF-020": fixture_built, "CNF-021": gate_refuses_draft,
    "CNF-022": gate_refuses_tampered, "CNF-023": approval_recorded,
    "CNF-030": migration_executed, "CNF-031": destination_state,
    "CNF-032": suppression_integrity, "CNF-040": fixture_cleanup,
}


def evaluate(obs: dict) -> list[Observation]:
    out: dict[str, Observation] = {}
    for check in CHECKS:
        blocked = [r for r in check.requires if out[r].outcome is not Outcome.PASS]
        if blocked:
            out[check.id] = Observation(check.id, check.name, Outcome.INSUFFICIENT,
                                        "prerequisite_not_passed", {"blocked_by": blocked})
            continue
        try:
            outcome, reason, ev = EVALUATORS[check.id](obs)
        except (KeyError, TypeError, ValueError) as exc:
            # Malformed evidence is never a pass, and never a crash that
            # loses the rest of the report.
            outcome, reason, ev = Outcome.INSUFFICIENT, "evidence_unreadable", {
                "error": type(exc).__name__}
        out[check.id] = Observation(check.id, check.name, outcome, reason, ev)
    return list(out.values())


def verdict(observations: list[Observation]) -> Outcome:
    outcomes = {o.outcome for o in observations}
    if Outcome.FAIL in outcomes:
        return Outcome.FAIL
    if Outcome.INSUFFICIENT in outcomes:
        return Outcome.INSUFFICIENT
    return Outcome.PASS
