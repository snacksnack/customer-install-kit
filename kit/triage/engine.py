"""One triage round for a case (RC1-643, ADR 0009).

    inspect (hostile-input gate) -> facts -> rules -> [agent] -> case store
                                                            -> metadata-only telemetry

Inputs are exported bundle archives and the customer's report-key
fingerprint, received out of band. Nothing else: no customer credential, no
evaluator label, no live system. A supplemental bundle is accepted only if it
answers a follow-up request this case actually issued.

Rules-only and agent-assisted results are recorded separately in every round
(`rules_outcome` and `outcome`), so the agent's contribution is measured
against the deterministic baseline on the same evidence.
"""

import secrets
from pathlib import Path
from typing import Any

import anthropic

from kit.bundle import archive
from kit.bundle.archive import BundleRefused
from kit.triage import agent as agent_mod
from kit.triage import registry, rules, telemetry
from kit.triage.casestore import CaseStore
from kit.triage.facts import Evidence

MODES = ("rules", "agent")


def eval_record(case_id: str, round_no: int, run_id: str, mode: str, result: rules.Result,
                r: agent_mod.RoundResult | None) -> dict[str, Any]:
    """The metadata-only record: what telemetry, CI logs and eval exports get.
    Ids, enums and numbers; no statement, remedy, hypothesis or bundle value."""
    findings = (r.diagnosis or {}).get("findings", []) if r and r.diagnosis else []
    rec = {
        "schema": "cik.triage-record/1", "case_id": case_id, "round": round_no,
        "run_id": run_id, "mode": mode, "registry_digest": registry.digest(),
        "rules_outcome": result.outcome,
        "rules_findings": [{"rule": f.rule, "status": f.status} for f in result.findings],
        "rules_followups": sorted({c for f in result.findings for c in f.followups}),
        "outcome": r.outcome if r else result.outcome,
        "stop_reason": r.stop_reason if r else "rules_only",
    }
    if r:
        rec |= {
            "agent_finding_statuses": [f.get("status") for f in findings],
            "followup_requested": (r.followup_request or {}).get("check_id"),
            "followup_request_id": (r.followup_request or {}).get("request_id"),
            "model_calls": r.model_calls, "tool_calls": r.tool_calls,
            "rejected_submissions": r.rejected_submissions,
            "citations": r.citations, "citations_resolved": r.citations_resolved,
            "usage": r.usage, "cost_usd": round(r.cost_usd, 6), "models": sorted(set(r.models)),
            "error_type": r.error_type,
        }
    return rec


def triage(primary: Path, fingerprint: str, *, supplements: list[Path] | None = None,
           mode: str = "rules", store: CaseStore | None = None, client: Any = None,
           budget: agent_mod.Budget | None = None, post=telemetry.post) -> dict[str, Any]:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    store = store or CaseStore()
    ins = archive.inspect(primary, fingerprint)
    sups = [archive.inspect(p, fingerprint) for p in supplements or []]
    case = store.case(ins.digest)
    issued = {r["request_id"]: r for r in case.requests()}
    for s in sups:
        fu = s.manifest.get("followup") or {}
        req = issued.get(fu.get("request_id"))
        if not req or req.get("check_id") != fu.get("check_id"):
            raise BundleRefused(f"supplement {s.manifest.get('bundle_id')} answers no "
                                "follow-up request issued in this case")
    ev = Evidence(ins, sups)
    result = rules.run(ev)
    n = case.next_round()
    rd = f"rounds/{n:02d}"
    run_id = "tr-" + secrets.token_hex(8)
    case.write("case.json", {"case_id": case.id, "primary_bundle": ins.digest,
                             "primary_bundle_id": ins.manifest.get("bundle_id"),
                             "install_id": ins.manifest.get("install_id"),
                             "fingerprint": ins.fingerprint})
    case.write(f"{rd}/rules.json", {"inputs": [ins.digest] + [s.digest for s in sups],
                                    **result.as_dict()})
    trace = telemetry.Trace(run_id, mode, n, registry.digest())
    r = None
    if mode == "agent":
        if client is None:
            client = anthropic.Anthropic()
        r = agent_mod.Agent(client, budget=budget).run_round(
            ev, result, list(issued.values()), trace,
            lambda e: case.append(f"{rd}/transcript.jsonl", e))
        if r.followup_request:
            case.write(f"requests/{r.followup_request['request_id']}.json", r.followup_request)
    rec = eval_record(case.id, n, run_id, mode, result, r)
    statuses = rec.get("agent_finding_statuses") or [f.status for f in result.findings]
    trace.finish(rec["outcome"], rec["stop_reason"], rec.get("followup_requested"),
                 [f.rule for f in result.findings], {
                     "model_calls": rec.get("model_calls", 0),
                     "tool_calls": rec.get("tool_calls", 0),
                     "followup_rounds": len(issued),
                     "citations": rec.get("citations", 0),
                     "citations_resolved": rec.get("citations_resolved", 0),
                     "estimated_cost_usd": rec.get("cost_usd", 0.0),
                     **{f"findings_{s}": statuses.count(s) for s in agent_mod.STATUSES},
                     **{k: v for k, v in (rec.get("usage") or {}).items()}},
                 (r.error_type if r else "none"))
    rec["telemetry_status"] = post(trace.payload())
    case.write(f"{rd}/result.json", {
        **rec, "rules": result.as_dict(),
        "diagnosis": r.diagnosis if r else None,
        "followup_request": r.followup_request if r else None})
    rec["case_path"] = str(case.path)
    return rec
