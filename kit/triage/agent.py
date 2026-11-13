"""The bounded triage agent (RC1-643, ADR 0009).

A manual tool loop over the Claude API, so the kit owns every bound. The
model sees the rules engine's output and reads bundle evidence by reference;
it can request ONE allowlisted follow-up check per round, or submit a
diagnosis. It has no tool that reaches the customer, and none that runs
anything: `read_evidence` resolves a reference in an already-inspected
bundle, `request_followup` writes a request the customer may choose to run,
`submit_diagnosis` is validated (outcome consistent with the findings, every
citation resolves, a remedy only on supported findings) and refused back to
the model until it is.

Bounds: model calls, tool calls, follow-up rounds per case, and dollars per
round. Hitting one ends the round as `budget_exhausted`.

Bundle values reach the model inside `untrusted_bundle_data`; the prompt
says they are data, and nothing in the loop acts on their text.
"""

import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from kit.bundle.archive import BundleRefused
from kit.triage import registry, rules
from kit.triage.facts import Evidence
from kit.triage.telemetry import Trace

MODEL = "claude-opus-5-5"
EFFORT = "high"
MAX_TOKENS = 16000
READ_CAP_CHARS = 12000
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# $ per million tokens: input, output, cache read, cache write (5 min).
PRICES = {
    "claude-opus-5-5": (4.0, 20.0, 0.20, 5.0),
    "claude-opus-5": (5.0, 25.0, 0.50, 6.25),
    "claude-opus-4-8": (5.0, 25.0, 0.50, 6.25),
}
# An unknown (fallback) model is priced high on purpose, so it never looks cheap.
UNKNOWN_PRICE = (10.0, 50.0, 1.0, 12.5)
STATUSES = ("supported", "insufficient", "conflicting", "resolved")
CASE_OUTCOMES = ("supported_diagnosis", "conflicting_evidence", "insufficient_evidence")


@dataclass
class Budget:
    model_calls: int = 10
    tool_calls: int = 24
    followup_rounds: int = 2
    usd: float = 1.50


@dataclass
class RoundResult:
    outcome: str
    stop_reason: str
    diagnosis: dict[str, Any] | None = None
    followup_request: dict[str, Any] | None = None
    model_calls: int = 0
    tool_calls: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    cost_usd: float = 0.0
    citations: int = 0
    citations_resolved: int = 0
    rejected_submissions: int = 0
    models: list[str] = field(default_factory=list)
    error_type: str = "none"


def cost(model: str, usage: dict[str, int]) -> float:
    p_in, p_out, p_cr, p_cw = PRICES.get(model, UNKNOWN_PRICE)
    return (usage.get("input_tokens", 0) * p_in + usage.get("output_tokens", 0) * p_out
            + usage.get("cache_read_input_tokens", 0) * p_cr
            + usage.get("cache_creation_input_tokens", 0) * p_cw) / 1_000_000


def _usage(resp: Any) -> dict[str, int]:
    u = getattr(resp, "usage", None)
    out = {}
    for k in ("input_tokens", "output_tokens", "cache_read_input_tokens",
              "cache_creation_input_tokens"):
        v = getattr(u, k, None)
        out[k] = int(v) if isinstance(v, int) else 0
    return out


def system_prompt() -> str:
    k = registry.knowledge()
    fups = "\n".join(f"- `{f.id}` ({f.title}): {f.purpose} Discriminates: {f.discriminates} "
                     f"Returns: {f.returns}" for f in registry.followups().values())
    knowledge = {key: k[key] for key in ("operations", "app_role", "sqlstates",
                                         "connect_classes", "provider_codes", "errno",
                                         "remedies")}
    text = (registry.HERE / "prompt.md").read_text()
    return (text.replace("{followups}", fups)
                .replace("{knowledge_version}", str(k["version"]))
                .replace("{knowledge}", "```json\n" + json.dumps(knowledge, indent=1) + "\n```"))


def tools(followups_left: int) -> list[dict[str, Any]]:
    finding = {
        "type": "object", "additionalProperties": False,
        "required": ["hypothesis", "status", "statement", "supports", "does_not_establish",
                     "citations", "remedy"],
        "properties": {
            "hypothesis": {"type": "string"},
            "status": {"type": "string", "enum": list(STATUSES)},
            "statement": {"type": "string"},
            "supports": {"type": "array", "items": {"type": "string"}},
            "does_not_establish": {"type": "array", "items": {"type": "string"}},
            "citations": {"type": "array", "items": {"type": "string"}},
            "remedy": {"type": ["string", "null"]},
        },
    }
    out = [
        {"name": "read_evidence", "strict": True,
         "description": "Read one value from a case bundle by evidence reference "
                        "(cik-ev:<bundle digest>/<file>#<JSON pointer>). Returns it inside "
                        "untrusted_bundle_data. Large values are truncated: narrow the pointer.",
         "input_schema": {"type": "object", "additionalProperties": False,
                          "required": ["ref"],
                          "properties": {"ref": {"type": "string"}}}},
        {"name": "submit_diagnosis", "strict": True,
         "description": "Conclude this round. Every citation must resolve; a remedy only on "
                        "supported findings; the outcome must follow from the statuses.",
         "input_schema": {"type": "object", "additionalProperties": False,
                          "required": ["outcome", "findings"],
                          "properties": {
                              "outcome": {"type": "string", "enum": list(CASE_OUTCOMES)},
                              "findings": {"type": "array", "items": finding}}}},
    ]
    if followups_left > 0:
        out.insert(1, {
            "name": "request_followup", "strict": True,
            "description": "Ask the customer to run one allowlisted read-only check. Ends "
                           f"this round. {followups_left} follow-up round(s) left in this case.",
            "input_schema": {"type": "object", "additionalProperties": False,
                             "required": ["check_id", "reason", "discriminates"],
                             "properties": {
                                 "check_id": {"type": "string",
                                              "enum": sorted(registry.followups())},
                                 "reason": {"type": "string"},
                                 "discriminates": {"type": "string"}}}})
    return out


def expected_outcome(statuses: list[str]) -> str:
    live = [s for s in statuses if s != "resolved"]
    if "conflicting" in live:
        return "conflicting_evidence"
    if "insufficient" in live or not live:
        return "insufficient_evidence"
    return "supported_diagnosis"


def validate_diagnosis(ev: Evidence, d: dict[str, Any]) -> tuple[list[str], int, int]:
    """Problems with a submitted diagnosis, plus citation counts."""
    problems: list[str] = []
    findings = d.get("findings") if isinstance(d.get("findings"), list) else []
    if not findings:
        problems.append("at least one finding is required")
    total = resolved = 0
    for i, f in enumerate(findings):
        cites = f.get("citations") or []
        if not cites:
            problems.append(f"finding {i}: no citations")
        for c in cites:
            total += 1
            try:
                ev.resolve(c)
                resolved += 1
            except (BundleRefused, AttributeError, TypeError):
                problems.append(f"finding {i}: citation does not resolve: {c[:120]}")
        if f.get("status") == "supported" and not f.get("remedy"):
            problems.append(f"finding {i}: a supported finding needs a remedy")
        if f.get("status") != "supported" and f.get("remedy"):
            problems.append(f"finding {i}: propose a remedy only for a supported finding")
    want = expected_outcome([f.get("status") for f in findings])
    if findings and d.get("outcome") != want:
        problems.append(f"outcome {d.get('outcome')!r} does not follow from the finding "
                        f"statuses; it should be {want!r}")
    return problems, total, resolved


def opening(ev: Evidence, result: rules.Result, requests: list[dict[str, Any]],
            followups_left: int) -> str:
    bundles = []
    for b in [ev.primary, *ev.supplements]:
        bundles.append({"digest": b.digest, "bundle_id": b.manifest.get("bundle_id"),
                        "role": "followup" if b.manifest.get("followup") else "primary",
                        "followup": b.manifest.get("followup"),
                        "collected_at": b.manifest.get("collected_started_at"),
                        "files": sorted(b.files) + ["manifest.signed.json"]})
    body = {"rules_result": result.as_dict(), "bundles": bundles,
            "followup_requests_so_far": [{k: r.get(k) for k in
                                          ("request_id", "check_id", "issued_at")}
                                         for r in requests],
            "followup_rounds_left": followups_left}
    return ("Triage this case. The rules engine's result and the bundle index follow; the "
            "bundle values themselves come only through read_evidence.\n\n"
            "<untrusted_bundle_data>\n" + json.dumps(body, indent=1, default=str)
            + "\n</untrusted_bundle_data>")


class Agent:
    def __init__(self, client: Any, model: str = MODEL, budget: Budget | None = None,
                 effort: str = EFFORT):
        self.client, self.model, self.effort = client, model, effort
        self.budget = budget or Budget()

    def _call(self, system: str, tool_defs, messages):
        return self.client.beta.messages.create(
            model=self.model, max_tokens=MAX_TOKENS,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=tool_defs, messages=messages, output_config={"effort": self.effort},
            betas=[FALLBACK_BETA], fallbacks="default")

    def run_round(self, ev: Evidence, result: rules.Result, requests: list[dict[str, Any]],
                  trace: Trace, log) -> RoundResult:
        left = max(self.budget.followup_rounds - len(requests), 0)
        system, tool_defs = system_prompt(), tools(left)
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": opening(ev, result, requests, left)}]
        log({"role": "user", "content": messages[0]["content"]})
        out = RoundResult("budget_exhausted", "budget_model_calls")
        nudged = False
        while True:
            if out.model_calls >= self.budget.model_calls:
                out.stop_reason = "budget_model_calls"
                return out
            if out.cost_usd >= self.budget.usd:
                out.stop_reason = "budget_usd"
                return out
            started = time.time_ns()
            try:
                resp = self._call(system, tool_defs, messages)
            except Exception as exc:  # the round ends; the type is kept, never the message
                kind = type(exc).__name__
                etype = ("rate_limited" if "RateLimit" in kind else
                         "connection_error" if "Connection" in kind or "Timeout" in kind
                         else "api_error")
                trace.model_call(self.model, started, {}, 0.0, "api_error", etype)
                log({"event": "model_error", "type": kind})
                out.outcome, out.stop_reason, out.error_type = (
                    result.outcome, "api_error", etype)
                return out
            served = getattr(resp, "model", None) or self.model
            usage = _usage(resp)
            c = cost(served, usage)
            out.model_calls += 1
            out.cost_usd += c
            out.models.append(served)
            for k, v in usage.items():
                out.usage[k] = out.usage.get(k, 0) + v
            stop = resp.stop_reason or "end_turn"
            trace.model_call(served if served.startswith("claude-") else self.model, started,
                             usage, c, stop if stop in ("end_turn", "tool_use", "max_tokens",
                                                        "refusal", "pause_turn") else "end_turn",
                             "refusal" if stop == "refusal" else "none")
            content = [b.model_dump(exclude_none=True) if hasattr(b, "model_dump") else b
                       for b in resp.content]
            log({"role": "assistant", "model": served, "stop_reason": stop,
                 "usage": usage, "content": content})
            if stop == "refusal":
                out.outcome, out.stop_reason, out.error_type = result.outcome, "refusal", \
                    "refusal"
                return out
            messages.append({"role": "assistant", "content": content})
            uses = [b for b in content if b.get("type") == "tool_use"]
            if not uses:
                if nudged:
                    out.stop_reason = "no_tool_call"
                    return out
                nudged = True
                messages.append({"role": "user", "content":
                                 "End the round with submit_diagnosis or request_followup."})
                continue
            replies = []
            for u in uses:
                out.tool_calls += 1
                t0 = time.time_ns()
                name, args = u.get("name"), u.get("input") or {}
                if out.tool_calls > self.budget.tool_calls:
                    trace.tool_call(name if name in ("read_evidence", "request_followup",
                                                     "submit_diagnosis") else "unknown",
                                    t0, "rejected")
                    out.stop_reason = "budget_tool_calls"
                    return out
                reply, status, terminal = self._tool(ev, name, args, left, out)
                trace.tool_call(name if name in ("read_evidence", "request_followup",
                                                 "submit_diagnosis") else "unknown", t0, status)
                log({"role": "tool", "name": name, "input": args, "status": status,
                     "result": reply})
                if terminal:
                    return out
                replies.append({"type": "tool_result", "tool_use_id": u["id"],
                                "content": json.dumps(reply, default=str),
                                "is_error": status != "ok"})
            messages.append({"role": "user", "content": replies})

    def _tool(self, ev: Evidence, name: str, args: dict[str, Any], left: int,
              out: RoundResult) -> tuple[Any, str, bool]:
        if name == "read_evidence":
            ref = args.get("ref")
            try:
                value = ev.resolve(ref) if isinstance(ref, str) else None
            except BundleRefused as exc:
                return {"error": str(exc)}, "rejected", False
            text = json.dumps(value, default=str)
            truncated = len(text) > READ_CAP_CHARS
            return ({"untrusted_bundle_data": text[:READ_CAP_CHARS] if truncated else value,
                     "truncated": truncated}, "ok", False)
        if name == "request_followup":
            cid = args.get("check_id")
            if left <= 0:
                return {"error": "no follow-up rounds left in this case"}, "rejected", False
            if cid not in registry.followups():
                return {"error": f"{cid!r} is not an allowlisted check"}, "rejected", False
            out.followup_request = {
                "schema": "cik.followup-request/1",
                "request_id": "fr-" + secrets.token_hex(6),
                "check_id": cid,
                "parent_bundle": ev.primary.digest,
                "reason": str(args.get("reason", ""))[:600],
                "discriminates": str(args.get("discriminates", ""))[:600],
                "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            out.outcome, out.stop_reason = "awaiting_followup", "followup_requested"
            return {"ok": True, "request_id": out.followup_request["request_id"]}, "ok", True
        if name == "submit_diagnosis":
            problems, total, ok = validate_diagnosis(ev, args)
            if problems:
                out.rejected_submissions += 1
                return {"error": "diagnosis refused; fix and resubmit",
                        "problems": problems}, "rejected", False
            out.diagnosis = args
            out.citations, out.citations_resolved = total, ok
            out.outcome, out.stop_reason = args["outcome"], "diagnosis"
            return {"ok": True}, "ok", True
        return {"error": f"unknown tool {name!r}"}, "rejected", False
