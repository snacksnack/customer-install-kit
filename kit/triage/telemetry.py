"""Metadata-only Datadog LLM Observability for triage (RC1-643, ADR 0009).

Built, not scrubbed, like the bundle itself. ddtrace's anthropic integration
is NOT used: it captures prompts, completions, tool inputs and outputs, and
exception messages, and those would carry bundle text, hypotheses and
diagnoses. Instead this module builds each span from an allowlist of fields
(opaque run and check ids, enums, numbers) and posts it to the LLM Obs
intake directly. `validate()` walks a payload and refuses anything outside
the allowlist; `post()` sends nothing that has not passed it.

There is no input/output on any span, no error message (only an error type
from a fixed set), and no free text anywhere. The content-bearing channel is
the Claude API itself, disclosed in ADR 0009; Datadog receives metadata.

Decoration, never load-bearing: without DD_API_KEY, `post()` declines, and a
failed POST is reported by status code only. Set CIK_TELEMETRY_CAPTURE to a
file path to also append every outgoing payload there for inspection.
"""

import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

ML_APP = "cik-triage"
SERVICE = "cik-triage"
INTAKE = "https://api.{site}/api/intake/llm-obs/v1/trace/spans"
TELEMETRY_VERSION = "2026-11-13"

SPAN_NAMES = frozenset({"triage.round", "triage.model_call", "triage.tool"})
KINDS = frozenset({"workflow", "llm", "tool"})
ERROR_TYPES = frozenset({"api_error", "rate_limited", "connection_error", "refusal",
                         "budget_exhausted", "invalid_tool_input", "none"})
TAG_VALUES: dict[str, re.Pattern] = {
    "service": re.compile(rf"^{SERVICE}$"),
    "env": re.compile(r"^(prod|dev|evals|dry-run|ci)$"),
    "version": re.compile(r"^[0-9A-Za-z.+-]{1,32}$"),
    "run_id": re.compile(r"^tr-[0-9a-f]{16}$"),
    "mode": re.compile(r"^(rules|agent)$"),
    "outcome": re.compile(r"^(supported_diagnosis|conflicting_evidence|insufficient_evidence"
                          r"|budget_exhausted|awaiting_followup)$"),
    "stop_reason": re.compile(r"^(end_turn|tool_use|max_tokens|refusal|pause_turn|diagnosis"
                              r"|followup_requested|budget_model_calls|budget_tool_calls"
                              r"|budget_usd|no_tool_call|api_error|rules_only)$"),
    "round": re.compile(r"^[0-9]{1,2}$"),
    "followup": re.compile(r"^(none|FUP-[A-Z-]{2,24})$"),
    "error": re.compile(r"^[01]$"),
    "error_type": re.compile("^(" + "|".join(sorted(ERROR_TYPES)) + ")$"),
    "rule": re.compile(r"^TRI-[A-Z-]{2,24}$"),
    "tool": re.compile(r"^(read_evidence|request_followup|submit_diagnosis|unknown)$"),
    "tool_status": re.compile(r"^(ok|rejected|error)$"),
    "registry": re.compile(r"^[0-9a-f]{12}$"),
}
METRICS = frozenset({
    "input_tokens", "output_tokens", "total_tokens", "cache_read_input_tokens",
    "cache_creation_input_tokens", "estimated_cost_usd", "model_calls", "tool_calls",
    "followup_rounds", "citations", "citations_resolved", "findings_supported",
    "findings_insufficient", "findings_conflicting", "findings_resolved", "latency_s",
})
MODELS = re.compile(r"^claude-[a-z0-9-]{3,40}$")
SPAN_KEYS = frozenset({"name", "span_id", "trace_id", "parent_id", "start_ns", "duration",
                       "status", "tags", "meta", "metrics"})
META_KEYS = {"workflow": frozenset({"kind"}), "tool": frozenset({"kind"}),
             "llm": frozenset({"kind", "model_name", "model_provider"})}
ID = re.compile(r"^[1-9][0-9]{0,19}$")


class TelemetryRefused(Exception):
    """A payload carried something outside the allowlist; it is not sent."""


def new_id() -> str:
    return str(secrets.randbelow(10**18) + 10**18)


def _tag(key: str, value: Any) -> str:
    return f"{key}:{value}"


@dataclass
class Span:
    name: str
    kind: str
    start_ns: int
    duration_ns: int = 0
    tags: list[tuple[str, str]] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    model_name: str | None = None
    error: bool = False
    span_id: str = field(default_factory=new_id)


class Trace:
    """Collects one triage round's spans in memory, then builds the payload."""

    def __init__(self, run_id: str, mode: str, round_no: int, registry_digest: str):
        self.run_id, self.mode, self.round = run_id, mode, round_no
        self.registry = registry_digest.removeprefix("sha256:")[:12]
        self.trace_id = new_id()
        self.root = Span("triage.round", "workflow", time.time_ns())
        self.children: list[Span] = []

    def model_call(self, model: str, started_ns: int, usage: dict[str, int], cost: float,
                   stop_reason: str, error_type: str = "none") -> None:
        tags = [("stop_reason", stop_reason), ("error_type", error_type),
                ("error", "1" if error_type != "none" else "0")]
        metrics = {k: float(v) for k, v in usage.items() if k in METRICS}
        metrics["total_tokens"] = float(usage.get("input_tokens", 0)
                                        + usage.get("output_tokens", 0))
        metrics["estimated_cost_usd"] = round(cost, 6)
        self.children.append(Span("triage.model_call", "llm", started_ns,
                                  time.time_ns() - started_ns, tags, metrics, model,
                                  error_type != "none"))

    def tool_call(self, tool: str, started_ns: int, status: str) -> None:
        self.children.append(Span("triage.tool", "tool", started_ns,
                                  time.time_ns() - started_ns,
                                  [("tool", tool), ("tool_status", status),
                                   ("error", "1" if status == "error" else "0")]))

    def finish(self, outcome: str, stop_reason: str, followup: str | None,
               rules: list[str], metrics: dict[str, float], error_type: str = "none") -> None:
        self.root.duration_ns = time.time_ns() - self.root.start_ns
        self.root.tags = [("outcome", outcome), ("stop_reason", stop_reason),
                          ("followup", followup or "none"), ("error_type", error_type),
                          ("error", "1" if error_type != "none" else "0")]
        self.root.tags += [("rule", r) for r in sorted(set(rules))[:8]]
        self.root.metrics = {k: float(v) for k, v in metrics.items() if k in METRICS}
        self.root.error = error_type != "none"

    def payload(self) -> dict[str, Any]:
        env = os.environ.get("DD_ENV", "dev")
        trace_tags = [_tag("service", SERVICE), _tag("env", env),
                      _tag("version", TELEMETRY_VERSION), _tag("run_id", self.run_id),
                      _tag("mode", self.mode), _tag("round", self.round),
                      _tag("registry", self.registry)]
        spans = [self._span(self.root, "undefined")]
        spans += [self._span(c, self.root.span_id) for c in self.children]
        return {"data": {"type": "span", "attributes": {
            "ml_app": ML_APP, "tags": trace_tags, "spans": spans}}}

    def _span(self, s: Span, parent: str) -> dict[str, Any]:
        tags = [_tag(k, v) for k, v in s.tags]
        meta: dict[str, Any] = {"kind": s.kind}
        if s.kind == "llm":
            meta |= {"model_name": s.model_name or "unknown", "model_provider": "anthropic"}
        return {"name": s.name, "span_id": s.span_id, "trace_id": self.trace_id,
                "parent_id": parent, "start_ns": s.start_ns, "duration": s.duration_ns,
                "status": "error" if s.error else "ok", "tags": tags, "meta": meta,
                "metrics": s.metrics}


def _check_tags(tags: Any, where: str) -> None:
    if not isinstance(tags, list):
        raise TelemetryRefused(f"{where}: tags is not a list")
    for t in tags:
        if not isinstance(t, str) or ":" not in t:
            raise TelemetryRefused(f"{where}: malformed tag")
        k, v = t.split(":", 1)
        pattern = TAG_VALUES.get(k)
        if pattern is None or not pattern.match(v):
            raise TelemetryRefused(f"{where}: tag {k!r} is not allowlisted or its value "
                                   "does not match")


def validate(payload: Any) -> None:
    """Refuse a payload holding any key, tag or value outside the allowlist."""
    if not isinstance(payload, dict) or set(payload) != {"data"}:
        raise TelemetryRefused("top level")
    data = payload["data"]
    if not isinstance(data, dict) or set(data) != {"type", "attributes"} \
            or data["type"] != "span":
        raise TelemetryRefused("data")
    attrs = data["attributes"]
    if not isinstance(attrs, dict) or set(attrs) != {"ml_app", "tags", "spans"} \
            or attrs["ml_app"] != ML_APP:
        raise TelemetryRefused("attributes")
    _check_tags(attrs["tags"], "trace")
    for i, s in enumerate(attrs["spans"]):
        where = f"span {i}"
        if not isinstance(s, dict) or set(s) - SPAN_KEYS:
            raise TelemetryRefused(f"{where}: keys")
        if s["name"] not in SPAN_NAMES or s["status"] not in ("ok", "error"):
            raise TelemetryRefused(f"{where}: name/status")
        for key in ("span_id", "trace_id"):
            if not ID.match(str(s[key])):
                raise TelemetryRefused(f"{where}: {key}")
        if s["parent_id"] != "undefined" and not ID.match(str(s["parent_id"])):
            raise TelemetryRefused(f"{where}: parent_id")
        for key in ("start_ns", "duration"):
            if not isinstance(s[key], int) or isinstance(s[key], bool):
                raise TelemetryRefused(f"{where}: {key}")
        _check_tags(s["tags"], where)
        meta = s["meta"]
        kind = meta.get("kind") if isinstance(meta, dict) else None
        if kind not in KINDS or set(meta) - META_KEYS[kind]:
            raise TelemetryRefused(f"{where}: meta")
        if kind == "llm" and (not MODELS.match(str(meta.get("model_name")))
                              or meta.get("model_provider") != "anthropic"):
            raise TelemetryRefused(f"{where}: model")
        metrics = s["metrics"]
        if not isinstance(metrics, dict) or set(metrics) - METRICS or any(
                not isinstance(v, (int, float)) or isinstance(v, bool)
                for v in metrics.values()):
            raise TelemetryRefused(f"{where}: metrics")


def post(payload: dict[str, Any]) -> int | None:
    """Validate, then send. Returns the HTTP status, or None if not sent."""
    validate(payload)
    body = json.dumps(payload, sort_keys=True).encode()
    capture = os.environ.get("CIK_TELEMETRY_CAPTURE")
    if capture:
        with open(capture, "ab") as fh:
            fh.write(body + b"\n")
    key = os.environ.get("DD_API_KEY")
    if not key:
        return None
    url = INTAKE.format(site=os.environ.get("DD_SITE", "datadoghq.com"))
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "DD-API-KEY": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        print(f"telemetry: LLM Obs intake returned {exc.code}", file=sys.stderr)
        return exc.code
    except (OSError, urllib.error.URLError) as exc:
        print(f"telemetry: LLM Obs intake unreachable ({type(exc).__name__})", file=sys.stderr)
        return None
