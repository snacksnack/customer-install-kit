"""Shared vocabulary for checks and observations (ADR 0005).

An observation is what a probe saw, never what it means: no fault labels,
no diagnoses. Outcome and reason are closed sets so every downstream
consumer (conformance, bundles, triage) can rely on them.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Outcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    # The check does not apply to this install's profile or configuration.
    NOT_APPLICABLE = "not_applicable"
    # The check applies, but the evidence could not be obtained.
    UNKNOWN = "unknown"


class Reason(StrEnum):
    OK = "ok"
    # fail
    MISSING = "missing"
    BELOW_MINIMUM = "below_minimum"
    UNSUPPORTED = "unsupported"
    REFUSED = "refused"
    INSECURE = "insecure"
    # not_applicable
    NOT_CONFIGURED = "not_configured"
    NOT_IN_PROFILE = "not_in_profile"
    NONE_REQUIRED = "none_required"
    # unknown
    INPUT_MISSING = "input_missing"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    PROBE_UNAVAILABLE = "probe_unavailable"
    PROBE_ERROR = "probe_error"


ALLOWED_REASONS: dict[Outcome, frozenset[Reason]] = {
    Outcome.PASS: frozenset({Reason.OK}),
    Outcome.FAIL: frozenset(
        {Reason.MISSING, Reason.BELOW_MINIMUM, Reason.UNSUPPORTED, Reason.REFUSED, Reason.INSECURE}
    ),
    Outcome.NOT_APPLICABLE: frozenset(
        {Reason.NOT_CONFIGURED, Reason.NOT_IN_PROFILE, Reason.NONE_REQUIRED}
    ),
    Outcome.UNKNOWN: frozenset(
        {
            Reason.INPUT_MISSING,
            Reason.BLOCKED,
            Reason.TIMEOUT,
            Reason.PROBE_UNAVAILABLE,
            Reason.PROBE_ERROR,
        }
    ),
}


class Context(StrEnum):
    OPERATOR = "operator"
    RUNTIME = "runtime"


class Severity(StrEnum):
    REQUIRED = "required"
    ADVISORY = "advisory"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    context: Context
    severity: Severity
    profiles: tuple[str, ...]
    purpose: str
    probe: str
    permission: str
    remediation: str
    timeout_s: float
    evidence: dict[str, str]
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProbeResult:
    """What a probe returns. Evidence must be empty or match the check's
    declared evidence schema exactly; the runner enforces that."""

    outcome: Outcome
    reason: Reason
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Observation:
    check_id: str
    outcome: Outcome
    reason: Reason
    evidence: dict[str, Any]
    duration_ms: int
    blocked_by: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "check_id": self.check_id,
            "outcome": str(self.outcome),
            "reason": str(self.reason),
            "evidence": self.evidence,
            "duration_ms": self.duration_ms,
        }
        if self.blocked_by:
            out["blocked_by"] = list(self.blocked_by)
        return out
