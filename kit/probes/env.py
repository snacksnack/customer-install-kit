"""Environment-variable probes. Names only ever reach the report; values are
checked for presence (and, for ENV-002, equality with a public constant)."""

from kit.model import Check, Outcome, ProbeResult, Reason
from kit.probes.base import ProbeEnv, probe


def _presence(check: Check, env: ProbeEnv) -> ProbeResult:
    names = check.params["names"]
    present = [n for n in names if env.environ.get(n, "").strip()]
    missing = [n for n in names if n not in present]
    evidence = {"present": present, "missing": missing}
    if missing:
        return ProbeResult(Outcome.FAIL, Reason.MISSING, evidence)
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)


@probe("ENV-001")
def required_secrets(check: Check, env: ProbeEnv) -> ProbeResult:
    return _presence(check, env)


@probe("ENV-002")
def session_secret_not_default(check: Check, env: ProbeEnv) -> ProbeResult:
    value = env.environ.get(check.params["name"], "")
    if not value.strip():
        return ProbeResult(Outcome.UNKNOWN, Reason.INPUT_MISSING)
    is_default = value == check.params["default_value"]
    if is_default:
        return ProbeResult(Outcome.FAIL, Reason.INSECURE, {"is_default": True})
    return ProbeResult(Outcome.PASS, Reason.OK, {"is_default": False})


@probe("ENV-003")
def model_api_key(check: Check, env: ProbeEnv) -> ProbeResult:
    return _presence(check, env)
