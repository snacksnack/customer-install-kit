"""Postgres probes, run as the owner role from the operator workstation.

Every probe opens its own short connection: checks stay independent, and a
connection that drops between checks shows up as that check's unknown
rather than a cascade. Exception text never reaches the report (it can name
roles, hosts or tables); only SQLSTATE and a coarse error class do.
"""

import psycopg

from kit.model import Check, Outcome, ProbeResult, Reason
from kit.probes.base import ProbeEnv, probe


class _NoInput(Exception):
    pass


def _connect(check: Check, env: ProbeEnv) -> psycopg.Connection:
    url = env.environ.get(check.params["url_var"], "").strip()
    if not url:
        raise _NoInput
    return env.connect_db(url, connect_timeout=check.params["connect_timeout_s"])


# psycopg attaches no SQLSTATE to errors raised while connecting, auth
# failures included (measured against Neon, 2026-11-11), so connect-time
# failures are classified from libpq's message. The message is matched here
# and never emitted: it names roles, databases and hosts.
CONNECT_PATTERNS = (
    ("auth", ("password authentication failed", "no pg_hba.conf entry", "role \"")),
    ("database", ("database \"",)),
    ("dns", ("could not translate host name", "nodename nor servname", "name or service not known",
             "temporary failure in name resolution")),
    ("tls", ("ssl", "certificate")),
    ("timeout", ("timeout expired", "timed out")),
)


def _classify(exc: psycopg.Error) -> str:
    state = getattr(exc, "sqlstate", None) or ""
    if state.startswith("28"):
        return "auth"
    if state.startswith("3D"):
        return "database"
    if state:
        return "server"
    text = str(exc).lower()
    for error_class, needles in CONNECT_PATTERNS:
        if any(n in text for n in needles):
            return error_class
    return "network"


@probe("DB-001")
def owner_connects_over_tls(check: Check, env: ProbeEnv) -> ProbeResult:
    try:
        conn = _connect(check, env)
    except _NoInput:
        return ProbeResult(Outcome.UNKNOWN, Reason.INPUT_MISSING)
    except psycopg.Error as exc:
        return ProbeResult(
            Outcome.FAIL,
            Reason.REFUSED,
            {
                "connected": False,
                "tls": None,
                "sqlstate": getattr(exc, "sqlstate", None),
                "error_class": _classify(exc),
            },
        )
    with conn:
        tls = bool(conn.pgconn.ssl_in_use)
    evidence = {"connected": True, "tls": tls, "sqlstate": None, "error_class": None}
    if not tls:
        return ProbeResult(Outcome.FAIL, Reason.INSECURE, evidence)
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)


def _query(check: Check, env: ProbeEnv, statement, args=()) -> tuple | None:
    """One row from a fresh owner connection, or None when the input is
    missing. Connection errors propagate: the dependency on DB-001 already
    passed, so a failure here is this check's unknown, not a fail."""
    try:
        conn = _connect(check, env)
    except _NoInput:
        return None
    with conn:
        return conn.execute(statement, args).fetchone()


@probe("DB-002")
def server_version(check: Check, env: ProbeEnv) -> ProbeResult:
    row = _query(check, env, "SELECT current_setting('server_version_num')::int")
    if row is None:
        return ProbeResult(Outcome.UNKNOWN, Reason.INPUT_MISSING)
    minimum = check.params["minimum_version_num"]
    evidence = {"server_version_num": row[0], "minimum": minimum}
    if row[0] < minimum:
        return ProbeResult(Outcome.FAIL, Reason.UNSUPPORTED, evidence)
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)


@probe("DB-003")
def owner_install_privileges(check: Check, env: ProbeEnv) -> ProbeResult:
    row = _query(
        check,
        env,
        "SELECT has_schema_privilege(current_user, 'public', 'CREATE'),"
        " (SELECT rolcreaterole OR rolsuper FROM pg_roles WHERE rolname = current_user)",
    )
    if row is None:
        return ProbeResult(Outcome.UNKNOWN, Reason.INPUT_MISSING)
    evidence = {"can_create_in_public": bool(row[0]), "can_create_role": bool(row[1])}
    if not all(evidence.values()):
        return ProbeResult(Outcome.FAIL, Reason.MISSING, evidence)
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)


@probe("DB-004")
def required_extensions(check: Check, env: ProbeEnv) -> ProbeResult:
    required = list(check.params["required"])
    if not required:
        return ProbeResult(Outcome.NOT_APPLICABLE, Reason.NONE_REQUIRED)
    row = _query(
        check,
        env,
        "SELECT array_agg(name) FROM pg_available_extensions WHERE name = ANY(%s)",
        (required,),
    )
    if row is None:
        return ProbeResult(Outcome.UNKNOWN, Reason.INPUT_MISSING)
    available = set(row[0] or [])
    missing = [name for name in required if name not in available]
    evidence = {"required": required, "missing": missing}
    if missing:
        return ProbeResult(Outcome.FAIL, Reason.MISSING, evidence)
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)
