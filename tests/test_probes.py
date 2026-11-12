"""Each probe family against healthy, failing and unavailable conditions.

Network tests use real localhost sockets where a real failure is cheap to
produce (refused TCP, a non-TLS server); fakes stand in only where the real
thing needs the internet or a database.
"""

import os
import socket
import threading
from contextlib import contextmanager

import psycopg
import pytest

from kit import registry
from kit.model import ALLOWED_REASONS, Outcome, Reason
from kit.probes import PROBES, ProbeEnv

REG = registry.load(probe_ids=frozenset(PROBES))


def run(check_id: str, env: ProbeEnv, **params):
    check = REG.get(check_id)
    if params:
        check = type(check)(**{**check.__dict__, "params": {**check.params, **params}})
    result = PROBES[check_id](check, env)
    assert result.reason in ALLOWED_REASONS[result.outcome]
    assert registry.validate_evidence(check, result.evidence) == []
    return result


# --- environment -----------------------------------------------------------

SECRETS = {
    "ESP_REVIEW_PASSWORD": "hunter2-hunter2",
    "ESP_REVIEW_SESSION_SECRET": "a-real-random-secret-value",
    "ESP_BREVO_API_KEY": "xkeysib-planted-value-123",
}


def test_env_required_present():
    result = run("ENV-001", ProbeEnv(environ=SECRETS))
    assert result.outcome is Outcome.PASS
    assert result.evidence["missing"] == []


def test_env_required_missing_reports_names_never_values():
    environ = {**SECRETS, "ESP_BREVO_API_KEY": "  "}
    result = run("ENV-001", ProbeEnv(environ=environ))
    assert (result.outcome, result.reason) == (Outcome.FAIL, Reason.MISSING)
    assert result.evidence["missing"] == ["ESP_BREVO_API_KEY"]
    assert not any(v in repr(result.evidence) for v in SECRETS.values())


def test_session_secret_default_fails_and_unset_is_unknown():
    default = {"ESP_REVIEW_SESSION_SECRET": "dev-secret-not-for-prod"}
    assert run("ENV-002", ProbeEnv(environ=default)).reason is Reason.INSECURE
    assert run("ENV-002", ProbeEnv(environ=SECRETS)).outcome is Outcome.PASS
    unset = run("ENV-002", ProbeEnv(environ={}))
    assert (unset.outcome, unset.reason) == (Outcome.UNKNOWN, Reason.INPUT_MISSING)


# --- database --------------------------------------------------------------

OWNER = {"ESP_DATABASE_OWNER_URL": "postgresql://owner:s3cret-pw@db.example/neondb"}


class FakeConn:
    def __init__(self, row=None, tls=True):
        self.row, self.pgconn = row, type("PG", (), {"ssl_in_use": tls})()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, *args):
        return self

    def fetchone(self):
        return self.row


def connecting(conn=None, error=None):
    def connect(url, **kwargs):
        if error:
            raise error
        return conn

    return connect


def test_db_connect_healthy():
    result = run("DB-001", ProbeEnv(environ=OWNER, connect_db=connecting(FakeConn())))
    assert result.outcome is Outcome.PASS and result.evidence["tls"] is True


def test_db_connect_without_tls_fails_insecure():
    env = ProbeEnv(environ=OWNER, connect_db=connecting(FakeConn(tls=False)))
    assert run("DB-001", env).reason is Reason.INSECURE


@pytest.mark.parametrize(
    "message,error_class",
    [
        ('connection failed: FATAL: password authentication failed for user "owner"', "auth"),
        ('FATAL: database "nosuchdb" does not exist', "database"),
        ('failed to resolve host "x": nodename nor servname provided', "dns"),
        ("SSL error: certificate verify failed", "tls"),
        ("connection failed: timeout expired", "timeout"),
        ("connection failed: Connection refused", "network"),
    ],
)
def test_db_connect_failures_are_classified_without_the_message(message, error_class):
    env = ProbeEnv(environ=OWNER, connect_db=connecting(error=psycopg.OperationalError(message)))
    result = run("DB-001", env)
    assert (result.outcome, result.reason) == (Outcome.FAIL, Reason.REFUSED)
    assert result.evidence["error_class"] == error_class
    assert "owner" not in repr(result.evidence) and "nosuchdb" not in repr(result.evidence)


def test_db_input_missing_is_unknown():
    for check_id in ("DB-001", "DB-002", "DB-003"):
        result = run(check_id, ProbeEnv(environ={}))
        assert (result.outcome, result.reason) == (Outcome.UNKNOWN, Reason.INPUT_MISSING)


def test_db_version():
    ok = run("DB-002", ProbeEnv(environ=OWNER, connect_db=connecting(FakeConn((170005,)))))
    old = run("DB-002", ProbeEnv(environ=OWNER, connect_db=connecting(FakeConn((100023,)))))
    assert ok.outcome is Outcome.PASS
    assert (old.outcome, old.reason) == (Outcome.FAIL, Reason.UNSUPPORTED)


def test_db_install_privileges():
    ok = run("DB-003", ProbeEnv(environ=OWNER, connect_db=connecting(FakeConn((True, True)))))
    no_role = run("DB-003", ProbeEnv(environ=OWNER, connect_db=connecting(FakeConn((True, False)))))
    assert ok.outcome is Outcome.PASS
    assert no_role.reason is Reason.MISSING and no_role.evidence["can_create_role"] is False


def test_db_extensions_not_applicable_when_none_required():
    result = run("DB-004", ProbeEnv(environ={}))
    assert (result.outcome, result.reason) == (Outcome.NOT_APPLICABLE, Reason.NONE_REQUIRED)


def test_db_extensions_missing_when_required():
    env = ProbeEnv(environ=OWNER, connect_db=connecting(FakeConn((None,))))
    result = run("DB-004", env, required=["pgcrypto"])
    assert result.reason is Reason.MISSING and result.evidence["missing"] == ["pgcrypto"]


# --- network ---------------------------------------------------------------


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def plain_tcp_server():
    """Accepts and immediately closes: a TLS client sees the handshake fail."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()

    def serve():
        try:
            conn, _ = server.accept()
            conn.sendall(b"HTTP/1.0 400 not tls\r\n\r\n")
            conn.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


def test_net_dns_failure():
    def no_dns(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "not known")

    result = run("NET-001", ProbeEnv(getaddrinfo=no_dns))
    assert result.evidence["failed_stage"] == "dns" and result.evidence["reached"] == "none"


def test_net_tcp_refused_real_socket():
    result = run("NET-001", ProbeEnv(), host="127.0.0.1", port=closed_port())
    assert result.outcome is Outcome.FAIL
    assert result.evidence["failed_stage"] == "tcp"
    assert result.evidence["error"] == "ECONNREFUSED"


def test_net_tls_failure_real_socket():
    with plain_tcp_server() as port:
        result = run("NET-001", ProbeEnv(), host="127.0.0.1", port=port)
    assert result.evidence["reached"] == "tcp"
    assert result.evidence["failed_stage"] == "tls"


def test_net_healthy_records_tls_version():
    class FakeTls:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def version(self):
            return "TLSv1.3"

    class FakeContext:
        def wrap_socket(self, sock, server_hostname):
            assert server_hostname == "api.brevo.com"
            return FakeTls()

    env = ProbeEnv(
        getaddrinfo=lambda *a, **k: [("addr",)],
        create_connection=lambda *a, **k: socket.socket(),
        tls_context=FakeContext,
    )
    result = run("NET-001", env)
    assert result.outcome is Outcome.PASS
    assert result.evidence["reached"] == "tls" and result.evidence["tls_version"] == "TLSv1.3"


# --- runtime ---------------------------------------------------------------


def test_architecture():
    assert run("RT-001", ProbeEnv(machine=lambda: "x86_64")).outcome is Outcome.PASS
    arm = run("RT-001", ProbeEnv(machine=lambda: "aarch64"))
    assert (arm.outcome, arm.reason) == (Outcome.FAIL, Reason.UNSUPPORTED)


def files(mapping):
    return lambda path: mapping.get(path)


def test_memory_cgroup_v2_limit():
    env = ProbeEnv(read_text=files({"/sys/fs/cgroup/memory.max": "1073741824\n"}))
    result = run("RT-002", env)
    assert result.outcome is Outcome.PASS and result.evidence["source"] == "cgroup_v2"


def test_memory_unlimited_cgroup_falls_back_to_meminfo_fly_512mb():
    # The real readings from a 512 MB Fly machine (cik-esp, 2026-11-11).
    env = ProbeEnv(
        read_text=files(
            {
                "/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712\n",
                "/proc/meminfo": "MemTotal:         472532 kB\nMemFree: 200096 kB\n",
            }
        )
    )
    result = run("RT-002", env)
    assert result.outcome is Outcome.PASS
    assert result.evidence["source"] == "proc_meminfo"


def test_memory_256mb_machine_fails():
    env = ProbeEnv(read_text=files({"/proc/meminfo": "MemTotal:         226000 kB\n"}))
    assert run("RT-002", env).reason is Reason.BELOW_MINIMUM


def test_memory_unavailable_is_unknown():
    result = run("RT-002", ProbeEnv(read_text=files({})))
    assert (result.outcome, result.reason) == (Outcome.UNKNOWN, Reason.PROBE_UNAVAILABLE)


def test_volume_writable(tmp_path):
    result = run("RT-003", ProbeEnv(), path=str(tmp_path), minimum_free_bytes=1)
    assert result.outcome is Outcome.PASS and result.evidence["writable"] is True
    assert list(tmp_path.iterdir()) == []  # probe file cleaned up


def test_volume_missing(tmp_path):
    result = run("RT-003", ProbeEnv(), path=str(tmp_path / "nope"))
    assert (result.outcome, result.reason) == (Outcome.FAIL, Reason.MISSING)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_volume_read_only(tmp_path):
    tmp_path.chmod(0o500)
    try:
        result = run("RT-003", ProbeEnv(), path=str(tmp_path), minimum_free_bytes=1)
    finally:
        tmp_path.chmod(0o700)
    assert result.reason is Reason.REFUSED and result.evidence["errno"] == 13


def test_volume_full_at_fsync_is_caught(tmp_path, monkeypatch):
    """Phase 0B: a full disk can accept write() and fail only at flush."""

    def enospc(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", enospc)
    result = run("RT-003", ProbeEnv(), path=str(tmp_path), minimum_free_bytes=1)
    assert result.reason is Reason.REFUSED and result.evidence["errno"] == 28
    assert list(tmp_path.iterdir()) == []


def test_volume_low_free_space(tmp_path):
    result = run("RT-003", ProbeEnv(), path=str(tmp_path), minimum_free_bytes=1 << 62)
    assert result.reason is Reason.BELOW_MINIMUM


def test_error_sink_not_applicable_when_unset_and_checked_when_set(tmp_path):
    unset = run("RT-004", ProbeEnv(environ={}))
    assert (unset.outcome, unset.reason) == (Outcome.NOT_APPLICABLE, Reason.NOT_CONFIGURED)
    env = ProbeEnv(environ={"ESP_ERROR_EVENTS_PATH": str(tmp_path / "events.jsonl")})
    assert run("RT-004", env).outcome is Outcome.PASS
