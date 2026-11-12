"""Destination reachability: DNS, then TCP, then a verified TLS handshake.

No HTTP request and no credential is sent. The probe records how far it got
and a short error code for the stage that failed, never exception text.
"""

import errno
import socket
import ssl

from kit.model import Check, Outcome, ProbeResult, Reason
from kit.probes.base import ProbeEnv, probe


def _os_code(exc: OSError) -> str:
    if isinstance(exc, TimeoutError | socket.timeout):
        return "timeout"
    if exc.errno is not None and exc.errno in errno.errorcode:
        return errno.errorcode[exc.errno]
    return type(exc).__name__


def _tls_code(exc: Exception) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate_verify_failed"
    if isinstance(exc, ssl.SSLError):
        return (exc.reason or type(exc).__name__).lower()
    if isinstance(exc, OSError):
        return _os_code(exc)
    return type(exc).__name__


def reach(check: Check, env: ProbeEnv) -> ProbeResult:
    host, port = check.params["host"], check.params["port"]
    # Leave headroom under the runner's hard timeout for the TLS stage.
    step_timeout = max(1.0, check.timeout_s / 3)
    evidence = {
        "host": host,
        "port": port,
        "reached": "none",
        "failed_stage": None,
        "error": None,
        "tls_version": None,
    }

    def failed(stage: str, code: str) -> ProbeResult:
        return ProbeResult(
            Outcome.FAIL, Reason.REFUSED, {**evidence, "failed_stage": stage, "error": code}
        )

    try:
        addresses = env.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return failed("dns", f"gai_{exc.errno}")
    if not addresses:
        return failed("dns", "no_addresses")
    evidence["reached"] = "dns"

    try:
        sock = env.create_connection((host, port), timeout=step_timeout)
    except OSError as exc:
        return failed("tcp", _os_code(exc))
    evidence["reached"] = "tcp"

    try:
        with env.tls_context().wrap_socket(sock, server_hostname=host) as tls:
            evidence["tls_version"] = tls.version()
    except (ssl.SSLError, OSError) as exc:
        sock.close()
        return failed("tls", _tls_code(exc))
    evidence["reached"] = "tls"
    return ProbeResult(Outcome.PASS, Reason.OK, evidence)


@probe("NET-001")
def destination_api(check: Check, env: ProbeEnv) -> ProbeResult:
    return reach(check, env)


@probe("NET-002")
def model_api(check: Check, env: ProbeEnv) -> ProbeResult:
    return reach(check, env)
