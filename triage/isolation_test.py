"""Isolation test for the triage runtime (RC1-643, ADR 0009; extends ADR 0002).

Runs INSIDE the triage container. Exits 0 only if:

  identity  no customer or vendor-infrastructure credential is in the
            environment, and no credential file is on the filesystem;
  network   a direct connection out (bypassing the proxy) fails, and the
            proxy refuses every destination but the allowlisted two,
            including the customer's Fly API, app, database and destination;
  control   the allowlisted path really works (Anthropic answers 401 to an
            unauthenticated request through the proxy), so the refusals
            above are the policy and not a dead network.

ADR 0002's probe proved the identity holds nothing. This one adds that the
network refuses non-allowlisted destinations even if a credential leaked
into a prompt. Standard library only.
"""

import fnmatch
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROXY = ("egress", 8888)
ALLOWED = ("api.anthropic.com", "api.datadoghq.com")
DENIED = [
    ("api.machines.dev", 443),         # customer Fly Machines API
    ("api.fly.io", 443),               # customer Fly GraphQL API
    ("cik-esp-p3.fly.dev", 443),       # the customer's app
    ("console.neon.tech", 443),        # customer database control plane
    ("api.brevo.com", 443),            # customer destination
    ("github.com", 443),               # anything else
    ("example.com", 80),
]
FORBIDDEN_ENV = ["FLY_*", "ESP_*", "PG*", "NEON_*", "*DATABASE_URL*", "AWS_*", "GITHUB_TOKEN",
                 "BREVO*", "GH_TOKEN", "DD_APP_KEY"]
ALLOWED_ENV = {"PROBE_PG_HOST"}
FILE_PATTERNS = [".env*", "*.pem", ".netrc", ".pgpass", "config.yml"]
SKIP_DIRS = {"/proc", "/sys", "/dev", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc",
             "/var/lib", "/app/.venv"}

PASSES: list[str] = []
FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    (PASSES if ok else FAILURES).append(f"{name}: {detail}")


def connect_via_proxy(host: str, port: int) -> str:
    with socket.create_connection(PROXY, timeout=15) as s:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        line = s.recv(256).split(b"\r\n", 1)[0].decode("latin-1")
    return line


def direct(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=5):
            return "CONNECTED"
    except OSError as exc:
        return type(exc).__name__


def main() -> int:
    leaked = sorted(k for k in os.environ if k not in ALLOWED_ENV
                    and any(fnmatch.fnmatch(k, p) for p in FORBIDDEN_ENV))
    check("env census", not leaked, f"forbidden variables: {leaked}" if leaked else "clean")

    found = []
    for root, dirs, files in os.walk("/"):
        if any(root == d or root.startswith(d + "/") for d in SKIP_DIRS):
            dirs[:] = []
            continue
        found += [str(Path(root) / f) for f in files
                  if any(fnmatch.fnmatch(f, p) for p in FILE_PATTERNS)]
        found += [str(Path(root) / d) for d in dirs if d in (".fly", ".aws", ".config")]
    check("filesystem census", not found, f"credential-shaped files: {found}" if found
          else "no .env, key, netrc, pgpass or CLI config files")

    for target in ("1.1.1.1", "api.anthropic.com"):
        got = direct(target, 443)
        check(f"direct {target}:443", got != "CONNECTED", got)

    for host, port in DENIED:
        try:
            line = connect_via_proxy(host, port)
        except OSError as exc:
            line = f"proxy error {type(exc).__name__}"
        check(f"proxy {host}:{port}", " 200 " not in f" {line} ", line)

    pg = os.environ.get("PROBE_PG_HOST")
    if pg:
        for port in (5432, 443):
            line = connect_via_proxy(pg, port)
            check(f"proxy customer-postgres:{port}", " 200 " not in f" {line} ", line)
    else:
        check("proxy customer-postgres", False, "PROBE_PG_HOST not provided; probe did not run")

    for host in ALLOWED:
        line = connect_via_proxy(host, 443)
        check(f"control: proxy {host}:443", " 200 " in f" {line} ", line)
    try:
        urllib.request.urlopen("https://api.anthropic.com/v1/models", timeout=20)
        status = 200
    except urllib.error.HTTPError as exc:
        status = exc.code
    except OSError as exc:
        status = type(exc).__name__
    check("control: Anthropic answers through the proxy", status == 401,
          f"unauthenticated GET /v1/models -> {status}")

    for p in PASSES:
        print(f"ok    {p}")
    for f in FAILURES:
        print(f"FAIL  {f}")
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
