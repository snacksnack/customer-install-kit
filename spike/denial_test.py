"""Denial test for the triage execution identity (ADR 0002, RC1-638 exit).

Runs INSIDE the triage container. Exits 0 only if every probe of a customer
surface is REFUSED. Any success is a boundary breach and fails loudly.

The customer Postgres hostname is passed in as PROBE_PG_HOST on purpose: the
claim is "even knowing where the database lives, the triage identity cannot
get in" — hostname knowledge is assumed (it can appear in a bundle), the
credential is what must be absent.
"""

import fnmatch
import os
import sys
import urllib.error
import urllib.request

FAILURES: list[str] = []
PASSES: list[str] = []


def refused(name: str, ok: bool, detail: str) -> None:
    (PASSES if ok else FAILURES).append(f"{name}: {detail}")


def http_status(url: str) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "cik-denial-test"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def main() -> int:
    # 1. No credential material in the environment.
    forbidden = ["FLY_API_TOKEN", "FLY_ACCESS_TOKEN", "ESP_*", "PG*", "NEON_*",
                 "DATABASE_URL", "AWS_*", "GITHUB_TOKEN"]
    leaked = sorted(
        k for k in os.environ
        if any(fnmatch.fnmatch(k, pat) for pat in forbidden) and k != "PROBE_PG_HOST"
    )
    refused("env census", not leaked, f"forbidden vars present: {leaked}" if leaked else "clean")

    # 2. Customer Fly org via Machines API, no token -> must be 401/403.
    try:
        code = http_status("https://api.machines.dev/v1/apps?org_slug=cik-customer")
        refused("fly machines api", code in (401, 403), f"HTTP {code}")
    except Exception as e:  # network refusal is also a denial
        refused("fly machines api", True, f"unreachable: {type(e).__name__}")

    # 3. Neon control plane, no token -> must be 401/403.
    try:
        code = http_status("https://console.neon.tech/api/v2/projects")
        refused("neon api", code in (401, 403), f"HTTP {code}")
    except Exception as e:
        refused("neon api", True, f"unreachable: {type(e).__name__}")

    # 4. Customer Postgres as esp_app with no password -> auth must fail.
    host = os.environ.get("PROBE_PG_HOST")
    if not host:
        refused("postgres", False, "PROBE_PG_HOST not provided; probe did not run")
    else:
        import socket

        import psycopg

        # Pin an IPv4 address (hostaddr) so the refusal is an AUTH refusal,
        # not an incidental network one (Docker here has no IPv6 egress, and
        # "network unreachable" would prove nothing about credentials).
        try:
            ipv4 = socket.getaddrinfo(host, 5432, socket.AF_INET)[0][4][0]
        except socket.gaierror as e:
            ipv4 = None
            refused("postgres", False, f"could not resolve IPv4 for probe: {e}")
        if ipv4:
            try:
                conn = psycopg.connect(
                    f"postgresql://esp_app@{host}/neondb"
                    f"?hostaddr={ipv4}&sslmode=require",
                    connect_timeout=15,
                )
                conn.close()
                refused("postgres", False, "CONNECTED WITHOUT CREDENTIALS")
            except psycopg.OperationalError as e:
                msg = str(e).strip().splitlines()[0]
                auth_refusal = "password" in msg or "authentication" in msg
                refused("postgres", auth_refusal,
                        f"{'auth refused' if auth_refusal else 'refused, but not by auth'}: {msg}")

    # 5. No env files visible anywhere in the filesystem.
    hits = []
    for root, dirs, files in os.walk("/", topdown=True):
        dirs[:] = [d for d in dirs if not d.startswith(("proc", "sys", "dev"))]
        hits.extend(os.path.join(root, f) for f in files if f.startswith(".env"))
        if root.count(os.sep) > 6:
            dirs[:] = []
    refused("filesystem census", not hits, f".env files found: {hits}" if hits else "clean")

    for line in PASSES:
        print(f"DENIED (good)  {line}")
    for line in FAILURES:
        print(f"BREACH (bad)   {line}")
    print(f"\n{len(PASSES)} denied, {len(FAILURES)} breaches")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
