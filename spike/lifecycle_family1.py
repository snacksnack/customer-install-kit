"""Timed lifecycle run for dev family 1 (RC1-646 cost measurement).

Runs the full per-case lifecycle for the simple case — valid DB login,
insufficient schema permission on review_audit — and prints per-stage
elapsed times. The probe INSERT runs inside a transaction that is rolled
back, so the audit chain is never actually extended; the permission check
(and the 42501 when revoked) fires regardless of the rollback.

Reads connection URLs from spike/customer-ws/.env.neon.owner (owner) and
spike/customer-ws/.env.neon (app role). Never prints either URL.

Usage: uv run python spike/lifecycle_family1.py
"""

import sys
import time
from pathlib import Path

import psycopg

WS = Path(__file__).parent / "customer-ws"

PROBE_INSERT = """
INSERT INTO review_audit (seq, at, event, actor, detail, prev_sha256, sha256)
SELECT coalesce(max(seq), 0) + 1, 'lifecycle-probe', 'lifecycle.probe',
       '{}'::jsonb, '{}'::jsonb, repeat('0', 64),
       md5(random()::text) || md5(random()::text)
FROM review_audit
"""

STAGES: list[tuple[str, float]] = []


def read_env(name: str, key: str) -> str:
    for line in (WS / name).read_text().splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    sys.exit(f"{key} not found in {name}")


def stage(label: str, fn):
    t0 = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - t0
    STAGES.append((label, elapsed))
    print(f"  {label:<28} {elapsed:7.2f}s  {result}")
    return result


def probe_write(url: str) -> str:
    """Attempt the audit INSERT and roll back. Returns outcome + SQLSTATE."""
    with psycopg.connect(url) as conn:
        try:
            with conn.cursor() as cur:
                cur.execute(PROBE_INSERT)
            outcome = "INSERT accepted (rolled back)"
        except psycopg.errors.InsufficientPrivilege as e:
            outcome = f"DENIED sqlstate={e.sqlstate}"
        conn.rollback()
    return outcome


def owner_exec(url: str, sql: str) -> str:
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(sql)
    return "ok"


def main() -> None:
    owner_url = read_env(".env.neon.owner", "ESP_DATABASE_OWNER_URL")
    app_url = read_env(".env.neon", "ESP_DATABASE_URL")

    print("family 1 lifecycle (timed stages):")
    baseline = stage("baseline (writable check)", lambda: probe_write(app_url))
    if "accepted" not in baseline:
        sys.exit("baseline not writable; environment dirty, aborting")

    stage("inject (REVOKE)", lambda: owner_exec(
        owner_url, "REVOKE INSERT ON review_audit FROM esp_app"))
    fault = stage("trigger + collect evidence", lambda: probe_write(app_url))
    stage("remedy (GRANT)", lambda: owner_exec(
        owner_url, "GRANT INSERT ON review_audit TO esp_app"))
    verify = stage("verify recovery", lambda: probe_write(app_url))
    residue = stage("cleanup check (residue)", lambda: probe_write(app_url))

    total = sum(t for _, t in STAGES)
    print(f"  {'TOTAL':<28} {total:7.2f}s")

    ok = "42501" in fault and "accepted" in verify and "accepted" in residue
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
