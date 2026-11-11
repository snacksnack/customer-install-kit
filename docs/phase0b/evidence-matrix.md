# Phase 0B evidence matrix (RC1-646)

For each fault family: how it is injected on the supported profile, what evidence the failure produces, what is unavailable, and the go/resize/drop call (final decisions land in the Phase 0B ADR). Held-out candidates (H1–H3) get feasibility proof only, stored evaluator-side — nothing about their evidence appears here or in any rule, prompt, or support document.

## Dev family 1 — valid DB login, insufficient schema permissions

- **Status: GO (proven live, 2026-11-10).**
- **Injection:** as the DB owner, `REVOKE INSERT ON review_audit FROM esp_app`. Applied to the running customer environment; no redeploy needed. Restore is the matching `GRANT`. Verified residue-free (app connection clean after restore).
- **Passes preflight because:** the app role still authenticates, still sees the schema, still SELECTs. Any reasonable preflight connectivity/read check is green.
- **Evidence produced:** `SQLSTATE 42501` (`insufficient_privilege`) at the first audit write — categorically distinct from auth failures (28xxx) and connection failures (08xxx). Postgres's message text names the table, but per RC1-647 the event contract carries **SQLSTATE + operation ID**, never message text; the op ID (e.g., `audit.append`) localizes the failure without leaking content.
- **Unavailable on platform:** nothing material; the driver surfaces full diagnostics.
- **Notes:** `review_audit` is the natural target — it is written on every gate decision, so the fault fires mid-workflow, not at boot. Variants for the matrix: revoke on `review_sso_sessions` (fires at login instead), revoke UPDATE vs INSERT (different op IDs).

## Dev family 2 — API host reachable, upload endpoint denied

- **Status: GO, evidence shape proven (2026-11-10); injection mechanics are dashboard-side.**
- **Destination:** the existing Brevo account serves as the demo customer's ESP (reconciliation lineage from RC1-547). The customer environment gets its own API key (a second key in the account) when Phase 3 wires the conformance migration; not needed for 0B.
- **Injection (matrix-time):** a **post-preflight state change**, explicitly permitted by RC1-646 — rotate/deactivate the API key or enable Brevo's authorized-IP restriction after install checks pass. Preflight was honestly green; the runtime then meets a denied endpoint.
- **Evidence produced (captured live):** baseline `GET /v3/contacts` 200 with the valid key; then `POST /v3/contacts` → **HTTP 401**, body `code: "unauthorized"` — host reachable, TLS fine, route denied. Event contract carries HTTP status + route template (`POST /v3/contacts`) + the provider's error *code* (a closed enum, not message text).
- **Feasibility shortcut, disclosed:** the 0B capture used an invalidated credential to produce the denied state; the matrix injection is the dashboard-side rotation/IP restriction, whose observable is the same status/route/code triple. If Phase 6 wants the IP-restriction variant specifically, prove it then.
- **Distinctness note:** this family is *endpoint denial* (401/403 on the operation). Held-out H2 is *credential valid but under-scoped* — whether Brevo even supports scoped keys is itself an open feasibility question for the evaluator-side H-candidate spike; if Brevo cannot express it, H2 drops from the pool (pool stays ≥2 with H1/H3).

## Dev family 3 — storage writable at install, unavailable/full later

- **Status: GO, fill variant (proven live, 2026-11-10).**
- **Injection:** 1 GB Fly volume `cik_data` mounted at `/data` (now part of the profile; `spike/fly.toml`). Baseline write succeeds at install; `dd` fills to 100% (958 MiB in ~57 s at ~17.6 MB/s). Restore: delete the fill file; verified back to 1% used and writable.
- **Passes preflight because:** the mount exists, is writable at install time, and — measured during the fault — **the app's health check stayed green at 100% full** (healthz 200, stateless app). Storage death is invisible to liveness.
- **Evidence produced:** `errno 28` / `No space left on device` on the failing write, captured as a structured event (`storage_write_failed`, `op: collector.write`).
- **Evidence-contract lesson (feeds RC1-647):** a small buffered write to a 100%-full filesystem *appears to succeed* — ENOSPC surfaces at flush/close, not at `write()`. Instrumentation that does not flush (or check close) will silently swallow exactly this fault. The event emitter must flush and treat close errors as write errors.
- **Sink survival: PROVEN.** With `/data` at 100%, app stdout still reached the Fly platform log stream (healthz access lines logged during the fault). Stdout → platform logs is the independent sink; it shares nothing with the faulted volume.
- **Variants for the matrix:** missing/misconfigured mount (deploy without `[mounts]` — mechanics known, not yet exercised); fill *during* a migration run rather than before it.

## Held-out candidates H1–H3

- **Status: pending.** Feasibility proof only, evaluator-only storage, after the dev families are done.

## Lifecycle cost measurements

- **Status: pending.** One simple case (family 1 is the candidate: no redeploy, seconds to inject/restore) and one difficult case (family 3: volume operations, machine state) measured per stage — elapsed time, cloud usage, operator interventions. Model cost stays provisional until representative bundles exist (RC1-647), then estimated from real inference calls on them.
