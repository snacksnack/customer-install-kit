# Spike log — customer-environment deploy (RC1-638)

Every step actually executed, in order, with outcomes. This is the raw material for the "record setup steps and projected costs" acceptance item and for ADR 0001.

## 2026-11-10

1. `flyctl orgs create cik-customer` — created, Pay As You Go plan, no prompts. The customer environment is a separate Fly organization under the same login; vendor org is `snacksnack` (personal).
2. `flyctl apps create cik-esp --org cik-customer` — created.
3. Generated `ESP_REVIEW_PASSWORD` (16-byte hex) and `ESP_REVIEW_SESSION_SECRET` (32-byte hex) via openssl; `flyctl secrets set -a cik-esp --stage ...` — staged. Password kept in `spike/.env.cik` (gitignored, mode 600); never printed.
4. `flyctl deploy -c spike/fly.toml --dockerfile Dockerfile ...` from the esp-migration-agent checkout:
   - First attempt failed: a `dockerfile` path inside `[build]` in the config resolves relative to the **config file**, not the working directory. Fix: no `[build]` section, pass `--dockerfile` on the CLI. (Install-doc lesson for Phase 2.)
   - Second attempt: image built and pushed (98 MB, remote builder; build itself ran without billing set up). Machine launch **refused**: `We require your billing information` → https://fly.io/dashboard/cik-customer/billing.
   - Noted for later: Fly warns the 264 MB build context (`.venv/`, `review_ui/node_modules` presumably under review_ui's 106 MB) uploads on every deploy — the ESP repo has no `.dockerignore`. A customer install from source would pay that too; the Phase 2 signed-release flow (deploy a prebuilt image, not a source build) avoids it entirely.

5. Reid added billing to the `cik-customer` org; redeploy succeeded. Fly created **two** machines by default (HA) despite `min_machines_running = 0` — an install-doc lesson for Phase 2: a customer following defaults gets double the expected machine count. Scaled to 1 (`fly scale count 1`).
6. `GET https://cik-esp.fly.dev/healthz` → 200; 1 machine, 1/1 checks passing, owner `cik-customer`. The app runs in no-database fallback mode (file audit log) with password auth; durable state waits on the customer Neon project.

Machine cost at the demo's shape (shared-cpu-1x, 512 MB, scale-to-zero) is the same as the vendor demo: cents/month at idle.

7. Customer Neon project created (by Reid, in the console — the MCP `create_project` call was classifier-blocked twice and no Neon CLI is installed): project `cik-customer` (`late-king-38036710`), free org, us-east-1, Postgres only; Neon's "set up with your coding agent" scaffold prompt deliberately skipped (ESP has its own `db_setup` flow, which is what the kit documents).
8. From `spike/customer-ws/` (so `db_setup`'s CWD-relative env files cannot clobber the vendor demo's `.env.neon` in the ESP checkout): wrote `.env.neon.owner` with the **direct** (non-pooler) owner URL, then `PYTHONPATH=<esp checkout> uv run --project <esp checkout> --group ui python -m review_ui.db_setup migrate` → `schema applied`; `create-app-role` → `esp_app ready`, wrote `.env.neon`; `verify` → chain intact, UPDATE/DELETE/TRUNCATE all refused for the app role.
9. `flyctl secrets import -a cik-esp < .env.neon` — rolling update succeeded, healthz 200, clean boot logs. Secret presence confirmed on the machine via `fly ssh console` (`durable-store-secrets-present`; values never printed).

**Honest limit:** the app boots healthy with the DB secrets present, but no write has yet gone through the app to Postgres — the review UI only writes on gate decisions/sessions. End-to-end proof of the durable path is Phase 3's (conformance) job, not claimed here.

10. GitHub repo created and branch pushed (by Reid; the classifier had blocked `gh repo create` for the agent): https://github.com/snacksnack/customer-install-kit
11. **Denial test green (RC1-638 exit criterion).** Built `cik-triage-probe` (python:3.12-slim + psycopg, no mounts, no credentials) and ran `denial_test.py` inside it: env census clean; Fly Machines API 401; Neon API 401; customer Postgres **auth-refused** (`fe_sendauth: no password supplied`); filesystem `.env` census clean. 5 denied, 0 breaches. First run exposed a weak probe: Docker had no IPv6 egress, so the Postgres refusal was "network unreachable" — a denial that proves nothing about credentials. Fixed by pinning an IPv4 `hostaddr` so the refusal is authentication, with the reasoning kept in the script.

## Found so far, for ADR 0001

- Fly org boundary is real and cheap: distinct org, distinct billing, apps and secrets invisible across orgs for scoped identities. The remaining question for the isolation test (RC1-638 exit) is whether a *deploy token scoped to the vendor org* is provably denied against `cik-esp` — to be tested once the machine runs.
- amd64 is the architecture: remote builder builds amd64; local Apple Silicon builds are out of the supported profile.
- Render was not exercised: no account exists, and creating one is Reid's call. If it stays unexercised, ADR 0001 records a one-platform spike and a paper comparison, explicitly.
