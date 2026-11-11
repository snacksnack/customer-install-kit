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

**Still pending:** customer Neon project (`cik-customer`, free org, us-east-1 — MCP tool classifier-blocked both attempts, no Neon CLI installed; Reid creates it in the console or adds a permission rule), then `db_setup migrate` / `create-app-role` / `verify` run from a customer workspace dir and the DB secrets set on `cik-esp`.

## Found so far, for ADR 0001

- Fly org boundary is real and cheap: distinct org, distinct billing, apps and secrets invisible across orgs for scoped identities. The remaining question for the isolation test (RC1-638 exit) is whether a *deploy token scoped to the vendor org* is provably denied against `cik-esp` — to be tested once the machine runs.
- amd64 is the architecture: remote builder builds amd64; local Apple Silicon builds are out of the supported profile.
- Render was not exercised: no account exists, and creating one is Reid's call. If it stays unexercised, ADR 0001 records a one-platform spike and a paper comparison, explicitly.
