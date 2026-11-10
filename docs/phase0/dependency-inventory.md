# ESP Migration Agent: actual runtime dependencies (Phase 0A inventory)

Inventoried 2026-11-10 from the esp-migration-agent repo (Dockerfile, pyproject.toml, fly.toml), not from its docs. This is what the install kit's preflight must verify in a customer environment.

## Runtime image

- Single OCI image: Python 3.12-slim, `uv sync --frozen --no-dev --group ui`, SPA built by Node 22 at image build time and baked in. Node is a **build-time** dependency only; a customer runtime needs only the ability to run the image.
- Entrypoint: `uv run --no-sync python -m review_ui --host 0.0.0.0 --port 8080`. Serves FastAPI backend + static SPA same-origin on 8080.
- Health endpoint: `GET /healthz`.
- Current deployment reference: Fly.io app `esp-migration-demo`, shared-cpu-1x / 512 MB, scale-to-zero, region iad.

## Required backing services

- **Postgres** — via `psycopg[binary]` + `psycopg-pool` (dependency group `ui`). Today: Neon. Schema in `review_ui/schema.sql`, setup in `review_ui/db_setup.py`. Extension requirements: **none** — `schema.sql` contains no `CREATE EXTENSION` (checked 2026-11-10). Consequence for RC1-638's held-out candidate list: the "missing extension" fault family is ruled out by the no-artificial-dependencies rule; the TLS trust/proxy family and other real-profile candidates remain.
- **Anthropic API** — `anthropic>=0.69`; both of the repo's LLM calls use claude-opus-5-5. Outbound HTTPS to api.anthropic.com. In the kit's v1 profile this is the **only** approved model path, through an enforced outbound allowlist (RC1-638 acceptance).
- **Destination ESP API** (Brevo in the demo arc) — outbound HTTPS via httpx.
- **Identity** — OIDC (Okta today: `ESP_OIDC_ISSUER`, `ESP_OIDC_CLIENT_ID`, `ESP_OIDC_CLIENT_SECRET` via authlib). Whether the supported customer profile requires OIDC or permits the password mode is an ADR 0001 decision.
- **Secrets** — `ESP_REVIEW_PASSWORD`, `ESP_REVIEW_SESSION_SECRET`, OIDC credentials, database URL, Anthropic key, destination API key. Platform secret store; never in the image.

## Explicitly optional (must be OFF or content-free in the customer profile)

- **Datadog / LLM Obs** (`ddtrace`, group `obs`) — deliberately not a hard dependency; the suite passes without it and without `DD_API_KEY`. RC1-638: no automatic telemetry upload from the customer environment; operational tracing stays separate and content-free. RC1-647 adds structured error events (metadata only, never message text) for the diagnostic bundle.
- **Eval harness** (`agent-evals`, group `evals`) — vendor-side only.

## Not required

- Live Mailchimp access — export ingestion works from a synthetic export fixture (RC1-638 scope).
- A volume — the demo runs stateless by design (ADR-0011 in the ESP repo). Whether the customer profile needs persistent storage is part of the storage fault family design (Phase 0B) and ADR 0001.
