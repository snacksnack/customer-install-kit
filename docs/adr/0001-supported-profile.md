# ADR 0001: Supported deployment profile for v1

Status: proposed (pending Reid's accept) · 2026-11-10 · RC1-638

## Decision

The kit supports exactly one deployment profile in v1:

- **Platform:** Fly.io. One Fly **organization per customer**; the org is the vendor/customer account boundary.
- **Architecture:** amd64. Images are built in CI on amd64; local Apple Silicon builds are out of profile. Docker in CI remains a test fixture, not a supported target.
- **Runtime:** the ESP Migration Agent single OCI image (Python 3.12-slim, SPA baked in), shared-cpu-1x / 512 MB, scale-to-zero, `GET /healthz` as the health contract, port 8080.
- **Database:** **Postgres, any provider reachable over TLS** — the kit checks Postgres capabilities (version range, role permissions, connectivity), never a vendor. The demo customer brings Neon (free plan, us-east-1). Setup is ESP's `db_setup` flow: owner role for `migrate`, least-privilege `esp_app` role for the app, `verify` proving the audit chain is append-only. Required extensions: none (ESP's schema uses none; checked 2026-11-10).
- **Identity:** password mode (`ESP_REVIEW_PASSWORD`) in the v1 profile. OIDC/SSO stays a documented option ESP supports, not a kit requirement — requiring an IdP would add an install dependency the conformance suite would then have to provision per customer. Revisit if the engagement story needs verified approvals.
- **Model access:** Anthropic API only, and only from the paths ESP already calls. The triage-side outbound allowlist is ADR 0002's subject.
- **Telemetry:** off/content-free in the customer environment. No automatic upload; RC1-647's structured error events feed the bundle instead.
- **Storage:** a Fly volume is introduced in the fault-injection phases (the storage fault family needs attachable/detachable, fillable storage); the base profile is stateless like the vendor demo.

## Evidence (what was actually run)

Spike, 2026-11-10 (`spike/log.md`): fresh org `cik-customer` created; app `cik-esp` deployed from documented steps; billing-info wall at first machine launch (recorded as R6); healthz 200 on `https://cik-esp.fly.dev`; customer Neon project set up via `db_setup` with all three steps green; DB secrets delivered and verified present on the machine.

**Render was not exercised.** No account existed and creating one is a cost/ownership call. This ADR therefore records a one-platform spike plus a paper comparison, not a two-platform bake-off. Paper points for Fly that the spike then confirmed in part: org-level isolation under one login, working Dockerfile/fly.toml lineage from the vendor demo, volumes for the storage fault family. If Render (or any second platform) enters scope later, that is a new ADR and new spike, not an edit to this one.

## Consequences

- Phase 1's preflight checks derive from this profile and the dependency inventory (`docs/phase0/dependency-inventory.md`), nothing else.
- Install docs must call out Fly's defaults that surprised the spike: two-machine HA on first deploy even with `min_machines_running = 0`; config-relative `dockerfile` paths.
- Kubernetes, additional platforms/architectures, OIDC-required installs, and production migrations are all deferred (RC1-638).
