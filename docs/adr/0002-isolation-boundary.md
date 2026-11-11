# ADR 0002: Vendor/customer isolation boundary and the triage execution identity

Status: proposed (pending Reid's accept) · 2026-11-10 · RC1-638

## The claim this ADR exists to make honest

Every triage conclusion is reached from the redacted bundle the customer chose to share. That is only a claim if the thing doing triage *provably cannot* reach the customer environment. The constraint is self-imposed (risk R2), so it is enforced by identity and credentials, and the denial is tested, not asserted.

## Identities

| Identity | Where it runs | Holds |
|---|---|---|
| **Customer operator** | Reid acting as the customer: Fly org `cik-customer`, customer Neon project, `spike/customer-ws/` | Fly org admin for `cik-customer`; Neon owner + `esp_app` URLs; `ESP_REVIEW_PASSWORD`; app secrets |
| **Vendor release** | CI in vendor repos (`esp-migration-agent`, `customer-install-kit`) | Source, image build, release signing key (ADR 0003). **No customer credentials, ever.** |
| **Triage** | An isolated container (vendor-side), one per case | The shared bundle (read-only mount) + model access via the restricted path below. **Nothing else: no Fly token, no database URL, no customer hostname credentials, no vendor `.env*` files.** |

## Permissions matrix

Resources: customer Fly API/apps, customer machine shell, customer Postgres, customer app secrets, customer telemetry/logs/caches/CI artifacts, vendor source, bundle.

| | cust. Fly API | cust. shell | cust. Postgres | cust. secrets | cust. telemetry/logs | vendor source | bundle |
|---|---|---|---|---|---|---|---|
| Customer operator | RW | RW | RW | RW | RW | R (public repo) | creates, reviews, shares |
| Vendor release | — | — | — | — | — | RW | — |
| Triage | **denied** | **denied** | **denied** | **denied** | **denied** | R | R (shared copy only) |

## Mechanics

- The boundary is the **Fly org** plus **credential absence**. The triage container is started with no ambient credentials: no mounted home directory, no `~/.fly`, no env beyond the model path and the bundle mount. Docker here is the vendor's triage runtime, not a customer deployment target (the "Docker in CI is a fixture" rule is about customer installs).
- **Model path:** Claude API only, through an outbound allowlist enforced at the network layer (default-deny egress namespace + proxy permitting `api.anthropic.com`), built with the triage engine in Phase 5. Approved bundle evidence is sent to the model provider — documented, disclosed, and that path grants no customer-system access. Operational tracing stays separate and content-free.
- **Follow-up channel:** bundle-only handoff, customer-mediated. Triage output may *request* one specific additional check; the customer runs it and shares the result. No persistent vendor agent in the customer environment, no automatic telemetry upload.

## The denial test (RC1-638 exit)

`spike/denial_test.sh` runs *inside* the triage container and exits 0 only if every probe is **refused**:

1. Customer Fly org via Machines API without credentials → 401, and `FLY_API_TOKEN`/`FLY_ACCESS_TOKEN` absent from the environment.
2. Customer Postgres: TCP/auth attempt as `esp_app` with no password → server refuses (auth required), and no `ESP_DATABASE_URL`/`PG*` credentials in the environment.
3. Neon API without credentials → 401.
4. No vendor or customer env files visible in the container filesystem (`.env*` census of the mounts).

The test proves the *identity* holds nothing; the Phase 5 egress build adds the complementary test that the *network* refuses non-allowlisted destinations even if a credential leaks into a prompt.

## Consequences

- Phase 4's collector runs customer-side under the customer operator identity; triage only ever sees its exported bundle.
- Any convenience that would let triage "just check" the live system (a read-only Fly token, a psql URL in a debug env) is a boundary breach, not a shortcut — R2 says one peek voids the story.
- The denial test joins CI once the triage engine exists, so the boundary is re-proven on every change, not once in a spike.
