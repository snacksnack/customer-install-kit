# Installing the ESP Migration Agent (profile v1)

For the customer operator. Everything below runs on your workstation, under your own Fly and database credentials. The vendor never receives a credential, a log stream, or access to your environment; what you share with the vendor is `install-record.json` and preflight reports, which hold no secret values.

## What you need

**Workstation:** `flyctl` (logged in to your org, or `FLY_API_TOKEN` set), Docker (amd64 images run under emulation on Apple Silicon), Python 3.12+ with `uv`, and outbound HTTPS to `github.com`, `ghcr.io` and Sigstore (`tuf-repo-cdn.sigstore.dev`, `rekor.sigstore.dev`, `fulcio.sigstore.dev`).

**Minimum permissions**

| Where | Permission | Needed for |
|---|---|---|
| Fly | Org-scoped token or org member (`fly tokens create org`) | **First install** (creates the app) and **teardown** (destroys it) |
| Fly | App deploy token (`fly tokens create deploy -a <app>`) | Re-install, upgrade, rollback of an existing app: volumes, secrets, deploys, runtime preflight over `fly ssh`. Verified live (RC1-640): a full converge run under only this token. Such a token cannot see other apps in your org, so it cannot be used to create one by mistake. |
| Postgres | A database owner role with `CREATE` on the database and `CREATEROLE` | Schema migration and creating the least-privilege `esp_app` role. Checked by preflight DB-001..DB-004. Used only from your workstation, never given to the app. |
| Postgres | `esp_app` (created by the install) | What the app connects as: `SELECT, INSERT` on the audit log, read/write on sessions and SCIM users, nothing else |
| GHCR | none (public image) | Pulling the signed image |

## Trusted publisher

A release is trusted only if its manifest's Sigstore signature was made by:

- identity `https://github.com/snacksnack/esp-migration-agent/.github/workflows/release.yml@refs/tags/v<VERSION>`
- issuer `https://token.actions.githubusercontent.com`

and the manifest names image repository `ghcr.io/snacksnack/esp-migration-agent`, platform `linux/amd64`, and an SBOM whose sha256 matches. The kit deploys by the digest in that manifest, never by tag. Check a release yourself at any time:

```sh
uv run python -m kit.install verify-release 0.1.2
# or, with cosign, the image directly:
cosign verify ghcr.io/snacksnack/esp-migration-agent@sha256:<digest> \
  --certificate-identity https://github.com/snacksnack/esp-migration-agent/.github/workflows/release.yml@refs/tags/v0.1.2 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A tampered, unsigned, or differently-signed release is refused before anything in your environment changes (exit 4).

## Install

Get the kit (`git clone https://github.com/snacksnack/customer-install-kit`, then `uv sync`) and run its commands from that checkout. Keep your install's files in a separate private directory and point `--config` at it; everything the install writes lands next to `install.toml`.

Make that private directory (`chmod 700`) with two files:

`install.toml` (no secrets):

```toml
[install]
profile = "v1"
release = "0.1.2"
fly_org = "acme-esp"
app = "acme-esp"
region = "iad"
volume = "esp_data"
volume_size_gb = 1
secrets_file = ".env.cik"
```

`.env.cik`, mode 600, holding at least your database owner URL (direct, not pooled):

```
ESP_DATABASE_OWNER_URL=postgresql://owner:...@host/db?sslmode=require
```

Optional: `ESP_REVIEW_PASSWORD` (generated if absent), `ESP_BREVO_API_KEY` (required for migrations, so runtime preflight fails without it), `ESP_ANTHROPIC_API_KEY`.

```sh
uv run python -m kit.install install --config ~/acme-install/install.toml
```

The steps are: verify release, generate the report keypair, operator preflight, Fly app, volume, schema, app role, secrets, deploy, health, runtime preflight. Each step looks first and acts only if needed, so **running install again is always safe**. After any failure, fix the cause and re-run; finished steps are recognized, not repeated. The kit never creates a second app or volume, never re-passwords a working app role, and never resets data.

Exit codes: 0 installed, 1 installed but a required runtime check is not passing (see `preflight-runtime.json`), 4 refused, 5 a step failed (re-run to resume), 3 kit error.

**What stays on your workstation:** `.env.cik` (all secrets; the owner URL is never pushed to Fly), `report-key.pem` (the private half of the per-install report key), `.cik-pushed.sha256` (hashes used to skip unchanged secrets). **What you can share:** `install-record.json`, `preflight-*.json`.

## Recovery

Three separate things can change, and each recovers differently.

1. **Application version.** `uv run python -m kit.install rollback --to 0.1.2` deploys an older verified release by digest. It never runs a migration and never touches data.
2. **Database schema and data.** Migrations only go forward. Each release declares its schema version and the oldest schema its code can run on; the database records the same in `review_schema_version`. A rollback is refused (exit 4) when the database's schema is too new for the target. Refusal changes nothing, and the message gives the recovery path: either roll forward to a fixed release, or restore the database to a point before the migration (Neon: point-in-time branch restore) and then roll back. Install also refuses to apply an older release's schema over a newer one.
3. **Destination side effects.** Contacts written to Brevo by a migration run are **not** reversed by a rollback, a restore, or a teardown. Reversing them is a destination-side operation (the execution journal lists every write).

## Teardown

```sh
uv run python -m kit.install teardown --config ~/acme-install/install.toml --confirm acme-esp [--drop-app-role]
```

Destroys only what `install-record.json` says this install **created**: the Fly app (with its machines and volumes) if the install created it, or only the volume, by ID, if the install created the volume inside an existing app. Resources that existed before the install are marked `adopted` and are kept. **Your database and its data are always kept.** `--drop-app-role` also removes the `esp_app` role (its grants, not your data). Deleting data is left to you on purpose.
