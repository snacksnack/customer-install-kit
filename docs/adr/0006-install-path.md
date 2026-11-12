# ADR 0006: Install path: verified digest, converging steps, three recovery planes

Status: proposed (RC1-640)

## Decision

**Release.** ESP's tag workflow publishes an amd64 image to GHCR by digest, cosign-signed keyless with the SBOM attached, plus `release.json` signed as a Sigstore bundle (esp ADR-0027). The kit verifies the manifest with `sigstore-python` against Sigstore's public trust root, the signer pinned to `release.yml@refs/tags/vX` and GitHub's OIDC issuer, then checks the manifest's version, repository, platform and digest form and the SBOM hash. Then it deploys **by the digest in the verified manifest**. The customer needs no cosign binary. A failure to fetch the trust root is reported as its own reason and still refuses: nothing unverified is installed.

**Install is an ordered list of steps, each observe-then-act.** Verify, report key, operator preflight, app, volume, schema, app role, secrets, deploy, health, runtime preflight. A re-run after any failure converges: an existing app or volume is reused, and the record notes whether this install created or adopted it. A working app-role URL is kept (create-app-role re-passwords, so it runs only when the stored URL fails). Secrets are re-staged only when their hashes change. A machine already on the target digest with nothing staged is not redeployed. The tests assert "no write on the second run", not just "second run passes", and inject a failure after every step.

**The owner credential stays on the workstation.** Migrations run ESP's own `db_setup` inside the verified image under local Docker, with the owner URL passed by variable name (`-e NAME`), never on argv and never to Fly. The schema applied is therefore exactly the release's. The app receives an allowlisted subset of the secrets file.

**Runtime preflight is shipped, not hand-copied.** The runtime-context kit (no `kit.install`, which needs sigstore) is tarred from the operator's checkout and unpacked into the machine over `fly ssh`, then run with the image's Python. Phase 1 did this by hand.

**Recovery is three planes.** Application version: rollback deploys an older verified digest, never migrates. Schema/data: forward-only. ESP's `migrate` records `(version, compatible_with)`, and a rollback is allowed only if `compatible_with <= target.schema_version`. Otherwise it stops with a customer-owned restore path. Destination writes are never reversed by any kit action. Install refuses to apply an older release's schema over a newer database.

**Teardown follows recorded ownership.** It destroys only `created` resources (the app, or a created volume by ID inside an adopted app). The database is always retained. Dropping the app role is opt-in, and deleting data is not offered.

**Install record (`cik.install/1`)** holds release, resource IDs, ownership, schema marker, secret names, the report public key (ADR 0003, generated at install, private half mode 600 on the workstation), steps and history. It is written atomically, and every write is scanned for secret values.

## Evidence

See "Live exercise" below, filled from the run against `cik-customer`.

## Consequences

- Customer prerequisites grow by Docker and outbound access to GitHub, GHCR and Sigstore (docs/install.md).
- Install-kit release files are not yet signed. ADR 0003 mentions them, but the kit runs from the customer's own checkout, and what it ships into the machine is that same code. Signing the kit itself is deferred until the kit is distributed as an artifact rather than a repo.
- The rollback-refusal path cannot be produced by a real release yet: ESP's schema has one version. It is exercised live by setting the marker on a throwaway database branch, and that is disclosed as simulated.
