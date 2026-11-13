# ADR 0006: Install path: verified digest, converging steps, three recovery planes

Status: proposed (RC1-640)

## Decision

**Release.** ESP's tag workflow publishes an amd64 image to GHCR by digest, cosign-signed keyless with the SBOM attached, plus `release.json` signed as a Sigstore bundle (esp ADR-0027). The kit verifies the manifest with `sigstore-python` against Sigstore's public trust root, the signer pinned to `release.yml@refs/tags/vX` and GitHub's OIDC issuer, then checks the manifest's version, repository, platform and digest form and the SBOM hash. Then it deploys **by the digest in the verified manifest**. The customer needs no cosign binary. A failure to fetch the trust root is reported as its own reason and still refuses: nothing unverified is installed.

**Install is an ordered list of steps, each observe-then-act.** Verify, report key, operator preflight, app, volume, schema, app role, secrets, deploy, health, runtime preflight. A re-run after any failure converges: an existing app or volume is reused, and the record notes whether this install created or adopted it. A working app-role URL is kept (create-app-role re-passwords, so it runs only when the stored URL fails). Secrets are re-staged only when their hashes change, or when Fly's digest for one differs from the last completed install's (a value set outside the kit; RC1-644 found that install called such a secret "unchanged" and left the wrong value in place). A machine already on the target digest with nothing staged is not redeployed. The tests assert "no write on the second run", not just "second run passes", and inject a failure after every step.

**The owner credential stays on the workstation.** Migrations run ESP's own `db_setup` inside the verified image under local Docker, with the owner URL passed by variable name (`-e NAME`), never on argv and never to Fly. The schema applied is therefore exactly the release's. The app receives an allowlisted subset of the secrets file.

**Runtime preflight is shipped, not hand-copied.** The runtime-context kit (no `kit.install`, which needs sigstore) is tarred from the operator's checkout and unpacked into the machine over `fly ssh`, then run with the image's Python. Phase 1 did this by hand.

**Recovery is three planes.** Application version: rollback deploys an older verified digest, never migrates. Schema/data: forward-only. ESP's `migrate` records `(version, compatible_with)`, and a rollback is allowed only if `compatible_with <= target.schema_version`. Otherwise it stops with a customer-owned restore path. Destination writes are never reversed by any kit action. Install refuses to apply an older release's schema over a newer database.

**Teardown follows recorded ownership.** It destroys only `created` resources (the app, or a created volume by ID inside an adopted app). The database is always retained. Dropping the app role is opt-in, and deleting data is not offered.

**Install record (`cik.install/1`)** holds release, resource IDs, ownership, schema marker, secret names, the report public key (ADR 0003, generated at install, private half mode 600 on the workstation), steps and history. It is written atomically, and every write is scanned for secret values.

## Evidence (live, 2026-11-12)

**Releases.** ESP v0.1.2 and v0.1.3 published by the tag workflow: GHCR digests `sha256:638215c5…` and `sha256:92e7356c…`, each cosign-signed with an SBOM attestation, and `release.json` signed and self-verified in CI. The GHCR package pulls anonymously. `kit.install verify-release 0.1.2` passes against Sigstore's production trust root. The real v0.1.2 files are committed as fixtures (`tests/test_release_live.py`). Four outcomes: the genuine release verifies; a manifest edited to point at another digest is refused (`signature`); the same valid signature requested as v0.1.3 is refused (identity pinned to the tag); a foreign bundle is refused. (v0.1.1 was tagged but never published: the release gate's bare `uv sync` failed collection, fixed in esp #40.)

**Install, into the customer org.** Kit-created app `cik-esp-p2` in `cik-customer`, against a throwaway branch of the customer Neon project (the original `cik-esp` was left untouched and stayed healthy throughout). Logs in the operator workspace, gitignored.

| Run | Identity | Result |
|---|---|---|
| 1 `--fail-after app_role` | org | app and volume created, schema migrated (first marker), role created, deliberate stop, nothing deployed |
| 2 retry | org | app/volume `exists`, role `kept`, schema `current`, secrets generated and staged, deployed by digest, healthz 200, runtime preflight shipped and run; `installed_not_ready` on ENV-001 only (no customer Brevo key, as in Phase 1) |
| 3 converge | org | every step exists/kept/current/unchanged; Fly release count 1 before and after |
| 4 converge | **app deploy token** | first attempt failed: `apps list --org` needs org scope. Fixed to app-scoped `fly status -a` plus an org match; rerun converged with no writes |
| 5–6 upgrade to 0.1.3 | deploy token | run 5 deployed, then reported a digest mismatch: the machines API lagged the finished deploy (Fly showed release 2 complete with the new digest seconds later). Fixed with a 60 s settle poll; run 6 completed `upgrade 0.1.2 → 0.1.3` |
| 7 rollback to 0.1.2 | deploy token | allowed (marker v1/1); deployed by digest, no migration, healthz 200 |
| 8–10 refusal | org | re-upgraded to 0.1.3, then **simulated** a breaking migration by setting the branch's marker to v2/2 by hand. `rollback --to 0.1.2` exit 4 with the recovery path; `install` of 0.1.2 exit 4 ("never migrates backward"); Fly release count 5 before and after; machine still on 0.1.3. Marker reset to v1/1 afterward |
| 11 converge | org | record consistent (`release` = `target_release` = `installed_version` = 0.1.3), no writes |
| 12–13 teardown `--drop-app-role` | org | app and volume destroyed; role drop **failed** first: on Postgres 16+ the creating owner holds ADMIN but not membership, so `DROP OWNED` is refused. Fixed (owner grants itself the role, refuses if the role owns any relation) and retried: role dropped, 7 audit rows and the schema marker retained |

Fly state after run 2 matched the record: one machine (`--ha=false`), on the signed GHCR digest, one attached volume, exactly four secrets, and no owner URL among them.

**Corrections the exercise forced, all with regression tests:** the app-scoped Fly lookup (and the finding that under a deploy token another app in the same org reads as "not found", the same as a missing app); the deploy settle poll; `release` means *deployed*, with the target held in `target_release`, after a refused install had overwritten it; history counts completed installs (`installed_version`). The live record's `installed_version` was back-filled by hand once, at the point of that fix, and the record's history says so. Also the non-superuser role drop.

## Consequences

- Customer prerequisites grow by Docker and outbound access to GitHub, GHCR and Sigstore (docs/install.md).
- Install-kit release files are not yet signed. ADR 0003 mentions them, but the kit runs from the customer's own checkout, and what it ships into the machine is that same code. Signing the kit itself is deferred until the kit is distributed as an artifact rather than a repo.
- The rollback-refusal path cannot be produced by a real release yet: ESP's schema has one version. It was exercised live by setting the marker on a throwaway database branch, disclosed above as simulated. The first real breaking schema change in ESP should re-run it for real.
- `docs/install.md`'s permissions table is evidence-backed for the deploy token (converge, upgrade, rollback) and the org identity (create, teardown). It is not proven for a Postgres provider other than Neon.
