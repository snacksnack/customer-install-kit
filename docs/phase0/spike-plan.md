# Phase 0A deployment spike: select one platform, one architecture

RC1-638 scope: one cloud target (Fly or Render) and one CPU architecture, chosen after a small deployment spike. Docker in CI stays a test fixture, not a supported target.

## Starting evidence

- The ESP Migration Agent already runs on Fly (`esp-migration-demo`, iad, amd64, scale-to-zero) with a working Dockerfile, fly.toml, and CI deploy. That is vendor-side evidence only; it says nothing yet about a clean customer install.
- No Render account or CLI exists on this machine. Exercising Render means creating a new external account.

## What the spike must demonstrate

The product's premise is "installable in an environment we cannot see," so the spike is a dry run of exactly that: stand up the selected profile in a **separate customer environment** (not the vendor org), following only written steps, and record every step and cost.

## Decision criteria

1. **Separate customer environment under distinct identity/billing** — on Fly: a second organization; on Render: a separate workspace/account. The vendor/customer boundary must be an account boundary, not a naming convention.
2. **Install from documented steps** — image deploy, secrets, Postgres URL, health check green, one fixture migration passes.
3. **Secret store** — platform-native, customer-controlled, never readable by the vendor identity.
4. **Storage fault family exercisable** — Phase 0B must be able to make initially-writable storage become unavailable or full at runtime. Fly: volumes (attach/detach, size). Render: disks. Confirm mechanics on the selected platform.
5. **Cost floor** — projected monthly cost of the installed profile at idle and during a conformance run; feeds the Phase 0A budget ceiling.
6. **CPU architecture** — the supported arch is whatever the platform runs (amd64 on both candidates today); images are built in CI on amd64. Local Apple Silicon builds are out of the supported profile.

## Prior and its limit

Fly is the incumbent and the likely pick: proven Dockerfile/fly.toml, org-level isolation under one login, volumes for the storage fault family. The honest limit: choosing Fly without deploying to Render means ADR 0001 records a comparison on paper plus a real Fly spike, not two real spikes. If Render is to be exercised, Reid creates the account (new external signup, his call). Either way the ADR states what was actually run.

## Out of scope for the spike

Kubernetes, multi-platform support, additional architectures, production migrations (all deferred by RC1-638); the triage-side outbound allowlist (vendor-side concern, designed in the isolation section of ADR 0002, not a platform-selection criterion).
