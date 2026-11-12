# ADR 0005: Check registry, observation contract, and preflight contexts

Status: proposed (RC1-639)

## Decision

**One registry, one ID space.** `kit/checks.toml` is the only place a check is defined. Each entry has a stable `<AREA>-<NNN>` ID (never reused), context, severity, profiles, purpose, probe description, permission needed, declared evidence schema, timeout, and remediation. Preflight runs these checks; conformance, bundles and triage will refer to the same IDs. `docs/requirements.md` is generated from the registry and CI fails if it is stale, if an ID is duplicated, or if a check and its probe implementation do not match one-to-one.

**Four outcomes with closed reasons.** `pass`; `fail` (requirement not met); `not_applicable` (does not apply to this profile or configuration); `unknown` (applies, but evidence could not be obtained: missing input, blocked by a dependency, timeout, probe unavailable, probe crash). Each outcome has a fixed set of reason codes, validated at runtime and on read.

**Two probe contexts.** Where a probe runs decides what it can see, so each check declares one:

- `operator`: the customer's workstation, holding install-time credentials. The database owner URL lives here and never goes into the app (ADR 0002's least-privilege split).
- `runtime`: a machine in the customer's Fly app. Only there do probes see the app's real egress path, injected secrets, architecture, memory and volume.

Dependencies may only point to earlier checks in the same context.

**Observations, not conclusions.** The report (`cik.preflight/1`) carries outcome, reason and evidence only. Remediation text lives in the registry; diagnostic rules will live in the triage engine; held-out truth stays in `cik-evaluator`. A probe may emit exactly its declared evidence fields. Undeclared fields are a kit error, which also stops a probe from smuggling a value into the report. Behind that, every output is scanned for the values of `ESP_*`/`CIK_*` variables and URL passwords, and the kit refuses to print or write anything that contains one.

**Bounded, with useful exits.** Each probe runs on a daemon thread and is abandoned at its registry timeout. Exit 0 ready, 1 a required check failed, 2 none failed but a required check is unknown, 3 kit error (including usage errors, which argparse would otherwise report as 2).

**Versioned.** The report records its schema and registry version. The reader accepts only versions this kit ships and rejects others explicitly; it never guesses at an unfamiliar bundle.

## Evidence (2026-11-11)

- Operator context against the customer Neon project: healthy run exits 0 (DB-004 not applicable, no extensions required); wrong password exits 1 with `error_class: auth`; no owner URL exits 2 with dependents blocked.
- Runtime context inside the customer machine (`cik-esp`, 512 MB, `/data` mounted): architecture, memory, volume and both destinations pass. ENV-001 fails, correctly, because the customer app has no Brevo key yet (Phase 3 adds it).
- Locally on Apple Silicon: arm64 fails RT-001, memory is unknown (no cgroup or /proc), `/data` is missing. This shows all four outcomes from real conditions.

## Findings that changed the design

- **psycopg attaches no SQLSTATE to connect-time errors**, auth failures included (measured against Neon). DB-001 therefore classifies from libpq's message, matched locally and never emitted. The same gap reaches ESP's RC1-647 events: a rotated database password surfaces as `psycopg_pool.PoolTimeout` after the pool timeout, and the event records `sqlstate: null`, which cannot be told apart from DNS, network, TLS or pool exhaustion. Tracked as RC1-648.
- **A 512 MB Fly machine reports MemTotal 472,532 kB**, with no cgroup limit. A literal 512 MiB floor would fail every correctly sized machine, so RT-002's floor is 450 MiB, which still separates a 256 MB machine.
- ENV-002 originally depended on ENV-001, so a missing Brevo key blocked the session-secret check. Dependencies are now only where the check truly cannot run without the other.

## R3 boundary

Preflight runs before installation, so it checks what install needs (owner connection, version, CREATE and CREATEROLE), not the app role's table grants, which do not exist yet. The development fault families are post-preflight state changes (a revoked grant, a rotated key, a filled volume), so a green preflight followed by those failures is the honest headline, not a gap preflight should have closed.

## Deferred

How the kit reaches a runtime machine is Phase 2's install path (signed artifact). The Phase 1 runtime run copied the kit into the existing app machine by hand.
