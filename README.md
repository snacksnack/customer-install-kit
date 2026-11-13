# Customer Install Kit

Install, conformance, and remote triage for the [ESP Migration Agent](https://github.com/snacksnack/esp-migration-agent) in an environment the vendor cannot see.

A customer installs the application in their own cloud account. The kit:

- checks that the environment has what the application needs (preflight),
- installs the application and tests a small migration using fake contacts (conformance),
- collects a diagnostic bundle the customer can review before sharing,
- explains failures from that bundle alone — rules first, then a bounded AI investigator — or asks for one specific additional check when evidence is missing.

The support side never gets SSH, cloud API access, telemetry, or database access to the customer environment. Every triage conclusion is reached from the redacted bundle the customer chose to share. That constraint is enforced and tested, not assumed.

Jira: epic RC1-594, phases RC1-638..647.

## Status

Phases 0A (RC1-638), 0B (RC1-646), 1 (RC1-639) and 2 (RC1-640) done. Phase 3 (RC1-641) done: customer-side conformance and signed reports. Phase 4 (RC1-642) done: diagnostic bundles. Phase 5 (RC1-643): rules-first triage, a bounded agent with allowlisted follow-up checks, and a sealed runtime.

## Preflight

```sh
uv run python -m kit preflight --context operator   # on the operator workstation (DB owner checks)
python -m kit preflight --context runtime           # inside a machine of the customer's app
uv run python -m kit registry                       # validate the registry and probe coverage
uv run python -m kit requirements [--check]         # regenerate (or check) docs/requirements.md
```

Exit 0 ready, 1 a required check failed, 2 a required check is unknown, 3 kit error. `--out FILE` writes the JSON report. Customer-facing requirements: [docs/requirements.md](docs/requirements.md) (generated; edit `kit/checks.toml`).

## Install (Phase 2)

```sh
uv run python -m kit.install verify-release 0.1.3              # verify a signed ESP release
uv run python -m kit.install install --config install.toml     # install or converge; safe to re-run
uv run python -m kit.install rollback --to 0.1.2 --config ...  # only if the database schema allows
uv run python -m kit.install teardown --confirm <app> --config ...
```

Customer guide, minimum permissions, trusted publisher and recovery planes: [docs/install.md](docs/install.md). Decision: [ADR 0006](docs/adr/0006-install-path.md).

## Conformance (Phase 3)

```sh
uv run python -m kit.verify run --config install.toml                    # real namespaced migration inside the machine
uv run python -m kit.verify verify-report REPORT --record install-record.json
uv run python -m kit.verify export <run-id> --config install.toml --out DIR [--with-evidence]
```

Exit 0 pass, 1 fail, 2 insufficient evidence, 3 kit error. Reports stay local until exported. Customer guide: [docs/conformance.md](docs/conformance.md). Decision: [ADR 0007](docs/adr/0007-conformance-and-report-integrity.md).

## Diagnostic bundles (Phase 4)

```sh
uv run python -m kit.bundle collect --config install.toml [--case SLUG]   # outside ESP; works during a crash loop
uv run python -m kit.bundle review <bundle-id> --config install.toml      # exactly what would leave
uv run python -m kit.bundle export <bundle-id> --config install.toml --out FILE
uv run python -m kit.bundle inspect FILE [--fingerprint FP] [--ref REF]   # vendor: validate an untrusted bundle
```

Exit 0 ok, 3 kit error, 4 refused. Nothing is uploaded. Customer guide: [docs/bundle.md](docs/bundle.md). Decision: [ADR 0008](docs/adr/0008-diagnostic-bundles.md).

## Layout

- `kit/` — registry (`checks.toml`), probes, preflight runner, report schema, CLI. Runs on the workstation and inside the customer machine.
- `kit/verify/` — operator-only conformance: in-machine runner, CNF checks, signed reports.
- `kit/bundle/` — diagnostic bundles: allowlist, event validation, sources, scanner, collector, export and untrusted inspect.
- `kit/install/` — operator-only: release verification (sigstore), install engine, Fly and image runners, install record.
- `docs/adr/` — one ADR per decision.
- `docs/requirements.md` — generated from the registry.
- `docs/risks.md` — risk log, reviewed at each phase exit.
- `docs/phase0/`, `docs/phase0b/` — Phase 0 working documents and evidence.
- `spike/` — Phase 0 live customer-org artifacts.

## Triage (Phase 5)

```sh
uv run python -m kit.triage run FILE --fingerprint FP [--supplement S] [--mode rules|agent]   # vendor
uv run python -m kit.triage show <case-id>                                                     # findings and proposed remedy
uv run python -m kit.triage.followup run --request REQ.json --config install.toml             # customer: one allowlisted check
docker compose -f triage/compose.yaml run --rm triage run /in/FILE --fingerprint FP --mode agent  # sealed runtime
```

Guide: [docs/triage.md](docs/triage.md). Decision: [ADR 0009](docs/adr/0009-triage-engine-and-egress.md).
