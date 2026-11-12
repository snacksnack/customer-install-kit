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

Phase 0A (RC1-638) and 0B (RC1-646) done. Phase 1 (RC1-639): check registry, generated requirements, customer preflight.

## Preflight

```sh
uv run python -m kit preflight --context operator   # on the operator workstation (DB owner checks)
python -m kit preflight --context runtime           # inside a machine of the customer's app
uv run python -m kit registry                       # validate the registry and probe coverage
uv run python -m kit requirements [--check]         # regenerate (or check) docs/requirements.md
```

Exit 0 ready, 1 a required check failed, 2 a required check is unknown, 3 kit error. `--out FILE` writes the JSON report. Customer-facing requirements: [docs/requirements.md](docs/requirements.md) (generated; edit `kit/checks.toml`).

## Layout

- `kit/` — registry (`checks.toml`), probes, preflight runner, report schema, CLI.
- `docs/adr/` — one ADR per decision.
- `docs/requirements.md` — generated from the registry.
- `docs/risks.md` — risk log, reviewed at each phase exit.
- `docs/phase0/`, `docs/phase0b/` — Phase 0 working documents and evidence.
- `spike/` — Phase 0 live customer-org artifacts.
