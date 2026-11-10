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

Phase 0A (RC1-638) in progress: platform/architecture selection spike, supported profile ADR, and the vendor/customer isolation boundary.

## Layout

- `docs/adr/` — one ADR per decision.
- `docs/risks.md` — risk log, reviewed at each phase exit.
- `docs/phase0/` — Phase 0A working documents: dependency inventory, spike plan.
