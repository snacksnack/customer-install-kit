# Fault-family candidates (RC1-638 naming; RC1-646 proves feasibility and cost)

The headline faults are **runtime failures that pass preflight**: the environment checks out green, the install succeeds, and the failure appears only when the application does real work. Obvious preflight failures (missing secret, unreachable host at install time) form a separate coverage suite and never count toward the headline. All families come from ESP's actual dependencies (`dependency-inventory.md`) — rule R7 forbids inventing a dependency to break it.

## Development families (rules and prompts are written from these, and only these)

1. **DB login valid, schema permissions insufficient.** The app role authenticates but lacks a permission the workload needs (e.g., INSERT on a table the audit path writes). Mechanism exists in the profile already: `db_setup`'s owner/`esp_app` split means a permissions matrix is one REVOKE away from this fault.
2. **API host reachable, upload endpoint denied.** The destination (Brevo) answers TCP/TLS and a ping-style call, but the specific write endpoint the migration needs is denied (quota, route block, method denial).
3. **Storage writable at install, unavailable or full later.** A Fly volume that mounts and accepts writes during install, then fills or detaches mid-run. Constraint from grooming (2026-11-10): the structured error sink must survive this fault — independent sink or tested fallback — or the bundle loses exactly the evidence that explains the failure.

## Reserved held-out candidates (named here; kept OUT of all rules, prompts, and support knowledge)

Per the protocol below, naming them is required and harmless — the discipline is that no triage rule, prompt, or support document may be written from them. The "missing Postgres extension" example from the epic is **ruled out**: ESP's schema requires no extensions, so it would be an artificial dependency (R7).

- **H1 — TLS trust/proxy failure.** Outbound calls from the app fail TLS verification (corporate proxy, broken trust store) for one destination while others succeed.
- **H2 — Destination credential valid but under-scoped.** The Brevo API key authenticates but lacks the permission scope a mid-migration operation needs — distinct from dev family 2, which is endpoint denial, not credential scope.
- **H3 — Database connection exhaustion.** Connections succeed at install and under light load; the pool exhausts the customer Postgres connection limit mid-run (Neon free-plan limits make this real, not synthetic).

## Held-out draw protocol (from RC1-638, binding)

1. Freeze rules, prompts, and support knowledge first; record the freeze commit hash.
2. Select the evaluation family from the reserved candidates by **recorded public randomness**, with the source and draw procedure committed before the draw — e.g., the NIST randomness beacon pulse at a pre-committed future timestamp, mapped to a candidate index by a committed formula. An author-controlled seed is not unbiased no matter how it is hashed; the beacon removes the author from the draw.
3. Disclose regardless that the author designed the candidate pool.
4. Fallback if keeping several families untouched becomes too expensive: an explicitly author-selected holdout, published as the narrower claim.
