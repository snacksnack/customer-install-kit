# ADR 0004: Phase 0B go/resize/drop decisions per fault family

- **Status:** Proposed (RC1-646)
- **Date:** 2026-11-10
- **Decides:** which fault families enter the evaluation matrix, at what size,
  based on proven injectability, evidence quality, and measured lifecycle cost.

## Decision

**All three development families: GO, at full RC1-644 size (≥3 distinct cases
each). The held-out pool: GO with all three candidates.** No family is resized
or dropped; the $120 ceiling holds with headroom.

Evidence backing each call lives in `docs/phase0b/evidence-matrix.md`; cost in
`docs/phase0b/lifecycle-costs.md`.

### Dev family 1 — valid DB login, insufficient schema permission: GO

Proven live (SQLSTATE 42501, preflight-green, residue-free restore). Measured
lifecycle 2.2 s, fully automated, ~$0 marginal infrastructure. The cheapest
family by far; distinct-case variants (target table, INSERT vs UPDATE) are
one-line changes. Nothing to resize.

### Dev family 2 — API host reachable, upload endpoint denied: GO

Evidence triple proven live (HTTP 401 + route template + provider error code).
The only family with a human in the injection loop (one dashboard action to
inject, one to restore) — minutes per run, acceptable at 3 cases. The
IP-restriction variant stays deferred to Phase 6 if wanted; the disclosed
feasibility shortcut (invalidated credential) remains recorded in the matrix.

### Dev family 3 — storage writable at install, full later: GO

Proven live (errno 28 at flush; sink survival proven; liveness blind to the
fault). Measured lifecycle 64.6 s end to end from a suspended machine, fully
automated. The 1 GB volume keeps the fill under a minute — the Phase 0A sizing
decision is confirmed, not revisited. The missing-mount and fill-mid-migration
variants have known mechanics and are exercised when the matrix cases are
built (Phase 6), not before.

### Held-out pool H1–H3: GO, pool of three

All three candidates proven feasible (verdicts in the public matrix; mechanics
evaluator-side only). The pool stays at three for the recorded-randomness draw
per the Phase 0A protocol. No candidate is dropped, so the draw keeps its full
entropy and the disclosed-pool claim stays at its strongest form.

## Cost basis

Projected suite total ~$65–85 against the $120 ceiling (lifecycle-costs.md):
per-case infrastructure is effectively free, agent-triage model spend is the
dominant line and is provisional until RC1-647 produces real bundles. Rule
from budget.md stands: if re-measurement at Phase 5 pushes the projection past
the ceiling, the matrix shrinks or Reid explicitly re-commits the ceiling —
it never silently stretches.

## Consequences

- Phase 6 commits to 12 unique fault cases + ~6 controls with no family-level
  caveats; any later resize is a ceiling decision, not a feasibility one.
- Family 2's per-run dashboard step is accepted as-is; automating the
  provider-side injection is explicitly out of scope for v1.
- Model-cost re-measurement at Phase 5 (real bundles, real triage calls) is a
  required checkpoint before evaluation runs start.
