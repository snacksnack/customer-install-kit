# Phase 0B lifecycle cost measurement (RC1-646)

Measured 2026-11-10 against the live customer environment (`cik-esp`, Neon project
`cik-customer`), using `spike/lifecycle_family1.py` and `spike/lifecycle_family3.sh`.
Per budget.md, the projection separates per-case cost from shared setup cost, and
model cost stays provisional until real triage calls exist (RC1-647 bundles).

## Measured: simple case (family 1 — schema permission)

Full lifecycle, one run, all stages automated (0 operator interventions):

| Stage | Elapsed |
|---|---|
| baseline (writable check) | 1.5 s |
| inject (REVOKE) | 0.1 s |
| trigger + collect evidence | 0.2 s |
| remedy (GRANT) | 0.1 s |
| verify recovery | 0.2 s |
| cleanup check (residue) | 0.2 s |
| **Total** | **2.2 s** |

No redeploy, no machine state change, no storage churn. Cloud usage: a few
Neon connections on the free plan. Marginal infrastructure cost per case: ~$0.

## Measured: difficult case (family 3 — storage full)

Full lifecycle, one run, starting from a suspended (scale-to-zero) machine,
all stages automated (0 operator interventions):

| Stage | Elapsed |
|---|---|
| wake (scale-to-zero start) | 0.5 s |
| baseline write | 1.4 s |
| inject (fill volume, 958 MiB dd) | 58.8 s |
| trigger + collect (errno 28) | 1.0 s |
| health check during fault | 0.1 s (200 — liveness blind to the fault, as proven in the matrix) |
| remedy (rm fill file) | 1.0 s |
| verify recovery (write ok) | 0.9 s |
| cleanup check (df, 1% used) | 0.9 s |
| **Total** | **64.6 s** |

The fill dominates (~17.4 MB/s to the 1 GB volume — the volume was sized small
in Phase 0A exactly so this stage stays under a minute). Cloud usage: ~65
machine-seconds at shared-cpu-1x/512MB rates plus 1 GB of volume writes —
fractions of a cent per run. Suspend/resume is sub-second, so scale-to-zero
adds no meaningful per-case cost.

## Operator interventions

- Families 1 and 3: zero — the whole lifecycle is scriptable.
- Family 2 (matrix-time injection): one dashboard action per run (key
  rotation/IP restriction at the ESP provider) plus one to restore — the only
  family with a human in the injection loop. Minutes, not hours.

## Shared setup cost (one-time, not per-case)

From the Phase 0A spike log: Fly org + app + deploy + Neon project + `db_setup`
was roughly an afternoon including the billing-wall and HA-default detours, and
is already paid. A reset between cases does not repeat it — the measured
lifecycles above start from the standing environment.

## Model cost (provisional, per budget.md)

No real triage calls exist yet (bundles arrive with RC1-647), so this is an
assumption-stated estimate, to be re-measured at Phase 5:

- Assumed triage-agent shape: an agentic investigation over a redacted bundle,
  ~3–6 model calls per case, cumulative ~100K input tokens + ~5K output tokens
  (conservative: no prompt-cache credit taken).
- At Claude Opus 5.5 rates ($4/M input, $20/M output): **~$0.50 per agent-triage
  run**. Sonnet 5.5 would halve it; the projection uses the Opus figure.
- Rules-only triage runs are deterministic and model-free: $0.

## Suite projection vs. the $120 ceiling

Case counts from RC1-644 (≥3 distinct cases per family; clean/ambiguous/
evidence-unavailable controls; repetition runs separated from unique cases):

| Line | Count | Est. cost |
|---|---|---|
| Unique fault cases (4 families × 3) | 12 | injection ≈ $0 infra |
| Control cases (clean, ambiguous, unavailable-evidence) | ~6 | ≈ $0 infra |
| Agent-triage runs on unique cases | 18 | ~$9 |
| Repetition runs for model variability (subset ×2 extra) | ~12 | ~$6 |
| Retry/contingency on triage runs (+30%) | — | ~$5 |
| Rules/prompt development iterations (Phases 4–5, est. 2–3× eval spend) | — | ~$40–60 |
| Fixed infrastructure over the project (Fly machine + volume, Neon free) | — | ~$5 |
| **Projected total** | | **~$65–85** |

**Verdict: inside the $120 ceiling with ~$35–55 headroom.** The dominant line
is development-phase model spend, not the evaluation matrix — so if the
projection drifts, it drifts during Phases 4–5 where it is visible early, not
at evaluation time. Per budget.md, evaluation spend and ongoing operating cost
are reported as separate lines when actuals exist; this projection commits the
matrix at full RC1-644 size with no resizing needed.

## Wall-clock projection for the matrix

Injection lifecycles are not the bottleneck: 12 fault cases × ≤65 s ≈ 13
minutes of injection time for the whole matrix, plus family-2 dashboard
minutes. Suite wall-clock will be dominated by triage runs and verification,
not by fault injection.
