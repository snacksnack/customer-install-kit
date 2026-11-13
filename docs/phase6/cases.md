# Phase 6 cases, protocol and scoring (RC1-644)

This file is committed before any case in it is triaged. It names the cases and fixes how they are run and scored. What counts as a correct answer for each case is sealed: it lives evaluator-side, and only its hash is published here.

## Sealed

| file (evaluator-side, `cik-evaluator/phase6/`) | sha256 |
|---|---|
| `dev-expected.toml`: per-case truth, cause, correct remedy, unsupported answers, whether abstaining is acceptable, confounds | `97687b24be746266300108e062622e8d877ef5afb222de7f65e4b1207fafd81a` |
| `judge.md`: the grading prompt | `4bcbfea90bce6fe330877b6f9e2354b018bf2e531a4bac5f8fb0efe3d34eeb40` |

Both files are revealed unchanged after scoring, and anyone can re-hash them. A case's expectation may be amended only before that case is first triaged. An amendment is a new version of the file with its reason recorded, and the new hash is published here before the case runs. The held-out family's cases are sealed the same way after the draw (`heldout-draw.md`).

## The development suite: 13 cases

Every fault case starts from a passing `kit verify` on `cik-esp-p3` (ESP v0.1.4). Both preflight contexts are run and must pass. The fault is injected after that, and the workload (`kit verify`) is run to make it fail. A case counts only if the failure is observed customer-side in runtime evidence. A scenario name isn't enough.

| id | family | what changes in the customer environment | preflight's limit |
|---|---|---|---|
| F1-1 | 1 DB privilege | `SELECT` on `review_audit` revoked from the app role | preflight runs as the owner, and app-role grants are not a preflight check |
| F1-2 | 1 | `USAGE` on schema `public` revoked from the app role | as above |
| F1-3 | 1 | `CONNECT` on the database revoked from the app role and `PUBLIC`, then the machine restarts | pooled sessions survive a revoke, so the failure starts at the next connect |
| F2-1 | 2 destination | the Brevo key is deactivated in the dashboard | NET-001 checks reachability, not the key |
| F2-2 | 2 | Brevo's authorized-IP list is turned on with only the operator's address | as above |
| F2-3 | 2 | the app's Brevo secret is replaced with a key Brevo does not recognize; the operator's secrets file keeps the valid one | ENV-001 checks presence, not validity |
| F3-1 | 3 storage | `/data` inodes exhausted by small files outside ESP's | RT-003 checks writability and free bytes when it runs |
| F3-2 | 3 | `/data` remounted read-only while the app runs | as above |
| F3-3 | 3 | `/data` blocks filled during the migration, after which ordinary request logs roll the platform's log buffer | as above |
| A1 | compound | F1-2 and F3-2 together | as above |
| A2 | 1 | F1-2, a failing `kit verify`, then the grant is restored before the bundle is collected | as above |
| C1 | control | a fresh `kit install` of the same release on a new app and Neon branch; `kit verify` passes | none |
| C2 | control | p3 after recovery from the preceding cases; `kit verify` passes | none |

Tags (sealed with the expectations, listed here for reporting): `evidence_limited` (F1-3, F3-3), `confusable` (F2-2 with F2-3), `ambiguous` (A1, A2). F2-1 and F2-2 need someone at the Brevo dashboard. The held-out family adds at least three more fault cases after the draw.

**The preflight coverage suite is separate.** It holds obvious failures preflight should catch (a missing required secret, a wrong owner password, an unwritable error-event sink). It is scored only as preflight catches and never counts toward the triage results.

## Protocol

1. **Same initial evidence:** one bundle per case, collected and exported once after the failure is observed. Every run of that case starts from that archive.
2. **Runs per case:**
   - rules-only once (deterministic, re-run once to confirm the same result),
   - agent-assisted three times (`claude-opus-5-5`, effort high, budgets as ADR 0009: 10 model calls, 24 tool calls and $1.50 per round; 2 follow-up rounds per case).

   Repeated agent runs measure variability. The denominator is unique cases, not runs.
3. **Same follow-up budget:** both modes get up to 2 follow-up rounds. Rules-only requests the check its own first open finding names (`engine.rules_followup`, deterministic). The agent chooses its own. Each requested check is run live, customer-side, while the fault is still present, and returned as a signed supplement.
4. **Recovery:** after all runs of a case, the remedy from the first `correct_supported` run is applied customer-side as written, and `kit verify` must pass. Diagnoses whose remedy was not applied are labeled "not recovery-verified".
5. **Frozen registry:** every run records `registry_digest`, and a run with any other digest is excluded. Triage runs in the sealed runtime (`triage/compose.yaml`) and sees only `/in`. It cannot read this repo, the evaluator repo, or the case names.

## Scoring

Each run's final answer (after its follow-up rounds) is graded by the sealed prompt into exactly one category:

| category | meaning |
|---|---|
| `correct_supported` | a supported finding names the true cause |
| `appropriate_abstention` | nothing is supported, abstaining is acceptable for this case, and the true cause is among the candidates (or a discriminating check was requested) |
| `missed` | nothing is supported, and the evidence allowed more |
| `unsupported` | a supported finding names a cause that is not the truth (any supported current fault on a control) |

The grader also records, per run:
- `detected` (failure detection, kept separate from causal diagnosis),
- `remedy_matches`,
- `overclaim` (correct, but the allowed evidence cannot rule out the case's sealed confound),
- `partial` (multi-fault).

The grader sees findings only. It never sees the mode, the run, or the bundle.

**Reported:** per suite, per family and per tag, for each mode:
- correct diagnoses over unique cases,
- unsupported diagnoses,
- appropriate abstentions,
- first-bundle resolution (correct with no follow-up),
- follow-up rounds,
- cost,
- customer-verified recovery,
- agent variability across the three runs.

The rules-versus-agent difference is published as measured, including zero or negative.

**Leakage checks across all runs:**
- every bundle is scanned for case ids, injection script names and sealed-file phrases,
- the planted canaries are checked across bundles, Datadog payloads, CI output and eval exports.

The report states N and coverage. Any detected leak fails the run.
