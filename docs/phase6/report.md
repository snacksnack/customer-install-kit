# Phase 6 results: rules versus agent triage (RC1-644)

This reports the sealed fault evaluation run on 2026-11-13 and 2026-11-14 against the protocol and scoring committed in [`cases.md`](cases.md) and the draw in [`heldout-draw.md`](heldout-draw.md). The sealed expectations and the grading prompt are revealed unchanged in [`sealed/`](sealed/), and their hashes match the ones published before any case ran.

## Headline

- **Held-out family (H2, a valid but under-scoped Brevo key): 0 of 2 scoreable cases diagnosed in either mode.** All 8 graded runs on H2-1 and H2-3 were `missed`, and every agent run found the failing call: Brevo's `403 permission_denied` on a route the key was not allowed to use. Neither the frozen registry nor either mode treats `403 permission_denied` differently from `401 unauthorized`, so nothing concluded "the key lacks a permission".
- **H2-2 is not a fair test of triage.** Its decisive event (`POST /emailCampaigns` → 403) was written by ESP, then dropped by the kit's bundle validator, which rejects camel-case route segments (finding 2). Its four `missed` grades stand as measured: for the customer, the system as a whole missed it.
- **Development fault cases (8):** rules mode diagnosed 3 and gave an unsupported diagnosis on 3. The agent's 24 runs gave 11 correct and 3 unsupported answers. By majority of its three runs per case, the agent diagnosed 4 of 8 and gave an unsupported diagnosis on 1.
- **Controls (2):** no unsupported diagnosis in either mode (2 of 2 rules, 6 of 6 agent runs abstained).
- **Determinism:** rules mode gave the identical result when replayed on its first run's exact inputs, on all 13 cases.
- **Leakage:** 0 hits in every bundle, supplement and triage output, on all 13 cases.
- **Recovery:** `kit verify` passed after every case.
- **Agent cost:** $20.75 over 39 graded runs ($0.53 a run). Rules mode costs nothing.

The rules-versus-agent difference is published as measured. On the development suite, the agent was right more often and wrong less often. On the held-out family, neither mode was right.

## What ran

| suite | cases | runs graded | notes |
|---|---|---|---|
| development, fault | 8 (F1-1..3, F2-1..3, A1, A2) | 8 rules, 24 agent | F3-1..3 withdrawn before triage (amendment v2) |
| development, control | 2 (C1, C2) | 2 rules, 6 agent | C1 on a fresh install (`cik-esp-p4`, torn down after) |
| held-out | 3 (H2-1..3) | 3 rules, 9 agent | H2 drawn 2026-11-14 00:02Z; cases sealed after the draw, before any ran |

Each case: one bundle collected after the failure, rules mode run once and re-run once (r1, r2), the agent run three times (a1..a3, `claude-opus-5-5`, effort high, ADR 0009 budgets). The grader saw r1 and a1..a3 in a shuffled order, findings only.

**Exclusions:** none by registry digest. All 510 triage records carry `sha256:4700a810…a7f0`. Three agent rounds on C2 (a2, a3, and a1's second round) failed with an API `connection_error` before reaching the model. Those runs were set aside unread, rerun, and graded. The harness now rejects any run with an API-error round.

## Results by case

`correct` = `correct_supported`, `abstain` = `appropriate_abstention`. Agent runs are a1, a2, a3.

| case | what changed | rules | agent | notes |
|---|---|---|---|---|
| F1-1 | `SELECT` on `review_audit` revoked | correct | correct ×3 | |
| F1-2 | `USAGE` on schema `public` revoked | unsupported | missed, correct, correct | rules misled by a follow-up probe bug (finding 3) |
| F1-3 | `CONNECT` revoked, machine restarted | unsupported | abstain ×3 | rules blamed the credential using old auth events (finding 6) |
| F2-1 | Brevo key deactivated | missed | correct, missed, correct | both misses saw Brevo half-way through the change (finding 7) |
| F2-2 | Brevo authorized IPs: workstation only | correct, overclaim | correct, overclaim ×3 | evidence can't exclude a key mismatch (sealed confound) |
| F2-3 | app's key replaced, secrets file kept | unsupported | unsupported ×3 | all named an IP restriction; none used the release history |
| A1 | F1-2 plus read-only `/data` | abstain, partial | abstain, partial ×3 | all supported the `USAGE` cause; read-only left insufficient |
| A2 | F1-2, grant restored before collection | correct | abstain, abstain, correct | |
| C1 | control, fresh install | abstain | abstain ×3 | |
| C2 | control, p3 after recovery | abstain | abstain ×3 | three agent rounds rerun after API errors |
| H2-1 | restricted key: Contacts read-only | missed | missed ×3 | `POST /contacts/lists` → 403 `permission_denied` in the bundle |
| H2-2 | restricted key: Email campaigns read-only | missed | missed ×3 | the campaign 403 was dropped by the kit's validator; triage saw only H2-1's stale event (finding 2) |
| H2-3 | restricted key: Account none | missed | missed ×3 | `GET /account` → 403 from both vantages, other routes 200 |

## By suite, family and tag

Rules: one run per case. Agent: runs, then cases by majority of three.

| group | cases | rules correct / unsupported / abstain / missed | agent runs correct / unsupported / abstain / missed | agent cases correct (majority) |
|---|---|---|---|---|
| dev fault, all | 8 | 3 / 3 / 1 / 1 | 11 / 3 / 8 / 2 | 4 |
| family 1 (DB privilege) | 3 | 1 / 2 / 0 / 0 | 5 / 0 / 3 / 1 | 2 |
| family 2 (destination) | 3 | 1 / 1 / 0 / 1 | 5 / 3 / 0 / 1 | 2 |
| compound and timing (A1, A2) | 2 | 1 / 0 / 1 / 0 | 1 / 0 / 5 / 0 | 0 |
| controls | 2 | 0 / 0 / 2 / 0 | 0 / 0 / 6 / 0 | n/a |
| held-out H2 | 3 | 0 / 0 / 0 / 3 | 0 / 0 / 0 / 9 | 0 |
| held-out H2, scoreable (H2-1, H2-3) | 2 | 0 / 0 / 0 / 2 | 0 / 0 / 0 / 6 | 0 |

| tag | cases | rules | agent runs |
|---|---|---|---|
| `evidence_limited` | F1-3 | unsupported | abstain ×3 |
| `confusable` | F2-2, F2-3 | correct (overclaim), unsupported | correct ×3 (overclaim), unsupported ×3 |
| `ambiguous` | A1, A2 | abstain, correct | abstain ×5, correct ×1 |

**Overclaims:** 4 runs, all on F2-2 (rules and every agent run). Each named the true cause but called it supported when the evidence could not rule out the sealed confound.

**Detection** (failure noticed, separate from diagnosis): rules 8 of 11 fault cases, agent 32 of 33 fault-case runs.

## Variability, follow-ups and cost

- **Agent variability:** the three runs disagreed on 3 of 13 cases (F1-2, F2-1, A2). On F2-1, the split followed the evidence each run saw, not the model (finding 7).
- **First-bundle resolution:** 0 in both modes. Every correct diagnosis used at least one follow-up round.
- **Follow-up rounds, mean per run:** dev fault cases 1.38 (rules), 1.21 (agent); controls 0 and 0; held-out 1.00 and 0.89.
- **Cost:** agent $14.36 on dev fault cases, $1.45 on controls, $4.94 held-out. Grading cost is not included.

## Determinism

Rules mode was replayed on r1's exact inputs (bundle and supplements) for every case. The result was identical every time. The live re-run (r2) can differ when its follow-ups return different live evidence. That happened on F1-3, where the machine was unreachable during r1's follow-up. The replay is the determinism test.

## Recovery

`kit verify` passed after every case. The remedy applied was the sealed correct remedy, scripted for database and secret faults and done by the operator in the Brevo dashboard for F2-1 and F2-2, not each run's own remedy text. The grader recorded `remedy_matches = true` on every correct diagnosis, so the applied remedy is the one those runs proposed in substance. Strictly, under protocol step 4, these diagnoses are recovery-verified via the sealed remedy.

## Leakage

Every bundle, live follow-up supplement and triage output was scanned for case ids, harness and sealed-file names, and six-word runs from every sealed `truth` and `evidence_note`: 0 hits on all 13 cases. A planted positive control was caught. The canary check across Datadog payloads, CI output and eval exports has not run yet (see open items).

## Findings

1. **Under-scoped keys are invisible to both modes (held-out H2).** Brevo answers a restricted key with `403 permission_denied` and a bad or deactivated key with `401 unauthorized`. Nothing in the registry separates them. Rules mode saw reads succeed and marked the destination finding resolved. The agent flagged the 403 as current and left it insufficient, once naming "key permission scope" as a possibility without committing. The kit's preflight never authenticates to Brevo (NET-001 checks reachability), so `kit install` accepts an under-scoped key. Brevo labels the Restricted key type "Recommended", which makes this a likely customer mistake.
2. **The kit's bundle validator drops Brevo's campaign events** (fixed in PR #18). `kit/bundle/events.py` accepts only lower-case route segments, so every `/emailCampaigns` event fails as `bad_route` and only a count reaches the bundle (15 dropped by H2-2's collection, including its 403 and every earlier rate-limit error). ESP had written the event 15 seconds before collection. H2-2's sealed evidence note describes evidence triage never received. The development cases' decisive events are all on lower-case routes and were unaffected.
3. **FUP-DB-PRIV returned the wrong answer without schema `USAGE`** (fixed in PR #13). `to_regclass` returns NULL when the role can't see the schema, so the probe reported missing table privileges instead of the missing `USAGE`. F1-2's rules result was graded as measured on the buggy probe.
4. **Secret drift went unnoticed by `kit install`** (fixed in PR #12). A secret changed on Fly outside the kit was not re-staged. PR #12's own fix then caused finding 5.
5. **`kit install` looped on its own push** (fixed in PR #17). A redeployed machine passes `/healthz` before `fly ssh` can reach it, so the runtime preflight failed. Fly digests were recorded only at the end of a successful install, so every retry saw the kit's own push as outside drift and redeployed into the same race.
6. **Error events accumulate across incidents.** The event sink is cumulative, and old `unauthorized` events from earlier Brevo faults stayed in later bundles. Rules mode blamed a credential on F1-3 using them, and the H2 bundles held 11 old `unauthorized` events beside the current `permission_denied`, and H2-2's only `permission_denied` was H2-1's. The bundle does not mark which events predate the current failure.
7. **Brevo applies dashboard changes unevenly for minutes.** After the key was deactivated (F2-1), probes returned mixed 200, 401 and 403 for several minutes. The two F2-1 misses (rules r1, agent a2) are the two runs whose live follow-ups caught that state. Reactivation took about 8 minutes to settle. The harness now waits for three consistent probes after any operator change. F2-2 ran with that in place.
8. **Storage faults don't fail ESP 0.1.4 on this install.** `/data` holds only the error-event file, so full or read-only storage only stops ESP recording errors. F3-1..3 were withdrawn before triage (amendment v2). Runtime preflight (RT-003) catches all three when it runs.
9. **Release history went unused.** On F2-3, every run named an IP restriction. The one distinguishing clue was a release with an unchanged image just before the failures (a secret change), and no run used it.
10. **The sealed F1-2 note was wrong about the error code.** It predicted SQLSTATE 42501. A `USAGE` revoke produces 42P01 (relation not found). The note could not be amended after F1-2 was triaged. The grader received the note as written, and F1-2's grades stand as measured.

## Deviations from the protocol

- **Recovery** used the sealed remedy, not each run's remedy text (see Recovery).
- **Harness changes during the suite:** the API-error invalidation, the Brevo settle wait (after F2-1) and the `kit install` retry (during H2) were added mid-suite. None changes what triage sees or how it is graded.
- **H2-2's sealed note** describes an event the kit's validator dropped (finding 2). The case cannot be amended after triage, so it is graded as written and reported separately.
- **Held-out design:** the author designed all three candidate families before the draw and the H2 cases after it. The draw removed the author from the choice of family, not from case design. The H2 mechanics were probed on the workstation with the restricted keys before sealing.
- **Not yet run:** the preflight coverage suite (scored separately, never part of these results) and the canary check across Datadog, CI and eval exports. Both are open in RC1-644.

## Sealed files, revealed

| file | sha256 (published before triage) |
|---|---|
| [`sealed/dev-expected.v1.toml`](sealed/dev-expected.v1.toml) | `97687b24be746266300108e062622e8d877ef5afb222de7f65e4b1207fafd81a` |
| [`sealed/dev-expected.v2.toml`](sealed/dev-expected.v2.toml) | `2febfea85e7b2c57af9f2494ad0fedddd56adc1fe8f10721c50c4fa2c242ccb7` |
| [`sealed/heldout-expected.v1.toml`](sealed/heldout-expected.v1.toml) | `495e234b49e322e08fb26c0be14f02feb962855776e3f43889120df63e134fb9` |
| [`sealed/judge.md`](sealed/judge.md) | `4bcbfea90bce6fe330877b6f9e2354b018bf2e531a4bac5f8fb0efe3d34eeb40` |

Check with `shasum -a 256 docs/phase6/sealed/*`.
