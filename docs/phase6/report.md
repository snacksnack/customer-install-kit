# Phase 6 results: rules versus agent triage (RC1-644)

## Verdict: mixed

**The agent beat the rules engine on the failures it was built for. Both failed the held-out test, a failure type neither had seen.** The evaluation itself held up, and running it found four kit bugs, all now fixed.

| | |
|---|---|
| ✅ **Known failures** | The agent diagnosed 4 of 8 development faults, the rules engine 3. The agent blamed the wrong cause once, the rules engine 3 times. |
| ✅ **No false alarms** | On healthy systems (2 controls), neither mode reported a fault. |
| ❌ **New failure type** | Neither mode diagnosed the held-out family, a Brevo key that works but lacks a permission: **0 of 2**. Both saw the error and didn't recognize what it meant. |
| 🛠️ **Kit bugs found** | 4, all fixed (PRs #12, #13, #17, #18). One of them hid the evidence in a third held-out case, so that case is not scored. |
| ✅ **Trustworthy test** | Rules results reproduced exactly, nothing leaked to the engines, and every system was restored. |

## Scorecard

| | Rules engine | Agent | Better |
|---|---|---|---|
| Development faults diagnosed (of 8) | 3 | **4** (11 of 24 runs) | Agent |
| Wrong cause given (of 8) | 3 | **1** (3 of 24 runs) | Agent |
| False alarms on healthy systems (of 2) | **0** | **0** | Tie |
| Held-out faults diagnosed (of 2) | 0 | 0 | Neither |
| Cost | **$0** | $0.53 a run | Rules |
| Same answer every time | **Yes** (replayed on all 13 cases) | Split on 3 of 13 cases | Rules |

Agent cases are counted by the majority of its three runs.

## What it means

- **The engines don't generalize to new failure types.** Brevo returns `403 permission_denied` for a key that lacks a permission and `401 unauthorized` for a bad key. Nothing in the frozen registry tells them apart, so both modes saw the 403 and concluded nothing. That is the gap the held-out test was there to find.
- **The agent's edge is restraint as much as insight.** Where the evidence was thin, it held back (8 of 24 runs) instead of guessing. The rules engine guessed and was wrong 3 times.
- **Both modes can be misled by the evidence they're given.** Old error events from earlier incidents stay in the bundle and pushed the rules engine to a wrong cause on F1-3. Neither mode used the release history that pointed to F2-3's cause.

**What to do next:** teach the registry the 403-versus-401 distinction; mark events that predate the current failure in the bundle; make preflight check that the Brevo key can actually write.

## Results by case

✅ correct · ❌ wrong cause · ⭕ missed (the evidence was there) · 🟡 held back (acceptable here) · `*` right cause but overclaimed

| case | what broke | rules | agent (3 runs) |
|---|---|---|---|
| F1-1 | app lost read access to one table | ✅ | ✅ ✅ ✅ |
| F1-2 | app lost access to the whole schema | ❌ | ⭕ ✅ ✅ |
| F1-3 | app lost permission to connect | ❌ | 🟡 🟡 🟡 |
| F2-1 | Brevo key deactivated | ⭕ | ✅ ⭕ ✅ |
| F2-2 | Brevo blocks the app's IP address | ✅* | ✅* ✅* ✅* |
| F2-3 | app's Brevo key replaced with a bad one | ❌ | ❌ ❌ ❌ |
| A1 | two faults at once (schema access + read-only disk) | 🟡 | 🟡 🟡 🟡 |
| A2 | schema access lost, then restored before evidence was collected | ✅ | 🟡 🟡 ✅ |
| C1 | nothing broken (fresh install) | ✅ | ✅ ✅ ✅ |
| C2 | nothing broken (after recovery) | ✅ | ✅ ✅ ✅ |
| **H2-1** | **held-out:** key can't write contacts | ⭕ | ⭕ ⭕ ⭕ |
| **H2-3** | **held-out:** key can't read the account | ⭕ | ⭕ ⭕ ⭕ |
| H2-2 | held-out: key can't create campaigns. **Not scored:** a kit bug dropped the evidence | ⭕ | ⭕ ⭕ ⭕ |

On C1 and C2, ✅ means no false alarm. The F1-2 rules error came from a probe bug since fixed (PR #13), and both F2-1 misses saw Brevo halfway through applying the change.

## Kit bugs this found

| bug | effect | fix |
|---|---|---|
| Bundle validator dropped Brevo campaign events (camel-case routes) | H2-2's decisive error never reached triage | PR #18 |
| `kit install` retried into the same failure after a deploy | Install looped instead of finishing | PR #17 |
| Database privilege probe misread a missing schema grant | Misled the rules engine on F1-2 | PR #13 |
| `kit install` ignored secrets changed on Fly by hand | A wrong key could stay live after an install | PR #12 |

Not bugs, but worth knowing: storage faults don't break ESP 0.1.4 on this install, so those three cases were withdrawn before they ran; and Brevo applies dashboard changes unevenly for several minutes.

## How it was run

13 cases (8 development faults, 2 healthy controls, 3 held-out), against the protocol and scoring committed in advance in [`cases.md`](cases.md). The held-out family was picked by public randomness after the registry was frozen ([`heldout-draw.md`](heldout-draw.md)), and its cases were sealed before any ran. For each case: the rules engine once (plus a re-run), the agent three times (`claude-opus-5-5`), all from the same evidence bundle, graded blind by a sealed prompt. The sealed answers and grading prompt are published in [`sealed/`](sealed/), and their hashes match the ones published before triage.

## Details

<details>
<summary><b>What ran</b></summary>

| suite | cases | runs graded | notes |
|---|---|---|---|
| development, fault | 8 (F1-1..3, F2-1..3, A1, A2) | 8 rules, 24 agent | F3-1..3 withdrawn before triage (amendment v2) |
| development, control | 2 (C1, C2) | 2 rules, 6 agent | C1 on a fresh install (`cik-esp-p4`, torn down after) |
| held-out | 3 (H2-1..3) | 3 rules, 9 agent | H2 drawn 2026-11-14 00:02Z; cases sealed after the draw, before any ran |

Each case: one bundle collected after the failure, rules mode run once and re-run once (r1, r2), the agent run three times (a1..a3, `claude-opus-5-5`, effort high, ADR 0009 budgets). The grader saw r1 and a1..a3 in a shuffled order, findings only.

**Exclusions:** none by registry digest. All 510 triage records carry `sha256:4700a810…a7f0`. Three agent rounds on C2 (a2, a3, and a1's second round) failed with an API `connection_error` before reaching the model. Those runs were set aside unread, rerun, and graded. The harness now rejects any run with an API-error round.

</details>

<details>
<summary><b>Every case, with notes</b></summary>

`correct` = `correct_supported`, `abstain` = `appropriate_abstention`.

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

</details>

<details>
<summary><b>By suite, family and tag</b></summary>

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

</details>

<details>
<summary><b>Variability, follow-ups and cost</b></summary>

- **Agent variability:** the three runs disagreed on 3 of 13 cases (F1-2, F2-1, A2). On F2-1, the split followed the evidence each run saw, not the model (finding 7).
- **First-bundle resolution:** 0 in both modes. Every correct diagnosis used at least one follow-up round.
- **Follow-up rounds, mean per run:** dev fault cases 1.38 (rules), 1.21 (agent); controls 0 and 0; held-out 1.00 and 0.89.
- **Cost:** agent $14.36 on dev fault cases, $1.45 on controls, $4.94 held-out. Grading cost is not included.

</details>

<details>
<summary><b>Determinism</b></summary>

Rules mode was replayed on r1's exact inputs (bundle and supplements) for every case. The result was identical every time. The live re-run (r2) can differ when its follow-ups return different live evidence. That happened on F1-3, where the machine was unreachable during r1's follow-up. The replay is the determinism test.

</details>

<details>
<summary><b>Recovery</b></summary>

`kit verify` passed after every case. The remedy applied was the sealed correct remedy, scripted for database and secret faults and done by the operator in the Brevo dashboard for F2-1 and F2-2, not each run's own remedy text. The grader recorded `remedy_matches = true` on every correct diagnosis, so the applied remedy is the one those runs proposed in substance. Strictly, under protocol step 4, these diagnoses are recovery-verified via the sealed remedy.

</details>

<details>
<summary><b>Leakage</b></summary>

Every bundle, live follow-up supplement and triage output was scanned for case ids, harness and sealed-file names, and six-word runs from every sealed `truth` and `evidence_note`: 0 hits on all 13 cases. A planted positive control was caught. The canary check across Datadog payloads, CI output and eval exports has not run yet (see open items).

</details>

<details>
<summary><b>All findings</b></summary>

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

</details>

<details>
<summary><b>Deviations from the protocol</b></summary>

- **Recovery** used the sealed remedy, not each run's remedy text (see Recovery).
- **Harness changes during the suite:** the API-error invalidation, the Brevo settle wait (after F2-1) and the `kit install` retry (during H2) were added mid-suite. None changes what triage sees or how it is graded.
- **H2-2's sealed note** describes an event the kit's validator dropped (finding 2). The case cannot be amended after triage, so it is graded as written and reported separately.
- **Held-out design:** the author designed all three candidate families before the draw and the H2 cases after it. The draw removed the author from the choice of family, not from case design. The H2 mechanics were probed on the workstation with the restricted keys before sealing.
- **Not yet run:** the preflight coverage suite (scored separately, never part of these results) and the canary check across Datadog, CI and eval exports. Both are open in RC1-644.

</details>

<details>
<summary><b>Sealed files and hashes</b></summary>

| file | sha256 (published before triage) |
|---|---|
| [`sealed/dev-expected.v1.toml`](sealed/dev-expected.v1.toml) | `97687b24be746266300108e062622e8d877ef5afb222de7f65e4b1207fafd81a` |
| [`sealed/dev-expected.v2.toml`](sealed/dev-expected.v2.toml) | `2febfea85e7b2c57af9f2494ad0fedddd56adc1fe8f10721c50c4fa2c242ccb7` |
| [`sealed/heldout-expected.v1.toml`](sealed/heldout-expected.v1.toml) | `495e234b49e322e08fb26c0be14f02feb962855776e3f43889120df63e134fb9` |
| [`sealed/judge.md`](sealed/judge.md) | `4bcbfea90bce6fe330877b6f9e2354b018bf2e531a4bac5f8fb0efe3d34eeb40` |

Check with `shasum -a 256 docs/phase6/sealed/*`.

</details>
