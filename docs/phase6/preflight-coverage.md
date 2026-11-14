# Phase 6 preflight coverage suite (RC1-644)

This suite holds obvious installation failures that preflight should catch. It is scored only as preflight catches. It never counts toward the triage results in `report.md`, and no case here is triaged.

The expectations below were committed before any case ran (evaluator harness `phase6/harness/preflight_suite.py`, commit 74276fb in `cik-evaluator`). Preflight is deterministic and has no model in it, so nothing here is sealed.

## Cases

All four run on `cik-esp-p3` (ESP v0.1.4), the same customer environment as the development suite.

| id | what changes | where it shows | expected |
|---|---|---|---|
| P1 | `ESP_BREVO_API_KEY` is unset on the app (`fly secrets unset`) | runtime | ENV-001 fail `missing`, evidence `missing = ["ESP_BREVO_API_KEY"]`; runtime exit 1 |
| P2 | the operator's owner URL carries a wrong password; the database is not touched | operator | DB-001 fail `refused`, `error_class = "auth"`; DB-002 and DB-003 unknown `blocked` by DB-001; operator exit 1 |
| P3 | `ESP_ERROR_EVENTS_PATH` points at `/data/logs/`, a directory that does not exist (ESP opens the path without creating directories) | runtime | RT-004 fail `missing`, `exists = false`; runtime exit **0**, because RT-004 is advisory |
| P4 | the data volume is remounted read-only, so the sink cannot be written | runtime | RT-003 and RT-004 fail `refused`, `errno = 30` (EROFS); runtime exit 1 |

## Protocol

Each case:

1. **Baseline:** both preflight contexts run, and every required check passes. ENV-003 (model API key, advisory) fails on p3 at baseline, because the customer app has no Anthropic key.
2. **Inject and confirm:** the fault goes in and is confirmed customer-side (the machine's environment, or a write probe on `/data`). P2's fault is operator-side state only.
3. **Observe:** both contexts run again with the fault present.
4. **Restore and confirm:** the fault comes out and is confirmed.
5. **Recovered:** both contexts run again.

## Scoring

Each case is scored on five properties.

| property | meaning |
|---|---|
| caught | every expected check has the expected outcome, reason and evidence |
| gating | the affected context's exit status is the expected one |
| specific | every other check keeps its baseline outcome |
| secret_safe | no secret value is in either report, the injected wrong password included |
| recovered | after restore, every check is back to its baseline outcome |

## Results

**Final: 4 of 4 caught, with the expected exit status, no other check changed, no secret in any report, and every case recovered.** That holds on kit `dcc8226`, which carries two preflight fixes this suite found. On the kit as it was before (`41cffbc`), P4 was a miss. All runs on 2026-11-14 on `cik-esp-p3`.

| id | caught | gating | specific | secret_safe | recovered | what preflight reported |
|---|---|---|---|---|---|---|
| P1 | yes | yes (runtime 1) | yes | yes | yes | ENV-001 fail `missing`, `missing = ["ESP_BREVO_API_KEY"]` |
| P2 | yes | yes (operator 1) | yes | yes | yes | DB-001 fail `refused`, `error_class = "auth"`, `sqlstate = null`; DB-002 and DB-003 unknown, blocked by DB-001 |
| P3 | yes | yes (runtime 0) | yes | yes | yes | RT-004 fail `missing`, `path = "/data/logs"`, `exists = false`; installation is not blocked |
| P4 | yes | yes (runtime 1) | yes | yes | yes | RT-003 and RT-004 fail `refused`, `errno = 30` |

### What the first P4 runs found

1. **A read-only volume was a probe error, not a failure (fixed).** On the first run, RT-003 and RT-004 came back `unknown/probe_error`, so runtime exit was 2. The write test's cleanup called `unlink(missing_ok=True)` on a file it never created. On a read-only mount, Linux checks the mount before the name, so the unlink raised `EROFS` instead of `ENOENT`, and the error escaped the probe. Confirmed on the machine. The probe now unlinks only a file it created. A regression test fakes `EROFS` on both calls.
2. **The kit refused to report any RT-004 failure on a default install (fixed).** On the second run, the kit exited 3 and printed nothing: `output contains a secret value from the environment`. The secret guard treats every `ESP_*` value as a secret. RT-004's remediation text quotes the default sink path, `/data/esp-error-events.jsonl`, which is exactly the value of `ESP_ERROR_EVENTS_PATH`. The kit now exempts the three non-secret `[env]` keys it writes into `fly.toml`. A test fails if that list and the template drift apart. P3 did not hit this because its sink path was not the default.

Both P4 failures were the same fault. Neither came from the fault being undetectable: the third run, on the fixed kit, caught it as expected. P1 to P3 were run again on the fixed kit, so all four final results come from one kit commit. The earlier runs are kept evaluator-side.

### Findings

- **RT-004 is advisory, and P3 shows what that costs.** Preflight reports the broken sink, and installation goes ahead. ESP still writes every event to stderr, which is why the check was made advisory. But Phase 4 (ADR 0008) found that work run over `fly ssh` (the executor that `kit verify` drives) reaches only the file sink. With a broken sink, those events are on no channel the bundle collects. Recommendation: make RT-004 required whenever `ESP_ERROR_EVENTS_PATH` is set. This is a registry change, so it is left for a decision and not made here.
- **A wrong owner password has no SQLSTATE** (`sqlstate = null`). The `auth` class comes from libpq's message pattern (ADR 0005), and that held against Neon.
- **The `report.md` claim that RT-003 "catches all three" storage faults was wrong for the read-only case** until `dcc8226`. A correction note has been added there.

### Limits

- Four cases, one platform, and each fault picked because it is obvious. This shows preflight catching these four states. It does not show preflight catching every installation failure.
- P2 changes the operator's copy of the password, not the database. From preflight's side, a password rotated in the database looks the same: a connection refused for `auth`.
- P3's path is set as an app secret, which overrides `fly.toml` `[env]` (confirmed in the machine's environment). A customer would more likely edit `fly.toml`. The machine ends up with the same environment either way.
