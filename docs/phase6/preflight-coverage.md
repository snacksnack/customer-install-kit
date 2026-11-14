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

Pending.
