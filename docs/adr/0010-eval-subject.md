# ADR 0010: The triage agent is an agent-evals subject, scored structurally, with no judge and no auto-instrumentation

Status: proposed (RC1-644)

## Decision

**`cik-triage` is a billed subject in agent-evals.** `python -m evals` (dependency group `evals`, agent-evals pinned by tag) runs the real triage agent over frozen bundles and records each run with its model, prompt version (system prompt plus registry digest), code version and exact cost. The weekly agent-evals sweep runs it, and `--post-datadog` posts `cik.evals.*` gauges for a monitor.

| case | billed | what it scores |
|---|---|---|
| `family1-privilege` | yes | asks for the privilege matrix, supports the cause only after the answer, cites the missing grant's row |
| `family2-destination` | yes | asks for the destination probe, supports the cause only after the answer, cites the workstation probe (what separates a rejected key from a source restriction) |
| `healthy-abstains` | yes | on a bundle with no fault, makes no supported finding |
| `budget-discipline` | yes, over the billed rounds | every round inside ADR 0009's budgets; a budget stop is advisory |
| `metadata-only-tracing` | no | every telemetry payload passes the allowlist; no span carries input or output; no planted canary or bundle content reaches telemetry, a triage record, an eval record or the console |
| `isolation` | no | the agent's tools reach no customer system; the sealed runtime's network, mounts and egress allowlist are as ADR 0009 states |

The free cases run in CI on every change (`--free`).

**Frozen inputs.** The primaries are the six committed Phase 4 bundles, re-signed with an eval-only key so follow-up answers can be signed the same way. The collector's `case` label is stripped from the manifest, because the agent can read the manifest and the label names the scenario. A follow-up request is answered with a canned supplement built from the real check's return shape: the decisive answer for the check that discriminates, a benign one for any other. Each supplement has its own bundle id and is dated a few minutes after its parent. The first version reused the healthy bundle's id and finish time, and the agent refused to trust a supplement whose timing contradicted itself. That refusal was correct.

**Correctness is structural.** A case is scored on its outcome, its finding statuses, the check it asked for, and whether a supported finding's citations land on the decisive row of the answer. Nothing compares the finding's text with an expected string.

**There is no LLM judge.** A judge would read finding text derived from customer evidence and send it to a model outside the reviewed inference payload, and the kit allows no such path. Phase 6's sealed judge graded cause-naming once, evaluator-side, on the record.

**`agent_evals.llmobs` is not used.** It turns on ddtrace's Anthropic integration, which records prompts and completions, and those carry bundle content. The kit's own metadata-only telemetry traces eval runs instead, with `ml_app:cik-triage` and `env:evals`.

**Canaries.** The healthy bundle carries three planted values: an email, an API-key-shaped string, and a database URL with a password, which sits where the bundle should carry only a variable name. The agent reads them, which the reviewed inference payload allows. `metadata-only-tracing` fails if any of them reaches one of four surfaces: telemetry payloads, triage records, eval records, or console output. A test proves each property fails when a leak is planted. This covers three canaries on four surfaces. It is not proof that nothing can leak.

## Consequences

- A run costs about $0.95 and takes about four minutes.
- The eval passes the agent an Anthropic client with a 300 s request timeout. The SDK default is 600 s with two retries, and one stalled call held a run for 12 minutes on 2026-11-14. The kit's own triage path still uses the default and has no wall-clock budget. That is an open kit finding.
- Citation grounding varies from run to run on `family2-destination`: it passed in 3 of 5 runs on 2026-11-14 after the supplement fix, and every one of those runs reached the right supported outcome. That characteristic gates anyway: a supported diagnosis that does not cite the evidence that discriminates is the failure this kit is built to prevent.
