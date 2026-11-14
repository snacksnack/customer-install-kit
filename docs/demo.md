# Demo: one install, one fault, one remote diagnosis, one verified recovery

Run on 2026-11-14 by the author, operating both sides. Every artifact below is in [`demo/`](demo/), redacted only where noted, and the archives are the exact bytes that crossed from customer to vendor. The numbers in [engagement.md](engagement.md) are re-derived from these files by `tests/test_engagement.py`.

## Setup

| | |
|---|---|
| customer environment | a Fly org created for the customer (`<customer-org>`), separate from the vendor's; a fresh app `cik-esp-p5`, `iad`, 512 MB, 1 GB volume |
| customer database | a Neon branch with no ESP schema, adopted by the install (the database exists before; the kit migrates it and creates `esp_app`) |
| destination | a Brevo account used only for this project; conformance writes synthetic contacts in a per-run namespace (`cik-<run>-NNNN@example.com`) and deletes them |
| release | ESP 0.1.4, signed, `ghcr.io/snacksnack/esp-migration-agent@sha256:957bc24a…` |
| vendor side | the sealed triage runtime (`triage/compose.yaml`) on the author's workstation, kit at `ebd20ec` (knowledge v1 at the time of triage, see below) |

**A compromise to know about:** the customer's Neon project lives in the same Neon organization as the vendor's. The kit never uses that fact (the owner URL comes from the customer's `.env.cik`, as for any provider), but a real customer's database would not share an account with the vendor.

## Timeline

From [`customer/timing.log`](demo/customer/timing.log):

| step | side | result | time |
|---|---|---|---|
| install | customer | verified 0.1.4, created app and volume, migrated, deployed; exit 0 ([log](demo/customer/install.log)) | 45 s |
| conformance, baseline | customer | pass, 14 of 14 ([log](demo/customer/verify-1-baseline.log)) | 38 s |
| **fault**: `REVOKE SELECT ON review_audit FROM esp_app` | operator | `/healthz` stays 200 | |
| conformance | customer | **fail**: CNF-012 sign-in failed, CNF-013 could not run ([log](demo/customer/verify-2-fault.log)) | |
| collect and review | customer | 11 files, 14,852 bytes, nothing withheld ([log](demo/customer/collect-and-review.log)) | 15 s |
| triage round 1, rules | vendor | `awaiting_followup`: asks for `FUP-DB-PRIV` | 2 s |
| triage round 1, agent | vendor | `awaiting_followup`: asks for `FUP-DB-PRIV`, $0.11 | 16 s |
| follow-up check | customer | privilege matrix as `esp_app` | 1 s |
| triage round 2, rules | vendor | `supported_diagnosis`: grant `review_audit SELECT` | 2 s |
| triage round 2, agent | vendor | `insufficient_evidence` overall: SELECT supported, a second finding left open, $0.15 | 36 s |
| remedy | customer | `GRANT SELECT ON review_audit TO esp_app` | |
| conformance | customer | pass, 14 of 14 ([log](demo/customer/verify-3-recovered.log)); signature valid | 35 s |
| teardown | customer | app, volume and role removed; database kept ([log](demo/customer/teardown.log)) | 3 s |

Install time runs from the `install` command's start to its exit 0. It includes downloading and verifying the signed release, which is the first step. It does not include writing `install.toml` and `.env.cik` or creating the Fly org and database, which are customer prerequisites.

## What the fault looks like from outside

The app stays healthy to every monitor that checks liveness. Conformance is what notices: the approver can't sign in, because ESP reads the audit chain's tip before appending a sign-in row and that read is now refused. The error-event file on the volume holds three events at 15:30:02Z: `audit.read` twice and `audit.append` once, each `db`, SQLSTATE `42501`, release 0.1.4. No log text, no SQL, no role name.

## The handoff

The customer exported [`handoff/p5-diag.tar.gz`](demo/handoff/p5-diag.tar.gz) (digest `sha256:afd0d071…`) and sent the fingerprint `sha256:e0edc151…cebcc5` separately. The vendor ran triage in the sealed runtime: an internal Docker network whose only way out is a proxy that allows `api.anthropic.com` and `api.datadoghq.com`. The triage container holds the vendor's own Anthropic and Datadog keys and no customer credential; its CI test proves the customer's Fly API, app, database and Brevo are all refused from inside it ([triage.md](triage.md)).

Rules and agent each asked for the same follow-up: which grants does `esp_app` actually hold? The two requests are in [`handoff/`](demo/handoff/). The agent's explains why it is asking and what each answer would mean; the rules' names the rule. The customer ran the check twice, once per request, and exported each answer ([`p5-followup-rules.tar.gz`](demo/handoff/p5-followup-rules.tar.gz), [`p5-followup-agent.tar.gz`](demo/handoff/p5-followup-agent.tar.gz)). Each shows `review_audit SELECT` expected and not granted, everything else in place, and no forbidden grant held.

## The diagnosis

Both modes' round 2 findings, as the vendor sees them with `show`: [rules](demo/vendor/show-rules-round2.txt), [agent](demo/vendor/show-agent-round2.txt). Metadata records for each round are in [`vendor/`](demo/vendor/).

- **Rules** named the missing grant, cited the three events and the matrix row, and proposed `GRANT SELECT ON review_audit TO esp_app` followed by `kit verify`. Correct.
- **The agent** reached the same supported finding for the two `audit.read` refusals, with 11 of 11 citations resolving. It refused to extend that to the `audit.append` refusal: the support knowledge said `audit.append` needs only `INSERT`, which the role held. It left that finding `insufficient` and the case `insufficient_evidence`.

The agent was right that the knowledge did not explain the evidence. The knowledge was wrong: ESP reads the audit chain's tip before every append, so `audit.append` needs `SELECT` too. That was fixed as knowledge v2 (PR #26, registry `sha256:07cd36a9…`). Replayed on the same bundle and the same follow-up answer, the agent's round 2 under v2 concluded `supported_diagnosis` with 8 of 8 citations, $0.10 ([record](demo/vendor/agent-round2-knowledge-v2.json)). The Phase 6 results were measured on the frozen v1 registry and stand as measured.

## Recovery

The customer applied the grant with their own owner credential, ran conformance (14 of 14), and could share the signed report. Anyone can check it against the install record:

```sh
uv run python -m kit.verify verify-report \
  docs/demo/customer/conformance/20261114t153407-a8dd/report.signed.json \
  --record docs/demo/customer/install-record.json
```

That shows the report is the one this install's key signed. It does not show the observations are true; the customer controls the environment.

## Check it yourself

```sh
FP=sha256:e0edc151ddde17a297a9ac22fed3b508bef3b4ff96b3bdd46b49c42c93cebcc5
uv run python -m kit.bundle inspect docs/demo/handoff/p5-diag.tar.gz --fingerprint $FP
uv run python -m kit.bundle inspect docs/demo/handoff/p5-diag.tar.gz \
  --ref 'cik-ev:sha256:afd0d0713be99736989256359f09399b671349f24d8f9bc60e1d6aff7884c4a7/files/file_sink.json#/data/error_events/1'
# re-run rules triage on the exact handoff (no model, no network)
uv run python -m kit.triage --case-store /tmp/demo-cases run docs/demo/handoff/p5-diag.tar.gz --fingerprint $FP
```

`tests/test_engagement.py` does this on every CI run: every archive verifies against the fingerprint, every citation in both `show` outputs resolves, all three conformance reports verify, and rules triage on the handoff reproduces round 1 (and, with the rules follow-up, round 2's remedy).

To run the whole demo in your own environment you need a Fly org, a Postgres database with an owner role, and a Brevo account; follow [install.md](install.md), then [support.md](support.md).

## Redactions and differences from a real engagement

- `customer/install-record.json`: the Fly org name, the database host and the public URL are replaced with placeholders. The record is unsigned, so this does not affect report verification.
- Conformance evidence directories are not published: their execution journal names the Brevo account. The signed reports list each evidence file's hash.
- Paths in logs are shown as `~/acme-install`.
- The archives, follow-up requests, triage records and `show` outputs are unchanged.
- The demo ran before RC1-651 and RC1-652 were fixed. Its case ids are the old bundle-only form (`case-afd0d0713be9`), and rules and agent ran against separate case stores. A first attempt with both modes in one store let the agent inherit the rules run's request ([RC1-652](adr/0009-triage-engine-and-egress.md)); it was discarded, and a case is now (bundle, mode).
- One person ran both sides. Nobody outside the project has installed from these docs yet.
