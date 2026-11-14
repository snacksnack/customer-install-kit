# Engagement: deploying and supporting ESP in an environment the vendor cannot see

This is the outcome of RC1-594. The product is the [ESP Migration Agent](https://github.com/snacksnack/esp-migration-agent); the kit installs it in a customer's own Fly org against the customer's own Postgres and Brevo, proves the installed workflow works, and supports it when it breaks, while the vendor holds no credential for anything the customer runs. Every number below is re-derived from committed artifacts by `tests/test_engagement.py`; the table at the end lists each one and its source.

## What the customer gets

1. **A verified install.** `kit.install` deploys a signed release by digest after checking its Sigstore signature, publisher identity and SBOM hash ([install.md](install.md)). In the [demo](demo.md) a clean install took 45 s, from command start to exit 0.
2. **Proof the workflow works, not just that the app is up.** `kit.verify` runs a real migration of synthetic contacts inside the app and signs the result with the install's own key: 14 of 14 checks in 38 s on the clean install ([conformance.md](conformance.md)).
3. **Support without access.** When something breaks, the customer collects a bundle built only from listed fields, reads it, and exports it. The vendor diagnoses from that archive alone, and may ask for one more read-only check from a fixed list ([support.md](support.md)).
4. **An upgrade, rollback and teardown path** that never deletes the customer's data ([install.md](install.md)).

## What one support case looked like

In the demo, revoking one table grant left `/healthz` at 200 while conformance failed (1 of 14 checks failed, 1 of 14 could not run). The customer shared an 11-file bundle. Rules triage and the agent each asked for the same follow-up, the privilege matrix, and both then named the missing grant. The rules engine proposed the exact `GRANT`. The agent proposed it too, but declined to call the case diagnosed because the support knowledge could not explain one of the three refusals, and the knowledge was the thing that was wrong. With the knowledge corrected, the agent's replay concluded the diagnosis. The customer applied the grant and conformance passed 14 of 14 in 35 s. Agent triage for the case cost $0.26. Teardown took 3 s and kept the database.

## How well triage works: rules versus the agent

Measured in Phase 6 on 13 cases with sealed answers and a held-out fault family drawn by public randomness ([phase6/report.md](phase6/report.md)). The agent ran three times per case.

| | rules | agent |
|---|---|---|
| development faults diagnosed | 3 of 8 | 4 of 8 (11 of 24 runs) |
| wrong cause given | 3 of 8 | 1 of 8 (3 of 24 runs) |
| false alarms on healthy installs | 0 of 2 | 0 of 2 |
| held-out faults diagnosed | 0 of 2 | 0 of 2 |
| failure detected | 8 of 11 | 32 of 33 runs |
| cost | $0.00 | $0.53 a run, $20.75 in all |
| same answer on every run | 13 of 13 replays identical | split on 3 of 13 cases |

The agent was better on the failures it was built for, mostly by holding back where the rules guessed. Neither generalized: a Brevo key that works but lacks a permission returns `403` instead of `401`, and nothing in the frozen registry knew the difference. No case was diagnosed from the first bundle alone (0 of 14 correct runs); every correct diagnosis used a follow-up. That is the honest summary: the follow-up channel carries the diagnosis, and the agent is an improvement over rules, not a replacement for support knowledge.

## What protects the customer, and its limits

- **Vendor access isolation.** The vendor's triage runtime sits on an internal network whose only way out is a proxy to the model provider and Datadog. A CI test proves the customer's Fly API, app, database and destination are unreachable from inside it. This does not remove the customer's own administrators, who run everything; it removes the vendor.
- **The customer's permissions.** An org-scoped Fly token for the first install and teardown, an app deploy token for everything after, and a database owner role used only from the customer's workstation. The app itself runs as a least-privilege role ([install.md](install.md)).
- **What leaves.** A bundle holds only allowlisted fields, scanned before writing, and the customer reads it before export. The agent sends what it reads to Anthropic; Datadog gets metadata only. In Phase 6, 18 planted canary values were searched for across 7 surfaces (LLM Obs spans, metrics, logs, CI logs, eval records) and none was found. That is bounded coverage by those detectors and those surfaces, not proof that nothing sensitive can leave.
- **What a signed report proves.** That it is unmodified and signed with the install's key. Not that its observations are true: the customer controls the environment and the key.
- **What the collector cannot see.** Database grants, destination-side permissions, log text, request bodies and contact data. The first two are what the follow-up checks exist for.

## Scope

- **Supported profile:** one Fly org per customer, `linux/amd64`, Postgres reachable from Fly (tested on Neon), Brevo as the destination, password sign-in ([ADR 0001](adr/0001-supported-profile.md)). Other clouds, architectures and Kubernetes are future work.
- **Synthetic data only.** Conformance and every test write contacts in a per-run `example.com` namespace and delete them. No real customer data was used.
- **Author-operated.** One person played customer and vendor. No outside person has installed from these docs yet; that stretch goal is open.
- **Fault coverage.** Two fault families have cases (database privileges, destination credentials). Storage faults did not break ESP 0.1.4 and were withdrawn; the held-out family was the 403.

## Check a release yourself

```sh
uv run python -m kit.install verify-release 0.1.4
cosign verify ghcr.io/snacksnack/esp-migration-agent@sha256:957bc24a72f1840733bf635a77d1f61794d7f89dbdc134eeaeff2641c53c0a91 \
  --certificate-identity https://github.com/snacksnack/esp-migration-agent/.github/workflows/release.yml@refs/tags/v0.1.4 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The release manifest names the image digest and the SBOM's sha256; `verify-release` checks both against the Sigstore-signed manifest. Sanitized example artifacts (bundle archives, follow-up requests, triage records, signed reports) are in [`demo/`](demo/).

## Numbers and their sources

| key | value | source |
|---|---|---|
| `install_seconds` | 45 s | `demo/customer/timing.log` |
| `conformance_baseline` | 14 of 14 | `demo/customer/verify-1-baseline.log` |
| `conformance_baseline_seconds` | 38 s | `demo/customer/timing.log` |
| `conformance_fault_failed` | 1 of 14 | `demo/customer/verify-2-fault.log` |
| `conformance_fault_insufficient` | 1 of 14 | `demo/customer/verify-2-fault.log` |
| `conformance_recovered` | 14 of 14 | `demo/customer/verify-3-recovered.log` |
| `conformance_recovered_seconds` | 35 s | `demo/customer/timing.log` |
| `bundle_files` | 11 | `demo/customer/collect-and-review.log` |
| `demo_agent_cost` | $0.26 | `demo/vendor/agent-round*.json` (v1 rounds) |
| `teardown_seconds` | 3 s | `demo/customer/timing.log` |
| `dev_rules_correct` | 3 of 8 | `phase6/results.json` |
| `dev_agent_correct_cases` | 4 of 8 | `phase6/results.json` (majority of 3 runs) |
| `dev_agent_correct_runs` | 11 of 24 | `phase6/results.json` |
| `dev_rules_wrong` | 3 of 8 | `phase6/results.json` |
| `dev_agent_wrong_cases` | 1 of 8 | `phase6/results.json` |
| `dev_agent_wrong_runs` | 3 of 24 | `phase6/results.json` |
| `control_false_alarms` | 0 of 2 | `phase6/results.json` |
| `heldout_correct` | 0 of 2 | `phase6/results.json` (scored cases H2-1, H2-3) |
| `rules_detected` | 8 of 11 | `phase6/results.json` |
| `agent_detected` | 32 of 33 | `phase6/results.json` |
| `rules_cost` | $0.00 | `phase6/results.json` |
| `agent_cost_per_run` | $0.53 | `phase6/results.json` |
| `agent_cost_total` | $20.75 | `phase6/results.json` |
| `rules_replays_identical` | 13 of 13 | `phase6/results.json` |
| `agent_split_cases` | 3 of 13 | `phase6/results.json` |
| `first_bundle_correct` | 0 of 14 | `phase6/results.json` (correct runs, both modes) |
| `canary_values` | 18 | `phase6/report.md` (evaluator canary harness; not re-derived here) |
| `canary_surfaces` | 7 | `phase6/report.md` (evaluator canary harness; not re-derived here) |
