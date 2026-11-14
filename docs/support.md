# Support: from a failure to a verified fix, without vendor access

For both sides of a support case: the customer operator, who runs everything in their environment, and the vendor's support engineer, who sees only what the customer exports. The vendor never gets a credential, a shell, a log stream or a database connection, at any step. A worked example with real artifacts is in [demo.md](demo.md).

## The procedure

| # | who | does | command | sends |
|---|---|---|---|---|
| 1 | customer | notices a failure, or runs conformance after a change | `kit.verify run` | |
| 2 | customer | collects a bundle, reads it, exports it | `kit.bundle collect`, `review`, `export` | the archive, through any channel |
| 3 | customer | sends the report key fingerprint, once per install | (from `install-record.json`) | the fingerprint, through a **different** channel (a call, the ticket) |
| 4 | vendor | triages the archive in the sealed runtime, rules mode and agent mode | `kit.triage run --mode rules`, `--mode agent` | |
| 5 | vendor | if a round ends `awaiting_followup`: sends the request file | | `requests/fr-<id>.json` |
| 6 | customer | reads the request, runs the one named check, reviews and exports the result | `kit.triage.followup run`, `kit.bundle review`, `export` | the follow-up archive |
| 7 | vendor | runs the same mode again with the supplement, reads the diagnosis | `kit.triage run --supplement`, `kit.triage show` | the findings and proposed remedy, as text |
| 8 | customer | reviews the remedy, applies it as their own operator | (their own tools) | |
| 9 | customer | proves recovery and shares the signed report | `kit.verify run`, `kit.verify export` | `report.signed.json` |
| 10 | vendor | checks the report against the install record, closes the case | `kit.verify verify-report` | |

Commands in full:

```sh
# customer (workstation, kit checkout)
uv run python -m kit.verify run --config ~/acme-install/install.toml
uv run python -m kit.bundle collect --config ~/acme-install/install.toml
uv run python -m kit.bundle review <bundle-id> --config ~/acme-install/install.toml
uv run python -m kit.bundle export <bundle-id> --config ~/acme-install/install.toml --out acme-diag.tar.gz

# vendor (sealed runtime; see triage.md)
docker compose -f triage/compose.yaml run --rm triage run /in/acme-diag.tar.gz --fingerprint sha256:<fp> --mode rules
docker compose -f triage/compose.yaml run --rm triage run /in/acme-diag.tar.gz --fingerprint sha256:<fp> --mode agent

# customer, if asked for a follow-up
uv run python -m kit.triage.followup run --request fr-<id>.json --config ~/acme-install/install.toml
uv run python -m kit.bundle review <followup-bundle-id> --config ~/acme-install/install.toml
uv run python -m kit.bundle export <followup-bundle-id> --config ~/acme-install/install.toml --out acme-followup.tar.gz

# vendor, with the answer (same mode that issued the request)
docker compose -f triage/compose.yaml run --rm triage run /in/acme-diag.tar.gz --fingerprint sha256:<fp> \
    --mode agent --supplement /in/acme-followup.tar.gz
docker compose -f triage/compose.yaml run --rm triage show case-<digest12>-agent

# customer, after applying the remedy
uv run python -m kit.verify run --config ~/acme-install/install.toml
uv run python -m kit.verify export <run-id> --config ~/acme-install/install.toml --out ~/share/<run-id>

# vendor
uv run python -m kit.verify verify-report report.signed.json --record install-record.json
```

## Rules for both sides

- **The fingerprint never travels with the archive.** Anyone who can swap the archive could swap a fingerprint sent beside it. The vendor records the fingerprint on first contact and refuses any archive that does not match it (`inspect` and `triage run` exit 4).
- **A follow-up request names one check from a fixed list of three** (`FUP-DB-PRIV`, `FUP-DEST-AUTH`, `FUP-VOLUME`; table in [triage.md](triage.md)). The customer's runner refuses anything else, whatever the request's text says, and prints what it will touch before it runs. The customer may decline; the case then stays at what the evidence supports.
- **A follow-up answer goes back to the case that asked for it.** Each mode is its own case (`case-<digest12>-rules`, `case-<digest12>-agent`), and a supplement is accepted only by the case that issued its request id. If both modes asked for the same check, the customer runs it twice or the vendor uses one mode's answer for that mode only.
- **Two follow-up rounds per case.** After that the case ends with what the evidence supports. The next step is a call where the customer operates and shares their screen, not vendor access.
- **The remedy is a proposal.** Triage changes nothing in the customer's environment. The customer applies the fix with their own credentials, and the signed conformance report from step 9, not triage's conclusion, is the evidence of recovery.
- **A signed report proves integrity, not truth.** The customer controls the environment and the key ([conformance.md](conformance.md)).

## What each side keeps

| item | where | who can read it |
|---|---|---|
| secrets, report private key, conformance evidence, unexported bundles | the customer's install workspace | the customer |
| exported archives, follow-up requests, signed reports | wherever the customer sent them | the customer and the vendor |
| investigation record (transcripts, evidence read, diagnosis) | the vendor's case store, owner-only files | the vendor's triage host |
| metadata (ids, enums, counts, cost) | the vendor's Datadog and CI | the vendor |

The agent sends the bundle values it reads to the model provider (Anthropic) to reason about them. That is the one content-bearing flow out of the vendor side, disclosed in [ADR 0009](adr/0009-triage-engine-and-egress.md).

## What triage cannot see

The collector reads the platform and the app's error events, not the database or the destination. So the first bundle can show that a database privilege is missing (SQLSTATE 42501) but not which one, and that Brevo refused a call but not why beyond the status and code. That gap is what the follow-up checks fill, and it is why every correct diagnosis in the Phase 6 evaluation used a follow-up round ([phase6/report.md](phase6/report.md)). Other evidence never reaches the vendor at all: log text, request bodies, contact data, secret values, and anything outside `kit/bundle/allowlist.toml`.
