# Triage: diagnosing from a shared bundle

For the vendor's support engineer, and for the customer who wants to know what happens to a bundle they share. Decision record: [ADR 0009](adr/0009-triage-engine-and-egress.md).

## What triage gets, and what it never gets

It gets the exported bundle archive and the customer's report-key fingerprint, sent through a separate channel. Later it may also get a follow-up bundle the customer chose to run and send. It never gets a customer credential, a shell, a database connection, or API access, and its runtime cannot reach the customer's systems at all (below).

## Running it (vendor)

```sh
uv run python -m kit.triage run acme-diag.tar.gz --fingerprint sha256:<from the customer> --mode rules
uv run python -m kit.triage run acme-diag.tar.gz --fingerprint sha256:... --mode agent
uv run python -m kit.triage show <case-id>        # findings, citations, proposed remedy
uv run python -m kit.triage record <case-id>      # metadata only, for eval exports
uv run python -m kit.triage freeze                # registry digest
```

`run` prints the metadata record only. The investigation record is in the case store (`~/.cik-triage/cases`, owner-only). It holds the agent's transcript, the evidence it read, and the diagnosis. In production, run it in the sealed runtime instead:

```sh
cp acme-diag.tar.gz triage/in/
docker compose -f triage/compose.yaml run --rm triage run /in/acme-diag.tar.gz --fingerprint sha256:... --mode agent
```

Outcomes: `supported_diagnosis`, `conflicting_evidence`, `insufficient_evidence`, `budget_exhausted`, or `awaiting_followup` when the agent asked the customer for a check. Every finding cites `cik-ev:` references that `python -m kit.bundle inspect ARCHIVE --ref REF` resolves against the same archive. A citation proves only that the value exists; the statement says how the values lead to the conclusion.

## Follow-up checks (customer)

When triage needs one more fact, it sends you a request file naming one of three read-only checks:

```sh
uv run python -m kit.triage.followup list
uv run python -m kit.triage.followup run --request followup-request.json --config ~/acme-install/install.toml
uv run python -m kit.bundle review <bundle-id> --config ~/acme-install/install.toml
uv run python -m kit.bundle export <bundle-id> --config ~/acme-install/install.toml --out acme-followup.tar.gz
```

| check | touches | returns |
|---|---|---|
| `FUP-DB-PRIV` | your database, as the app role, catalog functions only | which of ESP's expected grants the role holds |
| `FUP-DEST-AUTH` | Brevo's account and list endpoints, from your workstation and the app's machine | HTTP status and Brevo's error code per call; no response body |
| `FUP-VOLUME` | `df`, `du`, `stat` on the app's `/data` over `fly ssh` | block and inode counts, the error-event file's size; no file names |

The runner refuses any check that is not on this list, whatever the request says. It prints exactly what it will touch before it runs. The request's "reason" is the vendor's text and changes nothing about what runs. The result is a bundle like any other: fixed fields, scanned, signed, and kept in your workspace until you export it.

## Fixing it

A diagnosis comes with a proposed remedy for you to review and apply yourself. Triage changes nothing. After applying it, run `python -m kit.verify run`: the new conformance report, not triage, shows the recovery.

## Where your data goes

- **To the model provider (Anthropic):** the bundle values the agent reads, so it can reason about them. This is the content-bearing channel.
- **To the vendor's Datadog:** metadata only. That is opaque run ids, check and rule ids, outcomes, token counts, cost, and latency, with no bundle value, hypothesis, diagnosis, or error message. The span builder refuses anything outside its allowlist.
- **To the vendor's case store:** the full investigation record, on the triage host, in owner-only files.

## The runtime

`triage/compose.yaml` runs triage on an internal network whose only way out is a proxy. The proxy allows `api.anthropic.com` and `api.datadoghq.com` on 443 and refuses everything else. `triage/isolation_test.py` proves it on every CI run: no credentials in the environment or on disk, direct egress fails, and the customer's Fly APIs, app, database and destination are refused. The control half confirms the allowed path really works.
