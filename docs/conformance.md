# Conformance: does the installed migration workflow work?

For the customer operator, after `kit.install install`. A green `/healthz` only says the web process is up. Conformance runs a small, real migration through the application you installed and checks the result at the destination. Decision record: [ADR 0007](adr/0007-conformance-and-report-integrity.md).

```sh
uv run python -m kit.verify run --config ~/acme-install/install.toml
```

Exit 0 pass, 1 fail, 2 insufficient evidence, 3 kit error.

## What it does

1. **Release.** Your machines run the image digest that install verified.
2. **Health.** `/healthz` is recorded. It is never enough on its own.
3. **Identity (password mode).** An anonymous write is refused, a wrong password is refused, your configured password signs in, and the sign-in is written to the audit log.
4. **Migration, inside your machine, with fake contacts.**
   - A synthetic export is generated for this run only: addresses look like `cik-<run>-0001@example.com`, and the list and draft campaign are named `cik-conformance <run>`.
   - The approval gate must refuse the unapproved spec and a spec changed after approval.
   - The approved spec then migrates suppressions first, writes everything else, and proves a second pass would write nothing.
   - Reconciliation checks counts and that every suppressed address is non-mailable.
5. **Cleanup.** The run's contacts, list and campaign are deleted from your destination, and anything left is reported. Nothing outside the run's namespace is touched.

Each check is `pass`, `fail` or `insufficient_evidence`. A check that could not be judged, including any whose prerequisite failed, is never counted as a pass.

## What it changes in your environment

- **Audit log:** two records per run (`sign_in`, `sign_out`). The log is append-only by design, so they stay.
- **Destination:** fixture records exist only during the run and are deleted at the end; CNF-040 reports any that remain. No email is sent: campaigns are drafts.
- **Your app:** nothing. The spec the app serves and its configuration are not touched.

Needs `ESP_BREVO_API_KEY` in your secrets file (pushed to the app by install). Without it the migration is refused and conformance fails.

## The report

Written to `conformance/<run-id>/` next to `install.toml`:

- `report.signed.json`: the report, signed with your install's report key (`report-key.pem`, created by install, never leaves your workstation).
- `report.json`: the same content, readable.
- `evidence/`: the files the checks were judged from. Each one's sha256 is listed in the report.

Nothing is sent anywhere. To share a report:

```sh
uv run python -m kit.verify export <run-id> --config ~/acme-install/install.toml --out ~/share/<run-id>
# add --with-evidence to include the evidence files; the execution journal names your destination account
```

The first time you share, tell the vendor your report key fingerprint (`report_key.fingerprint` in `install-record.json`) over a separate channel, such as a call or a ticket.

## What the signature means

Anyone holding your install record can check a report:

```sh
uv run python -m kit.verify verify-report report.signed.json --record install-record.json
```

A valid signature shows the report is unmodified and was signed with your install's key. It does **not** show the observations are true: you control the environment and the key. This is integrity, not attestation.
