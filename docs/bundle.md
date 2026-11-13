# Diagnostic bundles: evidence you choose to share

For the customer operator, when something is wrong and you want the vendor to help without giving them access. The bundle is collected on your workstation, built only from listed fields, scanned, and kept in your install workspace until you export it. Nothing is uploaded. Decision record: [ADR 0008](adr/0008-diagnostic-bundles.md).

```sh
uv run python -m kit.bundle collect --config ~/acme-install/install.toml [--case startup-failure]
uv run python -m kit.bundle review  <bundle-id> --config ~/acme-install/install.toml
uv run python -m kit.bundle export  <bundle-id> --config ~/acme-install/install.toml --out acme-diag.tar.gz
```

Exit 0 ok, 3 kit error.

## It works when the app does not

The collector never runs inside the application. It reads the hosting platform (Fly status, machines, releases, secret names, the log buffer), the application's error-event file on its volume, `/healthz`, and the files `kit.install` and `kit.verify` already wrote to your workspace. During a crash loop, a failed deploy, or a stopped machine, every source that can still answer does. Every source that cannot is listed with the reason (for example `machine_unreachable`), so a missing file is never silent.

Collect soon after a failure. The platform keeps only about the last 100 log lines, which can be seconds under load. The error-event file on the volume keeps more, except when the volume itself is full.

## Permissions it uses

- An app-scoped Fly deploy token: read status, machines, releases, secret **names**, and logs, and open `fly ssh` to run one read-only `tail -c` of the error-event file.
- HTTPS GET of the app's `/healthz`.
- Your install workspace: the install record, preflight and conformance reports, and the report key (to sign the manifest). The secrets file is read only so the scanner can look for those values; they are never written.

It opens no database connection, writes nothing to the app or the machine, and sends nothing anywhere.

## What can be in it

Only the fields listed in `kit/bundle/allowlist.toml`, each source with a stated purpose. A field that is not listed is not copied, whatever it holds. In particular:

- **Secrets:** names and deploy status only. Fly's per-secret digest is dropped. Machine environment variables keep their names, never their values.
- **Logs:** no log text. Only error events that match the application's published event contract (codes and enums: operation, error class, SQLSTATE, HTTP status, provider code, errno name, route template), and the TYPE of any startup exception, never its message. Records that do not match are dropped and counted.
- **Database:** its schema version and ownership, never its host or credentials.

Before a file is written, an independent scanner checks it for credentials, personal data, and your own secret values in common encodings. A file with any finding is **withheld**, and `review` shows where and which detector fired, never the value. A clean scan is bounded coverage by those detectors, not proof that nothing sensitive is present. Read the files before you export.

## Review, then export

`review` lists every file with its purpose and size, what was kept and dropped, and every source that was unavailable or withheld. The files are plain JSON under `<workspace>/bundles/<bundle-id>/files/`. `export` writes one archive. Share it, and send the report key fingerprint from `install-record.json` through a separate channel.

## For the vendor

```sh
uv run python -m kit.bundle inspect acme-diag.tar.gz --fingerprint sha256:<from the customer>
uv run python -m kit.bundle inspect acme-diag.tar.gz --ref 'cik-ev:sha256:<digest>/files/file_sink.json#/data/error_events/3'
```

`inspect` treats the archive as untrusted: it enforces a size cap and bounded decompression, reads members into memory without extracting them, accepts only the exact file names a bundle holds, checks the signature and every file hash, and refuses anything unlisted. Exit 0 valid, 4 refused. Evidence references (`cik-ev:<bundle digest>/<file>#<JSON pointer>`) stay valid across export and import, because the digest is the signed manifest's.
