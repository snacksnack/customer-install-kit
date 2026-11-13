# ADR 0008: Diagnostic bundles are built from an allowlist, collected outside ESP, and reviewed before they leave

Status: proposed (RC1-642)

## Decision

**The collector runs on the operator workstation, never inside ESP.** `python -m kit.bundle collect` uses only what the customer already holds: an app-scoped Fly deploy token, the install workspace, and the app's public URL. It reads:

- Fly status, machines, releases, and secret names (the platform API, which answers while ESP crash-loops),
- the platform log buffer,
- ESP's error-event file on the volume, over `fly ssh` with one read-only `tail -c`,
- `/healthz`,
- the install record, the two preflight reports, and the latest conformance report.

It opens no database connection and calls nothing in ESP beyond `/healthz`. It writes nothing to the app or the machine and uploads nothing. The manifest lists these permissions and these non-actions verbatim.

**Every source contributes a file or an explicit reason it could not.** The reasons are `timeout`, `not_found`, `fly_logs_failed`, `machine_unreachable`, `sink_file_absent`, `no_conformance_run`, `total_time_budget`, or `error:<ExceptionClass>`. A source never raises into the collector, and the exception message is never kept, because messages carry hosts and roles.

**Built, not scrubbed.** `kit/bundle/allowlist.toml` (versioned, `version = 1`) lists the exact leaf paths each source may contribute, with a stated purpose per source. `project()` builds new output from those paths only, so a field Fly or ESP adds tomorrow stays out until someone lists it. A path that lands on a mapping or list yields nothing; `{keys}` keeps key names and drops their values (machine `config.env`). A bump in the allowlist version is recorded in the manifest, and `inspect` refuses a version it does not know.

Log text is never kept. The platform log contributes three things:

- validated error events,
- exception TYPES that ended a traceback (never the message after the colon),
- buffer statistics.

**Error events are validated against the kit's own copy of ESP's contract** (`kit/bundle/events.py`, schema v1 and v2). A record is kept only if:

- every field is in its version's field set,
- every value is an enum member, a code, or an opaque identifier of the documented shape,
- every route segment is a literal, a version, or a `{placeholder}`.

Anything else is dropped and counted by reason: `unknown_field`, `bad_route`, `bad_op`, `unsupported_version`, `malformed_json`, `over_limit`. An unknown schema version is dropped, never guessed at. Both channels are read independently of app health: the platform buffer (ESP's stderr sink) and the file sink on the volume (`ESP_ERROR_EVENTS_PATH=/data/esp-error-events.jsonl`, added to the install template here).

**Bounded.** These limits come from `[bounds]` in the allowlist:

- 16 files,
- 256 KiB per file,
- 1 MiB per bundle,
- 500 events per sink,
- 256 KiB read from the sink's tail (a first line cut by `tail` is discarded),
- 90 s per source and 300 s overall.

A file over a bound is withheld and the manifest says which bound.

**An independent scanner is the check behind the allowlist.** `kit/bundle/scan.py` reuses compatlab's redaction scanner (api-compatibility-lab, pinned to commit `cc37d57`). It is separate code that covers:

- emails, cards (Luhn), SSNs, phones, IPs, bearer tokens and base64-wrapped versions of all of them,
- the kit's own secret shapes: Postgres URL with password, Brevo `xkeysib-`, Anthropic `sk-ant-`, Fly tokens, PEM private keys,
- the install's own secret values, in the encodings a value picks up in transit (raw, case-folded, URL-encoded, JSON-escaped, hex, and base64 at all three byte alignments, standard and URL-safe).

A file with any finding is withheld. The manifest records the JSON path and detector name, never a preview of the value. The manifest itself is scanned before signing, and a hit there stops collection. The manifest states the claim: bounded coverage by these detectors, not proof of absence.

**No keyed fingerprints in v1.** Correlating a secret across bundles ("is this the same key as last time?") was not needed by any Phase 0B family. The secret-related signals that matter are already in the bundle without any value: which secret names exist and whether each is deployed (`fly_secrets`), and the destination's 401/`unauthorized` event. A keyed fingerprint would add a key to manage and a correlation surface. If a later phase needs one, it gets a per-install HMAC key that never leaves the workstation, and still no fingerprinting of PII.

**Signed manifest; evidence references stay stable.** `manifest.signed.json` is a `cik.signed/1` envelope (ADR 0007's signing, the install's report key) over `cik.bundle/1`. That manifest holds:

- the bundle and install IDs, plus an optional case slug,
- the kit, release, check-registry, allowlist, and event-schema versions,
- the collector's permissions,
- the bounds,
- the scanner coverage,
- per source: purpose, status, file, sha256, bytes, kept counts, and drop counts.

The bundle digest is the sha256 of the signed payload bytes. It covers every file through their hashes and does not change when the bundle is archived or extracted. An evidence reference is `cik-ev:<bundle digest>/<file>#<JSON pointer>`, and `inspect --ref` resolves it against an untrusted archive.

**Review before export; no upload.** `review` prints, file by file, what would leave and why: purpose, size, what was kept, what was dropped, and what was unavailable or withheld. `export` writes a deterministic `.tar.gz` (sorted members, zeroed times and owners, gzip mtime 0), so the same bundle always yields the same bytes. Nothing in the kit sends it anywhere.

**The vendor side treats an archive as hostile.** `inspect` checks, in order:

- the archive size cap (4 MiB),
- bounded decompression, so a gzip bomb stops at the budget,
- members read into memory and never extracted,
- only regular files at the exact names a bundle holds (`manifest.signed.json`, `report-key.pub.json`, `files/<source>.json`), with no traversal, absolute path, link, directory, or duplicate,
- a size bound per member and in total,
- the signature against the bundled key, and against `--fingerprint` when given,
- every listed file present with a matching sha256, and nothing unlisted.

Bundle content is parsed as JSON and never executed. The bundled public key only makes the bundle self-consistent. As with conformance reports, the customer's fingerprint must be compared out of band, and a re-signed bundle is caught only that way (tested).

## Live evidence (RC1-642, 2026-11-13, `cik-esp-p3`, v0.1.4)

| Case | Bundle | What the bundle showed |
|---|---|---|
| healthy, before the sink was configured | `diag-…004450Z-8eaf3b` | 10 files. `file_sink` **unavailable: `sink_file_absent`**. Scanner: no findings on real data. Export byte-identical across two runs; `inspect` valid; a re-tarred bundle refused. |
| startup failure: `esp_app` password rotated on the branch, machine restarted | `diag-…005337Z-7219b5` | `/healthz` **0** (unreachable). Machine events `exit` with `exit_code 1, restarting true`; health check `warning`. Startup exception type `psycopg_pool.PoolTimeout`, with no message kept. **File sink: 7** `db.ready_check db connect_class=auth`; platform buffer: **1** (100 lines covered 55 s). Repaired by install converge. |
| live canaries: fake Postgres URL, Brevo key, email, SSN and card, written into ESP's stderr (`/proc/<pid>/fd/2`) and appended to the sink, including base64-wrapped and event-shaped variants | `diag-…010233Z-65b4c7` | Both sinks dropped and counted all 4 event-shaped canaries (`unknown_field`, `bad_route`, `bad_op`, `malformed_json`). **0 of 44 variants** of the 6 values found in the bundle files, manifest, review output, or decompressed export. The independent scanner found nothing in any written file. |
| family 1: `REVOKE INSERT ON review_audit FROM esp_app`, sign-in | `diag-…010301Z-6e7edf` | Sign-in 500; `audit.append db sqlstate=42501` in both sinks; the ref `…/files/file_sink.json#/data/error_events/11` resolves from the exported archive. Grant restored. |
| family 3: volume filled (`dd` to 100%), events triggered | `diag-…010453Z-9d2987` | The platform log carries **`errorevents.sink storage errno_name=ENOSPC`**. The file sink stopped at 4096 bytes, and its last record was cut mid-write (dropped and counted as `malformed_json`). The first attempt (`…010422Z`) showed no failure: one 230-byte append still fit in the file's last block. Filler removed. |
| family 2: destination (Brevo) key deactivated by the customer, conformance run | `diag-…011012Z-a45f3f` | Conformance `fail` (CNF-030 `execute_failed`), and that verdict is in the bundle. **File sink: 2** `destination.request http status=401 provider_code=unauthorized route=GET /contacts/lists`; **platform log: 0**, because the executor runs over `fly ssh` and its stderr goes to the SSH session, not the platform. The ref `…/files/file_sink.json#/data/error_events/17` resolves from the exported archive. Key reactivated afterwards. |

**Findings.**

- **The file sink is the durable channel, but not on a full disk.** Under load, the platform buffer's 100 lines covered 2.8 s (1 of 25 audit events); in the crash loop they covered 55 s, against 7 sink events. On a full volume the sink cannot write, and the only witness is that short buffer. R4 holds, because the ENOSPC event reached the bundle through stderr. It holds only if the bundle is collected promptly after a storage fault.
- **Each channel saw something the other missed.** The destination 401 reached only the file sink, because work run over `fly ssh` never touches the platform log. The ENOSPC reached only stderr. Neither channel alone covers families 2 and 3, which is why the collector reads both.
- **ESP's sink leaves a partial last line after ENOSPC.** The next successful append joins it, so one valid event after recovery is lost as `malformed_json`. That is an ESP follow-up (start each append with a newline when the file does not end in one), not a kit change. The kit counts the loss.
- **`fly ssh` can fail on a Fly API tunnel timeout** even with the app healthy (seen once during repair). The file sink reports `machine_unreachable`, never a guess.

## Not done here

- OOM and wrong-architecture cases. Fly's machine events already carry `oom_killed` and exit codes, and the allowlist keeps them. Cases follow when a later phase injects them.
- Vendor-side triage of bundles (Phase 5). `inspect` is the trust gate only.
