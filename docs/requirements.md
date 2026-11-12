# Customer requirements: ESP Migration Agent v1 profile

<!-- Generated from kit/checks.toml by `uv run python -m kit requirements`. Do not edit by hand. -->

Registry version 1. Every requirement below is a preflight check with a stable ID; the same ID appears in preflight reports, conformance results and diagnostic bundles.

Outcomes: **pass**; **fail** (the requirement is not met); **not applicable** (the check does not apply to this profile or configuration); **unknown** (the check applies but its evidence could not be obtained, for example a timeout or a prerequisite check that did not pass). Preflight exits 0 when every required check passes or is not applicable, 1 when any required check fails, 2 when none fails but at least one is unknown, and 3 on a kit error.

Secret values are never recorded. Evidence is limited to the fields listed per check.

## Summary

| ID | Requirement | Severity | Where |
|---|---|---|---|
| ENV-001 | Required application secrets are set | required | runtime |
| ENV-002 | Session secret is not the development default | required | runtime |
| ENV-003 | Model API key is set | advisory | runtime |
| DB-001 | Owner role connects to Postgres over TLS | required | operator |
| DB-002 | Postgres server version is supported | required | operator |
| DB-003 | Owner role can install the schema and create the app role | required | operator |
| DB-004 | Required Postgres extensions are available | required | operator |
| NET-001 | Destination ESP API is reachable over verified TLS | required | runtime |
| NET-002 | Model API is reachable over verified TLS | advisory | runtime |
| RT-001 | CPU architecture is amd64 | required | runtime |
| RT-002 | Machine is sized at 512 MB or more | required | runtime |
| RT-003 | Data volume is writable with free space | required | runtime |
| RT-004 | Error-event file sink is writable | advisory | runtime |

## On the operator workstation

Run with `uv run python -m kit preflight --context operator`. These checks use install-time credentials (the database owner URL) that never go into the app.

### DB-001: Owner role connects to Postgres over TLS

**Required** · profiles: v1

- **Why:** Installation applies the schema and creates the app's least-privilege role as the database owner, over an encrypted connection.
- **How it is checked:** Opens one connection with ESP_DATABASE_OWNER_URL and records whether it authenticated and whether TLS is in use. A failure is recorded as a class (auth, database, dns, tls, timeout, network), never as the driver's message.
- **Access needed:** The owner connection URL, held on the operator workstation only. Never copied into the app.
- **If it fails:** auth: check the owner role name and password. database: check the database name in the URL. dns or network: check the host and port, and that the provider allows connections from this network. tls or connected without TLS: add sslmode=require (or verify-full) to the URL.
- **Evidence recorded:** `connected`, `tls`, `sqlstate`, `error_class`

### DB-002: Postgres server version is supported

**Required** · profiles: v1 · after: DB-001

- **Why:** The schema's triggers use EXECUTE FUNCTION, which needs Postgres 11 or later.
- **How it is checked:** Reads server_version_num over the owner connection.
- **Access needed:** The owner connection URL (see DB-001).
- **If it fails:** Upgrade the database to Postgres 11 or later (the vendor tests on the provider's current default major version).
- **Evidence recorded:** `server_version_num`, `minimum`

### DB-003: Owner role can install the schema and create the app role

**Required** · profiles: v1 · after: DB-001

- **Why:** Setup creates tables in the public schema and a separate login role for the app, so the app never connects as the owner.
- **How it is checked:** Asks Postgres whether the owner role holds CREATE on schema public and the CREATEROLE attribute. Creates nothing.
- **Access needed:** The owner connection URL (see DB-001).
- **If it fails:** Run setup as a role with CREATE on schema public and CREATEROLE (on Neon, the project owner role has both), or have a DBA grant them.
- **Evidence recorded:** `can_create_in_public`, `can_create_role`

### DB-004: Required Postgres extensions are available

**Required** · profiles: v1

- **Why:** Lists extensions the schema needs. The v1 schema needs none, so this check reports not applicable until a release adds one.
- **How it is checked:** If the release requires extensions, looks each up in pg_available_extensions over the owner connection. Needs no connection when none are required, so it does not wait on DB-001.
- **Access needed:** The owner connection URL (see DB-001).
- **If it fails:** Ask the database provider to enable each missing extension, or install it as a superuser.
- **Evidence recorded:** `required`, `missing`

## Inside a machine of the customer's app

Run with `python -m kit preflight --context runtime` inside a machine of the app, so the probes see the app's real network path, secrets, architecture, memory and volume.

### ENV-001: Required application secrets are set

**Required** · profiles: v1

- **Why:** The app refuses logins without a review password, signs sessions with the session secret, and cannot write to the destination ESP without its API key.
- **How it is checked:** Checks that each named variable is present and non-empty in the runtime environment. Values are never read into the report.
- **Access needed:** None beyond running in a machine of the customer's app.
- **If it fails:** Set each missing variable with `fly secrets set NAME=... -a <app>` before installing.
- **Evidence recorded:** `present`, `missing`

### ENV-002: Session secret is not the development default

**Required** · profiles: v1

- **Why:** The app falls back to a public development secret; sessions signed with it can be forged by anyone who has read the source.
- **How it is checked:** Compares ESP_REVIEW_SESSION_SECRET with the known public default and reports only whether they match. Unknown when the variable is unset (ENV-001 reports that).
- **Access needed:** None beyond running in a machine of the customer's app.
- **If it fails:** Generate a random secret (for example `python -c 'import secrets; print(secrets.token_urlsafe(48))'`) and set it as ESP_REVIEW_SESSION_SECRET.
- **Evidence recorded:** `is_default`

### ENV-003: Model API key is set

**Advisory** · profiles: v1

- **Why:** The discovery report's narrated summary needs the model API. Without the key the report still renders, minus the narration.
- **How it is checked:** Checks that ESP_ANTHROPIC_API_KEY is present and non-empty. The value is never read into the report.
- **Access needed:** None beyond running in a machine of the customer's app.
- **If it fails:** Set ESP_ANTHROPIC_API_KEY with `fly secrets set` if you want narrated discovery reports; otherwise no action.
- **Evidence recorded:** `present`, `missing`

### NET-001: Destination ESP API is reachable over verified TLS

**Required** · profiles: v1

- **Why:** The migration writes contacts, lists and draft campaigns to the destination ESP over HTTPS.
- **How it is checked:** Resolves the API host, opens TCP to port 443, and completes a TLS handshake verifying the certificate against the system trust store. Sends no HTTP request and no credential.
- **Access needed:** Outbound network access from the app's machines.
- **If it fails:** dns: check the machine's resolver. tcp: allow outbound 443 to the host in any egress policy. tls: the certificate did not verify; a proxy or custom trust store may be intercepting TLS.
- **Evidence recorded:** `host`, `port`, `reached`, `failed_stage`, `error`, `tls_version`

### NET-002: Model API is reachable over verified TLS

**Advisory** · profiles: v1

- **Why:** Narrated discovery reports call the model API. The migration itself does not need it.
- **How it is checked:** Same as NET-001, against the model API host.
- **Access needed:** Outbound network access from the app's machines.
- **If it fails:** Same as NET-001. If the customer does not want model calls from this environment, leave ESP_ANTHROPIC_API_KEY unset and ignore this check.
- **Evidence recorded:** `host`, `port`, `reached`, `failed_stage`, `error`, `tls_version`

### RT-001: CPU architecture is amd64

**Required** · profiles: v1

- **Why:** Release images are built and signed for amd64 only (ADR 0001).
- **How it is checked:** Reads the machine architecture reported by the kernel.
- **Access needed:** None beyond running in a machine of the customer's app.
- **If it fails:** Run the app on amd64 machines; Fly's shared-cpu presets are amd64.
- **Evidence recorded:** `machine`

### RT-002: Machine is sized at 512 MB or more

**Required** · profiles: v1

- **Why:** The app is sized and tested at shared-cpu-1x / 512 MB (ADR 0001).
- **How it is checked:** Reads the memory limit from cgroup v2, then cgroup v1, then /proc/meminfo, and records which source answered. The floor is 450 MiB, not 512: a 512 MB Fly machine reports MemTotal 472,532 kB because the kernel reserves memory (measured on cik-esp, 2026-11-11).
- **Access needed:** None beyond running in a machine of the customer's app.
- **If it fails:** Scale the machines to at least 512 MB: `fly scale memory 512 -a <app>`.
- **Evidence recorded:** `memory_bytes`, `source`, `minimum_bytes`

### RT-003: Data volume is writable with free space

**Required** · profiles: v1

- **Why:** The kit's collector and the app's optional error-event file write to the data volume.
- **How it is checked:** Writes, flushes, fsyncs and closes a small temporary file at the path, then deletes it, and reads the free space. A full disk often fails only at flush or close, so all three are checked.
- **Access needed:** None beyond running in a machine of the customer's app with the volume mounted.
- **If it fails:** Missing path: add the [mounts] section to fly.toml and attach a volume. Not writable: check the mount. Low free space: extend the volume with `fly volumes extend`.
- **Evidence recorded:** `path`, `exists`, `writable`, `errno`, `free_bytes`, `minimum_free_bytes`

### RT-004: Error-event file sink is writable

**Advisory** · profiles: v1

- **Why:** When ESP_ERROR_EVENTS_PATH is set, the app also appends error events to that file. Events always reach stderr regardless, so this is advisory.
- **How it is checked:** If ESP_ERROR_EVENTS_PATH is set, runs the RT-003 write test in its directory. Not applicable when unset.
- **Access needed:** None beyond running in a machine of the customer's app.
- **If it fails:** Point ESP_ERROR_EVENTS_PATH at a file on the data volume (for example /data/esp-error-events.jsonl), or unset it.
- **Evidence recorded:** `path`, `exists`, `writable`, `errno`, `free_bytes`, `minimum_free_bytes`
