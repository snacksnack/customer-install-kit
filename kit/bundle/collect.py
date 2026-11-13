"""Collect a diagnostic bundle into the install workspace (RC1-642, ADR 0008).

The collector runs on the operator workstation, never inside ESP, so it
answers when ESP cannot: during a crash loop, a failed deploy, or a stopped
machine. Every source either contributes a file or is listed as unavailable
with a reason. Every file is built from the allowlist, bounded in size, and
scanned before it is written; a file the scan flags is withheld and the
manifest says so.

Nothing is sent. The bundle stays in `<workspace>/bundles/<id>/` until the
operator reviews it and runs `export`.
"""

import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kit import preflight
from kit import registry as checks_registry
from kit.bundle import events, sources
from kit.bundle.allowlist import Allowlist
from kit.bundle.allowlist import load as load_allowlist
from kit.bundle.scan import SCANNER, Scanner
from kit.install import record as rec
from kit.install import secrets_file
from kit.install.config import InstallConfig
from kit.install.engine import REPORT_KEY, _http_status
from kit.install.fly import Fly
from kit.verify import signing

SCHEMA = "cik.bundle/1"
FILE_SCHEMA = "cik.bundle-file/1"
BUNDLES_DIR = "bundles"
FILES_DIR = "files"
MANIFEST = "manifest.signed.json"
PUBLIC_KEY_FILE = "report-key.pub.json"
REF_PREFIX = "cik-ev:"
CASE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
BUNDLE_ID = re.compile(r"^diag-\d{8}T\d{6}Z-[0-9a-f]{6}$")
KIT_VERSION = "0.1.0"

PERMISSIONS = (
    "Fly: read the app's status, machines, releases, secret NAMES, and log buffer "
    "(an app-scoped deploy token is enough; no org-wide token)",
    "Fly: `fly ssh console` to the app's machine, running one read-only command: "
    "`tail -c N` of the error-event file on the volume",
    "HTTPS GET of the app's public /healthz",
    "Read the install workspace: install-record.json, preflight reports, the "
    "latest conformance report, and the secrets file (values are used only to "
    "scan the bundle for them; they are never written)",
    "Read the install's report key to sign the manifest",
)
NOT_DONE = (
    "No database connection, no ESP API call beyond /healthz, no write to the app "
    "or the machine, no upload: the bundle stays in the workspace until export.",
)


class CollectError(Exception):
    pass


@dataclass
class Deps:
    fly: Fly | None = None
    http_status: Callable[[str], int] = _http_status
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    clock: Callable[[], float] = time.monotonic
    say: Callable[[str], None] = print
    token: Callable[[], str] = lambda: secrets.token_hex(3)


@dataclass
class Plan:
    """One source to run: its name and a thunk returning a SourceResult."""

    name: str
    run: Callable[[], sources.SourceResult]
    purpose: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def file_text(payload: dict[str, Any]) -> str:
    """How every bundle file is serialized: deterministic and readable."""
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bundle_digest(envelope: dict[str, Any]) -> str:
    """The bundle's identity: the sha256 of the signed manifest's payload
    bytes. The manifest lists every file's sha256, so this covers them all,
    and it does not change when the bundle is archived or extracted."""
    return "sha256:" + sha256_hex(envelope["payload"].encode())


def ref(digest: str, file: str, pointer: str = "") -> str:
    """A stable evidence reference: bundle digest, file, JSON pointer."""
    return f"{REF_PREFIX}{digest}/{file}#{pointer}"


def _secret_values(values: dict[str, str]) -> set[str]:
    return preflight.secret_values(values) | {v for v in values.values() if len(v) >= 8}


class Collector:
    def __init__(self, config: InstallConfig, deps: Deps | None = None,
                 allow: Allowlist | None = None):
        self.cfg = config
        self.deps = deps or Deps()
        self.allow = allow or load_allowlist()
        if self.deps.fly is None:
            self.deps.fly = Fly(sources.timed_runner(self.allow.bounds.source_timeout_s))
        self.record = rec.load(config.record_path) or {}
        self.scanner = Scanner(_secret_values(secrets_file.read(config.secrets_file)))

    # -- plan -----------------------------------------------------------------

    def _plans(self) -> tuple[list[Plan], dict[str, str], Any]:
        fly, app, allow, work = self.deps.fly, self.cfg.app, self.allow, self.cfg.workdir
        reg = checks_registry.load()
        purposes = {n: s.purpose for n, s in allow.sources.items()}
        # Health first: the profile scales to zero and `fly ssh` cannot reach a
        # suspended machine; a request through Fly's proxy wakes it (RC1-641).
        return [
            Plan("health", lambda: sources.health(
                self.deps.http_status, f"{self.cfg.public_url}/healthz"),
                 "Liveness of the web process, as the customer's users would see it."),
            Plan("fly_status", lambda: sources.fly_status(fly, app, allow)),
            Plan("fly_machines", lambda: sources.fly_machines(fly, app, allow)),
            Plan("fly_releases", lambda: sources.fly_releases(fly, app, allow)),
            Plan("fly_secrets", lambda: sources.fly_secrets(fly, app, allow)),
            Plan("platform_log", lambda: sources.platform_log(fly, app, allow),
                 "ESP error events (validated per schema version) and startup exception "
                 "TYPES from the platform's short log buffer. Log text is not kept."),
            Plan("file_sink", lambda: sources.file_sink(fly, app, allow),
                 "ESP error events from the file sink on the volume, read even when ESP "
                 "is down. Validated per schema version; non-conforming records dropped "
                 "and counted."),
            Plan("install_record", lambda: sources.install_record(self.cfg.record_path, allow)),
            Plan("preflight_operator", lambda: sources.preflight(
                work / "preflight-operator.json", "preflight_operator", reg),
                 "The operator-side preflight report, re-validated against this kit's "
                 "check registry."),
            Plan("preflight_runtime", lambda: sources.preflight(
                work / "preflight-runtime.json", "preflight_runtime", reg),
                 "The in-machine preflight report from the last install, re-validated."),
            Plan("conformance", lambda: sources.conformance(work, allow)),
        ], purposes, reg

    # -- run ------------------------------------------------------------------

    def collect(self, case: str | None = None) -> Path:
        if case is not None and not CASE.match(case):
            raise CollectError("case must be a short slug: lowercase letters, digits, -")
        key_path = self.cfg.workdir / REPORT_KEY
        if not self.record.get("report_key") or not key_path.exists():
            raise CollectError(f"no report key ({key_path}); run kit.install install first")
        key = signing.load_private(key_path)

        started = self.deps.now()
        bundle_id = f"diag-{started.strftime('%Y%m%dT%H%M%SZ')}-{self.deps.token()}"
        out = self.cfg.workdir / BUNDLES_DIR / bundle_id
        (out / FILES_DIR).mkdir(parents=True)

        bounds = self.allow.bounds
        plans, purposes, reg = self._plans()
        t0 = self.deps.clock()
        entries, files, total_bytes = [], [], 0
        for plan in plans:
            purpose = plan.purpose or purposes.get(plan.name, "")
            if self.deps.clock() - t0 > bounds.total_timeout_s:
                result = sources.SourceResult(plan.name, unavailable="total_time_budget")
            else:
                self.deps.say(f"collecting {plan.name}")
                result = plan.run()
            entry: dict[str, Any] = {"source": plan.name, "purpose": purpose,
                                     "seconds": result.seconds}
            if result.unavailable:
                entry |= {"status": "unavailable", "reason": result.unavailable}
                entries.append(entry)
                continue
            name = f"{FILES_DIR}/{plan.name}.json"
            payload = {"schema": FILE_SCHEMA, "source": plan.name, "data": result.data}
            text = file_text(payload)
            data = text.encode()
            hits = self.scanner.scan(payload, text)
            entry |= {"counts": result.counts, "dropped": result.dropped}
            if hits:
                entry |= {"status": "withheld", "reason": "scanner_finding",
                          "findings": [h.as_dict() for h in hits]}
            elif len(data) > bounds.max_file_bytes:
                entry |= {"status": "withheld", "reason": "over_file_bound",
                          "bytes": len(data)}
            elif total_bytes + len(data) > bounds.max_bundle_bytes:
                entry |= {"status": "withheld", "reason": "over_bundle_bound",
                          "bytes": len(data)}
            elif len(files) + 1 > bounds.max_files:
                entry |= {"status": "withheld", "reason": "over_file_count"}
            else:
                (out / name).write_bytes(data)
                total_bytes += len(data)
                entry |= {"status": "included", "file": name, "bytes": len(data),
                          "sha256": sha256_hex(data)}
                files.append(name)
            entries.append(entry)

        pub = {"algorithm": self.record["report_key"]["algorithm"],
               "public_key": self.record["report_key"]["public_key"],
               "fingerprint": self.record["report_key"]["fingerprint"]}
        (out / PUBLIC_KEY_FILE).write_text(file_text(pub))

        manifest = self._manifest(bundle_id, case, started, entries, reg)
        # The manifest is scanned like any file; it holds only names, counts
        # and hashes, so a hit here is a kit bug and stops the collection.
        if self.scanner.scan(manifest, file_text(manifest)):
            raise CollectError("the manifest itself tripped the scanner; refusing to sign")
        envelope = signing.sign(manifest, key)
        (out / MANIFEST).write_text(file_text(envelope))
        self.deps.say(f"bundle {bundle_id}: {len(files)} files, {total_bytes} bytes, "
                      f"digest {bundle_digest(envelope)}")
        return out

    def _manifest(self, bundle_id: str, case: str | None, started: datetime,
                  entries: list[dict[str, Any]], reg) -> dict[str, Any]:
        release = self.record.get("release") or {}
        return {
            "schema": SCHEMA,
            "bundle_id": bundle_id,
            "case": case,
            "install_id": self.record.get("install_id"),
            "app": self.cfg.app,
            "collected_started_at": _stamp(started),
            "collected_finished_at": _stamp(self.deps.now()),
            "versions": {
                "kit": KIT_VERSION,
                "release": release.get("version"),
                "release_image": release.get("image"),
                "check_registry": reg.version,
                "allowlist": self.allow.version,
                "error_event_schemas": sorted(events.SUPPORTED_VERSIONS),
            },
            "collector": {
                "runs_on": "the operator workstation, outside the ESP process",
                "permissions": list(PERMISSIONS),
                "does_not": list(NOT_DONE),
            },
            "bounds": vars(self.allow.bounds),
            "scanner": {
                "name": SCANNER,
                "detectors": self.scanner.detector_names(),
                "install_secret_variants_checked": self.scanner.secret_value_count,
                "claim": "A file is included only if no detector fired on its bytes. "
                         "This is bounded coverage by these detectors, not proof that "
                         "nothing sensitive is present.",
            },
            "evidence_refs": {
                "format": f"{REF_PREFIX}<bundle digest>/<file>#<JSON pointer>",
                "bundle_digest": "sha256 of this manifest's signed payload bytes",
            },
            "sources": entries,
        }
