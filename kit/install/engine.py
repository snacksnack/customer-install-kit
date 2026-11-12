"""Install, rollback and teardown, as the customer operator (RC1-640, ADR 0006).

Install is an ordered list of steps. Every step observes before it acts, so
running the whole list again after any failure converges: an existing app or
volume is reused (never duplicated), a working app-role URL is kept (never
re-passworded), unchanged secrets are not re-staged, and a machine already
running the target digest with nothing staged is not redeployed. The schema
step only ever migrates forward. No step resets or deletes data.

Recovery is three planes, kept apart on purpose:
- application version: a deploy of another verified digest (rollback);
- database schema/data: forward-only here; a rollback the schema marker
  forbids stops with a restore path the customer owns;
- destination side effects (Brevo writes): never reversed by any of this.
"""

import base64
import hashlib
import io
import json
import os
import secrets
import tarfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from psycopg import sql

from kit import preflight, registry
from kit.install import record as rec
from kit.install import release as rel
from kit.install import secrets_file
from kit.install.config import InstallConfig
from kit.install.esp_image import EspImage
from kit.install.fly import Fly
from kit.model import Context
from kit.probes import PROBES, ProbeEnv

KIT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = Path(__file__).with_name("fly.toml.tmpl")
REPORT_KEY = "report-key.pem"
PUSHED_DIGESTS = ".cik-pushed.sha256"
HEALTH_ATTEMPTS = 30
HEALTH_INTERVAL_S = 2.0
DEPLOY_SETTLE_ATTEMPTS = 20
DEPLOY_SETTLE_INTERVAL_S = 3.0

STEPS = (
    "verify_release",
    "report_key",
    "preflight_operator",
    "app",
    "volume",
    "schema",
    "app_role",
    "secrets",
    "deploy",
    "health",
    "preflight_runtime",
)


class InstallError(Exception):
    """A step could not complete. The record says which; re-run to resume."""


class InjectedFailure(InstallError):
    """Deliberate mid-install failure (--fail-after), for the retry exercise."""


class RecoveryRequired(Exception):
    """The requested change cannot be made safely by redeploying an image."""


# -- seams (replaced in tests) -------------------------------------------


def _http_status(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError):
        return 0


def _db_connects(url: str) -> bool:
    try:
        with psycopg.connect(url, connect_timeout=10) as conn:
            conn.execute("SELECT 1")
        return True
    except psycopg.Error:
        return False


RUNTIME_FILES = (
    "__init__.py", "__main__.py", "model.py", "preflight.py", "registry.py",
    "report.py", "requirements_doc.py", "checks.toml",
)


def runtime_bundle() -> str:
    """The runtime-context kit (no `kit.install`), as base64 tar.gz. It
    comes from the operator's own checkout: the customer ships into their
    machine exactly the code they ran locally."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in RUNTIME_FILES:
            tar.add(KIT_ROOT / name, arcname=f"kit/{name}")
        for probe in sorted((KIT_ROOT / "probes").glob("*.py")):
            tar.add(probe, arcname=f"kit/probes/{probe.name}")
    return base64.b64encode(buf.getvalue()).decode()


def _runtime_preflight(fly: Fly, app: str, profile: str) -> dict[str, Any]:
    unpack = (
        "rm -rf /tmp/cik && mkdir -p /tmp/cik && cd /tmp/cik"
        f" && echo {runtime_bundle()} | base64 -d | tar xzf -"
    )
    fly.run("ssh", "console", "-a", app, "-C", f"sh -c '{unpack}'")
    run = (
        "cd /tmp/cik && PYTHONPATH=/tmp/cik /app/.venv/bin/python -m kit preflight"
        f" --context runtime --profile {profile} --json"
    )
    result = fly.run("ssh", "console", "-a", app, "-C", f"sh -c '{run}'", check=False)
    if result.code not in (preflight.EXIT_OK, preflight.EXIT_FAILED, preflight.EXIT_UNKNOWN):
        raise InstallError(f"runtime preflight could not run (exit {result.code})")
    start = result.stdout.find("{")
    if start < 0:
        raise InstallError("runtime preflight printed no report")
    return json.loads(result.stdout[start:])


@dataclass
class Deps:
    fly: Fly = field(default_factory=Fly)
    fetch_release: Callable[[str, Path], rel.Release] = rel.fetch_and_verify
    image: Callable[[str, str], EspImage] = EspImage
    http_status: Callable[[str], int] = _http_status
    db_connects: Callable[[str], bool] = _db_connects
    runtime_preflight: Callable[[Fly, str, str], dict[str, Any]] = _runtime_preflight
    sleep: Callable[[float], None] = time.sleep
    say: Callable[[str], None] = print


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


APP_ROLE = "esp_app"


def drop_role(owner_url: str, role: str) -> str:
    """Drop the app role and its grants, never data. Since Postgres 16 the
    role's creator holds ADMIN on it but is not a member, so DROP OWNED is
    refused until the owner grants itself membership (seen live on Neon,
    RC1-640). DROP OWNED would also drop anything the role owns, so a role
    that owns any object is refused outright: the app role should own
    nothing, and if it does, that is data the kit will not delete."""
    ident = sql.Identifier(role)
    with psycopg.connect(owner_url, autocommit=True) as conn:
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
            return "absent"
        owned = conn.execute(
            "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner"
            " WHERE r.rolname = %s", (role,)).fetchone()[0]
        if owned:
            raise InstallError(f"{role} owns {owned} relation(s); refusing to drop it (that"
                               " would drop data). Reassign them, then re-run teardown.")
        with conn.transaction():
            conn.execute(sql.SQL("GRANT {} TO CURRENT_USER").format(ident))
            conn.execute(sql.SQL("DROP OWNED BY {}").format(ident))
            conn.execute(sql.SQL("DROP ROLE {}").format(ident))
    return "dropped"


def _db_identity(url: str) -> dict[str, str]:
    """Where the database is, never how to log in to it."""
    parts = urlsplit(url)
    return {"host": parts.hostname or "", "database": parts.path.lstrip("/")}


class Installer:
    def __init__(self, config: InstallConfig, deps: Deps | None = None):
        self.cfg = config
        self.deps = deps or Deps()
        self.fly = self.deps.fly
        self.secrets = secrets_file.read(config.secrets_file)
        self.record = rec.load(config.record_path)
        self.release: rel.Release | None = None

    # -- plumbing ---------------------------------------------------------

    def _secret_values(self) -> set[str]:
        values = preflight.secret_values({**self.secrets})
        return values | {v for v in self.secrets.values() if len(v) >= 8}

    def _save(self) -> None:
        rec.save(self.cfg.record_path, self.record, self._secret_values())

    def _say(self, text: str) -> None:
        if any(v in text for v in self._secret_values()):
            text = "[output withheld: it contained a secret value]"
        self.deps.say(text)

    def _owner_url(self) -> str:
        url = self.secrets.get(secrets_file.OWNER_URL)
        if not url:
            raise InstallError(
                f"{secrets_file.OWNER_URL} is not in {self.cfg.secrets_file}; the database"
                " owner URL is needed at install time (it never leaves this workstation)"
            )
        return url

    def _image(self, release: rel.Release) -> EspImage:
        return self.deps.image(release.image_ref, self._owner_url())

    def _set_secrets(self, updates: dict[str, str]) -> None:
        secrets_file.update(self.cfg.secrets_file, updates)
        self.secrets.update(updates)

    def _verify(self, version: str) -> rel.Release:
        cache = self.cfg.workdir / ".cik-releases"
        return self.deps.fetch_release(version, cache)

    # -- install ----------------------------------------------------------

    def install(self, fail_after: str | None = None) -> int:
        if fail_after and fail_after not in STEPS:
            raise InstallError(f"--fail-after must be one of {', '.join(STEPS)}")
        if self.record and self.record["state"] == rec.STATE_TORN_DOWN:
            raise InstallError("this install was torn down; start from a new directory")
        if self.record is None:
            self.record = rec.new(uuid.uuid4().hex, self.cfg.profile, {
                "fly_org": self.cfg.fly_org, "app": self.cfg.app, "region": self.cfg.region,
                "volume": self.cfg.volume, "public_url": self.cfg.public_url,
            })
        elif self.record["config"]["app"] != self.cfg.app:
            raise InstallError("install.toml names a different app than install-record.json")
        self.record["state"] = rec.STATE_INSTALLING
        # The last version an install or rollback COMPLETED, not the one a
        # failed run started: `release` is written at verify time.
        previous = self.record.get("installed_version")
        self._save()
        for name in STEPS:
            try:
                getattr(self, f"_step_{name}")()
            except (InstallError, RecoveryRequired, rel.ReleaseRejected) as exc:
                rec.step(self.record, name, "failed", error=str(exc)[:500])
                self._save()
                raise
            except Exception as exc:  # noqa: BLE001 - recorded, then re-raised as a step failure
                rec.step(self.record, name, "failed", error=type(exc).__name__)
                self._save()
                raise InstallError(f"step {name} failed: {exc}") from exc
            self._save()
            if name == fail_after:
                raise InjectedFailure(f"deliberate failure after step {name} (--fail-after)")
        failing = self.record["runtime_preflight"]["failing_required"]
        self.record["state"] = rec.STATE_NOT_READY if failing else rec.STATE_INSTALLED
        if previous != self.release.version:
            self.record["history"].append({
                "action": "install" if previous is None else "upgrade",
                "from": previous, "to": self.release.version, "at": rec.now(),
            })
        self.record["installed_version"] = self.release.version
        self._save()
        return 1 if failing else 0

    def _step_verify_release(self) -> None:
        self.release = self._verify(self.cfg.release)
        # `release` is what is DEPLOYED; it changes only once a deploy is
        # confirmed, so a refused or half-done install never misreports it.
        self.record["target_release"] = self.release.to_json()
        rec.step(self.record, "verify_release", "done", digest=self.release.image_digest)
        self._say(f"verified v{self.release.version} {self.release.image_ref}")

    def _step_report_key(self) -> None:
        """ADR 0003: per-install keypair, generated here, private half never
        leaves the customer's workstation."""
        path = self.cfg.workdir / REPORT_KEY
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            created = False
        else:
            key = Ed25519PrivateKey.generate()
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            created = True
        public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
        self.record["report_key"] = {
            "algorithm": "ed25519",
            "public_key": base64.b64encode(public).decode(),
            "fingerprint": "sha256:" + hashlib.sha256(public).hexdigest(),
        }
        rec.step(self.record, "report_key", "done", created=created)

    def _step_preflight_operator(self) -> None:
        reg = registry.load(probe_ids=frozenset(PROBES))
        environ = {**os.environ, **self.secrets}
        result = preflight.run(reg, Context.OPERATOR, self.cfg.profile,
                               env=ProbeEnv(environ=environ))
        preflight.assert_no_secrets(json.dumps(result.report), environ)
        (self.cfg.workdir / "preflight-operator.json").write_text(
            json.dumps(result.report, indent=2, sort_keys=True) + "\n")
        if result.exit_status != preflight.EXIT_OK:
            bad = [o.check_id for o in result.observations
                   if o.outcome.value in ("fail", "unknown")]
            raise InstallError(f"operator preflight exit {result.exit_status} ({', '.join(bad)});"
                               " see preflight-operator.json")
        rec.step(self.record, "preflight_operator", "done", exit_status=0)

    def _step_app(self) -> None:
        known = self.record["resources"].get("app")
        org = self.fly.app_org(self.cfg.app)
        if org is not None and org != self.cfg.fly_org:
            raise InstallError(f"app {self.cfg.app} belongs to org {org}, not {self.cfg.fly_org}")
        if org is not None:
            ownership = known["ownership"] if known else rec.ADOPTED
            action = "exists"
        else:
            if known:
                raise InstallError(f"app {self.cfg.app} is in the record but gone from Fly;"
                                   " it was deleted outside the kit")
            self.fly.create_app(self.cfg.fly_org, self.cfg.app)
            ownership, action = rec.CREATED, "created"
        self.record["resources"]["app"] = {"name": self.cfg.app, "org": self.cfg.fly_org,
                                           "ownership": ownership}
        rec.step(self.record, "app", "done", action=action)
        self._say(f"app {self.cfg.app}: {action} ({ownership})")

    def _step_volume(self) -> None:
        known = self.record["resources"].get("volume")
        found = self.fly.volumes(self.cfg.app, self.cfg.volume)
        if len(found) > 1:
            raise InstallError(f"{len(found)} volumes named {self.cfg.volume}; the profile has"
                               " one. Remove the extra by hand (data may be on either)")
        if found:
            vol_id, action = found[0]["id"], "exists"
            ownership = known["ownership"] if known and known["id"] == vol_id else rec.ADOPTED
        else:
            if known:
                raise InstallError(f"volume {known['id']} is in the record but gone from Fly")
            vol_id = self.fly.create_volume(self.cfg.app, self.cfg.volume,
                                            self.cfg.volume_size_gb, self.cfg.region)
            ownership, action = rec.CREATED, "created"
        self.record["resources"]["volume"] = {"name": self.cfg.volume, "id": vol_id,
                                              "ownership": ownership}
        rec.step(self.record, "volume", "done", action=action)
        self._say(f"volume {self.cfg.volume} {vol_id}: {action} ({ownership})")

    def _step_schema(self) -> None:
        image = self._image(self.release)
        marker = image.schema_marker()
        if marker and marker[0] > self.release.schema_version:
            raise RecoveryRequired(
                f"database schema is v{marker[0]}, newer than v{self.release.version}'s"
                f" v{self.release.schema_version}. Install never migrates backward; use"
                f" `rollback` (which checks compatibility) or install a newer release."
            )
        if marker == (self.release.schema_version, self.release.schema_compatible_with):
            action = "current"
        else:
            self._say(image.migrate())
            marker = image.schema_marker()
            action = "migrated"
        db = _db_identity(self._owner_url())
        db["schema"] = {"version": marker[0], "compatible_with": marker[1]}
        known = self.record["resources"].get("database") or {}
        db["migrated_at"] = rec.now() if action == "migrated" else known.get("migrated_at")
        db["ownership"] = rec.ADOPTED  # the customer brought it; the kit never deletes it
        self.record["resources"]["database"] = db
        rec.step(self.record, "schema", "done", action=action, version=marker[0])

    def _step_app_role(self) -> None:
        url = self.secrets.get("ESP_DATABASE_URL")
        if url and self.deps.db_connects(url):
            action = "kept"
        else:
            values = self._image(self.release).create_app_role(
                self.secrets.get("ESP_SESSION_TOKEN_KEY"))
            self._set_secrets(values)
            action = "created"
        self.record["resources"]["database"]["app_role"] = "esp_app"
        rec.step(self.record, "app_role", "done", action=action)

    def _step_secrets(self) -> None:
        generated = []
        for name, size in (("ESP_REVIEW_SESSION_SECRET", 48), ("ESP_REVIEW_PASSWORD", 18)):
            if not self.secrets.get(name):
                self._set_secrets({name: secrets.token_urlsafe(size)})
                generated.append(name)
        if generated:
            self._say(f"generated {', '.join(generated)} into {self.cfg.secrets_file.name}")
        subset = secrets_file.app_subset(self.secrets)
        digests = "\n".join(f"{k}:{_digest(v)}" for k, v in sorted(subset.items()))
        marker = self.cfg.workdir / PUSHED_DIGESTS
        status = self.fly.secret_status(self.cfg.app)
        all_on_fly = all(status.get(k) for k in subset)
        if marker.exists() and marker.read_text() == digests and all_on_fly:
            action = "unchanged"
        else:
            self.fly.stage_secrets(self.cfg.app, subset)
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(digests)
            action = "staged"
        self.record["secrets"] = {"pushed": sorted(subset), "generated": generated}
        rec.step(self.record, "secrets", "done", action=action)

    def _fly_toml(self) -> Path:
        path = self.cfg.workdir / "fly.toml"
        path.write_text(TEMPLATE.read_text().format(
            app=self.cfg.app, region=self.cfg.region, public_url=self.cfg.public_url,
            volume=self.cfg.volume))
        return path

    def _running_digests(self) -> set[str]:
        return {(m.get("image_ref") or {}).get("digest", "") for m in
                self.fly.machines(self.cfg.app) if m.get("state") != "destroyed"}

    def _deploy(self, release: rel.Release, force: bool = False) -> str:
        config = self._fly_toml()
        config_sha = _digest(config.read_text())
        staged = any(s == "Staged" for s in self.fly.secret_status(self.cfg.app).values())
        last = self.record["steps"].get("deploy", {})
        unchanged = (self._running_digests() == {release.image_digest} and not staged
                     and last.get("config_sha256") == config_sha)
        if unchanged and not force:
            return "current"
        self._say(f"deploying {release.image_ref}")
        self.fly.deploy(self.cfg.app, str(config), release.image_ref)
        # The machines API lags a completed deploy by a few seconds (seen
        # live, RC1-640): poll before calling it a mismatch.
        for _ in range(DEPLOY_SETTLE_ATTEMPTS):
            running = self._running_digests()
            if running == {release.image_digest}:
                break
            self.deps.sleep(DEPLOY_SETTLE_INTERVAL_S)
        else:
            raise InstallError(f"after deploy the machines run {sorted(running)},"
                               f" not {release.image_digest}")
        return "deployed"

    def _step_deploy(self) -> None:
        action = self._deploy(self.release)
        self.record["release"] = self.release.to_json()
        rec.step(self.record, "deploy", "done", action=action,
                 config_sha256=_digest(self._fly_toml().read_text()))

    def _wait_healthy(self) -> int:
        url = f"{self.cfg.public_url}/healthz"
        for attempt in range(1, HEALTH_ATTEMPTS + 1):
            if self.deps.http_status(url) == 200:
                return attempt
            self.deps.sleep(HEALTH_INTERVAL_S)
        raise InstallError(f"{url} did not return 200 after {HEALTH_ATTEMPTS} attempts")

    def _step_health(self) -> None:
        attempts = self._wait_healthy()
        rec.step(self.record, "health", "done", attempts=attempts)

    def _step_preflight_runtime(self) -> None:
        report = self.deps.runtime_preflight(self.fly, self.cfg.app, self.cfg.profile)
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if any(v in text for v in self._secret_values()):
            raise InstallError("runtime preflight report contained a secret value; discarded")
        (self.cfg.workdir / "preflight-runtime.json").write_text(text)
        reg = registry.load(probe_ids=frozenset(PROBES)).by_id()
        failing = sorted(
            o["check_id"] for o in report["observations"]
            if o["outcome"] in ("fail", "unknown")
            and reg[o["check_id"]].severity.value == "required"
        )
        self.record["runtime_preflight"] = {
            "exit_status": report["exit_status"], "summary": report["summary"],
            "failing_required": failing, "run_id": report.get("run_id"),
        }
        rec.step(self.record, "preflight_runtime", "done", exit_status=report["exit_status"])
        if failing:
            self._say(f"runtime preflight: required checks not passing: {', '.join(failing)}"
                      " (see preflight-runtime.json)")

    # -- rollback ---------------------------------------------------------

    def rollback(self, version: str) -> int:
        """Deploy an older verified release, only if the database's schema
        allows it. Never runs migrate, never touches data or destinations."""
        if not self.record or self.record["state"] in (rec.STATE_INSTALLING, rec.STATE_TORN_DOWN):
            raise InstallError("rollback needs a completed install (see install-record.json)")
        current = self.record["release"]["version"]
        target = self._verify(version)
        cur_release = self._verify(current)
        marker = self._image(cur_release).schema_marker()
        entry = {"action": "rollback", "from": current, "to": version, "at": rec.now()}
        if marker is None or marker[1] > target.schema_version:
            found = "no schema marker" if marker is None else (
                f"schema v{marker[0]} (compatible with application schema v{marker[1]}+)")
            entry["outcome"] = "refused"
            self.record["history"].append(entry)
            self._save()
            restore_from = (self.record["resources"].get("database") or {}).get(
                "migrated_at") or "the last migration"
            raise RecoveryRequired(
                f"rollback to v{version} refused: the database reports {found}, and"
                f" v{version}'s code supports schema v{target.schema_version}. An image"
                " rollback cannot reverse a migration. Recovery options, all customer-owned:"
                f" (1) roll forward to a fixed release (newer than v{current});"
                " (2) restore the database to a point before the migration (for Neon: a"
                f" point-in-time branch restore to before {restore_from}), then roll back;"
                " either way, destination writes (Brevo) already made are not reversed."
            )
        action = self._deploy(target, force=True)
        self.record["release"] = target.to_json()
        self._wait_healthy()
        entry["outcome"] = action
        self.record["history"].append(entry)
        self.record["installed_version"] = version
        rec.step(self.record, "deploy", "done", action=action,
                 config_sha256=_digest(self._fly_toml().read_text()))
        self._save()
        self._say(f"rolled back to v{version}; database schema untouched at v{marker[0]}")
        return 0

    # -- teardown ---------------------------------------------------------

    def teardown(self, confirm: str, drop_app_role: bool = False) -> int:
        """Destroy only what the record says this install CREATED. The
        customer's database and its data are always retained."""
        if not self.record:
            raise InstallError("no install-record.json here; nothing is known to be owned")
        if confirm != self.cfg.app:
            raise InstallError(f"--confirm must name the app ({self.cfg.app})")
        res = self.record["resources"]
        actions = {}
        app, vol = res.get("app"), res.get("volume")
        retained = "retained (adopted, not created by this install)"
        app_owned = bool(app) and app["ownership"] == rec.CREATED
        vol_owned = bool(vol) and vol["ownership"] == rec.CREATED
        app_present = bool(app) and self.fly.app_org(self.cfg.app) == self.cfg.fly_org
        # An adopted app can hold a volume this install created: destroy just
        # that volume, by the id the record holds, never by name.
        live = self.fly.volumes(self.cfg.app, self.cfg.volume) if app_present else []
        if vol_owned and not app_owned and any(v["id"] == vol["id"] for v in live):
            self.fly.destroy_volume(self.cfg.app, vol["id"])
        if app_owned and app_present:
            self.fly.destroy_app(self.cfg.app)  # takes its machines and volumes with it
        if app:
            actions["app"] = "destroyed" if app_owned else retained
        if vol:
            actions["volume"] = ("destroyed" if vol_owned
                                 else "destroyed with the app" if app_owned else retained)
        if drop_app_role:
            actions["app_role"] = drop_role(self._owner_url(), APP_ROLE)
            self._set_secrets({"ESP_DATABASE_URL": ""})
        actions["database"] = "retained (customer data is never deleted by the kit)"
        self.record["state"] = rec.STATE_TORN_DOWN
        self.record["history"].append({"action": "teardown", "at": rec.now(), **actions})
        self._save()
        for what, outcome in actions.items():
            self._say(f"{what}: {outcome}")
        return 0
