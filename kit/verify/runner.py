"""`kit verify`: does the installed workflow work? (RC1-641, ADR 0007)

Run on the customer workstation as the customer operator, after install.
It collects four kinds of observation, judges them (kit.verify.checks),
and writes a signed report that stays on this workstation:

1. release: the machines run the digest the install record verified;
2. health: /healthz (recorded, never sufficient on its own);
3. identity: password-mode probes over the app's public API;
4. workflow: a namespaced migration inside the machine, through ESP's own
   gate, executor, reconciliation and cleanup (kit/verify/machine.py).

Nothing is uploaded anywhere. `export` is the only way a report leaves,
and the customer runs it.
"""

import base64
import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kit import preflight
from kit.install import record as rec
from kit.install import secrets_file
from kit.install.config import InstallConfig
from kit.install.engine import REPORT_KEY, _http_status
from kit.install.fly import Fly
from kit.verify import checks, identity, signing

SCHEMA = "cik.conformance/1"
MACHINE_SCRIPT = Path(__file__).with_name("machine.py")
RESULT_MARK = "CIK-RESULT "
REPORTS_DIR = "conformance"
READY_STATES = (rec.STATE_INSTALLED, rec.STATE_NOT_READY)


class VerifyError(Exception):
    """The run could not be set up (not installed, no report key...)."""


def new_run_id(now: datetime) -> str:
    return now.strftime("%Y%m%dt%H%M%S") + "-" + secrets.token_hex(2)


def _machine_run(fly: Fly, app: str, run_id: str) -> dict[str, Any]:
    script = base64.b64encode(MACHINE_SCRIPT.read_bytes()).decode()
    cmd = (
        "mkdir -p /tmp/cik && echo " + script + " | base64 -d > /tmp/cik/verify_machine.py"
        f" && /app/.venv/bin/python /tmp/cik/verify_machine.py --run-id {run_id}"
    )
    result = fly.run("ssh", "console", "-a", app, "-C", f"sh -c '{cmd}'", check=False)
    line = next((ln for ln in result.stdout.splitlines() if ln.startswith(RESULT_MARK)), None)
    if line is None:
        tail = (result.stderr or result.stdout).strip().splitlines()[-3:]
        raise VerifyError(f"machine run printed no result (exit {result.code}): {' | '.join(tail)}")
    return json.loads(line[len(RESULT_MARK):])


@dataclass
class Deps:
    fly: Fly = field(default_factory=Fly)
    http_status: Callable[[str], int] = _http_status
    identity_probe: Callable[[str, str | None], dict] = identity.probe
    machine_run: Callable[[Fly, str, str], dict] = _machine_run
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    say: Callable[[str], None] = print


def _digest_of(image_ref: str | None) -> str | None:
    return image_ref.split("@", 1)[1] if image_ref and "@" in image_ref else None


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class Verifier:
    def __init__(self, config: InstallConfig, deps: Deps | None = None):
        self.cfg = config
        self.deps = deps or Deps()
        self.secrets = secrets_file.read(config.secrets_file)
        self.record = rec.load(config.record_path)

    def _secret_values(self) -> set[str]:
        return preflight.secret_values(self.secrets) | {
            v for v in self.secrets.values() if len(v) >= 8}

    def _require_install(self) -> Path:
        if not self.record or self.record.get("state") not in READY_STATES:
            state = (self.record or {}).get("state", "not installed")
            raise VerifyError(f"install is {state}; run kit.install install first")
        key = self.cfg.workdir / REPORT_KEY
        if not self.record.get("report_key") or not key.exists():
            raise VerifyError(f"no report key ({key}); re-run install to generate it")
        return key

    def _observe(self, run_id: str) -> dict[str, Any]:
        fly = self.deps.fly
        obs: dict[str, Any] = {}
        want = _digest_of((self.record.get("release") or {}).get("image"))
        try:
            running = sorted({(m.get("image_ref") or {}).get("digest", "")
                              for m in fly.machines(self.cfg.app)
                              if m.get("state") != "destroyed"})
        except Exception as exc:  # noqa: BLE001 - any failure is "could not read"
            self.deps.say(f"could not list machines: {type(exc).__name__}")
            running = None
        obs["release"] = {"record_digest": want, "running_digests": running}
        obs["health"] = {"status": self.deps.http_status(f"{self.cfg.public_url}/healthz")}
        obs["identity"] = self.deps.identity_probe(
            self.cfg.public_url, self.secrets.get("ESP_REVIEW_PASSWORD"))
        try:
            obs["machine"] = self.deps.machine_run(fly, self.cfg.app, run_id)
        except Exception as exc:  # noqa: BLE001 - recorded, judged insufficient
            obs["machine"], obs["machine_error"] = None, f"{type(exc).__name__}: {exc}"
        return obs

    def run(self) -> tuple[Path, checks.Outcome]:
        key_path = self._require_install()
        started = self.deps.now()
        run_id = new_run_id(started)
        self.deps.say(f"conformance run {run_id} against {self.cfg.app}")
        obs = self._observe(run_id)
        observations = checks.evaluate(obs)
        verdict = checks.verdict(observations)
        finished = self.deps.now()

        out = self.cfg.workdir / REPORTS_DIR / run_id
        evidence_dir = out / "evidence"
        evidence_dir.mkdir(parents=True)
        secret_values = self._secret_values()
        refs = []
        files = dict((obs.get("machine") or {}).get("files", {}))
        files["machine-steps.json"] = json.dumps((obs.get("machine") or {}).get("steps"),
                                                 indent=1, sort_keys=True)
        files["identity.json"] = json.dumps(obs["identity"], indent=1, sort_keys=True)
        for name, text in sorted(files.items()):
            if any(v in text for v in secret_values):
                raise VerifyError(f"evidence {name} contained a secret value; discarded")
            (evidence_dir / name).write_text(text)
            refs.append({"name": name, "sha256": _sha256_text(text), "bytes": len(text.encode())})

        release = self.record.get("release") or {}
        payload = {
            "schema": SCHEMA,
            "run_id": run_id,
            "install_id": self.record["install_id"],
            "app": self.cfg.app,
            "profile": self.cfg.profile,
            "release": {"version": release.get("version"), "image": release.get("image"),
                        "commit": release.get("commit")},
            "check_version": checks.CHECK_VERSION,
            "started_at": started.isoformat(timespec="seconds"),
            "finished_at": finished.isoformat(timespec="seconds"),
            "verdict": verdict.value,
            "summary": {o.value: sum(1 for x in observations if x.outcome is o)
                        for o in checks.Outcome},
            "observations": [o.to_json() for o in observations],
            "evidence": refs,
            "side_effects": {
                "audit_log": "a successful sign-in probe appends sign_in and sign_out "
                             "records to the append-only audit log; they are not removed",
                "destination": "fixture contacts, list and campaign are deleted by the "
                               "run's cleanup; see CNF-040 for anything remaining",
            },
            "machine_error": obs.get("machine_error"),
            "integrity": signing.NON_CLAIM,
        }
        text = signing.canonical(payload)
        if any(v in text for v in secret_values):
            raise VerifyError("report contained a secret value; discarded")
        envelope = signing.sign(payload, signing.load_private(key_path))
        report = out / "report.signed.json"
        report.write_text(json.dumps(envelope, indent=1) + "\n")
        (out / "report.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return report, verdict

