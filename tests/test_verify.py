"""RC1-641 (ADR 0007): conformance checks, signed reports, export. No network."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kit.install import config as cfg
from kit.install import record as rec
from kit.verify import __main__ as cli
from kit.verify import checks, machine, signing
from kit.verify.checks import Outcome
from kit.verify.runner import Deps, Verifier, VerifyError

DIGEST = "sha256:" + "ab" * 32
EMAILS = [f"cik-r1-{i:04d}@example.com" for i in range(5)]
PASSWORD = "correct-horse-battery-staple"


# -- observation builders --------------------------------------------------


def expected_json(**over) -> str:
    base = {"run_id": "r1", "exported_total": 5, "emails": EMAILS,
            "suppressed_emails": EMAILS[:2], "list_name": "cik-conformance r1 (imported "
            "from mailchimp)", "source_fingerprint": "f" * 64}
    return json.dumps({**base, **over})


def journal(written=None, converged=True, failed=False) -> str:
    events = [{"event": "run_start"}, {"event": "convergence", "converged": converged}]
    if failed:
        events.append({"event": "run_failed", "error": "TargetError"})
    else:
        events.append({"event": "run_complete", "written": written or {"create": 6},
                       "skipped_unchanged": 0, "conflicts": 0})
    return "\n".join(json.dumps(e) for e in events) + "\n"


def step(code, out=(), err=()):
    return {"exit": code, "stdout_tail": list(out), "stderr_tail": list(err)}


def healthy_machine() -> dict:
    return {
        "run_id": "r1",
        "steps": {
            "fixture": step(0),
            "gate_draft": step(1, err=["error: spec at x is draft, not approved; ..."]),
            "approve": step(0, out=["approved by cik", "content sha256: " + "c" * 64]),
            "tamper_applied": True,
            "gate_tampered": step(1, err=["error: spec at x was modified after approval"]),
            "execute": step(0, out=["converged: a second pass would write nothing"]),
            "reconcile": step(0, out=["reconcile PASS"]),
            "cleanup": step(0),
        },
        "files": {
            "expected.json": expected_json(),
            "spec.approved.yaml": "status: approved\n",
            "journal.jsonl": journal(),
            "reconcile-history.jsonl": json.dumps(
                {"passed": True, "failing": [], "suppression_pct": 100.0}) + "\n",
            "cleanup.json": json.dumps({"clean": True, "deleted": {"contacts": 5,
                                        "campaign": True, "list": True},
                                        "remaining": {"contacts": 0}}),
        },
    }


def healthy_identity() -> dict:
    return {"anonymous_write_status": 401, "wrong_password_status": 401,
            "audit_seq_before": 7, "login_status": 200,
            "me": {"authenticated": True, "identity": {"method": "password", "verified": False}},
            "audit_after": [{"seq": 8, "event": "sign_in"}, {"seq": 7, "event": "spec_approved"}]}


def healthy_obs() -> dict:
    return {"release": {"record_digest": DIGEST, "running_digests": [DIGEST]},
            "health": {"status": 200}, "identity": healthy_identity(),
            "machine": healthy_machine()}


def outcomes(obs) -> dict[str, Outcome]:
    return {o.check_id: o.outcome for o in checks.evaluate(obs)}


# -- checks ------------------------------------------------------------------


def test_healthy_install_passes_every_check():
    got = outcomes(healthy_obs())
    assert set(got.values()) == {Outcome.PASS}, got
    assert checks.verdict(checks.evaluate(healthy_obs())) is Outcome.PASS


def test_healthz_green_while_the_destination_refuses_writes_fails():
    """The headline case: liveness passes, the migration does not."""
    obs = healthy_obs()
    m = obs["machine"]
    m["steps"]["execute"] = step(1, err=["error: create contact ...: HTTP 401"])
    m["files"]["journal.jsonl"] = journal(failed=True)
    m["steps"]["reconcile"] = step(2, out=["reconcile ERROR: could not run"])
    del m["files"]["reconcile-history.jsonl"]
    got = outcomes(obs)
    assert got["CNF-002"] is Outcome.PASS
    assert got["CNF-030"] is Outcome.FAIL
    assert got["CNF-031"] is Outcome.INSUFFICIENT and got["CNF-032"] is Outcome.INSUFFICIENT
    assert checks.verdict(checks.evaluate(obs)) is Outcome.FAIL


def test_audit_insert_revoked_fails_sign_in_while_healthz_is_green():
    obs = healthy_obs()
    obs["identity"].update(login_status=500, me={"authenticated": False, "identity": None},
                           audit_after=[{"seq": 7, "event": "spec_approved"}])
    got = outcomes(obs)
    assert got["CNF-002"] is Outcome.PASS
    assert got["CNF-012"] is Outcome.FAIL
    assert got["CNF-013"] is Outcome.INSUFFICIENT


def test_a_draft_that_runs_is_a_fail_and_blocks_the_migration_checks():
    obs = healthy_obs()
    obs["machine"]["steps"]["gate_draft"] = step(0, out=["dry run only"])
    got = outcomes(obs)
    assert got["CNF-021"] is Outcome.FAIL
    assert got["CNF-030"] is Outcome.INSUFFICIENT


def test_accepted_anonymous_write_and_wrong_password_fail():
    obs = healthy_obs()
    obs["identity"].update(anonymous_write_status=200, wrong_password_status=200)
    got = outcomes(obs)
    assert got["CNF-010"] is Outcome.FAIL and got["CNF-011"] is Outcome.FAIL


def test_unreachable_machine_is_insufficient_never_pass():
    obs = healthy_obs()
    obs["machine"], obs["machine_error"] = None, "FlyError: ssh refused"
    got = outcomes(obs)
    assert got["CNF-020"] is Outcome.INSUFFICIENT
    assert all(got[c] is Outcome.INSUFFICIENT for c in ("CNF-030", "CNF-031", "CNF-032"))
    assert checks.verdict(checks.evaluate(obs)) is Outcome.INSUFFICIENT


def test_read_back_mismatch_fails_destination_state():
    obs = healthy_obs()
    obs["machine"]["files"]["cleanup.json"] = json.dumps(
        {"clean": True, "deleted": {"contacts": 3}, "remaining": {}})
    assert outcomes(obs)["CNF-031"] is Outcome.FAIL


def test_suppression_below_100_fails_and_zero_suppressed_is_vacuous():
    obs = healthy_obs()
    obs["machine"]["files"]["reconcile-history.jsonl"] = json.dumps(
        {"passed": False, "failing": ["suppression"], "suppression_pct": 50.0})
    assert outcomes(obs)["CNF-032"] is Outcome.FAIL
    obs = healthy_obs()
    obs["machine"]["files"]["expected.json"] = expected_json(suppressed_emails=[])
    assert outcomes(obs)["CNF-032"] is Outcome.INSUFFICIENT


def test_cleanup_leaving_resources_fails():
    obs = healthy_obs()
    obs["machine"]["steps"]["cleanup"] = step(1)
    obs["machine"]["files"]["cleanup.json"] = json.dumps(
        {"clean": False, "deleted": {"contacts": 5}, "remaining": {"list": True}})
    assert outcomes(obs)["CNF-040"] is Outcome.FAIL


def test_malformed_evidence_is_insufficient_not_a_crash():
    obs = healthy_obs()
    obs["machine"]["files"]["journal.jsonl"] = "not json\n"
    got = outcomes(obs)
    assert got["CNF-030"] is Outcome.INSUFFICIENT
    assert got["CNF-040"] is Outcome.PASS


def test_wrong_digest_fails_release_check():
    obs = healthy_obs()
    obs["release"]["running_digests"] = ["sha256:" + "cd" * 32]
    assert outcomes(obs)["CNF-001"] is Outcome.FAIL


# -- signing -------------------------------------------------------------------


def _key_record(key: Ed25519PrivateKey) -> dict:
    raw = signing.raw_public(key)
    return {"algorithm": "ed25519", "public_key": base64.b64encode(raw).decode(),
            "fingerprint": "sha256:" + hashlib.sha256(raw).hexdigest()}


def test_signed_payload_round_trips():
    key = Ed25519PrivateKey.generate()
    env = signing.sign({"verdict": "pass", "n": 1}, key)
    public, fp = signing.trusted_key(_key_record(key))
    assert signing.verify(env, public, fp) == {"verdict": "pass", "n": 1}


def test_any_payload_change_is_refused():
    key = Ed25519PrivateKey.generate()
    env = signing.sign({"verdict": "fail"}, key)
    env["payload"] = env["payload"].replace("fail", "pass")
    public, fp = signing.trusted_key(_key_record(key))
    with pytest.raises(signing.SignatureInvalid, match="modified"):
        signing.verify(env, public, fp)


def test_another_installs_key_is_refused_even_with_a_valid_signature():
    signer, trusted = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    env = signing.sign({"verdict": "pass"}, signer)
    public, fp = signing.trusted_key(_key_record(trusted))
    with pytest.raises(signing.SignatureInvalid, match="not the trusted"):
        signing.verify(env, public, fp)
    # Re-labeling the fingerprint does not help: the signature still fails.
    env["key_fingerprint"] = fp
    with pytest.raises(signing.SignatureInvalid, match="modified"):
        signing.verify(env, public, fp)


def test_a_record_whose_key_and_fingerprint_disagree_is_refused():
    rec_key = _key_record(Ed25519PrivateKey.generate())
    rec_key["fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(signing.SignatureInvalid, match="fingerprint"):
        signing.trusted_key(rec_key)


# -- runner + CLI ----------------------------------------------------------------


class FakeFly:
    def machines(self, app):
        return [{"state": "started", "image_ref": {"digest": DIGEST}}]


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "install.toml").write_text(
        '[install]\nrelease = "0.1.4"\nfly_org = "cust-org"\napp = "cust-esp"\n'
        'region = "iad"\nvolume = "cik_data"\n')
    secrets = tmp_path / ".env.cik"
    secrets.write_text(f"ESP_REVIEW_PASSWORD={PASSWORD}\n")
    os.chmod(secrets, 0o600)
    key = Ed25519PrivateKey.generate()
    (tmp_path / "report-key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    record = rec.new("inst-1", "v1", {})
    record.update(state=rec.STATE_INSTALLED, report_key=_key_record(key),
                  release={"version": "0.1.4", "image": f"ghcr.io/x/esp@{DIGEST}",
                           "commit": "2a4968c"})
    rec.save(tmp_path / "install-record.json", record, set())
    return tmp_path


def deps(machine_result=None, identity_result=None) -> Deps:
    def machine_run(_fly, _app, _run_id):
        if isinstance(machine_result, Exception):
            raise machine_result
        return copy.deepcopy(machine_result or healthy_machine())

    return Deps(fly=FakeFly(), http_status=lambda _url: 200,
                identity_probe=lambda _url, _pw: identity_result or healthy_identity(),
                machine_run=machine_run, say=lambda _t: None)


def run(workspace, d) -> tuple:
    return Verifier(cfg.load(workspace / "install.toml"), d).run()


def test_run_writes_a_signed_report_that_verifies(workspace, capsys):
    report, verdict = run(workspace, deps())
    assert verdict is Outcome.PASS
    code = cli.main(["verify-report", str(report), "--record",
                     str(workspace / "install-record.json")])
    out = capsys.readouterr().out
    assert code == 0 and "signature valid" in out and "does not show" in out
    payload = json.loads(json.loads(report.read_text())["payload"])
    assert payload["schema"] == "cik.conformance/1" and payload["release"]["version"] == "0.1.4"
    names = {e["name"] for e in payload["evidence"]}
    assert {"journal.jsonl", "identity.json", "machine-steps.json"} <= names
    for ref in payload["evidence"]:
        text = (report.parent / "evidence" / ref["name"]).read_text()
        assert ref["sha256"] == "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def test_a_tampered_report_file_is_refused(workspace, capsys):
    report, _ = run(workspace, deps())
    env = json.loads(report.read_text())
    env["payload"] = env["payload"].replace('"verdict":"pass"', '"verdict":"fail"')
    report.write_text(json.dumps(env))
    assert cli.main(["verify-report", str(report), "--record",
                     str(workspace / "install-record.json")]) == 4
    assert "modified after signing" in capsys.readouterr().err


def test_a_failed_machine_run_is_reported_not_raised(workspace):
    report, verdict = run(workspace, deps(machine_result=RuntimeError("ssh: no machine")))
    payload = json.loads(json.loads(report.read_text())["payload"])
    assert verdict is Outcome.INSUFFICIENT
    assert "ssh: no machine" in payload["machine_error"]


def test_a_secret_in_evidence_discards_the_report(workspace):
    bad = healthy_machine()
    bad["files"]["journal.jsonl"] += json.dumps({"event": "x", "leak": PASSWORD}) + "\n"
    with pytest.raises(VerifyError, match="secret"):
        run(workspace, deps(machine_result=bad))
    assert not list((workspace / "conformance").rglob("report.signed.json"))


def test_verify_refuses_an_install_that_is_not_installed(workspace):
    path = workspace / "install-record.json"
    record = json.loads(path.read_text())
    record["state"] = rec.STATE_TORN_DOWN
    path.write_text(json.dumps(record))
    with pytest.raises(VerifyError, match="torn_down"):
        run(workspace, deps())


def test_export_copies_the_signed_report_only_unless_asked(workspace):
    report, _ = run(workspace, deps())
    run_id = report.parent.name
    out = workspace / "share"
    assert cli.main(["export", run_id, "--config", str(workspace / "install.toml"),
                     "--out", str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["report.signed.json"]
    out2 = workspace / "share2"
    cli.main(["export", run_id, "--config", str(workspace / "install.toml"),
              "--out", str(out2), "--with-evidence"])
    assert (out2 / "evidence" / "journal.jsonl").exists()


def test_the_kit_never_imports_a_network_client_for_reports():
    """Reports leave only by export: no upload path exists in kit.verify."""
    source = Path(cli.__file__).read_text() + Path(signing.__file__).read_text()
    assert "urllib" not in source and "httpx" not in source and "requests" not in source


# -- machine script -----------------------------------------------------------


def test_machine_cleans_up_after_a_failed_execute(tmp_path, monkeypatch):
    monkeypatch.setattr(machine, "WORK_ROOT", tmp_path / "w")
    calls = []

    def fake_run(argv, cwd, capture_output, text, timeout):
        mod = argv[2]
        calls.append(mod if mod != "conformance" else f"conformance {argv[3]}")
        work = tmp_path / "w" / "r1"
        if mod == "conformance" and argv[3] == "fixture":
            work.mkdir(parents=True)
            (work / "expected.json").write_text("{}")
        if mod == "mapping.review":
            (work / "spec.approved.yaml").write_text("generated_at: '2026-11-12'\n")
        failing = mod == "executor.run" and "--execute" in argv
        return type("P", (), {"returncode": 1 if failing else 0, "stdout": "", "stderr": ""})

    monkeypatch.setattr(machine.subprocess, "run", fake_run)
    result = machine.run("r1", 40, "example.com")
    assert calls == ["conformance fixture", "executor.run", "mapping.review", "executor.run",
                     "executor.run", "executor.reconcile", "conformance cleanup"]
    assert result["steps"]["execute"]["exit"] == 1
    assert result["steps"]["tamper_applied"] is True
    assert not (tmp_path / "w" / "r1").exists()


def test_machine_skips_everything_but_reports_when_the_fixture_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(machine, "WORK_ROOT", tmp_path / "w")
    monkeypatch.setattr(machine.subprocess, "run", lambda *a, **k: type(
        "P", (), {"returncode": 2, "stdout": "", "stderr": "boom"}))
    result = machine.run("r1", 40, "example.com")
    assert result["steps"]["execute"] == {"exit": None, "skipped": "no fixture"}
    assert "cleanup" not in result["steps"]
