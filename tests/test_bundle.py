"""RC1-642 (ADR 0008): diagnostic bundles. No network: Fly and HTTP are faked.

The canary tests plant fake secrets and PII in every raw input a source
reads, collect, export, and then search every output path (bundle files,
manifest, public-key file, the exported archive's decompressed bytes) for
each planted value in every transformation `scan.variants` knows. A pass is
bounded coverage of these placements and encodings, not proof of absence.
"""

import base64
import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kit.bundle import __main__ as cli
from kit.bundle import allowlist, archive, collect, events, scan, sources
from kit.install import config as cfg
from kit.install import record as rec
from kit.install.fly import Fly, Result
from kit.verify import signing

DIGEST = "sha256:" + "ab" * 32

# -- planted values: never real, all shaped like the real thing ----------------

PG_PASSWORD = "Zq9canaryPgPass7731"
PG_URL = f"postgresql://esp_app:{PG_PASSWORD}@ep-canary-host.us-east-1.aws.neon.tech/esp"
BREVO_KEY = "xkeysib-" + "c0ffee" * 10 + "abcd" + "-CanaryBrevo0001"
ANTHROPIC_KEY = "sk-ant-api03-canaryCANARYcanary0123456789abcdef"
FLY_TOKEN = "FlyV1 fm2_canaryTokenAAAABBBBCCCCDDDDEEEE"
REVIEW_PASSWORD = "canary-review-password-41"
SESSION_SECRET = "canary-session-secret-9f8e7d6c5b4a"
SECRETS = {
    "ESP_DATABASE_URL": PG_URL, "ESP_BREVO_API_KEY": BREVO_KEY,
    "ESP_ANTHROPIC_API_KEY": ANTHROPIC_KEY, "ESP_REVIEW_PASSWORD": REVIEW_PASSWORD,
    "ESP_REVIEW_SESSION_SECRET": SESSION_SECRET,
}
PII_EMAIL = "jane.canary@customer-mail.com"
PII_SSN = "219-09-9999"
PII_CARD = "4111111111111111"
PII_PHONE = "(212) 867-5309"
PII_IP = "203.0.113.77"
PLANTED = [PG_URL, PG_PASSWORD, BREVO_KEY, ANTHROPIC_KEY, FLY_TOKEN, REVIEW_PASSWORD,
           SESSION_SECRET, PII_EMAIL, PII_SSN, PII_CARD, PII_PHONE, PII_IP]


def ev(**fields) -> dict:
    base = {"event": "esp_error_event", "v": 2, "at": "2026-11-12T10:00:00.123Z",
            "correlation_id": "0123abcd4567ef89", "release": "0.1.4"}
    return {**base, **fields}


# One distinguishing event per Phase 0B family, plus the startup failure.
FAMILY_EVENTS = {
    "family1_audit_revoked": ev(op="audit.append", error_class="db", sqlstate="42501"),
    "family2_destination_auth": ev(op="destination.request", error_class="http", status=401,
                                   provider_code="unauthorized",
                                   route="POST /v3/contacts/import"),
    "family3_disk_full": ev(op="errorevents.sink", error_class="storage", errno=28,
                            errno_name="ENOSPC"),
    "startup_db_auth": ev(op="db.ready_check", error_class="db", sqlstate="28P01",
                          connect_class="auth"),
}
FAMILY_SIGNATURES = {
    "family1_audit_revoked": "audit.append db sqlstate=42501",
    "family2_destination_auth": "destination.request http status=401 "
                                "provider_code=unauthorized route=POST /v3/contacts/import",
    "family3_disk_full": "errorevents.sink storage errno_name=ENOSPC",
    "startup_db_auth": "db.ready_check db sqlstate=28P01 connect_class=auth",
}
# Records that look like events but must be dropped, each carrying a planted value.
BAD_EVENTS = [
    ev(op="audit.append", error_class="db", detail=PG_URL),                # unknown_field
    ev(op="destination.request", error_class="http", route=f"GET /v3/contacts/{PII_EMAIL}"),
    ev(op="db.ready_check", error_class="db", sqlstate=PG_PASSWORD[:5] + "x"),
    {**ev(op="audit.append", error_class="db"), "v": 9},                  # unsupported
    ev(op="free text " + REVIEW_PASSWORD, error_class="db"),               # bad_op
]


def log_lines() -> list[str]:
    lines = ["INFO starting esp", f"connecting to {PG_URL}",
             f"user {PII_EMAIL} from {PII_IP} called {PII_PHONE}",
             "Traceback (most recent call last):",
             '  File "/app/esp/db.py", line 10, in connect',
             f"psycopg.OperationalError: password authentication failed: {PG_URL}"]
    lines += [json.dumps(e) for e in FAMILY_EVENTS.values()]
    lines += [json.dumps(e) for e in BAD_EVENTS]
    lines.append('{"event": "esp_error_event", "v": 2, "op": ' + json.dumps(BREVO_KEY))
    return lines


def fly_logs_json(lines: list[str]) -> str:
    rows = [{"instance": "m1", "level": "info", "message": m, "meta": {"secret": FLY_TOKEN},
             "region": "iad", "timestamp": f"2026-11-12T10:00:{i:02d}Z"}
            for i, m in enumerate(lines)]
    return "".join(json.dumps(r, indent=2) for r in rows)


def raw_machines(healthy: bool = True) -> list[dict]:
    exit_event = {"exit_code": 0 if healthy else 1, "oom_killed": False,
                  "requested_stop": healthy, "restarting": not healthy,
                  "stderr": f"auth failed for {PG_URL}"}
    return [{
        "id": "m1", "state": "started" if healthy else "stopped", "region": "iad",
        "version": 7, "private_ip": PII_IP, "name": PII_EMAIL,
        "created_at": "2026-11-11T00:00:00Z", "updated_at": "2026-11-12T00:00:00Z",
        "host_status": "ok", "image_ref": {"digest": DIGEST, "registry": FLY_TOKEN},
        "checks": [{"name": "healthz", "status": "passing" if healthy else "critical",
                    "output": f"GET /healthz with key {BREVO_KEY}",
                    "updated_at": "2026-11-12T00:00:00Z"}],
        "events": [{"type": "exit", "status": "stopped", "source": "flyd",
                    "timestamp": 1731400000000,
                    "request": {"exit_event": exit_event, "body": REVIEW_PASSWORD}}],
        "config": {"env": {"ESP_DATABASE_URL": PG_URL, "ESP_PUBLIC_URL": "https://x"},
                   "guest": {"cpu_kind": "shared", "cpus": 1, "memory_mb": 512},
                   "mounts": [{"path": "/data", "volume": "vol_1", "size_gb": 1,
                               "name": SESSION_SECRET}],
                   "restart": {"policy": "on-failure"}, "init": {"cmd": [ANTHROPIC_KEY]}},
    }]


class FakeFlyRunner:
    """Answers flyctl argv with canned stdout; records calls."""

    def __init__(self, healthy=True, sink_lines=None, ssh="present", fail=(), reason=None):
        self.healthy, self.ssh, self.fail = healthy, ssh, set(fail)
        self.sink_lines = log_lines() if sink_lines is None else sink_lines
        self.reason = reason
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], stdin: str | None) -> Result:
        self.calls.append(args)
        head = args[0] if args[0] != "machines" else "machines"
        if head in self.fail:
            raise subprocess.TimeoutExpired(args, 1)
        if head == "status":
            return Result(0, json.dumps({"Status": "deployed", "Version": 7, "Deployed": True,
                                         "PlatformVersion": "machines",
                                         "Hostname": PG_URL,
                                         "Organization": {"Slug": PII_EMAIL}}), "")
        if head == "machines":
            return Result(0, json.dumps(raw_machines(self.healthy)), "")
        if head == "releases":
            return Result(0, json.dumps([{"Version": 7, "Status": "complete", "Stable": True,
                                          "InProgress": False, "CreatedAt": "2026-11-12",
                                          "DeploymentStrategy": "immediate",
                                          "ImageRef": f"ghcr.io/x/esp@{DIGEST}",
                                          "Reason": self.reason or "deploy",
                                          "User": {"Email": PII_EMAIL},
                                          "Description": ANTHROPIC_KEY}]), "")
        if head == "secrets":
            return Result(0, json.dumps([{"name": k, "status": "Deployed", "digest": v}
                                         for k, v in SECRETS.items()]), "")
        if head == "logs":
            return Result(0, fly_logs_json(log_lines()), "")
        if head == "ssh":
            if self.ssh == "absent":
                return Result(0, "CIK-SINK-ABSENT\n", "")
            if self.ssh == "down":
                return Result(1, "", "Error: no started VMs")
            return Result(0, "CIK-SINK-PRESENT\n" + "\n".join(self.sink_lines) + "\n", "")
        return Result(1, "", "unexpected")


# -- workspace ----------------------------------------------------------------------


def _key_record(key: Ed25519PrivateKey) -> dict:
    raw = signing.raw_public(key)
    return {"algorithm": "ed25519", "public_key": base64.b64encode(raw).decode(),
            "fingerprint": "sha256:" + hashlib.sha256(raw).hexdigest()}


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "install.toml").write_text(
        '[install]\nrelease = "0.1.4"\nfly_org = "cust-org"\napp = "cust-esp"\n'
        'region = "iad"\nvolume = "cik_data"\n')
    secrets_path = tmp_path / ".env.cik"
    secrets_path.write_text("".join(f"{k}={v}\n" for k, v in SECRETS.items()))
    os.chmod(secrets_path, 0o600)
    key = Ed25519PrivateKey.generate()
    (tmp_path / "report-key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    record = rec.new("inst-1", "v1", {})
    record.update(state=rec.STATE_INSTALLED, report_key=_key_record(key),
                  release={"version": "0.1.4", "image": f"ghcr.io/x/esp@{DIGEST}",
                           "commit": "2a4968c"},
                  resources={"database": {"ownership": "customer", "host": PG_URL,
                                          "schema": {"version": 3}}},
                  runtime_preflight={"exit_status": 0, "raw_stderr": BREVO_KEY,
                                     "summary": {"pass": 9, "fail": 0}})
    rec.save(tmp_path / "install-record.json", record, set())
    run = tmp_path / "conformance" / "cnf-1"
    run.mkdir(parents=True)
    (run / "report.json").write_text(json.dumps({
        "schema": "cik.conformance/1", "run_id": "cnf-1", "verdict": "pass",
        "summary": {"pass": 14}, "operator": PII_EMAIL,
        "observations": [{"check_id": "CNF-001", "name": "n", "outcome": "pass",
                          "reason": "ok", "evidence": {"to": PII_EMAIL, "key": BREVO_KEY}}],
    }))
    return tmp_path


class Clock:
    def __init__(self, step=0.0):
        self.t, self.step = 0.0, step

    def __call__(self) -> float:
        self.t += self.step
        return self.t


def collector(workspace, runner=None, status=200, clock=None, allow=None):
    times = iter(datetime(2026, 11, 12, 10, 0, tzinfo=UTC) + timedelta(seconds=i)
                 for i in range(100))
    deps = collect.Deps(fly=Fly(runner or FakeFlyRunner()), http_status=lambda _u: status,
                        now=lambda: next(times), clock=clock or Clock(), say=lambda _t: None,
                        token=lambda: "a1b2c3")
    return collect.Collector(cfg.load(workspace / "install.toml"), deps, allow)


def entries(bundle: Path) -> dict[str, dict]:
    _, m = archive.load_local(bundle)
    return {e["source"]: e for e in m["sources"]}


def file_data(bundle: Path, source: str):
    return json.loads((bundle / "files" / f"{source}.json").read_text())["data"]


def all_output_bytes(bundle: Path, exported: Path | None = None) -> bytes:
    blob = b"".join(p.read_bytes() for p in sorted(bundle.rglob("*")) if p.is_file())
    if exported:
        blob += gzip.decompress(exported.read_bytes())
    return blob


def assert_no_planted(blob: bytes):
    text = blob.decode("utf-8", "replace")
    folded = text.lower()
    for value in PLANTED:
        for form in scan.variants(value) | {value}:
            assert form not in text and form.lower() not in folded, \
                f"planted value leaked (form of {value[:6]}...)"


# -- allowlist projection --------------------------------------------------------------


def test_projection_keeps_only_listed_leaves():
    data = {"a": {"b": 1, "c": "drop"}, "l": [{"x": 1, "y": PG_URL}, {"x": 2}],
            "env": {"K": PG_URL}, "d": {"nested": {"deep": 1}}}
    out = allowlist.project(data, ("a.b", "l[].x", "env{keys}", "d"))
    assert out == {"a": {"b": 1}, "l": [{"x": 1}, {"x": 2}], "env": ["K"]}


def test_projection_star_keeps_keys_and_listed_children():
    data = {"steps": {"deploy": {"status": "done", "log": PG_URL}, "db": {"status": "ok"}}}
    assert allowlist.project(data, ("steps.*.status",)) == {
        "steps": {"deploy": {"status": "done"}, "db": {"status": "ok"}}}


def test_unknown_allowlist_version_is_refused(tmp_path):
    p = tmp_path / "a.toml"
    p.write_text((allowlist.ALLOWLIST_PATH.read_text()).replace("version = 1", "version = 2"))
    with pytest.raises(allowlist.AllowlistError, match="version"):
        allowlist.load(p)


def test_bad_path_fails_at_load(tmp_path):
    p = tmp_path / "a.toml"
    p.write_text('version = 1\n[bounds]\nmax_files=1\nmax_file_bytes=1\nmax_bundle_bytes=1\n'
                 'max_events=1\nmax_sink_read_bytes=1\nsource_timeout_s=1\n'
                 'total_timeout_s=1\n[sources.x]\npurpose="p"\npaths=["a{keys}.b"]\n')
    with pytest.raises(allowlist.AllowlistError, match="keys"):
        allowlist.load(p)


# -- event validation ---------------------------------------------------------------


def test_contract_events_are_kept_and_others_dropped_and_counted():
    kept, drops = events.from_lines(log_lines(), limit=100)
    assert kept == list(FAMILY_EVENTS.values())
    assert drops == {"unknown_field": 1, "bad_route": 1, "bad_sqlstate": 1,
                     "unsupported_version": 1, "bad_op": 1, "malformed_json": 1}


def test_v1_rejects_the_v2_only_field():
    rec_v1 = {**FAMILY_EVENTS["startup_db_auth"], "v": 1}
    assert events.check(rec_v1) == "unknown_field"
    rec_v1.pop("connect_class")
    assert events.check(rec_v1) is None


def test_event_limit_keeps_newest_and_counts_the_rest():
    lines = [json.dumps(ev(op="audit.append", error_class="db",
                           at=f"2026-11-12T10:00:{i:02d}Z")) for i in range(10)]
    kept, drops = events.from_lines(lines, limit=3)
    assert [e["at"][-3:-1] for e in kept] == ["07", "08", "09"] and drops["over_limit"] == 7


def test_startup_exceptions_keep_types_never_messages():
    found = sources.startup_exceptions(log_lines())
    assert dict(found) == {"psycopg.OperationalError": 1}


def test_log_rows_parse_concatenated_pretty_json():
    rows = sources._log_rows(fly_logs_json(["a", "b"]))
    assert [r["message"] for r in rows] == ["a", "b"]


# -- scanner ----------------------------------------------------------------------


@pytest.mark.parametrize("value", [PG_URL, BREVO_KEY, ANTHROPIC_KEY, FLY_TOKEN,
                                   "-----BEGIN PRIVATE KEY-----", PII_EMAIL, PII_SSN,
                                   PII_CARD, PII_IP])
def test_scanner_flags_planted_shapes_with_no_secret_list(value):
    s = scan.Scanner()
    assert s.scan({"x": f"prefix {value} suffix"}, "")


@pytest.mark.parametrize("transform", [
    lambda v: v, str.upper, lambda v: quote(v, safe=""), lambda v: v.encode().hex(),
    lambda v: base64.b64encode(v.encode()).decode(),
    lambda v: base64.b64encode(b"x" + v.encode()).decode(),
    lambda v: base64.b64encode(b"xy" + v.encode()).decode(),
    lambda v: base64.urlsafe_b64encode(v.encode()).decode(),
    lambda v: json.dumps({"k": v})[7:-1],
])
def test_scanner_finds_install_secrets_through_transformations(transform):
    s = scan.Scanner([REVIEW_PASSWORD, SESSION_SECRET])
    text = f"note: {transform(SESSION_SECRET)} end"
    hits = s.scan({"x": "clean"}, text)
    assert [h.rule for h in hits] == ["install_secret_value"]


def test_scanner_hits_carry_no_value():
    hits = scan.Scanner([REVIEW_PASSWORD]).scan({"x": BREVO_KEY}, REVIEW_PASSWORD)
    for h in hits:
        assert BREVO_KEY not in json.dumps(h.as_dict())
        assert REVIEW_PASSWORD not in json.dumps(h.as_dict())


# -- collection: healthy, canaries, families -------------------------------------------


def test_healthy_collection_includes_every_source_and_signs(workspace):
    bundle = collector(workspace).collect("healthy")
    e = entries(bundle)
    assert {k for k, v in e.items() if v["status"] == "included"} >= {
        "health", "fly_status", "fly_machines", "fly_releases", "fly_secrets",
        "platform_log", "file_sink", "install_record", "conformance"}
    assert e["preflight_operator"]["status"] == "unavailable"  # no report in this workspace
    env = json.loads((bundle / collect.MANIFEST).read_text())
    rec_key = json.loads((workspace / "install-record.json").read_text())["report_key"]
    public, fp = signing.trusted_key(rec_key)
    m = signing.verify(env, public, fp)
    assert m["schema"] == collect.SCHEMA and m["case"] == "healthy"
    assert m["versions"]["release"] == "0.1.4" and m["versions"]["allowlist"] == 1
    assert m["versions"]["check_registry"] == 1
    for entry in m["sources"]:
        assert entry["purpose"], entry["source"]
        if entry["status"] == "included":
            data = (bundle / entry["file"]).read_bytes()
            assert entry["sha256"] == hashlib.sha256(data).hexdigest()


def test_planted_values_reach_no_output_path(workspace, tmp_path):
    bundle = collector(workspace).collect()
    out = archive.export(bundle, tmp_path / "out" / "b.tar.gz")
    assert_no_planted(all_output_bytes(bundle, out))
    review = "\n".join(archive.review_lines(bundle)).encode()
    assert_no_planted(review)


def test_unlisted_fields_are_absent_not_scrubbed(workspace):
    bundle = collector(workspace).collect()
    machine = file_data(bundle, "fly_machines")[0]
    assert set(machine) == {"id", "state", "region", "version", "created_at", "updated_at",
                            "host_status", "image_ref", "checks", "events", "config"}
    assert machine["config"]["env"] == ["ESP_DATABASE_URL", "ESP_PUBLIC_URL"]
    assert set(machine["checks"][0]) == {"name", "status", "updated_at"}
    assert file_data(bundle, "fly_secrets") == [{"name": k, "status": "Deployed"}
                                                for k in SECRETS]
    assert "host" not in file_data(bundle, "install_record")["resources"]["database"]


def test_every_family_signal_survives_export_and_planted_values_do_not(workspace, tmp_path):
    bundle = collector(workspace).collect()
    out = archive.export(bundle, tmp_path / "b.tar.gz")
    got = archive.inspect(out)
    for source in ("platform_log", "file_sink"):
        body = got.files[f"files/{source}.json"]["data"]
        sigs = body["error_event_summary"]["signatures"]
        for family, sig in FAMILY_SIGNATURES.items():
            assert sigs.get(sig) == 1, (source, family)
        assert body["error_events"] == list(FAMILY_EVENTS.values())
    e = {x["source"]: x for x in got.manifest["sources"]}
    assert e["file_sink"]["dropped"]["unknown_field"] == 1
    assert e["platform_log"]["dropped"]["malformed_json"] == 1
    assert_no_planted(gzip.decompress(out.read_bytes()))


def test_a_planted_value_in_an_allowlisted_field_withholds_the_file(workspace):
    runner = FakeFlyRunner(reason=f"rollback, see {ANTHROPIC_KEY}")
    bundle = collector(workspace, runner).collect()
    e = entries(bundle)["fly_releases"]
    assert e["status"] == "withheld" and e["reason"] == "scanner_finding"
    assert {"anthropic_api_key", "install_secret_value"} == {f["rule"] for f in e["findings"]}
    assert not (bundle / "files" / "fly_releases.json").exists()
    assert_no_planted(all_output_bytes(bundle))


def test_an_encoded_install_secret_in_an_allowlisted_field_is_withheld(workspace):
    wrapped = base64.b64encode(f"pw={REVIEW_PASSWORD}".encode()).decode()
    bundle = collector(workspace, FakeFlyRunner(reason=wrapped)).collect()
    e = entries(bundle)["fly_releases"]
    assert e["status"] == "withheld"
    assert "install_secret_value" in {f["rule"] for f in e["findings"]}


# -- collection: failure cases ------------------------------------------------------------


def test_startup_failure_collects_without_esp(workspace):
    runner = FakeFlyRunner(healthy=False, ssh="down")
    bundle = collector(workspace, runner, status=503).collect("startup-failure")
    e = entries(bundle)
    assert file_data(bundle, "health")["healthz_status"] == 503
    assert e["file_sink"] == {**e["file_sink"], "status": "unavailable",
                              "reason": "machine_unreachable"}
    log = file_data(bundle, "platform_log")
    assert log["startup_exception_types"] == {"psycopg.OperationalError": 1}
    assert "db.ready_check db sqlstate=28P01 connect_class=auth" in \
        log["error_event_summary"]["signatures"]
    exit_event = file_data(bundle, "fly_machines")[0]["events"][0]["request"]["exit_event"]
    assert exit_event == {"exit_code": 1, "oom_killed": False, "requested_stop": False,
                          "restarting": True}
    assert file_data(bundle, "fly_machines")[0]["checks"][0]["status"] == "critical"


def test_sink_absent_and_source_timeouts_are_explicit(workspace):
    runner = FakeFlyRunner(ssh="absent", fail={"releases"})
    e = entries(collector(workspace, runner).collect())
    assert (e["file_sink"]["status"], e["file_sink"]["reason"]) == \
        ("unavailable", "sink_file_absent")
    assert (e["fly_releases"]["status"], e["fly_releases"]["reason"]) == \
        ("unavailable", "timeout")


def test_total_time_budget_marks_the_rest_unavailable(workspace):
    bundle = collector(workspace, clock=Clock(step=100.0)).collect()
    reasons = [x.get("reason") for x in entries(bundle).values()]
    assert "total_time_budget" in reasons


def test_file_bound_withholds_an_oversized_file(workspace):
    allow = allowlist.load()
    allow = replace(allow, bounds=replace(allow.bounds, max_file_bytes=600))
    e = entries(collector(workspace, allow=allow).collect())
    assert e["fly_machines"]["status"] == "withheld"
    assert e["fly_machines"]["reason"] == "over_file_bound"


def test_sink_tail_drops_a_record_cut_by_tail(workspace):
    allow = allowlist.load()
    line = json.dumps(FAMILY_EVENTS["family1_audit_revoked"])
    allow = replace(allow, bounds=replace(allow.bounds, max_sink_read_bytes=10))
    runner = FakeFlyRunner(sink_lines=[line[40:], line])
    result = sources.file_sink(Fly(runner), "app", allow)
    assert result.data["error_events"] == [FAMILY_EVENTS["family1_audit_revoked"]]


def test_missing_report_key_refuses_to_collect(workspace):
    (workspace / "report-key.pem").unlink()
    with pytest.raises(collect.CollectError, match="report key"):
        collector(workspace).collect()


def test_case_must_be_a_slug(workspace):
    with pytest.raises(collect.CollectError, match="slug"):
        collector(workspace).collect(f"note {PII_EMAIL}")


# -- export and inspect ------------------------------------------------------------------


def test_export_is_deterministic_and_inspects_clean(workspace, tmp_path):
    bundle = collector(workspace).collect()
    a = archive.export(bundle, tmp_path / "a.tar.gz")
    b = archive.export(bundle, tmp_path / "b.tar.gz")
    assert a.read_bytes() == b.read_bytes()
    fp = json.loads((workspace / "install-record.json").read_text())["report_key"]["fingerprint"]
    got = archive.inspect(a, expect_fingerprint=fp)
    assert got.digest == collect.bundle_digest(
        json.loads((bundle / collect.MANIFEST).read_text()))


def test_evidence_refs_resolve_the_same_before_and_after_export(workspace, tmp_path):
    bundle = collector(workspace).collect()
    env = json.loads((bundle / collect.MANIFEST).read_text())
    r = collect.ref(collect.bundle_digest(env), "files/platform_log.json",
                    "/data/error_events/0/sqlstate")
    got = archive.inspect(archive.export(bundle, tmp_path / "x.tar.gz"))
    assert archive.resolve(got, r) == "42501"
    with pytest.raises(archive.BundleRefused, match="another bundle"):
        archive.resolve(got, r.replace("sha256:", "sha256:0"))
    with pytest.raises(archive.BundleRefused, match="does not resolve"):
        archive.resolve(got, r + "/nope")


def _tar(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return gzip.compress(raw.getvalue())


def _members_of(archive_path: Path) -> list[tuple[tarfile.TarInfo, bytes]]:
    out = []
    with tarfile.open(archive_path, "r:gz") as tar:
        for info in tar:
            out.append((info, tar.extractfile(info).read()))
    return out


def _info(name: str, data: bytes, kind=tarfile.REGTYPE) -> tarfile.TarInfo:
    i = tarfile.TarInfo(name)
    i.size, i.type = (len(data) if kind == tarfile.REGTYPE else 0), kind
    return i


@pytest.fixture
def exported(workspace, tmp_path):
    return archive.export(collector(workspace).collect(), tmp_path / "good.tar.gz")


@pytest.mark.parametrize("mutate,match", [
    (lambda m: m + [(_info("../escape.json", b"{}"), b"{}")], "not one a bundle holds"),
    (lambda m: m + [(_info("/etc/passwd", b"x"), b"x")], "not one a bundle holds"),
    (lambda m: m + [(_info("files/link.json", b"", tarfile.SYMTYPE), None)], "regular file"),
    (lambda m: m + [(_info("files", b"", tarfile.DIRTYPE), None)], "regular file"),
    (lambda m: m + [(_info("files/extra.json", b"{}"), b"{}")], "do not match the manifest"),
    (lambda m: m + [m[-1]], "duplicate"),
    (lambda m: [x for x in m if x[0].name != "report-key.pub.json"], "missing"),
    (lambda m: [(x[0], x[1].replace(b'"Deployed"', b'"Pending!"'))
                if x[0].name == "files/fly_secrets.json" else x for x in m], "manifest hash"),
])
def test_inspect_refuses_hostile_archives(exported, tmp_path, mutate, match):
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(_tar(mutate(_members_of(exported))))
    with pytest.raises(archive.BundleRefused, match=match):
        archive.inspect(bad)


def test_inspect_refuses_an_oversized_member(exported, tmp_path):
    big = b"x" * (allowlist.load().bounds.max_file_bytes + 10)
    bad = tmp_path / "big.tar.gz"
    bad.write_bytes(_tar(_members_of(exported) + [(_info("files/big.json", big), big)]))
    with pytest.raises(archive.BundleRefused, match="bytes"):
        archive.inspect(bad)


def test_inspect_refuses_a_decompression_bomb(tmp_path):
    bomb = tmp_path / "bomb.tar.gz"
    bomb.write_bytes(gzip.compress(b"\0" * (64 * 1024 * 1024)))
    assert bomb.stat().st_size < archive.MAX_ARCHIVE_BYTES
    with pytest.raises(archive.BundleRefused, match="expands"):
        archive.inspect(bomb)


def test_inspect_refuses_non_gzip_and_oversized_files(tmp_path):
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"not an archive at all")
    with pytest.raises(archive.BundleRefused, match="gzip"):
        archive.inspect(junk)
    huge = tmp_path / "huge.tar.gz"
    huge.write_bytes(os.urandom(archive.MAX_ARCHIVE_BYTES + 1))
    with pytest.raises(archive.BundleRefused, match="cap"):
        archive.inspect(huge)


def test_inspect_refuses_a_resigned_bundle_under_the_wrong_fingerprint(exported, tmp_path):
    other = Ed25519PrivateKey.generate()
    members = _members_of(exported)
    env = json.loads(dict((i.name, d) for i, d in members)["manifest.signed.json"])
    forged = signing.sign(json.loads(env["payload"]), other)
    swap = {"manifest.signed.json": json.dumps(forged).encode(),
            "report-key.pub.json": json.dumps(_key_record(other)).encode()}
    rebuilt = [(_info(i.name, swap.get(i.name, d)), swap.get(i.name, d)) for i, d in members]
    bad = tmp_path / "forged.tar.gz"
    bad.write_bytes(_tar(rebuilt))
    archive.inspect(bad)  # self-consistent, so only the out-of-band fingerprint catches it
    real_fp = env["key_fingerprint"]
    with pytest.raises(archive.BundleRefused, match="not the expected"):
        archive.inspect(bad, expect_fingerprint=real_fp)


def test_inspect_never_writes_member_files(exported, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = set(tmp_path.rglob("*"))
    archive.inspect(exported)
    assert set(tmp_path.rglob("*")) == before


# -- CLI -------------------------------------------------------------------------------------


def test_cli_review_export_inspect(workspace, tmp_path, capsys):
    bundle = collector(workspace).collect()
    conf = str(workspace / "install.toml")
    assert cli.main(["review", bundle.name, "--config", conf]) == 0
    assert "Nothing has been sent" in capsys.readouterr().out
    out = tmp_path / "e.tar.gz"
    assert cli.main(["export", bundle.name, "--config", conf, "--out", str(out)]) == 0
    assert cli.main(["export", bundle.name, "--config", conf, "--out", str(out)]) == 3
    assert cli.main(["inspect", str(out)]) == 0
    assert cli.main(["review", "../../etc", "--config", conf]) == 3
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(b"junk")
    assert cli.main(["inspect", str(bad)]) == 4
