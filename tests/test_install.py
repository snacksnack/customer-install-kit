"""Install converges, recovers from a mid-install failure, rolls back only
when the schema allows, and tears down only what it created (RC1-640).

Fly, the image and the release are fakes with state, so "converges" means
the second run made no create/stage/deploy call, not merely that it passed.
"""

import json
import os
import stat

import pytest

from kit.install import config as cfg
from kit.install import record as rec
from kit.install import release as rel
from kit.install import secrets_file
from kit.install.engine import (
    STEPS,
    Deps,
    InjectedFailure,
    Installer,
    InstallError,
    RecoveryRequired,
)

OWNER_URL = "postgresql://owner:owner-password-123@db.customer.example/esp"
DIGESTS = {"0.1.1": "sha256:" + "1" * 64, "0.1.2": "sha256:" + "2" * 64}


def make_release(version: str, schema=(1, 1)) -> rel.Release:
    return rel.Release(version=version, commit="c" * 40, image_digest=DIGESTS[version],
                       sbom_sha256="s" * 64, manifest_sha256="m" * 64,
                       schema_version=schema[0], schema_compatible_with=schema[1])


class FakeFly:
    def __init__(self, apps=(), volumes=None):
        self.apps = set(apps)
        self.vols = dict(volumes or {})          # id -> (app, name)
        self.machine_digest = {}                  # app -> digest
        self.secrets = {}                         # app -> {name: status}
        self.staged_values = []
        self.calls = []

    def app_org(self, app):
        return "acme-org" if app in self.apps else None

    def volumes(self, app, name):
        return [{"id": i, "name": n} for i, (a, n) in self.vols.items() if a == app and n == name]

    def machines(self, app):
        d = self.machine_digest.get(app)
        return [{"state": "started", "image_ref": {"digest": d}}] if d else []

    def secret_status(self, app):
        return dict(self.secrets.get(app, {}))

    def create_app(self, org, app):
        self.calls.append(("create_app", app))
        self.apps.add(app)

    def create_volume(self, app, name, size, region):
        self.calls.append(("create_volume", name))
        vid = f"vol_{len(self.vols) + 1}"
        self.vols[vid] = (app, name)
        return vid

    def stage_secrets(self, app, values):
        self.calls.append(("stage_secrets", tuple(sorted(values))))
        self.staged_values.append(dict(values))
        self.secrets.setdefault(app, {}).update({k: "Staged" for k in values})

    def deploy(self, app, config, image):
        self.calls.append(("deploy", image))
        self.machine_digest[app] = image.split("@")[1]
        self.secrets[app] = {k: "Deployed" for k in self.secrets.get(app, {})}

    def destroy_volume(self, app, vid):
        self.calls.append(("destroy_volume", vid))
        del self.vols[vid]

    def destroy_app(self, app):
        self.calls.append(("destroy_app", app))
        self.apps.discard(app)
        self.vols = {i: v for i, v in self.vols.items() if v[0] != app}

    def created(self, kind):
        return [c for c in self.calls if c[0] == kind]


class FakeDb:
    def __init__(self):
        self.marker = None
        self.app_url = None
        self.calls = []


class FakeImage:
    def __init__(self, db: FakeDb, schema=(1, 1)):
        self.db, self.schema = db, schema

    def schema_marker(self):
        return self.db.marker

    def migrate(self):
        self.db.calls.append("migrate")
        self.db.marker = self.schema
        return "schema applied"

    def create_app_role(self, token_key=None):
        self.db.calls.append("create_app_role")
        self.db.app_url = f"postgresql://esp_app:app-pw-{len(self.db.calls)}x@db.customer.example/esp"
        return {"ESP_DATABASE_URL": self.db.app_url,
                "ESP_SESSION_TOKEN_KEY": token_key or "token-key-abcdefgh"}


def runtime_report(failing=()):
    obs = [{"check_id": c, "outcome": "fail" if c in failing else "pass", "reason": "ok",
            "evidence": {}} for c in ("ENV-001", "ENV-002", "RT-001")]
    return {"schema": "cik.preflight/1", "exit_status": 1 if failing else 0,
            "summary": {"pass": 3 - len(failing), "fail": len(failing)},
            "observations": obs, "run_id": "r1"}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    (tmp_path / "install.toml").write_text(
        '[install]\nrelease = "0.1.1"\nfly_org = "acme-org"\napp = "acme-esp"\n'
        'region = "iad"\nvolume = "esp_data"\n')
    secrets_file.update(tmp_path / ".env.cik", {secrets_file.OWNER_URL: OWNER_URL})
    state = {"fly": FakeFly(), "db": FakeDb(), "said": [], "failing": (),
             "releases": {v: make_release(v) for v in DIGESTS}, "health": 200}

    def operator_preflight_ok(self):
        rec.step(self.record, "preflight_operator", "done", exit_status=0)

    monkeypatch.setattr(Installer, "_step_preflight_operator", operator_preflight_ok)

    def build():
        r = state["releases"]
        deps = Deps(
            fly=state["fly"],
            fetch_release=lambda v, dest: r[v],
            image=lambda ref, owner: FakeImage(
                state["db"], next((x.schema_version, x.schema_compatible_with)
                                  for x in r.values() if x.image_ref == ref)),
            http_status=lambda url: state["health"],
            db_connects=lambda url: url == state["db"].app_url,
            runtime_preflight=lambda fly, app, profile: runtime_report(state["failing"]),
            sleep=lambda s: None,
            say=state["said"].append,
        )
        return Installer(cfg.load(tmp_path / "install.toml"), deps)

    state["build"] = build
    state["dir"] = tmp_path
    return state


def read_record(world):
    return json.loads((world["dir"] / "install-record.json").read_text())


def test_fresh_install_creates_owns_and_records_without_secrets(world):
    assert world["build"]().install() == 0
    fly, db = world["fly"], world["db"]
    assert [c[0] for c in fly.calls] == ["create_app", "create_volume", "stage_secrets", "deploy"]
    assert db.calls == ["migrate", "create_app_role"]
    r = read_record(world)
    assert r["state"] == rec.STATE_INSTALLED
    assert r["resources"]["app"]["ownership"] == rec.CREATED
    assert r["resources"]["volume"]["ownership"] == rec.CREATED
    assert r["resources"]["database"]["host"] == "db.customer.example"
    assert r["release"]["image"].endswith(DIGESTS["0.1.1"])
    assert r["history"][-1]["action"] == "install"
    text = (world["dir"] / "install-record.json").read_text()
    for value in secrets_file.read(world["dir"] / ".env.cik").values():
        assert value not in text
    assert "owner-password" not in " ".join(world["said"])


def test_owner_url_never_reaches_the_app(world):
    world["build"]().install()
    pushed = world["fly"].staged_values[0]
    assert secrets_file.OWNER_URL not in pushed
    assert OWNER_URL not in pushed.values()
    assert set(pushed) == {"ESP_REVIEW_PASSWORD", "ESP_REVIEW_SESSION_SECRET",
                           "ESP_DATABASE_URL", "ESP_SESSION_TOKEN_KEY"}


def test_second_install_converges_with_no_writes(world):
    world["build"]().install()
    before = list(world["fly"].calls), list(world["db"].calls)
    assert world["build"]().install() == 0
    assert (world["fly"].calls, world["db"].calls) == before


@pytest.mark.parametrize("step", STEPS)
def test_failure_after_any_step_then_retry_converges(world, step):
    with pytest.raises(InjectedFailure):
        world["build"]().install(fail_after=step)
    assert read_record(world)["state"] == rec.STATE_INSTALLING
    assert world["build"]().install() == 0
    fly, db = world["fly"], world["db"]
    assert len(fly.created("create_app")) == 1
    assert len(fly.created("create_volume")) == 1
    assert db.calls.count("create_app_role") == 1  # never re-passworded on retry
    assert len(fly.vols) == 1
    assert read_record(world)["state"] == rec.STATE_INSTALLED


def test_a_failing_step_is_recorded_and_retry_resumes(world):
    world["health"] = 503
    with pytest.raises(InstallError, match="did not return 200"):
        world["build"]().install()
    assert read_record(world)["steps"]["health"]["status"] == "failed"
    world["health"] = 200
    assert world["build"]().install() == 0
    assert len(world["fly"].created("deploy")) == 1


def test_existing_resources_are_adopted_and_survive_teardown(world):
    world["fly"].apps.add("acme-esp")
    world["fly"].vols["vol_old"] = ("acme-esp", "esp_data")
    world["build"]().install()
    r = read_record(world)
    assert r["resources"]["app"]["ownership"] == rec.ADOPTED
    assert r["resources"]["volume"] == {"name": "esp_data", "id": "vol_old",
                                        "ownership": rec.ADOPTED}
    world["build"]().teardown("acme-esp")
    assert not world["fly"].created("destroy_app") and not world["fly"].created("destroy_volume")
    assert "acme-esp" in world["fly"].apps


def test_teardown_destroys_only_what_it_created_and_keeps_data(world):
    world["build"]().install()
    with pytest.raises(InstallError, match="--confirm"):
        world["build"]().teardown("wrong-name")
    assert world["build"]().teardown("acme-esp") == 0
    assert world["fly"].created("destroy_app") == [("destroy_app", "acme-esp")]
    r = read_record(world)
    assert r["state"] == rec.STATE_TORN_DOWN
    assert "retained" in r["history"][-1]["database"]
    assert world["db"].marker == (1, 1)  # the schema and data were never touched
    with pytest.raises(InstallError, match="torn down"):
        world["build"]().install()


def test_volume_created_inside_an_adopted_app_is_destroyed_by_id(world):
    world["fly"].apps.add("acme-esp")
    world["build"]().install()
    world["build"]().teardown("acme-esp")
    assert world["fly"].created("destroy_volume") == [("destroy_volume", "vol_1")]
    assert not world["fly"].created("destroy_app")


def test_upgrade_then_compatible_rollback_redeploys_without_migrating(world):
    world["build"]().install()
    (world["dir"] / "install.toml").write_text(
        (world["dir"] / "install.toml").read_text().replace("0.1.1", "0.1.2"))
    world["build"]().install()
    assert world["fly"].machine_digest["acme-esp"] == DIGESTS["0.1.2"]
    migrations = world["db"].calls.count("migrate")
    assert world["build"]().rollback("0.1.1") == 0
    assert world["fly"].machine_digest["acme-esp"] == DIGESTS["0.1.1"]
    assert world["db"].calls.count("migrate") == migrations
    actions = [h["action"] for h in read_record(world)["history"]]
    assert actions == ["install", "upgrade", "rollback"]


def test_rollback_refused_when_the_schema_forbids_it(world):
    world["releases"]["0.1.2"] = make_release("0.1.2", schema=(2, 2))
    (world["dir"] / "install.toml").write_text(
        (world["dir"] / "install.toml").read_text().replace("0.1.1", "0.1.2"))
    world["build"]().install()
    deploys = len(world["fly"].created("deploy"))
    with pytest.raises(RecoveryRequired, match="cannot reverse a migration") as exc:
        world["build"]().rollback("0.1.1")
    assert "point-in-time" in str(exc.value) and "not reversed" in str(exc.value)
    assert len(world["fly"].created("deploy")) == deploys
    assert world["fly"].machine_digest["acme-esp"] == DIGESTS["0.1.2"]
    assert read_record(world)["history"][-1]["outcome"] == "refused"


def test_install_never_migrates_a_newer_database_backward(world):
    world["db"].marker = (3, 2)
    with pytest.raises(RecoveryRequired, match="never migrates backward"):
        world["build"]().install()
    assert "migrate" not in world["db"].calls
    assert not world["fly"].created("deploy")


def test_a_refused_install_does_not_misreport_what_is_deployed(world):
    world["build"]().install()
    world["db"].marker = (2, 2)  # a newer release migrated, breaking
    (world["dir"] / "install.toml").write_text(
        (world["dir"] / "install.toml").read_text().replace("0.1.1", "0.1.2"))
    world["releases"]["0.1.2"] = make_release("0.1.2", schema=(1, 1))
    with pytest.raises(RecoveryRequired):
        world["build"]().install()
    r = read_record(world)
    assert r["release"]["version"] == "0.1.1"          # still what runs
    assert r["target_release"]["version"] == "0.1.2"
    assert r["installed_version"] == "0.1.1"


def test_runtime_check_failure_is_installed_not_ready(world):
    world["failing"] = ("ENV-001",)
    assert world["build"]().install() == 1
    r = read_record(world)
    assert r["state"] == rec.STATE_NOT_READY
    assert r["runtime_preflight"]["failing_required"] == ["ENV-001"]


def test_untrusted_release_stops_before_any_customer_change(world):
    def reject(version, dest):
        raise rel.ReleaseRejected("signature", "identity mismatch")
    installer = world["build"]()
    installer.deps.fetch_release = reject
    with pytest.raises(rel.ReleaseRejected):
        installer.install()
    assert world["fly"].calls == [] and world["db"].calls == []


def test_secrets_file_must_be_private(world):
    path = world["dir"] / ".env.cik"
    path.chmod(0o644)
    with pytest.raises(secrets_file.SecretsFileError, match="600"):
        world["build"]()


def test_generated_secrets_land_in_the_customer_file_mode_600(world):
    world["build"]().install()
    path = world["dir"] / ".env.cik"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    values = secrets_file.read(path)
    assert values["ESP_REVIEW_PASSWORD"] and values["ESP_REVIEW_SESSION_SECRET"]
    assert stat.S_IMODE(os.stat(world["dir"] / "report-key.pem").st_mode) == 0o600
    assert read_record(world)["report_key"]["fingerprint"].startswith("sha256:")


def test_an_app_in_another_org_is_never_adopted(world):
    world["fly"].app_org = lambda app: "someone-else"
    with pytest.raises(InstallError, match="belongs to org someone-else"):
        world["build"]().install()
    assert not world["fly"].created("create_app")


def test_deploy_waits_out_a_lagging_machines_api(world):
    fly = world["fly"]
    real_deploy, stale = fly.deploy, {"left": 0, "old": None}

    def deploy(app, config, image):
        stale["old"], stale["left"] = fly.machine_digest.get(app), 3
        real_deploy(app, config, image)

    real_machines = fly.machines

    def machines(app):
        if stale["left"] and stale["old"]:
            stale["left"] -= 1
            return [{"state": "stopped", "image_ref": {"digest": stale["old"]}}]
        return real_machines(app)

    fly.deploy, fly.machines = deploy, machines
    world["build"]().install()
    (world["dir"] / "install.toml").write_text(
        (world["dir"] / "install.toml").read_text().replace("0.1.1", "0.1.2"))
    assert world["build"]().install() == 0  # seen live: deploy done, list still old
    assert fly.machine_digest["acme-esp"] == DIGESTS["0.1.2"]


def test_history_counts_completed_installs_not_started_ones(world):
    with pytest.raises(InjectedFailure):
        world["build"]().install(fail_after="schema")
    world["build"]().install()
    r = read_record(world)
    assert [(h["action"], h["from"], h["to"]) for h in r["history"]] == [("install", None, "0.1.1")]
    assert r["installed_version"] == "0.1.1"
