"""Runner behavior: bounded probes, dependency blocking, exit statuses, the
evidence contract, the secret guard, and the report schema round trip."""

import json
import time
from dataclasses import replace

import pytest

from kit import __main__ as cli
from kit import preflight, registry, report
from kit.model import Context, Outcome, ProbeResult, Reason, Severity
from kit.probes import PROBES, ProbeEnv

REG = registry.load(probe_ids=frozenset(PROBES))
RUNTIME_IDS = [c.id for c in REG.checks if c.context is Context.RUNTIME]


def passing(check, env):
    if check.id == "ENV-002":
        return ProbeResult(Outcome.PASS, Reason.OK, {"is_default": False})
    return ProbeResult(Outcome.NOT_APPLICABLE, Reason.NOT_CONFIGURED)


def probes_with(**overrides):
    table = {cid: passing for cid in PROBES}
    table.update({k.replace("_", "-"): v for k, v in overrides.items()})
    return table


def runtime(probes, reg=REG):
    return preflight.run(reg, Context.RUNTIME, env=ProbeEnv(environ={}), probes=probes)


def test_all_passing_exits_zero_and_report_round_trips():
    result = runtime(probes_with())
    assert result.exit_status == preflight.EXIT_OK
    assert [o["check_id"] for o in result.report["observations"]] == RUNTIME_IDS
    assert report.parse(json.loads(json.dumps(result.report)), REG) is not None


def test_required_failure_exits_one():
    fail = lambda c, e: ProbeResult(Outcome.FAIL, Reason.UNSUPPORTED, {"machine": "arm64"})  # noqa: E731
    assert runtime(probes_with(RT_001=fail)).exit_status == preflight.EXIT_FAILED


def test_advisory_failure_does_not_block():
    assert REG.get("ENV-003").severity is Severity.ADVISORY
    fail = lambda c, e: ProbeResult(  # noqa: E731
        Outcome.FAIL, Reason.MISSING, {"present": [], "missing": ["ESP_ANTHROPIC_API_KEY"]}
    )
    assert runtime(probes_with(ENV_003=fail)).exit_status == preflight.EXIT_OK


def test_required_unknown_without_failure_exits_two():
    unknown = lambda c, e: ProbeResult(Outcome.UNKNOWN, Reason.PROBE_UNAVAILABLE)  # noqa: E731
    assert runtime(probes_with(RT_002=unknown)).exit_status == preflight.EXIT_UNKNOWN


def test_probe_is_abandoned_at_its_timeout():
    def hang(check, env):
        time.sleep(30)

    fast = replace(REG.get("RT-001"), timeout_s=0.2)
    reg = registry.Registry(REG.version, (fast,))
    started = time.monotonic()
    result = runtime(probes_with(RT_001=hang), reg)
    assert time.monotonic() - started < 5
    obs = result.observations[0]
    assert (obs.outcome, obs.reason) == (Outcome.UNKNOWN, Reason.TIMEOUT)
    assert result.exit_status == preflight.EXIT_UNKNOWN


def test_probe_crash_is_unknown_not_a_kit_error(capsys):
    def boom(check, env):
        raise KeyError("ESP_SOMETHING")

    obs = runtime(probes_with(RT_001=boom)).observations
    rt001 = next(o for o in obs if o.check_id == "RT-001")
    assert (rt001.outcome, rt001.reason) == (Outcome.UNKNOWN, Reason.PROBE_ERROR)
    assert "KeyError" in capsys.readouterr().err


def test_dependency_not_passing_blocks_dependents():
    fail = lambda c, e: ProbeResult(  # noqa: E731
        Outcome.FAIL, Reason.REFUSED,
        {"connected": False, "tls": None, "sqlstate": None, "error_class": "auth"},
    )
    result = preflight.run(
        REG, Context.OPERATOR, env=ProbeEnv(environ={}), probes=probes_with(DB_001=fail)
    )
    by_id = {o.check_id: o for o in result.observations}
    assert by_id["DB-002"].reason is Reason.BLOCKED
    assert by_id["DB-002"].blocked_by == ("DB-001",)
    assert by_id["DB-003"].reason is Reason.BLOCKED
    assert by_id["DB-004"].reason is Reason.NOT_CONFIGURED  # no dependency, ran anyway


def test_check_outside_profile_is_not_applicable():
    result = preflight.run(
        REG, Context.RUNTIME, profile="v2", env=ProbeEnv(environ={}), probes=probes_with()
    )
    assert {o.reason for o in result.observations} == {Reason.NOT_IN_PROFILE}


def test_undeclared_evidence_is_a_kit_error():
    leak = lambda c, e: ProbeResult(  # noqa: E731
        Outcome.PASS, Reason.OK, {"machine": "x86_64", "password": "p"}
    )
    with pytest.raises(preflight.KitError, match="undeclared evidence field 'password'"):
        runtime(probes_with(RT_001=leak))


def test_reason_must_match_outcome():
    wrong = lambda c, e: ProbeResult(Outcome.PASS, Reason.MISSING, {"machine": "x"})  # noqa: E731
    with pytest.raises(preflight.KitError, match="not valid for pass"):
        runtime(probes_with(RT_001=wrong))


def test_secret_guard():
    environ = {
        "ESP_BREVO_API_KEY": "xkeysib-planted-secret",
        "ESP_DATABASE_OWNER_URL": "postgresql://owner:planted-pw-77@db.example/x",
        "ESP_ENVIRONMENT": "prod",  # too short to be treated as a secret
        "HOME": "/home/someone-long-path",  # not a secret variable
    }
    preflight.assert_no_secrets("all clear, prod, /home/someone-long-path", environ)
    for leaked in ("key=xkeysib-planted-secret", "pw planted-pw-77 in text"):
        with pytest.raises(preflight.KitError):
            preflight.assert_no_secrets(leaked, environ)


def test_report_reader_rejects_what_it_cannot_interpret():
    good = runtime(probes_with()).report
    for mutate, message in (
        (lambda r: r.update(schema="cik.preflight/2"), "report schema"),
        (lambda r: r.update(registry_version=2), "registry v2"),
        (lambda r: r["observations"][0].update(check_id="ZZ-001"), "unknown check id"),
        (lambda r: r["observations"][0].update(reason="ok", outcome="fail"), "not valid"),
        (lambda r: r["observations"][1].update(evidence={"x": 1}), "undeclared"),
    ):
        data = json.loads(json.dumps(good))
        mutate(data)
        with pytest.raises(report.UnsupportedReport, match=message):
            report.parse(data, REG)


def test_cli_operator_without_input_exits_two_and_writes_report(tmp_path, monkeypatch, capsys):
    for name in ("ESP_DATABASE_OWNER_URL",):
        monkeypatch.delenv(name, raising=False)
    out = tmp_path / "report.json"
    status = cli.main(["preflight", "--context", "operator", "--out", str(out)])
    assert status == preflight.EXIT_UNKNOWN
    data = report.load(out, REG)
    assert data["context"] == "operator"
    assert "NOT confirmed" in capsys.readouterr().out
    assert cli.main(["read-report", str(out)]) == 0


def test_cli_usage_error_is_a_kit_error_not_unknown():
    with pytest.raises(SystemExit) as exc:
        cli.main(["preflight", "--context", "cloud"])
    assert exc.value.code == preflight.EXIT_KIT_ERROR


def test_cli_refuses_to_print_a_leaked_secret(monkeypatch, capsys):
    monkeypatch.setenv("ESP_BREVO_API_KEY", "xkeysib-planted-secret")
    leak = lambda c, e: ProbeResult(  # noqa: E731
        Outcome.FAIL, Reason.UNSUPPORTED, {"machine": "xkeysib-planted-secret"}
    )
    for check_id in PROBES:  # no real network or filesystem probes in this test
        monkeypatch.setitem(PROBES, check_id, passing)
    monkeypatch.setitem(PROBES, "RT-001", leak)
    status = cli.main(["preflight", "--context", "runtime"])
    captured = capsys.readouterr()
    assert status == preflight.EXIT_KIT_ERROR
    assert "xkeysib-planted-secret" not in captured.out + captured.err
