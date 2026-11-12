"""The registry is a contract: malformed entries must fail the build."""

import copy
import tomllib

import pytest

from kit import registry
from kit.probes import PROBES
from kit.requirements_doc import DOC_PATH, render

with registry.REGISTRY_PATH.open("rb") as fh:
    SHIPPED = tomllib.load(fh)


def raw_copy() -> dict:
    return copy.deepcopy(SHIPPED)


def test_shipped_registry_is_valid_and_every_check_has_a_probe():
    reg = registry.load(probe_ids=frozenset(PROBES))
    assert len(reg.checks) == len(SHIPPED["check"])


def test_duplicate_id_is_rejected():
    raw = raw_copy()
    raw["check"].append(copy.deepcopy(raw["check"][0]))
    assert any("duplicate id" in p for p in registry.validate_raw(raw))


def test_missing_field_is_rejected():
    raw = raw_copy()
    del raw["check"][0]["remediation"]
    assert any("missing field 'remediation'" in p for p in registry.validate_raw(raw))


def test_unknown_field_is_rejected():
    raw = raw_copy()
    raw["check"][0]["fault_family"] = "db-perms"
    assert any("unknown field 'fault_family'" in p for p in registry.validate_raw(raw))


@pytest.mark.parametrize("bad_id", ["env-001", "ENV-1", "ENV_001", "", 7])
def test_bad_id_format_is_rejected(bad_id):
    raw = raw_copy()
    raw["check"][0]["id"] = bad_id
    assert any("id must match" in p for p in registry.validate_raw(raw))


def test_unknown_evidence_type_is_rejected():
    raw = raw_copy()
    raw["check"][0]["evidence"] = {"present": "dict"}
    assert any("unknown type 'dict'" in p for p in registry.validate_raw(raw))


def test_forward_or_missing_dependency_is_rejected():
    raw = raw_copy()
    raw["check"][0]["depends_on"] = ["RT-003"]
    assert any("not an earlier check" in p for p in registry.validate_raw(raw))


def test_cross_context_dependency_is_rejected():
    raw = raw_copy()
    db_002 = next(c for c in raw["check"] if c["id"] == "DB-002")
    db_002["depends_on"] = ["ENV-001"]
    assert any("another context" in p for p in registry.validate_raw(raw))


def test_unknown_registry_version_is_rejected():
    raw = raw_copy()
    raw["registry_version"] = 99
    assert any("registry_version 99" in p for p in registry.validate_raw(raw))


def test_probe_coverage_both_directions():
    reg = registry.load()
    ids = frozenset(c.id for c in reg.checks)
    assert registry.match_probes(reg, ids - {"RT-004"}) == ["RT-004: registered but has no probe"]
    assert registry.match_probes(reg, ids | {"XX-999"}) == [
        "XX-999: probe exists but is not registered"
    ]


def test_evidence_validation():
    check = registry.load().get("RT-003")
    good = {
        "path": "/data",
        "exists": True,
        "writable": None,
        "errno": None,
        "free_bytes": None,
        "minimum_free_bytes": 1,
    }
    assert registry.validate_evidence(check, good) == []
    assert registry.validate_evidence(check, {}) == []
    assert registry.validate_evidence(check, {**good, "secret": "x"}) == [
        "RT-003: undeclared evidence field 'secret'"
    ]
    missing = dict(good)
    del missing["path"]
    assert registry.validate_evidence(check, missing) == ["RT-003: missing evidence field 'path'"]
    assert registry.validate_evidence(check, {**good, "exists": "yes"})
    assert registry.validate_evidence(check, {**good, "minimum_free_bytes": True})


def test_requirements_doc_is_current():
    reg = registry.load(probe_ids=frozenset(PROBES))
    assert DOC_PATH.read_text() == render(reg), "run `uv run python -m kit requirements`"
    for check in reg.checks:
        assert f"### {check.id}: {check.title}" in DOC_PATH.read_text()
