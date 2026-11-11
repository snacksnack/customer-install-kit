"""Tests for the denial probe's pure logic (spike/denial_test.py).

The probe itself runs inside the triage container against live surfaces;
these tests pin the local logic that decides what counts as a leak, so a
refactor can't quietly stop flagging credential material.
"""

import fnmatch
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "denial_test", Path(__file__).parent.parent / "spike" / "denial_test.py"
)
denial_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(denial_test)

FORBIDDEN = ["FLY_API_TOKEN", "FLY_ACCESS_TOKEN", "ESP_*", "PG*", "NEON_*",
             "DATABASE_URL", "AWS_*", "GITHUB_TOKEN"]


def matches_forbidden(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in FORBIDDEN)


def test_credential_vars_are_flagged():
    for leak in ["FLY_API_TOKEN", "ESP_DATABASE_URL", "ESP_REVIEW_PASSWORD",
                 "PGPASSWORD", "NEON_API_KEY", "DATABASE_URL", "AWS_SECRET_ACCESS_KEY",
                 "GITHUB_TOKEN"]:
        assert matches_forbidden(leak), leak


def test_probe_inputs_and_benign_vars_are_not_flagged():
    for benign in ["PROBE_PG_HOST", "PATH", "HOSTNAME", "LANG", "PYTHONHASHSEED"]:
        assert not matches_forbidden(benign), benign


def test_refused_routes_to_passes_and_failures():
    denial_test.PASSES.clear()
    denial_test.FAILURES.clear()
    denial_test.refused("a", True, "denied")
    denial_test.refused("b", False, "breach")
    assert denial_test.PASSES == ["a: denied"]
    assert denial_test.FAILURES == ["b: breach"]
