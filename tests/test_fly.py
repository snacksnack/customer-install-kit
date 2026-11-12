"""Fly app lookup is app-scoped and tells "not found" from a real error."""

import json

import pytest

from kit.install.fly import Fly, FlyError, Result


def fly_with(result):
    return Fly(runner=lambda args, stdin: result)


def test_app_org_reads_the_owning_org():
    out = json.dumps({"Name": "acme-esp", "Organization": {"Slug": "acme-org"}})
    assert fly_with(Result(0, out, "")).app_org("acme-esp") == "acme-org"


def test_not_found_is_none():
    err = 'Error: failed to get app: ...: Could not find App "acme-esp"'
    assert fly_with(Result(1, "", err)).app_org("acme-esp") is None


def test_any_other_failure_raises():
    with pytest.raises(FlyError):
        fly_with(Result(1, "", "Error: unauthorized")).app_org("acme-esp")
