"""The install record (`cik.install/1`), customer-side (RC1-640, ADR 0006).

What was installed and what the install owns: release, resource identifiers
and ownership, the schema the database reports, secret NAMES, the report
public key, step outcomes and an action history. It is what the customer
shares with the vendor when asking for help, so it holds no credential and
no value from the secrets file; every write is scanned for those values and
refused if one appears.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = "cik.install/1"

# Ownership drives teardown: only "created" resources are ever destroyed.
CREATED = "created"
ADOPTED = "adopted"

STATE_INSTALLING = "installing"
STATE_INSTALLED = "installed"
STATE_NOT_READY = "installed_not_ready"
STATE_TORN_DOWN = "torn_down"


class RecordError(Exception):
    pass


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new(install_id: str, profile: str, config: dict[str, Any]) -> dict[str, Any]:
    stamp = now()
    return {
        "schema": SCHEMA,
        "install_id": install_id,
        "profile": profile,
        "created_at": stamp,
        "updated_at": stamp,
        "state": STATE_INSTALLING,
        "config": config,
        "release": None,             # deployed now
        "target_release": None,      # what the latest install run is installing
        "installed_version": None,   # last install/rollback that COMPLETED
        "resources": {},
        "secrets": {"pushed": []},
        "report_key": None,
        "steps": {},
        "runtime_preflight": None,
        "history": [],
    }


def load(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    if data.get("schema") != SCHEMA:
        raise RecordError(f"{path}: schema {data.get('schema')!r}, this kit reads {SCHEMA}")
    return data


def save(path: Path, record: dict[str, Any], secret_values: set[str]) -> None:
    record["updated_at"] = now()
    text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if any(v in text for v in secret_values):
        raise RecordError("install record would contain a secret value; refusing to write it")
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def step(record: dict[str, Any], name: str, status: str, **detail: Any) -> None:
    record["steps"][name] = {"status": status, "at": now(), **detail}
