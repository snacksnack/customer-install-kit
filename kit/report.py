"""The preflight report: a versioned envelope of observations.

The report carries evidence only. Remediation text and any diagnostic rule
stay in the registry and the triage engine, so a bundle never mixes what was
seen with what someone concluded from it.
"""

import json
from pathlib import Path
from typing import Any

from kit.model import ALLOWED_REASONS, Outcome, Reason
from kit.registry import KNOWN_REGISTRY_VERSIONS, Registry, validate_evidence

SCHEMA = "cik.preflight/1"
SUPPORTED_SCHEMAS = frozenset({SCHEMA})


class UnsupportedReport(Exception):
    """A report this kit cannot interpret. Raised instead of guessing."""


def load(path: Path, registry: Registry) -> dict[str, Any]:
    return parse(json.loads(path.read_text()), registry)


def parse(data: dict[str, Any], registry: Registry) -> dict[str, Any]:
    schema = data.get("schema")
    if schema not in SUPPORTED_SCHEMAS:
        raise UnsupportedReport(
            f"report schema {schema!r}; this kit reads {sorted(SUPPORTED_SCHEMAS)}"
        )
    version = data.get("registry_version")
    if version not in KNOWN_REGISTRY_VERSIONS:
        raise UnsupportedReport(
            f"report was written against registry v{version}; this kit knows "
            f"{sorted(KNOWN_REGISTRY_VERSIONS)}"
        )
    if version != registry.version:
        raise UnsupportedReport(
            f"report registry v{version} does not match the loaded registry v{registry.version}"
        )
    checks = registry.by_id()
    problems = []
    for obs in data.get("observations", []):
        check_id = obs.get("check_id")
        if check_id not in checks:
            problems.append(f"unknown check id {check_id!r}")
            continue
        try:
            outcome, reason = Outcome(obs["outcome"]), Reason(obs["reason"])
        except (KeyError, ValueError):
            problems.append(f"{check_id}: bad outcome/reason")
            continue
        if reason not in ALLOWED_REASONS[outcome]:
            problems.append(f"{check_id}: reason {reason} is not valid for {outcome}")
        problems += validate_evidence(checks[check_id], obs.get("evidence", {}))
    if problems:
        raise UnsupportedReport("; ".join(problems))
    return data
