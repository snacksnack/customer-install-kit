"""Load and validate the check registry (kit/checks.toml).

Validation is strict on purpose: the registry is a contract shared by
preflight, conformance, bundles and triage, so a malformed entry is a build
failure, not a runtime surprise.
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kit.model import Check, Context, Severity

REGISTRY_PATH = Path(__file__).with_name("checks.toml")

# Registry versions this kit can interpret. A report written against any
# other version is rejected explicitly (kit/report.py), never guessed at.
KNOWN_REGISTRY_VERSIONS = frozenset({1})

ID_PATTERN = re.compile(r"^[A-Z]{2,4}-\d{3}$")
EVIDENCE_TYPES = frozenset(
    {"str", "int", "bool", "list[str]", "str?", "int?", "bool?", "list[str]?"}
)
REQUIRED_FIELDS = (
    "id",
    "title",
    "context",
    "severity",
    "profiles",
    "purpose",
    "probe",
    "permission",
    "remediation",
    "timeout_s",
    "evidence",
)
OPTIONAL_FIELDS = ("params", "depends_on")


class RegistryError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class Registry:
    version: int
    checks: tuple[Check, ...]

    def by_id(self) -> dict[str, Check]:
        return {c.id: c for c in self.checks}

    def get(self, check_id: str) -> Check:
        return self.by_id()[check_id]


def load(path: Path = REGISTRY_PATH, probe_ids: frozenset[str] | None = None) -> Registry:
    """Parse and validate. With probe_ids, also require a one-to-one match
    between registry entries and probe implementations."""
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    problems = validate_raw(raw)
    if problems:
        raise RegistryError(problems)
    registry = Registry(
        version=raw["registry_version"],
        checks=tuple(_to_check(entry) for entry in raw["check"]),
    )
    if probe_ids is not None:
        problems = match_probes(registry, probe_ids)
        if problems:
            raise RegistryError(problems)
    return registry


def validate_raw(raw: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    version = raw.get("registry_version")
    if version not in KNOWN_REGISTRY_VERSIONS:
        problems.append(f"registry_version {version!r} is not one this kit knows")
    entries = raw.get("check")
    if not isinstance(entries, list) or not entries:
        return [*problems, "registry has no [[check]] entries"]

    seen: list[str] = []
    for index, entry in enumerate(entries):
        label = entry.get("id", f"entry #{index}")
        for name in REQUIRED_FIELDS:
            if name not in entry:
                problems.append(f"{label}: missing field {name!r}")
        for name in entry:
            if name not in REQUIRED_FIELDS + OPTIONAL_FIELDS:
                problems.append(f"{label}: unknown field {name!r}")

        check_id = entry.get("id")
        if not isinstance(check_id, str) or not ID_PATTERN.match(check_id):
            problems.append(f"{label}: id must match {ID_PATTERN.pattern}")
        elif check_id in seen:
            problems.append(f"{check_id}: duplicate id")
        if entry.get("context") not in {c.value for c in Context}:
            problems.append(f"{label}: context must be one of {[c.value for c in Context]}")
        if entry.get("severity") not in {s.value for s in Severity}:
            problems.append(f"{label}: severity must be one of {[s.value for s in Severity]}")
        profiles = entry.get("profiles")
        if not isinstance(profiles, list) or not profiles:
            problems.append(f"{label}: profiles must be a non-empty list")
        timeout = entry.get("timeout_s")
        if not isinstance(timeout, int | float) or isinstance(timeout, bool) or timeout <= 0:
            problems.append(f"{label}: timeout_s must be a positive number")
        for text_field in ("title", "purpose", "probe", "permission", "remediation"):
            value = entry.get(text_field)
            if text_field in entry and (not isinstance(value, str) or not value.strip()):
                problems.append(f"{label}: {text_field} must be non-empty text")

        evidence = entry.get("evidence")
        if not isinstance(evidence, dict) or not evidence:
            problems.append(f"{label}: evidence must declare at least one field")
        else:
            for name, kind in evidence.items():
                if kind not in EVIDENCE_TYPES:
                    problems.append(f"{label}: evidence {name!r} has unknown type {kind!r}")

        # Dependencies must point backwards, which keeps the graph acyclic and
        # lets the runner execute in file order.
        for dep in entry.get("depends_on", []):
            if dep not in seen:
                problems.append(f"{label}: depends_on {dep!r} is not an earlier check")
            else:
                dep_entry = entries[seen.index(dep)]
                if dep_entry.get("context") != entry.get("context"):
                    problems.append(f"{label}: depends_on {dep!r} runs in another context")
        if isinstance(check_id, str):
            seen.append(check_id)
    return problems


def match_probes(registry: Registry, probe_ids: frozenset[str]) -> list[str]:
    ids = {c.id for c in registry.checks}
    problems = [f"{i}: registered but has no probe" for i in sorted(ids - probe_ids)]
    problems += [f"{i}: probe exists but is not registered" for i in sorted(probe_ids - ids)]
    return problems


def validate_evidence(check: Check, evidence: dict[str, Any]) -> list[str]:
    """Evidence is either empty (the probe could not observe anything) or
    exactly the declared fields with the declared types. Anything else is a
    contract breach, and the field allowlist is also what keeps a probe from
    smuggling a secret into the report."""
    if not evidence:
        return []
    problems = []
    declared, given = set(check.evidence), set(evidence)
    for name in sorted(given - declared):
        problems.append(f"{check.id}: undeclared evidence field {name!r}")
    for name in sorted(declared - given):
        problems.append(f"{check.id}: missing evidence field {name!r}")
    for name in sorted(declared & given):
        if not _type_ok(check.evidence[name], evidence[name]):
            problems.append(
                f"{check.id}: evidence {name!r}={evidence[name]!r} is not {check.evidence[name]}"
            )
    return problems


def _type_ok(kind: str, value: Any) -> bool:
    if kind.endswith("?"):
        if value is None:
            return True
        kind = kind[:-1]
    if kind == "str":
        return isinstance(value, str)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "list[str]":
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    return False


def _to_check(entry: dict[str, Any]) -> Check:
    return Check(
        id=entry["id"],
        title=entry["title"],
        context=Context(entry["context"]),
        severity=Severity(entry["severity"]),
        profiles=tuple(entry["profiles"]),
        purpose=entry["purpose"],
        probe=entry["probe"],
        permission=entry["permission"],
        remediation=entry["remediation"],
        timeout_s=float(entry["timeout_s"]),
        evidence=dict(entry["evidence"]),
        params=dict(entry.get("params", {})),
        depends_on=tuple(entry.get("depends_on", ())),
    )
