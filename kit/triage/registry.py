"""The triage registry: rules, prompt, support knowledge, follow-up checks
(RC1-643, ADR 0009).

These files are what gets frozen before held-out evaluation. Every triage
record carries `digest()`, the sha256 over their bytes in a fixed order, so
a result can always be tied to the exact registry that produced it, and a
change after the freeze is visible as a different digest.
"""

import hashlib
import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
FILES = ("knowledge.toml", "followups.toml", "rules.py", "facts.py", "prompt.md")
FOLLOWUP_ID_PREFIX = "FUP-"


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class Followup:
    id: str
    title: str
    purpose: str
    runs_on: str
    permissions: tuple[str, ...]
    returns: str
    discriminates: str


def digest() -> str:
    h = hashlib.sha256()
    for name in FILES:
        data = (HERE / name).read_bytes()
        h.update(f"{name}\0{len(data)}\0".encode())
        h.update(data)
    return "sha256:" + h.hexdigest()


@cache
def knowledge() -> dict[str, Any]:
    raw = tomllib.loads((HERE / "knowledge.toml").read_text())
    if raw.get("version") != 1:
        raise RegistryError("knowledge.toml version is not one this kit knows")
    return raw


@cache
def followups() -> dict[str, Followup]:
    raw = tomllib.loads((HERE / "followups.toml").read_text())
    if raw.get("version") != 1:
        raise RegistryError("followups.toml version is not one this kit knows")
    out = {}
    for cid, spec in raw["checks"].items():
        if not cid.startswith(FOLLOWUP_ID_PREFIX):
            raise RegistryError(f"follow-up id {cid!r} must start with {FOLLOWUP_ID_PREFIX}")
        out[cid] = Followup(cid, spec["title"], spec["purpose"], spec["runs_on"],
                            tuple(spec["permissions"]), spec["returns"], spec["discriminates"])
    return out


def versions() -> dict[str, Any]:
    return {"registry_digest": digest(), "knowledge": knowledge()["version"],
            "followups": 1, "rules": RULES_VERSION}


RULES_VERSION = 1
