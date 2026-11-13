"""The controlled case store (RC1-643, ADR 0009).

Investigation records carry evidence: the rules output, the agent's full
transcript (prompts, tool inputs, the evidence it read, its reasoning text),
follow-up requests and diagnoses. They live here, on the vendor's triage
host, in owner-only files, and nowhere else. They are not telemetry, not CI
output, and not eval exports; those get the metadata-only record instead.

Layout under the store root (default ~/.cik-triage/cases, or CIK_CASE_STORE):

    case-<12 hex of the primary bundle digest>/
        case.json                    inputs: bundle digests, fingerprint
        requests/fr-<id>.json        follow-up requests issued
        rounds/NN/rules.json         deterministic result for this round's evidence
        rounds/NN/transcript.jsonl   agent messages and tool calls (agent mode)
        rounds/NN/result.json        the round's outcome and diagnosis
"""

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path.home() / ".cik-triage" / "cases"


def _mkdirs(path: Path) -> None:
    """mkdir -p where EVERY created level is 0700 (mkdir's mode= applies only
    to the leaf; the parents would get the umask default)."""
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for d in reversed(missing):
        d.mkdir(mode=0o700)
        d.chmod(0o700)


def _write(path: Path, text: str) -> None:
    _mkdirs(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2, default=str) + "\n"


class Case:
    def __init__(self, path: Path):
        self.path = path
        self.id = path.name

    def write(self, rel: str, obj: Any) -> Path:
        p = self.path / rel
        _write(p, dumps(obj))
        return p

    def append(self, rel: str, obj: Any) -> None:
        p = self.path / rel
        _mkdirs(p.parent)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(obj, sort_keys=True, default=str) + "\n")

    def read(self, rel: str) -> Any:
        return json.loads((self.path / rel).read_text())

    def requests(self) -> list[dict[str, Any]]:
        d = self.path / "requests"
        return [json.loads(p.read_text()) for p in sorted(d.glob("fr-*.json"))] \
            if d.exists() else []

    def next_round(self) -> int:
        d = self.path / "rounds"
        done = [int(p.name) for p in d.iterdir() if p.name.isdigit()] if d.exists() else []
        return max(done, default=0) + 1


class CaseStore:
    def __init__(self, root: Path | None = None):
        env = os.environ.get("CIK_CASE_STORE")
        self.root = (root or (Path(env) if env else DEFAULT_ROOT)).expanduser()

    def case(self, primary_digest: str) -> Case:
        path = self.root / f"case-{primary_digest.removeprefix('sha256:')[:12]}"
        _mkdirs(path)
        self.root.chmod(0o700)
        return Case(path)

    def get(self, case_id: str) -> Case:
        path = self.root / case_id
        if not case_id.startswith("case-") or not path.is_dir():
            raise FileNotFoundError(f"no case {case_id!r} in {self.root}")
        return Case(path)
