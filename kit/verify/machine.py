"""The conformance run inside the customer's machine (RC1-641, ADR 0007).

Shipped into the running app over `fly ssh` and run with the image's own
Python, from /app, so every step is the INSTALLED release's code against
the machine's own secrets and network. Standard library only: it drives
ESP's CLIs as subprocesses and judges nothing. It prints one JSON object
(each step's exit code and output tail, plus the evidence files' text) for
the operator side to evaluate, hash, and sign.

    python machine.py --run-id RUN [--count N] [--domain D]

Steps, in order; a step whose inputs do not exist is recorded as skipped:
fixture, gate_draft (must be refused), approve, gate_tampered (must be
refused), execute, reconcile, cleanup. Cleanup runs whenever a fixture was
built, even after a failure, so a failed run still removes its records.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

PYTHON = "/app/.venv/bin/python"
APP_DIR = "/app"
WORK_ROOT = Path("/tmp/cik-verify")
TAIL_LINES = 12
STEP_TIMEOUT_S = 900
EVIDENCE = ("expected.json", "spec.approved.yaml", "journal.jsonl", "reconcile.md",
            "reconcile-history.jsonl", "cleanup.json")


def _run(name: str, args: list[str], steps: dict) -> int:
    proc = subprocess.run(
        [PYTHON, "-m", *args], cwd=APP_DIR, capture_output=True, text=True,
        timeout=STEP_TIMEOUT_S,
    )
    steps[name] = {
        "exit": proc.returncode,
        "stdout_tail": proc.stdout.strip().splitlines()[-TAIL_LINES:],
        "stderr_tail": proc.stderr.strip().splitlines()[-TAIL_LINES:],
    }
    return proc.returncode


def _skip(name: str, steps: dict, why: str) -> None:
    steps[name] = {"exit": None, "skipped": why}


def _bundle(work: Path) -> list[str]:
    return ["--audience-dir", str(work / "audience"),
            "--supplement-dir", str(work / "api_supplement"), "--target", "brevo"]


def run(run_id: str, count: int, domain: str) -> dict:
    work = WORK_ROOT / run_id
    if work.exists():
        raise SystemExit(f"{work} exists: run ids are single-use")
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    steps: dict = {}
    draft, approved = work / "spec.draft.yaml", work / "spec.approved.yaml"
    tampered = work / "spec.tampered.yaml"

    _run("fixture", ["conformance", "fixture", "--run-id", run_id, "--out", str(work),
                     "--count", str(count), "--domain", domain], steps)
    built = (work / "expected.json").exists()
    try:
        if not built:
            for name in ("gate_draft", "approve", "gate_tampered", "execute", "reconcile"):
                _skip(name, steps, "no fixture")
            return {"run_id": run_id, "steps": steps, "files": {}}

        _run("gate_draft", ["executor.run", "--spec", str(draft), *_bundle(work)], steps)
        _run("approve", ["mapping.review", "approve", str(draft),
                         "--by", f"cik conformance {run_id}", "--out", str(approved)], steps)
        if approved.exists():
            # One byte of content changed after sign-off: the hash must catch it.
            text = approved.read_text()
            changed = re.sub(r"^generated_at: .*$", "generated_at: '2000-01-01T00:00:00Z'",
                             text, count=1, flags=re.M)
            tampered.write_text(changed)
            steps["tamper_applied"] = changed != text
            _run("gate_tampered", ["executor.run", "--spec", str(tampered), *_bundle(work)],
                 steps)
            journal = work / "journal.jsonl"
            _run("execute", ["executor.run", "--spec", str(approved), *_bundle(work),
                             "--execute", "--verify-convergence",
                             "--journal", str(journal)], steps)
            # Reconcile runs even after a failed execute: it reads what did
            # land, and the evaluator never counts it as a pass on its own.
            _run("reconcile", ["executor.reconcile", "--spec", str(approved),
                               *_bundle(work), "--journal", str(journal),
                               "--out", str(work / "reconcile.md"),
                               "--history", str(work / "reconcile-history.jsonl")], steps)
        else:
            for name in ("gate_tampered", "execute", "reconcile"):
                _skip(name, steps, "approval produced no spec")
    finally:
        if built:
            _run("cleanup", ["conformance", "cleanup", "--expected", str(work / "expected.json"),
                             "--out", str(work / "cleanup.json")], steps)
    files = {n: (work / n).read_text() for n in EVIDENCE if (work / n).exists()}
    shutil.rmtree(work, ignore_errors=True)
    return {"run_id": run_id, "steps": steps, "files": files}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--domain", default="example.com")
    args = parser.parse_args()
    result = run(args.run_id, args.count, args.domain)
    sys.stdout.write("CIK-RESULT " + json.dumps(result, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
