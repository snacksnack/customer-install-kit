"""`python -m evals`: the cik-triage eval subject (RC1-644).

    uv run --group evals python -m evals                  # all six cases (~$1-3)
    uv run --group evals python -m evals --free           # the free cases only (CI)
    uv run --group evals python -m evals --case isolation
    uv run --group evals python -m evals --post-datadog   # also the cik.evals.* gauges

The billed cases need ANTHROPIC_API_KEY exported. EVAL_DATABASE_URL makes
the run comparable to the shared history; without it agent_evals records to
local JSONL and says so (`--no-record` skips recording, for CI).

Tracing is the kit's own metadata-only LLM Obs telemetry (ml_app cik-triage),
tagged env:evals, and only with DD_API_KEY. agent_evals.llmobs is NOT used: it
turns on ddtrace's Anthropic integration, which would record the prompts and
completions, and those carry bundle content (ADR 0009).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime

import anthropic
from agent_evals.runner import UnknownCase, exit_code, record_run, select_cases

from evals import subject

SERIES = "https://api.{site}/api/v2/series"
GAUGE = 3  # the v2 series `type` is an int enum
# The SDK default is 600 s a request with 2 retries, so one stalled call can
# hold a sweep for half an hour (seen 2026-11-14). The kit itself has no
# wall-clock budget; that is a kit finding, not fixed here.
MODEL_TIMEOUT_S = 300.0


def gauges(results) -> list[tuple[str, float, list[str]]]:
    """A None observation is left out, never sent as zero."""
    pts: list[tuple[str, float, list[str]]] = []
    for r in results:
        tags = [f"case:{r.case_id}"]
        pts.append(("cik.evals.case_passed", float(r.passed and not r.error), tags))
        if r.usage.cost_usd:
            pts.append(("cik.evals.model_usd", float(r.usage.cost_usd), tags))
        rounds = r.observations.get("rounds") if r.observations else None
        if rounds is not None:
            pts.append(("cik.evals.rounds", float(rounds), tags))
    pts.append(("cik.evals.cases_passed", float(sum(r.passed for r in results)), []))
    pts.append(("cik.evals.cases_failed", float(sum(not r.passed for r in results)), []))
    pts.append(("cik.evals.advisory_failures",
                float(sum(len(r.advisory_failures) for r in results)), []))
    return pts


def submit(pts: list[tuple[str, float, list[str]]]) -> bool:
    key = os.environ.get("DD_API_KEY")
    if not key:
        return False
    now = int(time.time())
    body = {"series": [{"metric": m, "type": GAUGE, "points": [{"timestamp": now, "value": v}],
                        "tags": ["service:cik-triage", "env:evals", *t]} for m, v, t in pts]}
    req = urllib.request.Request(SERIES.format(site=os.environ.get("DD_SITE", "datadoghq.com")),
                                 data=json.dumps(body).encode(), method="POST",
                                 headers={"DD-API-KEY": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 202
    except urllib.error.HTTPError as exc:
        # A swallowed 400 looks exactly like no traffic: say it.
        print(f"datadog: series intake returned {exc.code}", file=sys.stderr)
        return False
    except (OSError, urllib.error.URLError) as exc:
        print(f"datadog: series intake unreachable ({type(exc).__name__})", file=sys.stderr)
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", help="run a single case by id")
    parser.add_argument("--free", action="store_true", help="run only the unbilled cases")
    parser.add_argument("--no-record", action="store_true", help="do not record the run")
    parser.add_argument("--post-datadog", action="store_true",
                        help="publish the cik.evals.* gauges to Datadog")
    args = parser.parse_args(argv)
    try:
        cases = select_cases(subject.CASES, args.case)
    except UnknownCase as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.free:
        cases = tuple(c for c in cases if "billed" not in c.tags)
    billed = [c.id for c in cases if "billed" in c.tags]
    if billed and not os.environ.get("ANTHROPIC_API_KEY"):
        print(f"ANTHROPIC_API_KEY is not exported; billed cases {billed} need it "
              "(or pass --free).", file=sys.stderr)
        return 78
    os.environ.setdefault("DD_ENV", "evals")  # the kit's telemetry reads it per payload
    version = subject.version()
    print(f"{len(cases)} case(s) against {version.subject} {version.code_version}, "
          f"{version.model}, {version.prompt_version}; billed: {billed or 'none'}; "
          f"tracing {'on' if os.environ.get('DD_API_KEY') else 'off'} (metadata-only).\n")
    client = anthropic.Anthropic(timeout=MODEL_TIMEOUT_S, max_retries=2) if billed else None
    started = datetime.now(UTC)
    results = []
    try:
        for case in cases:
            results.append(subject.run(case, client))
    finally:
        subject.STATE.close()
    if not args.no_record:
        record_run(version, started, results)
        if not os.environ.get("EVAL_DATABASE_URL"):
            print("\nEVAL_DATABASE_URL is not set: this run recorded to local JSONL and is "
                  "not comparable to the shared history.")
    total = sum(float(r.usage.cost_usd) for r in results)
    print(f"model spend this run: ${total:.4f}")
    if args.post_datadog:
        pts = gauges(results)
        print(f"datadog: {len(pts)} gauge(s) {'submitted' if submit(pts) else 'not submitted'}")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
