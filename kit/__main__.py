"""Command line: `python -m kit {preflight,registry,requirements}`.

Exit statuses for preflight: 0 ready, 1 a required check failed, 2 none
failed but a required check is unknown, 3 kit error.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from kit import preflight, registry, report, requirements_doc
from kit.model import Context, Outcome, Severity
from kit.probes import PROBES

MARKS = {
    Outcome.PASS: "PASS",
    Outcome.FAIL: "FAIL",
    Outcome.NOT_APPLICABLE: "N/A ",
    Outcome.UNKNOWN: "UNKN",
}
VERDICTS = {
    preflight.EXIT_OK: "ready to install",
    preflight.EXIT_FAILED: "NOT ready: a required check failed",
    preflight.EXIT_UNKNOWN: "NOT confirmed: a required check could not be evaluated",
}


def _human(reg: registry.Registry, result: preflight.Run) -> str:
    checks = reg.by_id()
    lines = [f"Preflight ({result.report['context']}, profile {result.report['profile']})", ""]
    for obs in result.observations:
        check = checks[obs.check_id]
        advisory = " (advisory)" if check.severity is Severity.ADVISORY else ""
        lines.append(f"  {MARKS[obs.outcome]}  {check.id}  {check.title}{advisory}")
        detail = obs.reason.value
        if obs.blocked_by:
            detail += f" by {', '.join(obs.blocked_by)}"
        if obs.outcome is not Outcome.PASS:
            lines.append(f"              reason: {detail}")
        if obs.outcome in (Outcome.FAIL, Outcome.UNKNOWN) and obs.evidence:
            lines.append(f"              evidence: {json.dumps(obs.evidence, sort_keys=True)}")
        if obs.outcome is Outcome.FAIL:
            lines.append(f"              fix: {check.remediation}")
    lines += ["", f"Result: {VERDICTS[result.exit_status]} (exit {result.exit_status})"]
    return "\n".join(lines)


def cmd_preflight(args: argparse.Namespace) -> int:
    reg = registry.load(probe_ids=frozenset(PROBES))
    result = preflight.run(reg, Context(args.context), profile=args.profile)
    report_text = json.dumps(result.report, indent=2, sort_keys=True) + "\n"
    human_text = _human(reg, result)
    environ = dict(os.environ)
    preflight.assert_no_secrets(report_text + human_text, environ)
    if args.out:
        Path(args.out).write_text(report_text)
    print(report_text if args.json else human_text, end="" if args.json else "\n")
    return result.exit_status


def cmd_registry(args: argparse.Namespace) -> int:
    reg = registry.load(probe_ids=frozenset(PROBES))
    print(f"registry v{reg.version}: {len(reg.checks)} checks, every check has a probe")
    return 0


def cmd_requirements(args: argparse.Namespace) -> int:
    reg = registry.load(probe_ids=frozenset(PROBES))
    rendered = requirements_doc.render(reg)
    path = requirements_doc.DOC_PATH
    if args.check:
        current = path.read_text() if path.exists() else ""
        if current != rendered:
            print(f"{path} is stale; run `uv run python -m kit requirements`", file=sys.stderr)
            return 1
        print(f"{path.name} is current")
        return 0
    path.write_text(rendered)
    print(f"wrote {path}")
    return 0


def cmd_read_report(args: argparse.Namespace) -> int:
    reg = registry.load(probe_ids=frozenset(PROBES))
    data = report.load(Path(args.path), reg)
    print(f"{args.path}: {data['schema']}, registry v{data['registry_version']}, "
          f"{len(data['observations'])} observations, exit {data['exit_status']}")
    return 0


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors, which would read as "unknown"."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"kit error: {message}", file=sys.stderr)
        sys.exit(preflight.EXIT_KIT_ERROR)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="kit", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    pf = sub.add_parser("preflight", help="run the checks for one context")
    pf.add_argument("--context", required=True, choices=[c.value for c in Context])
    pf.add_argument("--profile", default="v1")
    pf.add_argument("--out", help="also write the JSON report to this path")
    pf.add_argument("--json", action="store_true", help="print the JSON report, not the summary")
    pf.set_defaults(fn=cmd_preflight)

    rg = sub.add_parser("registry", help="validate the registry and probe coverage")
    rg.set_defaults(fn=cmd_registry)

    rq = sub.add_parser("requirements", help="generate docs/requirements.md")
    rq.add_argument("--check", action="store_true", help="fail if the committed doc is stale")
    rq.set_defaults(fn=cmd_requirements)

    rr = sub.add_parser("read-report", help="validate a preflight report against this kit")
    rr.add_argument("path")
    rr.set_defaults(fn=cmd_read_report)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (registry.RegistryError, report.UnsupportedReport, preflight.KitError) as exc:
        print(f"kit error: {exc}", file=sys.stderr)
        return preflight.EXIT_KIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
