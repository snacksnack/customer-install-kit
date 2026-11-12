"""Generate the customer requirements document from the registry.

The document is derived, never hand-edited: CI regenerates it and fails if
the committed copy differs, so requirements and preflight cannot drift.
"""

from pathlib import Path

from kit.model import Check, Context
from kit.registry import Registry

DOC_PATH = Path(__file__).resolve().parent.parent / "docs" / "requirements.md"

CONTEXT_HEADINGS = {
    Context.OPERATOR: (
        "On the operator workstation",
        "Run with `uv run python -m kit preflight --context operator`. These checks use "
        "install-time credentials (the database owner URL) that never go into the app.",
    ),
    Context.RUNTIME: (
        "Inside a machine of the customer's app",
        "Run with `python -m kit preflight --context runtime` inside a machine of the app, "
        "so the probes see the app's real network path, secrets, architecture, memory and "
        "volume.",
    ),
}


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def _check_section(check: Check) -> list[str]:
    lines = [f"### {check.id}: {check.title}", ""]
    lines.append(
        f"**{check.severity.value.capitalize()}** · profiles: {', '.join(check.profiles)}"
        + (f" · after: {', '.join(check.depends_on)}" if check.depends_on else "")
    )
    lines += [
        "",
        f"- **Why:** {_cell(check.purpose)}",
        f"- **How it is checked:** {_cell(check.probe)}",
        f"- **Access needed:** {_cell(check.permission)}",
        f"- **If it fails:** {_cell(check.remediation)}",
        f"- **Evidence recorded:** {', '.join(f'`{k}`' for k in check.evidence)}",
        "",
    ]
    return lines


def render(registry: Registry) -> str:
    lines = [
        "# Customer requirements: ESP Migration Agent v1 profile",
        "",
        "<!-- Generated from kit/checks.toml by `uv run python -m kit requirements`."
        " Do not edit by hand. -->",
        "",
        f"Registry version {registry.version}. Every requirement below is a preflight check "
        "with a stable ID; the same ID appears in preflight reports, conformance results and "
        "diagnostic bundles.",
        "",
        "Outcomes: **pass**; **fail** (the requirement is not met); **not applicable** (the "
        "check does not apply to this profile or configuration); **unknown** (the check "
        "applies but its evidence could not be obtained, for example a timeout or a "
        "prerequisite check that did not pass). Preflight exits 0 when every required check "
        "passes or is not applicable, 1 when any required check fails, 2 when none fails but "
        "at least one is unknown, and 3 on a kit error.",
        "",
        "Secret values are never recorded. Evidence is limited to the fields listed per "
        "check.",
        "",
        "## Summary",
        "",
        "| ID | Requirement | Severity | Where |",
        "|---|---|---|---|",
    ]
    for check in registry.checks:
        lines.append(
            f"| {check.id} | {_cell(check.title)} | {check.severity.value} | "
            f"{check.context.value} |"
        )
    lines.append("")
    for context, (heading, intro) in CONTEXT_HEADINGS.items():
        checks = [c for c in registry.checks if c.context is context]
        if not checks:
            continue
        lines += [f"## {heading}", "", intro, ""]
        for check in checks:
            lines += _check_section(check)
    return "\n".join(lines).rstrip() + "\n"
