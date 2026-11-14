"""The engagement writeup's numbers, re-derived from committed artifacts (RC1-645).

docs/engagement.md ends with a table of every number it states. Each row's value
is recomputed here from docs/demo/ (the demo's logs, archives and records) or
docs/phase6/results.json (the evaluator's export of every graded run). Every
"N of M", "$X.YZ" and "N s" anywhere in the writeup must be one of those values,
so prose cannot drift from the table. The demo's archives, citations and signed
reports are checked too, so docs/demo.md's "check it yourself" stays true.
"""

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from kit.bundle import archive
from kit.triage import engine
from kit.triage.casestore import CaseStore
from kit.verify import __main__ as verify_cli

DOCS = Path(__file__).resolve().parent.parent / "docs"
DEMO = DOCS / "demo"
ENGAGEMENT = DOCS / "engagement.md"
FP = "sha256:e0edc151ddde17a297a9ac22fed3b508bef3b4ff96b3bdd46b49c42c93cebcc5"
CORRECT, ABSTAIN, WRONG = "correct_supported", "appropriate_abstention", "unsupported"


def of(n: int, m: int) -> str:
    return f"{n} of {m}"


def usd(x: float) -> str:
    return f"${x:.2f}"


# -- sources ---------------------------------------------------------------------------

def timing() -> dict[str, int]:
    out = {}
    for line in (DEMO / "customer" / "timing.log").read_text().splitlines():
        m = re.match(r"^(.*?)\s+(?:end .*?)?exit=0 seconds=(\d+)$", line) or \
            re.match(r"^(install) end .* seconds=(\d+)$", line)
        if m:
            out[m.group(1).strip()] = int(m.group(2))
    return out


def conformance(log: str) -> Counter:
    text = (DEMO / "customer" / log).read_text()
    return Counter(m.group(1) for m in re.finditer(r"^\s+CNF-\d+\s+(\S+)", text, re.M))


def record(name: str) -> dict:
    return json.loads((DEMO / "vendor" / name).read_text())


RESULTS = json.loads((DOCS / "phase6" / "results.json").read_text())
RUNS = RESULTS["runs"]


def runs(suite: str, mode: str, cases=None) -> list[dict]:
    return [r for r in RUNS if r["suite"] == suite and r["mode"] == mode
            and (cases is None or r["case"] in cases)]


def by_case(rs: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in rs:
        out.setdefault(r["case"], []).append(r["category"])
    return out


def majority(cats: list[str], cat: str) -> bool:
    return cats.count(cat) * 2 > len(cats)


def derived() -> dict[str, str]:
    t = timing()
    base, fault, rec = (conformance(f"verify-{n}.log")
                        for n in ("1-baseline", "2-fault", "3-recovered"))
    collect = (DEMO / "customer" / "collect-and-review.log").read_text()
    files = int(re.search(r": (\d+) files, [\d]+ bytes", collect).group(1))
    agent_v1 = sum(record(f"agent-round{n}.json")["cost_usd"] for n in (1, 2))

    dev_r, dev_a = runs("dev_fault", "rules"), runs("dev_fault", "agent")
    dev_cases = len(by_case(dev_r))
    ctl_r, ctl_a = runs("control", "rules"), runs("control", "agent")
    scored = RESULTS["scored_heldout"]
    ho_r, ho_a = runs("heldout", "rules", scored), runs("heldout", "agent", scored)
    fault_r = dev_r + runs("heldout", "rules")
    fault_a = dev_a + runs("heldout", "agent")
    agent_all = [r for r in RUNS if r["mode"] == "agent"]
    agent_cost = sum(r["cost_usd"] for r in agent_all)
    correct = [r for r in RUNS if r["category"] == CORRECT]
    splits = sum(1 for cats in by_case(agent_all).values() if len(set(cats)) > 1)
    replays = [c["rules_replay_identical"] for c in RESULTS["cases"].values()]
    false_alarms_r = sum(r["detected"] for r in ctl_r)
    false_alarms_a = sum(1 for cats in by_case(ctl_a).values() if not majority(cats, ABSTAIN))
    ho_a_correct = sum(majority(c, CORRECT) for c in by_case(ho_a).values())
    ho_r_correct = sum(r["category"] == CORRECT for r in ho_r)
    assert false_alarms_r == false_alarms_a and ho_a_correct == ho_r_correct
    rules_cost = sum(r["cost_usd"] for r in RUNS if r["mode"] == "rules")

    return {
        "install_seconds": f"{t['install']} s",
        "conformance_baseline": of(base["pass"], sum(base.values())),
        "conformance_baseline_seconds": f"{t['verify-1']} s",
        "conformance_fault_failed": of(fault["fail"], sum(fault.values())),
        "conformance_fault_insufficient": of(fault["insufficient_evidence"],
                                             sum(fault.values())),
        "conformance_recovered": of(rec["pass"], sum(rec.values())),
        "conformance_recovered_seconds": f"{t['verify-3']} s",
        "bundle_files": str(files),
        "demo_agent_cost": usd(agent_v1),
        "teardown_seconds": f"{t['teardown']} s",
        "dev_rules_correct": of(sum(r["category"] == CORRECT for r in dev_r), dev_cases),
        "dev_agent_correct_cases": of(sum(majority(c, CORRECT)
                                          for c in by_case(dev_a).values()), dev_cases),
        "dev_agent_correct_runs": of(sum(r["category"] == CORRECT for r in dev_a), len(dev_a)),
        "dev_rules_wrong": of(sum(r["category"] == WRONG for r in dev_r), dev_cases),
        "dev_agent_wrong_cases": of(sum(majority(c, WRONG) for c in by_case(dev_a).values()),
                                    dev_cases),
        "dev_agent_wrong_runs": of(sum(r["category"] == WRONG for r in dev_a), len(dev_a)),
        "control_false_alarms": of(false_alarms_r, len(ctl_r)),
        "heldout_correct": of(ho_r_correct, len(scored)),
        "rules_detected": of(sum(r["detected"] for r in fault_r), len(fault_r)),
        "agent_detected": of(sum(r["detected"] for r in fault_a), len(fault_a)),
        "rules_cost": usd(rules_cost),
        "agent_cost_per_run": usd(agent_cost / len(agent_all)),
        "agent_cost_total": usd(agent_cost),
        "rules_replays_identical": of(sum(bool(x) for x in replays), len(replays)),
        "agent_split_cases": of(splits, len(RESULTS["cases"])),
        "first_bundle_correct": of(sum(r["followup_rounds"] == 0 for r in correct),
                                   len(correct)),
    }


# Numbers the evaluator's canary harness produced; the raw scans are not exported.
REPORTED = {"canary_values": "18", "canary_surfaces": "7"}


def table() -> dict[str, str]:
    rows = re.findall(r"^\| `([a-z_0-9]+)` \| ([^|]+?) \|", ENGAGEMENT.read_text(), re.M)
    return dict(rows)


# -- tests ----------------------------------------------------------------------------

def test_every_tabled_number_is_rederived():
    want = derived() | REPORTED
    got = table()
    assert set(got) == set(want), f"table keys differ: {set(got) ^ set(want)}"
    wrong = {k: (got[k], want[k]) for k in want if got[k] != want[k]}
    assert not wrong, f"stated vs derived: {wrong}"


def test_reported_numbers_match_the_phase6_report():
    report = (DOCS / "phase6" / "report.md").read_text()
    assert "searched for all 18" in report and "18 values on 7 surfaces" in report


def test_every_number_in_the_prose_is_a_tabled_value():
    text = ENGAGEMENT.read_text()
    body = text[:text.index("## Numbers and their sources")]
    values = set(derived().values())
    claims = re.findall(r"\b\d+ of \d+\b|\$\d+\.\d{2}|\b\d+ s\b", body)
    assert claims, "the writeup states no numbers?"
    stray = sorted({c for c in claims if c not in values})
    assert not stray, f"numbers in the prose with no derivation: {stray}"


def test_every_writeup_link_resolves():
    for name in ("engagement.md", "demo.md", "support.md"):
        text = (DOCS / name).read_text()
        for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
            if target.startswith("http"):
                continue
            assert (DOCS / target).exists(), f"{name}: broken link {target}"


# -- the demo's artifacts --------------------------------------------------------------

ARCHIVES = {p.name: p for p in sorted((DEMO / "handoff").glob("*.tar.gz"))}


@pytest.mark.parametrize("name", sorted(ARCHIVES))
def test_demo_archives_verify_against_the_fingerprint(name):
    archive.inspect(ARCHIVES[name], FP)


def test_every_citation_in_the_demo_diagnoses_resolves():
    inspected = {i.digest: i for i in (archive.inspect(p, FP) for p in ARCHIVES.values())}
    refs = []
    for f in (DEMO / "vendor").glob("show-*.txt"):
        refs += re.findall(r"cites (cik-ev:\S+)", f.read_text())
    assert len(refs) >= 15
    for ref in refs:
        digest = ref.removeprefix("cik-ev:").split("/", 1)[0]
        archive.resolve(inspected[digest], ref)


@pytest.mark.parametrize("report", sorted((DEMO / "customer" / "conformance")
                                          .glob("*/report.signed.json")))
def test_demo_conformance_reports_verify(report, capsys):
    args = type("A", (), {"report": str(report),
                          "record": str(DEMO / "customer" / "install-record.json")})
    assert verify_cli.cmd_verify_report(args) == 0
    assert "signature valid" in capsys.readouterr().out


def test_rules_triage_reproduces_the_demo(tmp_path):
    """Round 1 asks for the same check; with the customer's answer to the rules
    request, the rules reach the same diagnosis and remedy as the demo's round 2."""
    store = CaseStore(tmp_path / "cases")
    primary = ARCHIVES["p5-diag.tar.gz"]
    first = engine.triage(primary, FP, store=store, post=lambda p: None)
    demo1 = record("rules-round1.json")
    assert (first["outcome"], first["followup_requested"]) == \
        (demo1["outcome"], demo1["followup_requested"])

    # Replay the demo's round 2: the case holds the request the customer answered.
    replay = CaseStore(tmp_path / "replay")
    req = json.loads((DEMO / "handoff" / "followup-request-rules.json").read_text())
    case = replay.case(archive.inspect(primary, FP).digest, "rules")
    case.write(f"requests/{req['request_id']}.json", req)
    second = engine.triage(primary, FP, supplements=[ARCHIVES["p5-followup-rules.tar.gz"]],
                           store=replay, post=lambda p: None)
    demo2 = record("rules-round2.json")
    assert second["outcome"] == demo2["outcome"] == "supported_diagnosis"
    assert second["rules_findings"] == demo2["rules_findings"]
    res = replay.get(second["case_id"]).read("rounds/01/result.json")
    remedy = res["rules"]["findings"][0]["remedy"]
    assert "GRANT SELECT ON review_audit TO esp_app" in remedy
    shown = (DEMO / "vendor" / "show-rules-round2.txt").read_text()
    assert remedy in shown
