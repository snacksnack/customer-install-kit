"""The eval subject's scoring, offline (RC1-644). A scripted client plays the
agent so each characteristic is shown to pass for the right answer and fail
for the wrong one. The billed run itself is `python -m evals`."""

import json
import re
from types import SimpleNamespace

import pytest

from evals import __main__ as cli
from evals import bundles, subject


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(subject, "STATE", subject.RunState())
    monkeypatch.setattr(subject.telemetry, "post", lambda p: None)
    yield
    subject.STATE.close()


def tool(name, inp):
    return {"type": "tool_use", "id": f"tu_{name}", "name": name, "input": inp}


class ScriptedAgent:
    """Reads the round's bundle index from the opening message, then either
    requests `check` (no follow-up yet) or submits a diagnosis citing row `row`
    of the follow-up answer."""

    def __init__(self, check, source, key, row, status="supported", ask=True):
        self.check, self.source, self.key, self.row = check, source, key, row
        self.status, self.ask = status, ask
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kw):
        opening = kw["messages"][0]["content"]
        body = json.loads(re.search(r"<untrusted_bundle_data>\n(.*)\n</untrusted_bundle_data>",
                                    opening, re.S).group(1))
        fups = [b for b in body["bundles"] if b["role"] == "followup"]
        primary = next(b for b in body["bundles"] if b["role"] == "primary")
        if not fups and self.ask:
            turn = [tool("request_followup", {"check_id": self.check, "reason": "r",
                                              "discriminates": "d"})]
        else:
            tail = "" if self.row is None else f"/{self.row}"
            ref = (f"cik-ev:{fups[-1]['digest']}/files/{self.source}.json#/data/{self.key}{tail}"
                   if fups else
                   f"cik-ev:{primary['digest']}/files/health.json#/data/healthz_status")
            status = self.status if fups else "insufficient"
            turn = [tool("submit_diagnosis", {
                "outcome": "supported_diagnosis" if status == "supported"
                else "insufficient_evidence",
                "findings": [{"hypothesis": "h", "status": status, "statement": "s",
                              "supports": [], "does_not_establish": [], "citations": [ref],
                              "remedy": "r" if status == "supported" else None}]})]
        return SimpleNamespace(content=turn, model="claude-opus-5-5", stop_reason="tool_use",
                               usage=SimpleNamespace(input_tokens=1000, output_tokens=200,
                                                     cache_read_input_tokens=0,
                                                     cache_creation_input_tokens=0))


def case(cid):
    return next(c for c in subject.CASES if c.id == cid)


def missing_row():
    rows = bundles.db_priv(missing=("review_audit INSERT",))["grants"]
    return next(i for i, r in enumerate(rows) if r["expected"] and not r["granted"])


def test_family1_right_answer_passes_every_characteristic():
    client = ScriptedAgent("FUP-DB-PRIV", "fup_db_priv", "grants", missing_row())
    r = subject.run(case("family1-privilege"), client)
    assert r.error is None, r.error
    assert {c.name: c.passed for c in r.characteristics} == dict.fromkeys(
        case("family1-privilege").expect, True)
    assert r.observations["followups"] == ["FUP-DB-PRIV"]
    assert r.observations["rules_final_outcome"] == "supported_diagnosis"


def test_family1_citing_a_granted_row_fails_only_the_citation():
    client = ScriptedAgent("FUP-DB-PRIV", "fup_db_priv", "grants", missing_row() + 1)
    r = subject.run(case("family1-privilege"), client)
    failed = {c.name for c in r.characteristics if not c.passed}
    assert failed == {"cites-the-decisive-row"}


def test_family2_wrong_check_then_conclusion_fails_followup_usefulness():
    # Asks for the volume, gets a benign answer, then gives up.
    client = ScriptedAgent("FUP-VOLUME", "fup_volume", "x", 0, status="insufficient")
    r = subject.run(case("family2-destination"), client)
    failed = {c.name for c in r.characteristics if not c.passed}
    assert {"requests-the-discriminating-check", "supported-after-the-answer"} <= failed


def test_healthy_supported_finding_is_an_unsupported_diagnosis():
    client = ScriptedAgent("FUP-VOLUME", "fup_volume", "blocks_avail_kib", None)
    r = subject.run(case("healthy-abstains"), client)
    assert not next(c for c in r.characteristics if c.name == "no-supported-finding").passed


def test_healthy_abstention_passes():
    client = ScriptedAgent("FUP-VOLUME", "fup_volume", "x", 0, ask=False)
    r = subject.run(case("healthy-abstains"), client)
    assert r.passed, [c.detail for c in r.characteristics]


def test_budget_and_tracing_after_billed_rounds():
    client = ScriptedAgent("FUP-DB-PRIV", "fup_db_priv", "grants", missing_row())
    subject.run(case("family1-privilege"), client)
    b = subject.run(case("budget-discipline"))
    assert b.passed, [c.detail for c in b.characteristics]
    t = subject.run(case("metadata-only-tracing"))
    assert t.passed, [c.detail for c in t.characteristics]
    assert t.observations["payloads"] == 4 and t.observations["content_strings"] > 0


def test_tracing_catches_a_canary_and_bundle_content():
    subject.run(case("metadata-only-tracing"))
    subject.STATE.records.append({"leak": subject.STATE.canaries["api_key"],
                                  "more": sorted(subject.STATE.content)[0]})
    t = subject.tracing_case(case("metadata-only-tracing"))
    failed = {c.name for c in t.characteristics if not c.passed}
    assert failed == {"no-canary-escapes", "no-bundle-content-escapes"}


def test_tracing_catches_span_input():
    subject.run(case("metadata-only-tracing"))
    span = subject.STATE.payloads[0]["data"]["attributes"]["spans"][0]
    span["meta"]["input"] = {"value": "x"}
    t = subject.tracing_case(case("metadata-only-tracing"))
    failed = {c.name for c in t.characteristics if not c.passed}
    assert failed == {"payloads-pass-the-allowlist", "no-span-input-or-output"}


def test_isolation_passes_on_the_committed_runtime():
    r = subject.run(case("isolation"))
    assert r.passed, [c.detail for c in r.characteristics]


def test_free_cli_needs_no_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DD_API_KEY", raising=False)
    assert cli.main(["--free", "--no-record"]) == 0
    assert "billed: none" in capsys.readouterr().out
    assert cli.main(["--case", "family1-privilege", "--no-record"]) == 78
