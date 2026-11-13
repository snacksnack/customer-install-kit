import json
from pathlib import Path

import pytest

from kit.evaluation import draw
from kit.triage import registry

FIX = Path(__file__).parent / "fixtures" / "beacon"


def pulse(i: int) -> dict:
    return json.loads((FIX / f"pulse-{i}.json").read_text())["pulse"]


@pytest.fixture
def at_fixture(monkeypatch):
    monkeypatch.setattr(draw, "DRAW_AT", "2026-11-13T04:03:30.000Z")


def test_committed_freeze_matches_the_registry():
    # The draw is only valid against the frozen registry. Any registry edit fails here.
    assert registry.digest() == draw.REGISTRY_DIGEST


def test_draw_is_the_formula_over_the_first_pulse_at_or_after(at_fixture):
    p = pulse(2025443)
    assert draw.select(p, pulse(2025442)) == draw.CANDIDATES[int(p["outputValue"], 16) % 3]


def test_refuses_a_pulse_before_the_committed_time(at_fixture):
    with pytest.raises(draw.DrawError, match="before"):
        draw.select(pulse(2025442), pulse(2025442))


def test_refuses_a_later_pulse_than_the_first(monkeypatch):
    monkeypatch.setattr(draw, "DRAW_AT", "2026-11-13T04:02:30.000Z")
    with pytest.raises(draw.DrawError, match="first one"):
        draw.select(pulse(2025443), pulse(2025442))


def test_refuses_another_chain(at_fixture):
    p = dict(pulse(2025443), chainIndex=1)
    with pytest.raises(draw.DrawError, match="chain"):
        draw.select(p, pulse(2025442))


def test_cli_rechecks_from_saved_pulses(at_fixture, capsys):
    assert draw.main(["--pulse", str(FIX / "pulse-2025443.json"),
                      "--previous", str(FIX / "pulse-2025442.json")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["drawn"] in draw.CANDIDATES and out["registry_digest"] == registry.digest()


def test_cli_refuses_before_the_committed_time(monkeypatch):
    monkeypatch.setattr(draw, "DRAW_AT", "2099-01-01T00:00:00.000Z")
    assert draw.main([]) == 4
