"""Held-out family draw (RC1-644; protocol in docs/phase6/heldout-draw.md).

The draw maps one public NIST Randomness Beacon pulse, chosen by a timestamp
committed before it exists, to one of the reserved candidates. Nothing here is
author-controlled: the timestamp, the candidate order and the formula are all
committed first, and anyone can re-run this against the same pulse.

    python -m kit.evaluation.draw            # fetch the committed pulse and draw
    python -m kit.evaluation.draw --pulse F  # re-check from a saved pulse JSON
"""

import argparse
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

# Committed before the pulse exists. Changing any of these after the draw voids it.
DRAW_AT = "2026-11-14T00:00:00.000Z"
CANDIDATES = ("H1", "H2", "H3")  # order as named in docs/phase0/fault-families.md
FREEZE_COMMIT = "95890a4"
REGISTRY_DIGEST = "sha256:4700a81003e099163a84acf6eb407aaefe0745b310f15a8d80d23030d335a7f0"
BEACON = "https://beacon.nist.gov/beacon/2.0"
CHAIN = 2


class DrawError(Exception):
    """The pulse does not satisfy the committed procedure; no draw is made."""


def _ms(stamp: str) -> int:
    return int(datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp() * 1000)


def fetch(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.load(resp)["pulse"]


def select(pulse: dict, previous: dict) -> str:
    """Apply the committed formula to the committed pulse, refusing any other pulse."""
    at = _ms(DRAW_AT)
    stamp = _ms(pulse["timeStamp"])
    if pulse.get("chainIndex") != CHAIN:
        raise DrawError(f"pulse is on chain {pulse.get('chainIndex')}, not {CHAIN}")
    if stamp < at:
        raise DrawError(f"pulse {pulse['timeStamp']} is before the committed time {DRAW_AT}")
    if previous["pulseIndex"] != pulse["pulseIndex"] - 1 or _ms(previous["timeStamp"]) >= at:
        raise DrawError("pulse is not the first one at or after the committed time")
    value = pulse["outputValue"]
    if len(value) != 128:
        raise DrawError("outputValue is not a 512-bit hex string")
    return CANDIDATES[int(value, 16) % len(CANDIDATES)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kit.evaluation.draw")
    parser.add_argument("--pulse", help="saved pulse JSON (re-check without fetching)")
    parser.add_argument("--previous", help="saved JSON of the pulse before it (with --pulse)")
    args = parser.parse_args(argv)
    if bool(args.pulse) != bool(args.previous):
        parser.error("--pulse and --previous go together")
    if args.pulse:
        pulse = json.loads(Path(args.pulse).read_text())["pulse"]
        previous = json.loads(Path(args.previous).read_text())["pulse"]
    else:
        if datetime.now(UTC).timestamp() * 1000 < _ms(DRAW_AT):
            print(f"refused: the committed pulse ({DRAW_AT}) does not exist yet", file=sys.stderr)
            return 4
        pulse = fetch(f"{BEACON}/pulse/time/{_ms(DRAW_AT)}")
        previous = fetch(f"{BEACON}/chain/{CHAIN}/pulse/{pulse['pulseIndex'] - 1}")
    try:
        drawn = select(pulse, previous)
    except DrawError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    print(json.dumps({"draw_at": DRAW_AT, "pulse": pulse["uri"], "timeStamp": pulse["timeStamp"],
                      "outputValue": pulse["outputValue"], "candidates": list(CANDIDATES),
                      "index": int(pulse["outputValue"], 16) % len(CANDIDATES), "drawn": drawn,
                      "freeze_commit": FREEZE_COMMIT, "registry_digest": REGISTRY_DIGEST},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
