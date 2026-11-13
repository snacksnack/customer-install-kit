# Held-out family draw (RC1-644)

This is the procedure for drawing the held-out family, committed before the randomness it uses exists. It carries out steps 1 and 2 of the binding protocol in [`docs/phase0/fault-families.md`](../phase0/fault-families.md#held-out-draw-protocol-from-rc1-638-binding).

## 1. The freeze (done)

| | |
|---|---|
| freeze commit | `95890a4` (merge of PR #8, RC1-643) |
| registry digest | `sha256:4700a81003e099163a84acf6eb407aaefe0745b310f15a8d80d23030d335a7f0` |
| registry files | `kit/triage/{knowledge.toml, followups.toml, rules.py, facts.py, prompt.md}` |

`python -m kit.triage freeze` prints the digest. `tests/test_draw.py` fails if the registry changes, so a post-freeze edit can't go unnoticed. A registry changed after the draw can't be scored against this draw.

## 2. The draw

- **Source:** the NIST Randomness Beacon v2.0, chain 2 (`https://beacon.nist.gov/beacon/2.0`). It publishes a signed 512-bit `outputValue` every 60 seconds, and nobody on this project can influence it.
- **Pulse:** the first chain-2 pulse whose `timeStamp` is at or after **2026-11-14T00:00:00.000Z**. That is what `GET /beacon/2.0/pulse/time/1794614400000` returns. The draw also fetches the pulse before it, to prove it is the first.
- **Candidates, in order:** `H1`, `H2`, `H3`, as named in `fault-families.md`.
- **Formula:** `index = int(outputValue, 16) mod 3`, then `drawn = (H1, H2, H3)[index]`. The modulo bias over 512 bits is below 2⁻⁵⁰⁰.
- **Code:** `python -m kit.evaluation.draw`. It refuses to run before the committed time, and refuses any pulse that is not the first one at or after it. `--pulse`/`--previous` re-run the formula on saved pulse JSON, so anyone can check the result without trusting this repo's output.

This procedure is public when this commit is pushed, which is before the pulse exists. GitHub's push and PR timestamps are the record, because commit dates can be set by the author.

**If the beacon is down at the committed time,** the rule above still names one pulse: the first one published at or after it, however late. The draw waits for that pulse. Nothing else is substituted.

## 3. After the draw

- The result (pulse URI, `outputValue`, index, drawn family) is committed here, with the raw pulse JSON under `tests/fixtures/beacon/`.
- Only the drawn family becomes the held-out evaluation family. The other two stay reserved: they are not used for development or evaluation, and they remain unseen by the registry.
- The author designed all three candidates (step 3 of the protocol). The draw removes the author from the *choice* among them, not from their design. Results are reported that way.
- If the drawn family turns out to be infeasible or too costly to run at the case count the evaluation needs, the gap is reported. Any author-selected substitute is published as the narrower claim (protocol step 4), never as the draw.
