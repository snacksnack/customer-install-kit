"""Conformance commands: `python -m kit.verify {run,verify-report,export}`.

    run --config install.toml          customer: run conformance, write a signed report
    verify-report REPORT --record REC  anyone: check a report against the install's key
    export RUN_ID --config ... --out D customer: copy a report out for sharing

`run` exits 0 pass, 1 fail, 2 insufficient evidence, 3 kit error.
`verify-report` exits 0 valid, 4 refused (tampered, wrong key, bad record).
Reports stay in the install workspace until `export` copies them; nothing
here sends anything anywhere.
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

from kit.install import config as cfg
from kit.install import record as rec
from kit.install import secrets_file
from kit.install.fly import FlyError
from kit.verify import checks, signing
from kit.verify.runner import REPORTS_DIR, Verifier, VerifyError

EXIT = {checks.Outcome.PASS: 0, checks.Outcome.FAIL: 1, checks.Outcome.INSUFFICIENT: 2}
EXIT_KIT_ERROR = 3
EXIT_REFUSED = 4


def cmd_run(args: argparse.Namespace) -> int:
    report, verdict = Verifier(cfg.load(Path(args.config))).run()
    payload = json.loads(json.loads(report.read_text())["payload"])
    for o in payload["observations"]:
        print(f"  {o['check_id']}  {o['outcome']:<22} {o['name']} ({o['reason']})")
    print(f"conformance {verdict.value}: {report}")
    return EXIT[verdict]


def cmd_verify_report(args: argparse.Namespace) -> int:
    record = json.loads(Path(args.record).read_text())
    try:
        public, fp = signing.trusted_key(record.get("report_key") or {})
        payload = signing.verify(json.loads(Path(args.report).read_text()), public, fp)
    except (signing.SignatureInvalid, KeyError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    if payload.get("install_id") != record.get("install_id"):
        print("REFUSED: report names another install than this record", file=sys.stderr)
        return EXIT_REFUSED
    print(f"signature valid: install {payload['install_id']}, key {fp}")
    print(f"run {payload['run_id']}  release {payload['release']['version']}  "
          f"verdict {payload['verdict']}  {payload['summary']}")
    print(signing.NON_CLAIM)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    conf = cfg.load(Path(args.config))
    src = conf.workdir / REPORTS_DIR / args.run_id
    if not (src / "report.signed.json").exists():
        raise VerifyError(f"no report for run {args.run_id} in {src.parent}")
    out = Path(args.out)
    if out.exists():
        raise VerifyError(f"{out} exists; export writes a new directory")
    out.mkdir(parents=True)
    shutil.copy2(src / "report.signed.json", out / "report.signed.json")
    shipped = ["report.signed.json"]
    if args.with_evidence:
        shutil.copytree(src / "evidence", out / "evidence")
        shipped.append("evidence/ (includes the execution journal, which names the "
                       "destination account, and the fixture's synthetic addresses)")
    print(f"exported to {out}: " + ", ".join(shipped))
    print("Nothing was sent. Share this directory, and the install record's report "
          "key fingerprint through a separate channel.")
    return 0


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"kit error: {message}", file=sys.stderr)
        sys.exit(EXIT_KIT_ERROR)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="kit.verify", description=__doc__,
                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run conformance against the installed app")
    run.add_argument("--config", default="install.toml")
    run.set_defaults(fn=cmd_run)
    vr = sub.add_parser("verify-report", help="verify a signed report (offline)")
    vr.add_argument("report")
    vr.add_argument("--record", required=True, help="the install record holding the key")
    vr.set_defaults(fn=cmd_verify_report)
    ex = sub.add_parser("export", help="copy a report out of the workspace for sharing")
    ex.add_argument("run_id")
    ex.add_argument("--config", default="install.toml")
    ex.add_argument("--out", required=True)
    ex.add_argument("--with-evidence", action="store_true")
    ex.set_defaults(fn=cmd_export)
    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (VerifyError, FlyError, cfg.ConfigError, rec.RecordError,
            secrets_file.SecretsFileError) as exc:
        print(f"kit error: {exc}", file=sys.stderr)
        return EXIT_KIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
