"""Operator commands: `python -m kit.install {verify-release,install,status,rollback,teardown}`.

Run from the customer's workstation, as the customer operator. Exit 0 done,
1 installed but a required runtime check is not passing, 3 kit error, 4
refused (untrusted release, or a change only a data restore can make), 5 a
step failed (re-run install to resume).
"""

import argparse
import json
import sys
from pathlib import Path

import psycopg

from kit.install import config as cfg
from kit.install import record as rec
from kit.install import release as rel
from kit.install import secrets_file
from kit.install.engine import STEPS, InjectedFailure, Installer, InstallError, RecoveryRequired
from kit.install.esp_image import ImageError
from kit.install.fly import FlyError

EXIT_OK = 0
EXIT_NOT_READY = 1
EXIT_KIT_ERROR = 3
EXIT_REFUSED = 4
EXIT_STEP_FAILED = 5


def cmd_verify(args: argparse.Namespace) -> int:
    release = rel.fetch_and_verify(args.version, Path(args.dest))
    print(json.dumps(release.to_json(), indent=2))
    print(f"verified: signed by {rel.signer_identity(args.version)}", file=sys.stderr)
    return EXIT_OK


def cmd_install(args: argparse.Namespace) -> int:
    installer = Installer(cfg.load(Path(args.config)))
    status = installer.install(fail_after=args.fail_after)
    state = installer.record["state"]
    print(f"install {state}: v{installer.release.version} on {installer.cfg.app}")
    return EXIT_OK if status == 0 else EXIT_NOT_READY


def cmd_status(args: argparse.Namespace) -> int:
    conf = cfg.load(Path(args.config))
    record = rec.load(conf.record_path)
    if record is None:
        print("not installed (no install-record.json)")
        return EXIT_OK
    print(json.dumps({k: record[k] for k in ("state", "release", "resources", "steps",
                                              "runtime_preflight", "history")}, indent=2))
    return EXIT_OK


def cmd_rollback(args: argparse.Namespace) -> int:
    return Installer(cfg.load(Path(args.config))).rollback(args.to)


def cmd_teardown(args: argparse.Namespace) -> int:
    installer = Installer(cfg.load(Path(args.config)))
    return installer.teardown(args.confirm, drop_app_role=args.drop_app_role)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"kit error: {message}", file=sys.stderr)
        sys.exit(EXIT_KIT_ERROR)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="kit.install", description=__doc__,
                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    vr = sub.add_parser("verify-release", help="download and verify a signed release")
    vr.add_argument("version")
    vr.add_argument("--dest", default=".cik-releases")
    vr.set_defaults(fn=cmd_verify)

    for name, fn, text in (("install", cmd_install, "install or converge (idempotent)"),
                           ("status", cmd_status, "print the install record"),
                           ("rollback", cmd_rollback, "deploy an older verified release"),
                           ("teardown", cmd_teardown, "destroy what this install created")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--config", default="install.toml")
        p.set_defaults(fn=fn)
        if name == "install":
            p.add_argument("--fail-after", choices=STEPS, help=argparse.SUPPRESS)
        if name == "rollback":
            p.add_argument("--to", required=True, help="release version, e.g. 0.1.1")
        if name == "teardown":
            p.add_argument("--confirm", required=True, help="the app name, typed out")
            p.add_argument("--drop-app-role", action="store_true",
                           help="also drop the esp_app database role (data is kept)")

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except rel.ReleaseRejected as exc:
        print(f"REFUSED (untrusted release): {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except RecoveryRequired as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except InjectedFailure as exc:
        print(f"stopped: {exc}; re-run install to resume", file=sys.stderr)
        return EXIT_STEP_FAILED
    except psycopg.Error as exc:
        print(f"database step failed: {type(exc).__name__}: {str(exc).splitlines()[0]}\n"
              "re-run to resume", file=sys.stderr)
        return EXIT_STEP_FAILED
    except (InstallError, FlyError, ImageError) as exc:
        print(f"install step failed: {exc}\nre-run install to resume", file=sys.stderr)
        return EXIT_STEP_FAILED
    except (cfg.ConfigError, rec.RecordError, secrets_file.SecretsFileError) as exc:
        print(f"kit error: {exc}", file=sys.stderr)
        return EXIT_KIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
