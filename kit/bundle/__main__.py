"""Diagnostic bundle commands: `python -m kit.bundle {collect,review,export,inspect}`.

    collect --config install.toml [--case SLUG]   customer: collect into the workspace
    review BUNDLE_ID --config install.toml        customer: see exactly what would leave
    export BUNDLE_ID --config ... --out FILE      customer: write the archive to share
    inspect ARCHIVE [--fingerprint FP] [--ref R]  vendor: validate an untrusted bundle

Exits 0 ok, 3 kit error, 4 refused (inspect: the bundle is not one to trust).
Nothing here sends anything anywhere.
"""

import argparse
import json
import sys
from pathlib import Path

from kit.bundle import archive, collect
from kit.install import config as cfg

EXIT_KIT_ERROR = 3
EXIT_REFUSED = 4


def _bundle_dir(args: argparse.Namespace) -> Path:
    conf = cfg.load(Path(args.config))
    if not collect.BUNDLE_ID.match(args.bundle_id):
        raise collect.CollectError(f"{args.bundle_id!r} is not a bundle id (diag-...)")
    path = conf.workdir / collect.BUNDLES_DIR / args.bundle_id
    if not (path / collect.MANIFEST).exists():
        raise collect.CollectError(f"no bundle {args.bundle_id!r} in {path.parent}")
    return path


def cmd_collect(args: argparse.Namespace) -> int:
    out = collect.Collector(cfg.load(Path(args.config))).collect(args.case)
    print()
    print("\n".join(archive.review_lines(out)))
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    print("\n".join(archive.review_lines(_bundle_dir(args))))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    out = archive.export(_bundle_dir(args), Path(args.out))
    print(f"wrote {out}. Nothing was sent. Share it, and the install record's report "
          "key fingerprint through a separate channel.")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    try:
        got = archive.inspect(Path(args.archive), args.fingerprint)
        if args.ref:
            print(json.dumps(archive.resolve(got, args.ref), indent=2, sort_keys=True))
            return 0
    except archive.BundleRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    m = got.manifest
    print(f"bundle {m['bundle_id']} valid: install {m['install_id']}, key {got.fingerprint}")
    if not args.fingerprint:
        print("  (no --fingerprint given: compare the key fingerprint with the "
              "customer out of band)")
    print(f"digest {got.digest}")
    for e in m["sources"]:
        tail = e.get("file") or e.get("reason")
        print(f"  {e['source']:<20} {e['status']:<12} {tail}")
    print("References: " + collect.ref(got.digest, "files/<source>.json", "/data/..."))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m kit.bundle", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--config", required=True)
    c.add_argument("--case", help="optional slug naming the situation (e.g. startup-failure)")
    c.set_defaults(fn=cmd_collect)
    for name, fn in (("review", cmd_review), ("export", cmd_export)):
        s = sub.add_parser(name)
        s.add_argument("bundle_id")
        s.add_argument("--config", required=True)
        if name == "export":
            s.add_argument("--out", required=True)
        s.set_defaults(fn=fn)
    i = sub.add_parser("inspect")
    i.add_argument("archive")
    i.add_argument("--fingerprint", help="the report key fingerprint the customer gave you")
    i.add_argument("--ref", help="resolve one evidence reference")
    i.set_defaults(fn=cmd_inspect)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (collect.CollectError, cfg.ConfigError, FileExistsError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_KIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
