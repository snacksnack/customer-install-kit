"""Vendor-side triage: `python -m kit.triage {run,show,record,freeze}`.

    run BUNDLE.tar.gz --fingerprint FP [--supplement S.tar.gz ...] [--mode rules|agent]
        One triage round. Prints metadata only (ids, enums, counts); the diagnosis
        and the investigation record stay in the case store.
    show CASE_ID [--round N]      print a round's findings and remedy from the case store
    record CASE_ID [--round N]    print the metadata-only record (for eval exports)
    freeze                        print the registry digest and the files it covers

The customer-side half is `python -m kit.triage.followup`. Exit 0 ok,
3 kit error, 4 refused (a bundle is not one to trust).
"""

import argparse
import json
import sys
from pathlib import Path

from kit.bundle.archive import BundleRefused
from kit.triage import engine, registry
from kit.triage.casestore import CaseStore

EXIT_KIT_ERROR, EXIT_REFUSED = 3, 4


def _round(case, n: int | None) -> int:
    return n or case.next_round() - 1


def cmd_run(args: argparse.Namespace) -> int:
    rec = engine.triage(Path(args.bundle), args.fingerprint,
                        supplements=[Path(s) for s in args.supplement or []],
                        mode=args.mode, store=CaseStore(args.case_store))
    print(json.dumps({k: v for k, v in rec.items() if k != "case_path"}, indent=1))
    print(f"case store: {rec['case_path']}  (`python -m kit.triage show {rec['case_id']}`)")
    if rec.get("followup_request_id"):
        print(f"follow-up request for the customer: {rec['case_path']}/requests/"
              f"{rec['followup_request_id']}.json")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    case = CaseStore(args.case_store).get(args.case_id)
    res = case.read(f"rounds/{_round(case, args.round):02d}/result.json")
    print(f"{case.id} round {res['round']}  mode {res['mode']}  outcome {res['outcome']}  "
          f"(rules only: {res['rules_outcome']})  stop {res['stop_reason']}")
    findings = (res.get("diagnosis") or {}).get("findings") or res["rules"]["findings"]
    for f in findings:
        print(f"\n[{f['status']}] {f.get('rule', '')} {f['hypothesis']}\n  {f['statement']}")
        for s in f.get("supports") or []:
            print(f"  supports: {s}")
        for s in f.get("does_not_establish") or []:
            print(f"  does not establish: {s}")
        for c in f.get("citations") or []:
            print(f"  cites {c}")
        if f.get("remedy"):
            print(f"  proposed remedy (for customer review): {f['remedy']}")
    if res.get("followup_request"):
        r = res["followup_request"]
        print(f"\nfollow-up requested: {r['check_id']} ({r['request_id']}): {r['reason']}")
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    case = CaseStore(args.case_store).get(args.case_id)
    res = case.read(f"rounds/{_round(case, args.round):02d}/result.json")
    drop = {"rules", "diagnosis", "followup_request"}
    print(json.dumps({k: v for k, v in res.items() if k not in drop}, indent=1, sort_keys=True))
    return 0


def cmd_freeze(args: argparse.Namespace) -> int:
    print(registry.digest())
    for name in registry.FILES:
        print(f"  kit/triage/{name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m kit.triage", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--case-store", type=Path, help="default ~/.cik-triage/cases")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("bundle")
    r.add_argument("--fingerprint", required=True,
                   help="the customer's report key fingerprint, received out of band")
    r.add_argument("--supplement", action="append")
    r.add_argument("--mode", choices=engine.MODES, default="rules")
    r.set_defaults(fn=cmd_run)
    for name, fn in (("show", cmd_show), ("record", cmd_record)):
        s = sub.add_parser(name)
        s.add_argument("case_id")
        s.add_argument("--round", type=int)
        s.set_defaults(fn=fn)
    sub.add_parser("freeze").set_defaults(fn=cmd_freeze)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except BundleRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_KIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
