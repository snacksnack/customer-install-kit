"""Customer-side follow-up checks (RC1-643, ADR 0009).

Triage can only REQUEST a check from `followups.toml`. The customer runs it:

    uv run python -m kit.triage.followup run --request followup-request.json \\
        --config ~/acme-install/install.toml

The request names a check id, the bundle it follows up, and the vendor's
reason. This runner refuses any id not in the allowlist, prints exactly what
the check will touch, runs it read-only, and writes a supplemental bundle
into the workspace through the same collector as `kit.bundle collect`:
fixed fields, the independent scanner, a signed manifest. The customer then
reviews and exports it like any bundle (`python -m kit.bundle review|export`).
Nothing is sent.
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg

from kit import registry as checks_registry
from kit.bundle import archive, collect, events, sources
from kit.bundle.collect import Collector, Plan
from kit.install import config as cfg
from kit.install import secrets_file
from kit.install.fly import Fly
from kit.probes.db import _classify
from kit.triage import registry

REQUEST_SCHEMA = "cik.followup-request/1"
REQUEST_ID = re.compile(r"^fr-[0-9a-f]{12}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
BREVO = "https://api.brevo.com/v3"
DEST_ROUTES = (("GET /account", "/account"), ("GET /contacts/lists", "/contacts/lists?limit=1"))
HTTP_TIMEOUT_S = 15
EXIT_REFUSED = 4


class FollowupError(Exception):
    pass


# -- the request the vendor sends ---------------------------------------------


def load_request(path: Path) -> dict[str, Any]:
    try:
        req = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FollowupError(f"cannot read the request: {type(exc).__name__}") from exc
    if not isinstance(req, dict) or req.get("schema") != REQUEST_SCHEMA:
        raise FollowupError(f"not a {REQUEST_SCHEMA} request")
    cid = req.get("check_id")
    if cid not in registry.followups():
        raise FollowupError(f"check {cid!r} is not an allowlisted follow-up; nothing was run")
    if not REQUEST_ID.match(str(req.get("request_id"))):
        raise FollowupError("request_id is malformed")
    if not DIGEST.match(str(req.get("parent_bundle"))):
        raise FollowupError("parent_bundle is not a bundle digest")
    reason = req.get("reason")
    req["reason"] = reason[:600] if isinstance(reason, str) else ""
    return req


# -- the checks ------------------------------------------------------------------


@dataclass
class Deps:
    fly: Fly | None = None
    connect: Callable[..., Any] = psycopg.connect
    http_get: Callable[[str, str], tuple[int, str | None]] = None  # type: ignore[assignment]
    say: Callable[[str], None] = print
    collector_deps: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


def _grant_rows() -> list[tuple[str, str, bool]]:
    app = registry.knowledge()["app_role"]
    rows = [(*g.rsplit(" ", 1), True) for g in app["expected"]]
    rows += [(*g.rsplit(" ", 1), False) for g in app["must_not_have"]]
    return rows


_TABLE_PRIV = ("SELECT (SELECT has_table_privilege(c.oid, %(priv)s) FROM pg_class c"
               " JOIN pg_namespace n ON n.oid = c.relnamespace"
               " WHERE c.relname = %(obj)s AND n.nspname = %(nsp)s)")


def db_privileges(url: str, connect: Callable[..., Any]) -> dict[str, Any]:
    """The app role's grants, read with its own credential. Read-only catalog
    functions on ESP's own object names; no row of any table is read."""
    out: dict[str, Any] = {"check_id": "FUP-DB-PRIV", "role": "current_user"}
    try:
        conn = connect(url, connect_timeout=10, autocommit=True)
    except psycopg.Error as exc:
        return out | {"connected": False, "connect_class": _classify(exc), "grants": []}
    grants = []
    rows = _grant_rows()
    nsp = next((o.split(" ", 1)[1] for o, _, _ in rows if o.startswith("schema ")), "public")
    with conn:
        for obj, priv, expected in rows:
            if obj == "database":
                q, args = "SELECT has_database_privilege(current_database(), %s)", (priv,)
            elif obj.startswith("schema "):
                q, args = "SELECT has_schema_privilege(%s, %s)", (obj.split(" ", 1)[1], priv)
            else:
                # By OID from the catalog, not by name: a name lookup (to_regclass)
                # needs USAGE on the schema, so with USAGE revoked every table
                # looked missing (RC1-644 case F1-2). NULL: no such table.
                q, args = _TABLE_PRIV, {"obj": obj, "nsp": nsp, "priv": priv}
            granted = conn.execute(q, args).fetchone()[0]
            grants.append({"object": obj, "privilege": priv, "expected": expected,
                           "granted": granted, "object_exists": granted is not None})
    return out | {"connected": True, "connect_class": None, "grants": grants}


def _provider_code(body: str | None) -> str | None:
    try:
        code = json.loads(body or "").get("code")
    except (json.JSONDecodeError, AttributeError):
        return None
    return code if code in events.PROVIDER_CODES else None


def _urllib_get(url: str, key: str) -> tuple[int, str | None]:
    req = urllib.request.Request(url, headers={"api-key": key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            resp.read(0)
            return resp.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", "replace")


# Runs inside the app's machine with the image's Python, passed with -c so
# nothing is written there. It prints statuses and Brevo's error code only.
MACHINE_PROBE = r'''
import json, os, urllib.request, urllib.error
key = os.environ.get("ESP_BREVO_API_KEY", "")
out = {}
for name, path in ROUTES:
    req = urllib.request.Request("https://api.brevo.com/v3" + path,
                                 headers={"api-key": key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            out[name] = [r.status, None]
    except urllib.error.HTTPError as e:
        try:
            code = json.loads(e.read(4096).decode("utf-8", "replace")).get("code")
        except Exception:
            code = None
        out[name] = [e.code, code if isinstance(code, str) else None]
    except Exception as e:
        out[name] = [None, type(e).__name__]
print("CIK-FUP " + json.dumps(out))
'''


def dest_auth(key: str | None, fly: Fly, app: str,
              http_get: Callable[[str, str], tuple[int, str | None]]) -> dict[str, Any]:
    probes = []
    for route, path in DEST_ROUTES:
        if not key:
            probes.append({"vantage": "workstation", "route": route, "status": None,
                           "provider_code": None, "unavailable": "key_not_in_secrets_file"})
            continue
        try:
            status, body = http_get(BREVO + path, key)
            probes.append({"vantage": "workstation", "route": route, "status": status,
                           "provider_code": _provider_code(body)})
        except (OSError, urllib.error.URLError) as exc:
            probes.append({"vantage": "workstation", "route": route, "status": None,
                           "provider_code": None, "unavailable": f"error:{type(exc).__name__}"})
    script = MACHINE_PROBE.replace("ROUTES", repr(DEST_ROUTES))
    b64 = base64.b64encode(script.encode()).decode()
    cmd = f"/app/.venv/bin/python -c \"import base64;exec(base64.b64decode('{b64}'))\""
    result = fly.run("ssh", "console", "-a", app, "-C", cmd, check=False)
    line = next((ln for ln in result.stdout.splitlines() if ln.startswith("CIK-FUP ")), None)
    try:
        machine = json.loads(line[8:]) if line else None
    except json.JSONDecodeError:
        machine = None
    for route, _ in DEST_ROUTES:
        got = (machine or {}).get(route)
        if not isinstance(got, list) or len(got) != 2:
            probes.append({"vantage": "machine", "route": route, "status": None,
                           "provider_code": None, "unavailable": "machine_unreachable"})
            continue
        status, code = got
        ok_status = isinstance(status, int) and 100 <= status <= 599
        probes.append({"vantage": "machine", "route": route,
                       "status": status if ok_status else None,
                       "provider_code": code if code in events.PROVIDER_CODES else None}
                      | ({} if ok_status else {"unavailable": "request_failed"}))
    return {"check_id": "FUP-DEST-AUTH", "destination": "api.brevo.com", "probes": probes}


VOLUME_CMD = ("sh -c 'echo CIK-DF $(df -Pk /data | tail -1); echo CIK-DFI $(df -Pi /data | "
              f"tail -1); echo CIK-SINK $(stat -c %s {sources.SINK_PATH} 2>/dev/null || echo 0);"
              " echo CIK-DU $(du -sk /data 2>/dev/null | cut -f1)'")


def volume(fly: Fly, app: str) -> dict[str, Any]:
    result = fly.run("ssh", "console", "-a", app, "-C", VOLUME_CMD, check=False)
    lines = {ln.split(" ", 1)[0]: ln.split()[1:] for ln in result.stdout.splitlines()
             if ln.startswith("CIK-")}
    out: dict[str, Any] = {"check_id": "FUP-VOLUME", "path": "/data"}

    def num(key: str, i: int) -> int | None:
        try:
            return int(lines[key][i])
        except (KeyError, IndexError, ValueError):
            return None

    if "CIK-DF" not in lines:
        return out | {"unavailable": "machine_unreachable"}
    # df -P columns: filesystem, total, used, available, capacity, mount
    sink = num("CIK-SINK", 0) or 0
    du_kib = num("CIK-DU", 0)
    return out | {
        "blocks_total_kib": num("CIK-DF", 1), "blocks_used_kib": num("CIK-DF", 2),
        "blocks_avail_kib": num("CIK-DF", 3),
        "inodes_total": num("CIK-DFI", 1), "inodes_used": num("CIK-DFI", 2),
        "inodes_avail": num("CIK-DFI", 3),
        "sink_bytes": sink,
        "other_bytes": max(du_kib * 1024 - sink, 0) if du_kib is not None else None,
    }


# -- the supplemental bundle ------------------------------------------------------


class FollowupCollector(Collector):
    """A bundle with one source, the follow-up, and a `followup` block naming
    the request it answers and the bundle it follows up."""

    def __init__(self, config: cfg.InstallConfig, request: dict[str, Any],
                 deps: Deps | None = None):
        self.fdeps = deps or Deps()
        super().__init__(config, self.fdeps.collector_deps)
        if self.fdeps.fly is None:
            self.fdeps.fly = self.deps.fly
        if self.fdeps.http_get is None:
            self.fdeps.http_get = _urllib_get
        self.request = request
        self.check = registry.followups()[request["check_id"]]

    def _plans(self):
        cid, values = self.check.id, secrets_file.read(self.cfg.secrets_file)
        fly, app = self.fdeps.fly, self.cfg.app
        runs: dict[str, Callable[[], dict[str, Any]]] = {
            "FUP-DB-PRIV": lambda: db_privileges(values.get("ESP_DATABASE_URL", ""),
                                                 self.fdeps.connect),
            "FUP-DEST-AUTH": lambda: dest_auth(values.get("ESP_BREVO_API_KEY"), fly, app,
                                               self.fdeps.http_get),
            "FUP-VOLUME": lambda: volume(fly, app),
        }
        name = cid.lower().replace("-", "_")

        def run() -> sources.SourceResult:
            def inner() -> sources.SourceResult:
                return sources.SourceResult(name, data=runs[cid]())
            return sources._guard(name, inner)

        if cid in ("FUP-VOLUME", "FUP-DEST-AUTH"):
            # Wake a scale-to-zero machine first; `fly ssh` cannot reach a suspended one.
            sources.health(self.deps.http_status, f"{self.cfg.public_url}/healthz")
        return [Plan(name, run, self.check.purpose)], {}, checks_registry.load()

    def _manifest(self, bundle_id, case, started, entries, reg):
        m = super()._manifest(bundle_id, case, started, entries, reg)
        m["collector"] = {
            "runs_on": self.check.runs_on,
            "permissions": list(self.check.permissions),
            "does_not": ["Read-only: nothing in the app, the machine, the database or the "
                         "destination is changed. No upload: the bundle stays in the "
                         "workspace until export."],
        }
        m["followup"] = {"check_id": self.check.id, "request_id": self.request["request_id"],
                         "parent_bundle": self.request["parent_bundle"],
                         "registry_digest": registry.digest()}
        return m


def cmd_run(args: argparse.Namespace) -> int:
    try:
        req = load_request(Path(args.request))
    except FollowupError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    conf = cfg.load(Path(args.config))
    check = registry.followups()[req["check_id"]]
    print(f"{check.id}: {check.title}\n  {check.purpose}\n  runs on: {check.runs_on}")
    for p in check.permissions:
        print(f"  - {p}")
    print(f"  returns: {check.returns}")
    if req["reason"]:
        print(f"  vendor's reason (text from the vendor; the kit runs only the check above):"
              f"\n    {req['reason']}")
    out = FollowupCollector(conf, req).collect(case=check.id.lower())
    print()
    print("\n".join(archive.review_lines(out)))
    print(f"\nReview the file under {out / collect.FILES_DIR}, then export it with "
          f"`python -m kit.bundle export {out.name} --config {args.config} --out <file>`.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m kit.triage.followup", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--request", required=True)
    r.add_argument("--config", required=True)
    r.set_defaults(fn=cmd_run)
    lst = sub.add_parser("list")
    lst.set_defaults(fn=lambda a: print("\n".join(
        f"{c.id}  {c.title}: {c.purpose}" for c in registry.followups().values())) or 0)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (collect.CollectError, cfg.ConfigError, FileExistsError, OSError,
            subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
