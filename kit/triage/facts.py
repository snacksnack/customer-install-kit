"""Facts read from inspected bundles, each carrying evidence references
(RC1-643, ADR 0009).

Triage never reads a bundle any other way. `Evidence` takes bundles that
`kit.bundle.archive.inspect` already validated (signature, hashes, exact
members), and derives typed facts from fixed JSON paths. Every fact keeps the
`cik-ev:` references it came from, so a rule or the agent can cite it and
anyone can resolve the citation against the same archive.

Bundle content is data. Strings are only compared against enums and
patterns here; nothing in a bundle selects code to run.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from kit.bundle import archive, collect
from kit.bundle.archive import BundleRefused, Inspected

EVENT_FIELDS = ("op", "error_class", "sqlstate", "connect_class", "status", "provider_code",
                "route", "errno_name", "errno", "kind", "release")
SINKS = ("file_sink", "platform_log")
FOLLOWUP_SOURCES = {"FUP-DB-PRIV": "fup_db_priv", "FUP-DEST-AUTH": "fup_dest_auth",
                    "FUP-VOLUME": "fup_volume"}


def parse_time(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, UTC)  # Fly event timestamps are ms
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def stamp(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


@dataclass
class Event:
    at: datetime
    fields: dict[str, Any]
    refs: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def signature(self) -> str:
        parts = [self.fields.get("op"), self.fields.get("error_class")]
        for key in ("sqlstate", "connect_class", "status", "provider_code", "errno_name", "kind"):
            if self.fields.get(key) is not None:
                parts.append(f"{key}={self.fields[key]}")
        if self.fields.get("route"):
            parts.append(f"route={self.fields['route']}")
        return " ".join(str(p) for p in parts)


@dataclass
class Check:
    check_id: str
    outcome: str
    reason: str
    ref: str


@dataclass
class Conformance:
    run_id: str
    started_at: datetime | None
    finished_at: datetime | None
    checks: dict[str, Check]
    ref: str

    def failing(self) -> list[Check]:
        return [c for c in self.checks.values() if c.outcome == "fail"]


@dataclass
class Followup:
    check_id: str
    request_id: str | None
    collected_at: datetime | None
    data: dict[str, Any]
    ref: str
    bundle: Inspected
    file: str


class Evidence:
    """The primary bundle plus any supplemental (follow-up) bundles for one case."""

    def __init__(self, primary: Inspected, supplements: list[Inspected] | None = None):
        self.primary = primary
        self.supplements = list(supplements or [])
        for s in self.supplements:
            fu = s.manifest.get("followup") or {}
            if fu.get("parent_bundle") != primary.digest:
                raise BundleRefused(
                    f"supplement {s.manifest.get('bundle_id')} answers another bundle")
        self.collected_at = parse_time(primary.manifest.get("collected_started_at"))
        self.events = self._events()
        self.followups = self._followups()

    # -- references ------------------------------------------------------------

    def ref(self, file: str, pointer: str = "", bundle: Inspected | None = None) -> str:
        return collect.ref((bundle or self.primary).digest, file, pointer)

    def manifest_ref(self, pointer: str, bundle: Inspected | None = None) -> str:
        return self.ref(collect.MANIFEST, pointer, bundle)

    def resolve(self, reference: str) -> Any:
        """Resolve against whichever of this case's bundles the reference names."""
        for b in [self.primary, *self.supplements]:
            if reference.startswith(f"{collect.REF_PREFIX}{b.digest}/"):
                return archive.resolve(b, reference)
        raise BundleRefused("reference names a bundle that is not part of this case")

    def file(self, source: str, bundle: Inspected | None = None) -> Any:
        body = (bundle or self.primary).files.get(f"{collect.FILES_DIR}/{source}.json")
        return body.get("data") if isinstance(body, dict) else None

    # -- facts -----------------------------------------------------------------

    def source_status(self) -> list[dict[str, Any]]:
        out = []
        for i, e in enumerate(self.primary.manifest.get("sources", [])):
            out.append({"source": e.get("source"), "status": e.get("status"),
                        "reason": e.get("reason"), "dropped": e.get("dropped") or {},
                        "ref": self.manifest_ref(f"/sources/{i}")})
        return out

    def health(self) -> tuple[int | None, str | None]:
        data = self.file("health")
        if not isinstance(data, dict):
            return None, None
        status = data.get("healthz_status")
        return (status if isinstance(status, int) else None,
                self.ref("files/health.json", "/data/healthz_status"))

    def current_release(self) -> tuple[dict[str, Any] | None, str | None]:
        data = self.file("fly_releases")
        if not isinstance(data, list) or not data:
            return None, None
        best = max(range(len(data)), key=lambda i: data[i].get("Version") or 0)
        rel = data[best]
        return ({"version": rel.get("Version"), "created_at": parse_time(rel.get("CreatedAt")),
                 "status": rel.get("Status")},
                self.ref("files/fly_releases.json", f"/data/{best}"))

    def machine_events(self) -> list[dict[str, Any]]:
        out = []
        data = self.file("fly_machines")
        for mi, m in enumerate(data if isinstance(data, list) else []):
            for ei, ev in enumerate(m.get("events") or []):
                exit_event = ((ev.get("request") or {}).get("exit_event")) or {}
                out.append({"type": ev.get("type"), "status": ev.get("status"),
                            "at": parse_time(ev.get("timestamp")),
                            "exit_code": exit_event.get("exit_code"),
                            "oom_killed": exit_event.get("oom_killed"),
                            "ref": self.ref("files/fly_machines.json",
                                            f"/data/{mi}/events/{ei}")})
        return sorted(out, key=lambda e: e["at"] or datetime.min.replace(tzinfo=UTC))

    def machine_checks(self) -> list[dict[str, Any]]:
        out = []
        data = self.file("fly_machines")
        for mi, m in enumerate(data if isinstance(data, list) else []):
            for ci, c in enumerate(m.get("checks") or []):
                out.append({"name": c.get("name"), "status": c.get("status"),
                            "ref": self.ref("files/fly_machines.json", f"/data/{mi}/checks/{ci}")})
        return out

    def preflight(self, which: str) -> dict[str, Any] | None:
        data = self.file(f"preflight_{which}")
        if not isinstance(data, dict):
            return None
        failing = [o.get("check_id") for o in data.get("observations") or []
                   if o.get("outcome") == "fail"]
        return {"exit_status": data.get("exit_status"), "failing": failing,
                "finished_at": parse_time(data.get("finished_at")),
                "ref": self.ref(f"files/preflight_{which}.json", "/data/exit_status")}

    def preflight_green(self) -> tuple[bool | None, list[str]]:
        """Green means every required check passed (exit 0) in both contexts."""
        reports = [self.preflight("operator"), self.preflight("runtime")]
        if any(r is None for r in reports):
            return None, [r["ref"] for r in reports if r]
        return all(r["exit_status"] == 0 for r in reports), [r["ref"] for r in reports]

    def conformance(self) -> Conformance | None:
        data = self.file("conformance")
        if not isinstance(data, dict):
            return None
        checks = {}
        for i, o in enumerate(data.get("observations") or []):
            cid = o.get("check_id")
            if isinstance(cid, str):
                checks[cid] = Check(cid, o.get("outcome"), o.get("reason"),
                                    self.ref("files/conformance.json", f"/data/observations/{i}"))
        return Conformance(data.get("run_id"), parse_time(data.get("started_at")),
                           parse_time(data.get("finished_at")), checks,
                           self.ref("files/conformance.json", "/data/run_id"))

    def _events(self) -> list[Event]:
        """Both sinks merged. The same record seen in both sinks is one event
        with two references (same correlation id, operation and time)."""
        merged: dict[tuple, Event] = {}
        for source in SINKS:
            data = self.file(source)
            if not isinstance(data, dict):
                continue
            for i, rec in enumerate(data.get("error_events") or []):
                at = parse_time(rec.get("at"))
                if at is None:
                    continue
                key = (rec.get("correlation_id"), rec.get("op"), rec.get("at"))
                ev = merged.get(key)
                if ev is None:
                    ev = merged[key] = Event(at, {k: rec.get(k) for k in EVENT_FIELDS})
                ev.refs.append(self.ref(f"files/{source}.json", f"/data/error_events/{i}"))
                ev.sources.append(source)
        return sorted(merged.values(), key=lambda e: e.at)

    def startup_exception_types(self) -> dict[str, tuple[int, str]]:
        data = self.file("platform_log")
        types = (data or {}).get("startup_exception_types") if isinstance(data, dict) else None
        def pointer(t: str) -> str:
            return "/data/startup_exception_types/" + t.replace("~", "~0").replace("/", "~1")
        return {t: (n, self.ref("files/platform_log.json", pointer(t)))
                for t, n in (types or {}).items() if isinstance(n, int)}

    def _followups(self) -> list[Followup]:
        out = []
        for s in self.supplements:
            fu = s.manifest.get("followup") or {}
            cid = fu.get("check_id")
            source = FOLLOWUP_SOURCES.get(cid)
            data = self.file(source, s) if source else None
            if isinstance(data, dict):
                file = f"files/{source}.json"
                out.append(Followup(cid, fu.get("request_id"),
                                    parse_time(s.manifest.get("collected_started_at")), data,
                                    self.ref(file, "/data", s), s, file))
        return out

    def followup(self, check_id: str) -> Followup | None:
        found = [f for f in self.followups if f.check_id == check_id]
        return max(found, key=lambda f: f.collected_at or datetime.min.replace(tzinfo=UTC)) \
            if found else None
