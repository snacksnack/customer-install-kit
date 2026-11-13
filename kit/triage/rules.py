"""Deterministic triage rules (RC1-643, ADR 0009).

Written from the development cases only (the six RC1-642 bundles and the
three development families). Each rule reads facts with references
(`kit.triage.facts`) and returns findings. A finding says what the evidence
SUPPORTS, what it does NOT establish, which references back each claim, a
proposed remedy for the customer to review (or none), and which allowlisted
follow-up check would discriminate between the remaining explanations.

Finding statuses:
  supported     the cause is established well enough to propose a remedy
  insufficient  a fault is evidenced, its cause is not; a follow-up may help
  conflicting   current evidence disagrees with itself
  resolved      evidence of a fault that later evidence shows has stopped

The case outcome is the weakest status among findings about a CURRENT fault:
conflicting, then insufficient, then supported. No current fault at all is
`insufficient_evidence` with a `no_current_fault` note, because a quiet
bundle does not prove health. `budget_exhausted` is set only by the agent.

Citing a reference proves only that the cited value exists. Whether the
statement follows from it is the rule's (or the reviewer's) argument, and
the statement spells it out.
"""

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from kit.triage import registry
from kit.triage.facts import Event, Evidence, stamp

SUPPORTED, INSUFFICIENT, CONFLICTING, RESOLVED = "supported", "insufficient", "conflicting", \
    "resolved"
OUTCOMES = ("supported_diagnosis", "conflicting_evidence", "insufficient_evidence",
            "budget_exhausted")
MAX_EVENT_REFS = 4
FULL_AVAIL_BYTES = 1024 * 1024
AUDIT_OPS = frozenset({"audit.append"})
DEST_STATUSES = frozenset({401, 402, 403, 405, 429})


@dataclass
class Finding:
    rule: str
    status: str
    hypothesis: str
    statement: str
    supports: list[str] = field(default_factory=list)
    does_not_establish: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    remedy: str | None = None
    followups: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Result:
    outcome: str
    findings: list[Finding]
    notes: list[dict[str, Any]]
    facts: dict[str, Any]
    registry_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {"outcome": self.outcome, "findings": [f.as_dict() for f in self.findings],
                "notes": self.notes, "facts": self.facts,
                "registry_digest": self.registry_digest}


def _refs(events: list[Event]) -> list[str]:
    out: list[str] = []
    for e in reversed(events):
        out += e.refs[:1]
        if len(out) >= MAX_EVENT_REFS:
            break
    return out


def _span(events: list[Event]) -> str:
    first, last = events[0].at, events[-1].at
    n = len(events)
    return f"{n} time{'s' if n != 1 else ''}, {stamp(first)} to {stamp(last)}" if n > 1 \
        else f"once, at {stamp(last)}"


class Rules:
    def __init__(self, ev: Evidence):
        self.ev = ev
        self.k = registry.knowledge()
        self.release, self.release_ref = ev.current_release()
        self.health, self.health_ref = ev.health()
        self.conf = ev.conformance()
        self.epoch: datetime | None = (self.release or {}).get("created_at")
        self.claimed: set[int] = set()

    def current(self, events: list[Event]) -> bool:
        return bool(events) and (self.epoch is None or events[-1].at >= self.epoch)

    def claim(self, events: list[Event]) -> list[Event]:
        for e in events:
            self.claimed.add(id(e))
        return events

    def conf_after(self, t: datetime) -> bool:
        return bool(self.conf and self.conf.started_at and self.conf.started_at > t)

    def conf_window(self, events: list[Event]) -> list[Event]:
        c = self.conf
        if not (c and c.started_at and c.finished_at):
            return []
        return [e for e in events if c.started_at <= e.at <= c.finished_at]

    # -- family: database credential (startup failure, dev bundle 7219b5) -------

    def db_auth(self) -> list[Finding]:
        events = self.claim([e for e in self.ev.events
                             if e.fields["error_class"] == "db"
                             and e.fields.get("connect_class") == "auth"])
        if not events:
            return []
        exc = self.ev.startup_exception_types()
        exits = [m for m in self.ev.machine_events()
                 if m["type"] == "exit" and m["exit_code"] not in (None, 0)]
        cites = _refs(events) + [r for _, r in exc.values()][:2] + [m["ref"] for m in exits][-2:]
        if self.current(events) or (self.health is not None and self.health != 200):
            if self.health_ref:
                cites.append(self.health_ref)
            down = self.health is not None and self.health != 200
            return [Finding(
                "TRI-DB-AUTH", SUPPORTED,
                "The database rejects the app role's credential.",
                f"ESP's database connect failed with connect_class=auth {_span(events)}"
                + (f"; /healthz returned {self.health}" if down else "")
                + (f"; the machine exited non-zero {len(exits)} time(s)" if exits else "")
                + ". ESP classifies auth when Postgres refuses the password, so the role's "
                  "stored credential no longer matches the database.",
                supports=["The database host answers and refuses this role's password.",
                          "The failure is at connect, before any statement runs."],
                does_not_establish=["Why the credential changed (rotation, role dropped and "
                                    "re-created, or a different branch)."],
                citations=cites, remedy=self.k["remedies"]["db_credential"])]
        return [Finding(
            "TRI-DB-AUTH", RESOLVED,
            "The database rejected the app role's credential earlier.",
            f"connect_class=auth {_span(events)}, all before release v"
            f"{self.release['version']} ({stamp(self.epoch)}); /healthz now returns "
            f"{self.health}. Nothing in this bundle shows the failure after that release.",
            supports=["An earlier credential failure that a later release replaced."],
            does_not_establish=["That the credential cannot fail again."],
            citations=_refs(events) + [r for r in (self.release_ref, self.health_ref) if r])]

    # -- family 1: valid login, insufficient privilege ---------------------------

    def db_privilege(self) -> list[Finding]:
        events = self.claim([e for e in self.ev.events
                             if e.fields["error_class"] == "db"
                             and e.fields.get("sqlstate") == "42501"])
        if not events:
            return []
        ops = sorted({e.fields["op"] for e in events})
        needs = sorted({n for op in ops
                        for n in self.k["operations"].get(op, {}).get("needs", [])})
        last = events[-1].at
        cites = _refs(events)
        fu = self.ev.followup("FUP-DB-PRIV")
        if fu and fu.collected_at and fu.collected_at > last:
            return [self._db_privilege_matrix(events, ops, needs, fu, cites)]
        audit = [e for e in events if e.fields["op"] in AUDIT_OPS]
        cnf013 = self.conf.checks.get("CNF-013") if self.conf else None
        if audit and cnf013 and cnf013.outcome == "pass":
            during = self.conf_window(audit)
            if during:
                return [Finding(
                    "TRI-DB-PRIV", CONFLICTING,
                    "The app role lacks a privilege the audit append needs.",
                    f"audit.append was refused with 42501 at {stamp(during[-1].at)}, inside "
                    f"conformance run {self.conf.run_id}, whose audit-append check passed in "
                    "the same window.",
                    supports=["Both observations are in the bundle; they cannot both describe "
                              "the same moment unless the grant changed during the run."],
                    does_not_establish=["Which observation is current."],
                    citations=_refs(during) + [cnf013.ref], followups=["FUP-DB-PRIV"])]
            if self.conf_after(last):
                return [Finding(
                    "TRI-DB-PRIV", RESOLVED,
                    "The app role lacked a privilege the audit append needs.",
                    f"audit.append was refused with 42501 {_span(audit)}; conformance run "
                    f"{self.conf.run_id} started after that and its audit-append check "
                    f"passed ({cnf013.reason}).",
                    supports=["The audit append works again as of the later conformance run."],
                    does_not_establish=["Who restored the grant, or that every other grant "
                                        "is intact."],
                    citations=cites + [cnf013.ref])]
        return [Finding(
            "TRI-DB-PRIV", INSUFFICIENT,
            "The app role lacks a privilege an ESP operation needs.",
            f"The database refused {', '.join(ops)} with SQLSTATE 42501 "
            f"(insufficient_privilege) {_span(events)}. A 42501 is raised after a successful "
            f"login, so the role authenticates. Per ESP's operation contract these operations "
            f"need: {'; '.join(needs) or 'unknown'}.",
            supports=["The app role connects and authenticates.",
                      "A statement on the named operation lacked a privilege."],
            does_not_establish=["Which of the needed privileges is missing.",
                                "Whether it is still missing now.",
                                "Whether other grants are also gone."],
            citations=cites, followups=["FUP-DB-PRIV"])]

    def _db_privilege_matrix(self, events, ops, needs, fu, cites) -> Finding:
        data = fu.data
        if not data.get("connected"):
            return Finding(
                "TRI-DB-PRIV", INSUFFICIENT,
                "The app role lacks a privilege an ESP operation needs.",
                f"The follow-up could not connect as the app role "
                f"(connect_class={data.get('connect_class')}), so the grants are unknown.",
                does_not_establish=["Which privilege is missing."],
                citations=cites + [fu.ref], followups=["FUP-DB-PRIV"])
        rows = data.get("grants") or []
        missing, extra, row_refs = [], [], []
        for i, g in enumerate(rows):
            name = f"{g.get('object')} {g.get('privilege')}"
            ref = self.ev.ref(fu.file, f"/data/grants/{i}", fu.bundle)
            if g.get("expected") and not g.get("granted"):
                missing.append(name)
                row_refs.append(ref)
            if g.get("expected") is False and g.get("granted"):
                extra.append(name)
                row_refs.append(ref)
        relevant = [m for m in missing if m in needs]
        if relevant:
            stmts = [_grant_sql(m, self.k["app_role"]["name"]) for m in missing]
            return Finding(
                "TRI-DB-PRIV", SUPPORTED,
                "The app role is missing grants ESP needs.",
                f"{', '.join(ops)} was refused with 42501 {_span(events)}. The privilege "
                f"matrix, read afterwards with the role's own credential, shows "
                f"{len(missing)} expected grant(s) missing: {', '.join(missing)}. "
                f"{', '.join(relevant)} is what the refused operation needs.",
                supports=["The missing grant explains the refusal.",
                          "The grant was still missing when the follow-up ran."],
                does_not_establish=["Who or what removed it."],
                citations=cites + row_refs,
                remedy=self.k["remedies"]["db_grants"] + " Statements: " + "; ".join(stmts)
                + (f". Also revoke grants the role must not have: {', '.join(extra)}"
                   if extra else ""))
        return Finding(
            "TRI-DB-PRIV", RESOLVED,
            "The app role lacked a privilege an ESP operation needs.",
            f"42501 on {', '.join(ops)} {_span(events)}; the privilege matrix read afterwards "
            "shows every grant those operations need is present.",
            supports=["The grants are intact now."],
            does_not_establish=["What removed and restored them."],
            citations=cites + [fu.ref])

    # -- family 2: destination reachable, request refused ------------------------

    def destination(self) -> list[Finding]:
        codes = self.k["provider_codes"]
        events = self.claim([e for e in self.ev.events
                             if e.fields["op"] == "destination.request"
                             and e.fields["error_class"] == "http"
                             and (e.fields.get("status") in DEST_STATUSES
                                  or e.fields.get("provider_code") in codes)])
        if not events:
            return []
        groups = defaultdict(list)
        for e in events:
            groups[(e.fields.get("route"), e.fields.get("status"),
                    e.fields.get("provider_code"))].append(e)
        desc = "; ".join(f"{r or 'route unknown'}: HTTP {s}"
                         + (f" {p} ({codes.get(p, 'unknown code')})" if p else "")
                         + f", {_span(g)}" for (r, s, p), g in groups.items())
        last = events[-1].at
        cites = _refs(events)
        pre = self.ev.preflight("runtime")
        if pre:
            cites.append(pre["ref"])
        fu = self.ev.followup("FUP-DEST-AUTH")
        if fu and fu.collected_at and fu.collected_at > last:
            return [self._destination_probe(desc, cites, fu)]
        cnf030 = self.conf.checks.get("CNF-030") if self.conf else None
        if cnf030 and cnf030.outcome == "pass" and self.conf_after(last):
            return [Finding(
                "TRI-DEST", RESOLVED, "The destination refused ESP's requests.",
                f"{desc}. Conformance run {self.conf.run_id} started later and executed a "
                "migration against the destination.",
                supports=["The destination accepts ESP's requests again."],
                citations=cites + [cnf030.ref])]
        corroborating = [cnf030.ref] if cnf030 and cnf030.outcome == "fail" else []
        return [Finding(
            "TRI-DEST", INSUFFICIENT,
            "The destination refuses ESP's requests.",
            f"The destination answered and refused: {desc}."
            + (f" Conformance {self.conf.run_id} failed CNF-030 ({cnf030.reason})."
               if corroborating else "")
            + " The host is reachable (it answered); the refusal is about this request.",
            supports=["The destination is reachable from the app.",
                      "It refused the request's credential or operation."],
            does_not_establish=["Whether the key itself is rejected (deactivated, deleted, "
                                "wrong), refused only from the app's address, or refused "
                                "only for this route."],
            citations=cites + corroborating, followups=["FUP-DEST-AUTH"])]

    def _destination_probe(self, desc, cites, fu) -> Finding:
        probes = fu.data.get("probes") or []
        acct = {p.get("vantage"): (i, p) for i, p in enumerate(probes)
                if p.get("route") == "GET /account"}
        route = [(i, p) for i, p in enumerate(probes) if p.get("route") != "GET /account"]
        pref = [self.ev.ref(fu.file, f"/data/probes/{i}", fu.bundle) for i in range(len(probes))]
        ws, mc = acct.get("workstation"), acct.get("machine")
        ws_s = ws[1].get("status") if ws else None
        mc_s = mc[1].get("status") if mc else None
        if ws_s == 401 and mc_s == 401:
            return Finding(
                "TRI-DEST", SUPPORTED, "The destination rejects the API key itself.",
                f"{desc}. The follow-up called GET /account with the same key from the "
                "workstation and from the app's machine; both were refused with 401. A key "
                "refused for the account endpoint from two different addresses is rejected "
                "as a credential, not for a route or a source address.",
                supports=["The key is rejected everywhere it was tried."],
                does_not_establish=["Whether it was deactivated, deleted, or mistyped."],
                citations=cites + [pref[ws[0]], pref[mc[0]]],
                remedy=self.k["remedies"]["destination_key_rejected"])
        if ws_s == 200 and mc_s in (401, 403):
            return Finding(
                "TRI-DEST", SUPPORTED,
                "The destination refuses the key from the app's address only.",
                f"{desc}. GET /account with the same key succeeded from the workstation "
                f"and was refused ({mc_s}) from the app's machine.",
                supports=["The key is valid.", "The refusal depends on where the call "
                          "comes from."],
                does_not_establish=["Which address list the destination applies."],
                citations=cites + [pref[ws[0]], pref[mc[0]]],
                remedy=self.k["remedies"]["destination_source_restricted"])
        refused_routes = [(i, p) for i, p in route if p.get("status") in DEST_STATUSES]
        if ws_s == 200 and mc_s == 200 and not refused_routes:
            return Finding(
                "TRI-DEST", RESOLVED, "The destination refused ESP's requests.",
                f"{desc}. The follow-up's calls, account and route, all succeeded from both "
                "places.",
                supports=["The key works now from both places."],
                citations=cites + pref)
        return Finding(
            "TRI-DEST", INSUFFICIENT, "The destination refuses ESP's requests.",
            f"{desc}. The follow-up's answers (account: workstation {ws_s}, machine {mc_s}; "
            f"{len(refused_routes)} route probe(s) refused) do not match a cause this "
            "knowledge version can name.",
            does_not_establish=["Why the destination refuses."],
            citations=cites + pref)

    # -- family 3: storage writable at install, full later ----------------------

    def storage(self) -> list[Finding]:
        events = self.claim([e for e in self.ev.events if e.fields["error_class"] == "storage"])
        if not events:
            return []
        full = [e for e in events if e.fields.get("errno_name") in self.k["errno"]]
        other = [e for e in events if e not in full]
        out = []
        if full:
            sink_last = max((e.at for e in self.ev.events if "file_sink" in e.sources),
                            default=None)
            sink_note = ""
            if sink_last and sink_last < full[-1].at:
                sink_note = (f" ESP's error-event file has nothing after {stamp(sink_last)}: "
                             "the sink itself could not write, which is why this event "
                             "reached only the platform log.")
            cites = _refs(full)
            names = sorted({e.fields['errno_name'] for e in full})
            fu = self.ev.followup("FUP-VOLUME")
            if fu and fu.collected_at and fu.collected_at > full[-1].at:
                out.append(self._volume(full, names, cites, fu))
            else:
                out.append(Finding(
                    "TRI-STORAGE", SUPPORTED, "The app's volume is full.",
                    f"ESP's writes to the volume failed with {', '.join(names)} "
                    f"({'; '.join(self.k['errno'][n] for n in names)}) {_span(full)}."
                    + sink_note,
                    supports=["The volume had no space when the write failed."],
                    does_not_establish=["Whether it is still full.",
                                        "What fills it (ESP's own files or something else)."],
                    citations=cites, remedy=self.k["remedies"]["volume_full"],
                    followups=["FUP-VOLUME"]))
        if other:
            out.append(Finding(
                "TRI-STORAGE-OTHER", INSUFFICIENT, "A storage write failed.",
                f"Storage errors outside this knowledge version: "
                f"{', '.join(sorted({e.signature() for e in other}))}, {_span(other)}.",
                does_not_establish=["The cause."],
                citations=_refs(other), followups=["FUP-VOLUME"]))
        return out

    def _volume(self, full, names, cites, fu) -> Finding:
        d = fu.data
        avail = d.get("blocks_avail_kib")
        if not isinstance(avail, int):
            return Finding("TRI-STORAGE", INSUFFICIENT, "The app's volume is full.",
                           "The follow-up could not read the volume.",
                           citations=cites + [fu.ref], followups=["FUP-VOLUME"])
        sink, other_b = d.get("sink_bytes") or 0, d.get("other_bytes") or 0
        filler = ("files outside ESP's error-event file" if other_b > sink
                  else "ESP's error-event file")
        if avail * 1024 <= FULL_AVAIL_BYTES:
            return Finding(
                "TRI-STORAGE", SUPPORTED, "The app's volume is full.",
                f"Writes failed with {', '.join(names)} {_span(full)}, and the follow-up "
                f"found {avail} KiB free on /data afterwards. {filler.capitalize()} hold most "
                f"of it ({other_b} bytes outside the sink, {sink} in it).",
                supports=["The volume is still full.", f"Most of it is {filler}."],
                does_not_establish=["Which process wrote the other files."],
                citations=cites + [fu.ref], remedy=self.k["remedies"]["volume_full"])
        return Finding(
            "TRI-STORAGE", RESOLVED, "The app's volume was full.",
            f"Writes failed with {', '.join(names)} {_span(full)}; the follow-up found "
            f"{avail} KiB free afterwards.",
            supports=["Space was freed after the failure."], citations=cites + [fu.ref])

    # -- whatever no rule above claimed -------------------------------------------

    def crash(self, have_cause: bool) -> list[Finding]:
        exits = [m for m in self.ev.machine_events()
                 if m["type"] == "exit" and m["exit_code"] not in (None, 0)
                 and (self.epoch is None or (m["at"] and m["at"] >= self.epoch))]
        down = self.health is not None and self.health != 200
        if have_cause or not (exits or down):
            return []
        exc = self.ev.startup_exception_types()
        return [Finding(
            "TRI-CRASH", INSUFFICIENT, "ESP is not serving or keeps exiting.",
            f"/healthz {self.health}; {len(exits)} non-zero machine exit(s) since the current "
            f"release; startup exception types: {', '.join(sorted(exc)) or 'none kept'}. "
            "Nothing in the bundle names the cause.",
            does_not_establish=["The cause."],
            citations=[m["ref"] for m in exits][-3:] + [r for _, r in exc.values()]
            + ([self.health_ref] if self.health_ref else []))]

    def unknown(self) -> list[Finding]:
        rest = [e for e in self.ev.events if id(e) not in self.claimed]
        current = [e for e in rest if self.epoch is None or e.at >= self.epoch]
        if not current:
            return []
        sigs = sorted({e.signature() for e in current})
        return [Finding(
            "TRI-UNKNOWN", INSUFFICIENT, "ESP reports failures this knowledge version does "
            "not cover.",
            f"Events since the current release that no rule recognizes: {'; '.join(sigs)} "
            f"({_span(current)}). Triage does not guess at signals it has no knowledge of.",
            does_not_establish=["The cause."], citations=_refs(current))]

    def notes(self) -> list[dict[str, Any]]:
        out = []
        for s in self.ev.source_status():
            if s["status"] != "included":
                out.append({"note": "source_not_included", "source": s["source"],
                            "status": s["status"], "reason": s["reason"], "ref": s["ref"]})
            if s["dropped"]:
                out.append({"note": "records_dropped", "source": s["source"],
                            "dropped": s["dropped"], "ref": s["ref"]})
        green, refs = self.ev.preflight_green()
        out.append({"note": "preflight", "green": green, "refs": refs})
        if self.conf and self.ev.events and self.conf.finished_at \
                and self.conf.finished_at < self.ev.events[-1].at:
            out.append({"note": "conformance_older_than_latest_event",
                        "run_id": self.conf.run_id, "ref": self.conf.ref})
        return out


def _grant_sql(grant: str, role: str) -> str:
    obj, priv = grant.rsplit(" ", 1)
    if obj == "database":
        return f"GRANT {priv} ON DATABASE <database> TO {role}"
    if obj.startswith("schema "):
        return f"GRANT {priv} ON SCHEMA {obj.split(' ', 1)[1]} TO {role}"
    return f"GRANT {priv} ON {obj} TO {role}"


def facts_summary(ev: Evidence, r: Rules) -> dict[str, Any]:
    green, _ = ev.preflight_green()
    return {
        "bundle": ev.primary.manifest.get("bundle_id"),
        "bundle_digest": ev.primary.digest,
        "supplements": [s.manifest.get("bundle_id") for s in ev.supplements],
        "collected_at": stamp(ev.collected_at),
        "healthz": r.health,
        "release": {"version": (r.release or {}).get("version"),
                    "created_at": stamp((r.release or {}).get("created_at"))},
        "preflight_green": green,
        "conformance": ({"run_id": r.conf.run_id, "finished_at": stamp(r.conf.finished_at),
                         "failing": [c.check_id for c in r.conf.failing()]}
                        if r.conf else None),
        "event_signatures": dict(sorted(_count(e.signature() for e in ev.events).items())),
    }


def _count(items) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for i in items:
        out[i] += 1
    return out


def outcome(findings: list[Finding]) -> str:
    live = [f.status for f in findings if f.status != RESOLVED]
    if CONFLICTING in live:
        return "conflicting_evidence"
    if INSUFFICIENT in live or not live:
        return "insufficient_evidence"
    return "supported_diagnosis"


def run(ev: Evidence) -> Result:
    r = Rules(ev)
    findings = r.db_auth() + r.db_privilege() + r.destination() + r.storage()
    have_cause = any(f.status == SUPPORTED for f in findings)
    findings += r.crash(have_cause) + r.unknown()
    notes = r.notes()
    if not [f for f in findings if f.status != RESOLVED]:
        notes.append({"note": "no_current_fault",
                      "detail": "Nothing in this bundle shows a current fault. A quiet "
                                "bundle is not proof of health."})
    return Result(outcome(findings), findings, notes, facts_summary(ev, r), registry.digest())
