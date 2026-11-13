"""Identity and permission probes over the app's public API (RC1-641, ADR 0007).

The v1 profile's identity is password mode (ADR 0001), so conformance
checks exactly that: an anonymous write is refused, a wrong password is
refused, the configured password signs in, and the sign-in is appended to
the audit log (the app role's INSERT on review_audit, the grant dev family 1
revokes). The probe signs out at the end. Both audit rows stay: the log is
append-only by design, and the report says so.

The anonymous write is a PATCH of mapping 0 with a mismatched `source`: the
approver check runs first and refuses it, and even an app that wrongly let
it through would answer 409 instead of writing.
"""

import json
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from typing import Any

TIMEOUT_S = 20
NOT_A_FIELD = "cik-conformance-probe-not-a-field"


class Http:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"content-type": "application/json"})
        try:
            with self.opener.open(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return 0, None


def _max_seq(http: Http) -> tuple[int | None, list[dict] | None]:
    status, body = http.call("GET", "/api/audit?limit=50")
    if status != 200 or not isinstance(body, dict):
        return None, None
    records = body.get("records") or []
    return max((r.get("seq", 0) for r in records), default=0), records


def probe(base_url: str, password: str | None) -> dict[str, Any]:
    anon = Http(base_url)
    out: dict[str, Any] = {}
    out["anonymous_write_status"], _ = anon.call(
        "PATCH", "/api/mappings/field/0", {"source": NOT_A_FIELD, "status": "approved"})
    out["wrong_password_status"], _ = anon.call(
        "POST", "/api/login", {"password": "cik-conformance-wrong-password"})
    if not password:
        out["login_status"] = None
        return out
    out["audit_seq_before"], _ = _max_seq(anon)
    session = Http(base_url)
    out["login_status"], _ = session.call("POST", "/api/login", {"password": password})
    _status, out["me"] = session.call("GET", "/api/me")
    _seq, out["audit_after"] = _max_seq(session)
    if out["audit_after"] is not None:
        # Only the fields the check reads: actor details stay out of the report.
        out["audit_after"] = [{"seq": r.get("seq"), "event": r.get("event")}
                              for r in out["audit_after"]]
    session.call("POST", "/api/logout")
    return out
