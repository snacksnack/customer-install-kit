"""ESP structured error events, validated by the kit (RC1-642, ADR 0008).

The collector runs outside ESP and never imports it, so the kit holds its
own copy of ESP's published event contract (esp docs/error_events.md,
schema v1 RC1-647, v2 RC1-648). A record is kept only if every field is in
the contract for its version and every value is an enum member, a code, or
an opaque identifier of the documented shape. Anything else is dropped and
counted by reason; the manifest reports the counts. An unknown schema
version is dropped, never guessed at.
"""

import json
import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

EVENT_NAME = "esp_error_event"
SUPPORTED_VERSIONS = frozenset({1, 2})

OPERATIONS = frozenset({
    "db.ready_check", "audit.append", "audit.read", "audit.verify",
    "sessions.load", "sessions.save", "sessions.drop", "sessions.revoke",
    "sessions.claim", "scim.read", "scim.write", "destination.request",
    "journal.open", "journal.append", "journal.close", "errorevents.sink",
})
ERROR_CLASSES = frozenset({"db", "http", "network", "storage"})
NETWORK_KINDS = frozenset({"connect_error", "ambiguous_outcome", "retries_exhausted"})
PROVIDER_CODES = frozenset({
    "unauthorized", "bad_request", "invalid_parameter", "missing_parameter",
    "out_of_range", "not_found", "method_not_allowed", "duplicate_parameter",
    "duplicate_request", "document_not_found", "account_under_validation",
    "permission_denied", "not_enough_credits", "unprocessable_entity",
})
CONNECT_CLASSES = frozenset({
    "auth", "database", "dns", "tls", "timeout", "network", "server",
    "pool_exhausted", "unclassified",
})
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"})

V1_FIELDS = frozenset({
    "event", "v", "at", "correlation_id", "release", "op", "error_class",
    "sqlstate", "status", "route", "provider_code", "errno", "errno_name", "kind",
})
FIELDS = {1: V1_FIELDS, 2: V1_FIELDS | {"connect_class"}}

_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_CORRELATION = re.compile(r"^[0-9a-f]{8,64}$")
_RELEASE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$")
_SQLSTATE = re.compile(r"^[0-9A-Z]{5}$")
_ERRNO_NAME = re.compile(r"^E[A-Z0-9]{1,15}$")
# ESP's own route mask (esp errorevents/events.py _SAFE_SEGMENT): a plain word in
# either case (Brevo's paths are camel case), an API version, or a placeholder.
_SEGMENT = re.compile(r"^([A-Za-z_-]+|v\d{1,3}|\{[A-Za-z_]+\})$")


def _route_ok(route: str) -> bool:
    method, _, path = route.partition(" ")
    if method not in METHODS or not path.startswith("/"):
        return False
    segments = [s for s in path.split("/")[1:] if s]
    return all(_SEGMENT.match(s) for s in segments)


def check(record: Any) -> str | None:
    """None if the record conforms; otherwise the drop reason."""
    if not isinstance(record, dict) or record.get("event") != EVENT_NAME:
        return "not_an_event"
    v = record.get("v")
    if v not in SUPPORTED_VERSIONS:
        return "unsupported_version"
    if set(record) - FIELDS[v]:
        return "unknown_field"
    for key, ok in (
        ("at", lambda x: isinstance(x, str) and _AT.match(x)),
        ("correlation_id", lambda x: isinstance(x, str) and _CORRELATION.match(x)),
        ("release", lambda x: isinstance(x, str) and _RELEASE.match(x)),
        ("op", lambda x: x in OPERATIONS),
        ("error_class", lambda x: x in ERROR_CLASSES),
    ):
        if key not in record or not ok(record[key]):
            return f"bad_{key}"
    optional = {
        "sqlstate": lambda x: isinstance(x, str) and _SQLSTATE.match(x),
        "connect_class": lambda x: x in CONNECT_CLASSES,
        "status": lambda x: isinstance(x, int) and not isinstance(x, bool) and 100 <= x <= 599,
        "route": lambda x: isinstance(x, str) and _route_ok(x),
        "provider_code": lambda x: x in PROVIDER_CODES,
        "errno": lambda x: isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 4096,
        "errno_name": lambda x: isinstance(x, str) and _ERRNO_NAME.match(x),
        "kind": lambda x: x in NETWORK_KINDS,
    }
    for key, ok in optional.items():
        if key in record and record[key] is not None and not ok(record[key]):
            return f"bad_{key}"
    return None


def from_lines(lines: Iterable[str], limit: int) -> tuple[list[dict], Counter]:
    """Validated events from raw text lines (newest `limit` kept), plus drop
    counts. A line that is not JSON at all is not an event and is ignored,
    not counted: sinks interleave other output."""
    kept: list[dict] = []
    drops: Counter = Counter()
    for line in lines:
        start = line.find('{"event"')
        if start < 0 or EVENT_NAME not in line:
            continue
        try:
            record = json.loads(line[start:])
        except json.JSONDecodeError:
            drops["malformed_json"] += 1
            continue
        reason = check(record)
        if reason:
            drops[reason] += 1
        else:
            kept.append(record)
    if len(kept) > limit:
        drops["over_limit"] += len(kept) - limit
        kept = kept[-limit:]
    return kept, drops


def summarize(events: list[dict]) -> dict[str, Any]:
    """The distinguishing signals, counted: what a reader looks at first."""
    keys = Counter()
    for e in events:
        parts = [e["op"], e["error_class"]]
        for field in ("sqlstate", "connect_class", "status", "provider_code", "errno_name",
                      "kind"):
            if e.get(field) is not None:
                parts.append(f"{field}={e[field]}")
        if e.get("route"):
            parts.append(f"route={e['route']}")
        keys[" ".join(str(p) for p in parts)] += 1
    return {"count": len(events), "signatures": dict(keys.most_common()),
            "releases": sorted({e["release"] for e in events}),
            "first_at": min((e["at"] for e in events), default=None),
            "last_at": max((e["at"] for e in events), default=None)}
