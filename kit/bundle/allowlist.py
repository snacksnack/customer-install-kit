"""The bundle allowlist and the projection that applies it (RC1-642, ADR 0008).

`project(data, paths)` builds a new value holding ONLY the listed paths.
It never copies a subtree wholesale: a path must name a leaf (or a list of
leaves with `[]`, or a mapping's key names with `{keys}`), so a field added
upstream tomorrow stays out until someone lists it here.
"""

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALLOWLIST_PATH = Path(__file__).with_name("allowlist.toml")
SCHEMA = "cik.bundle-allowlist"
KNOWN_VERSIONS = frozenset({1})
SCALARS = (str, int, float, bool, type(None))


class AllowlistError(Exception):
    pass


@dataclass(frozen=True)
class Bounds:
    max_files: int
    max_file_bytes: int
    max_bundle_bytes: int
    max_events: int
    max_sink_read_bytes: int
    source_timeout_s: int
    total_timeout_s: int


@dataclass(frozen=True)
class Source:
    name: str
    purpose: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class Allowlist:
    version: int
    bounds: Bounds
    sources: dict[str, Source]


def load(path: Path = ALLOWLIST_PATH) -> Allowlist:
    raw = tomllib.loads(path.read_text())
    version = raw.get("version")
    if version not in KNOWN_VERSIONS:
        raise AllowlistError(f"allowlist version {version!r} is not one this kit knows")
    sources = {
        name: Source(name, spec["purpose"], tuple(spec["paths"]))
        for name, spec in raw["sources"].items()
    }
    for src in sources.values():
        for p in src.paths:
            _parse(p)  # fail at load, not mid-collection
    return Allowlist(version, Bounds(**raw["bounds"]), sources)


def _parse(path: str) -> list[str]:
    """`a.b[].c{keys}` -> ['a', 'b', '[]', 'c', '{keys}']."""
    if not path or path.strip() != path:
        raise AllowlistError(f"bad path {path!r}")
    tokens: list[str] = []
    for part in path.split("."):
        keys = part.endswith("{keys}")
        part = part.removesuffix("{keys}")
        lists = 0
        while part.endswith("[]"):
            part, lists = part[:-2], lists + 1
        if part:
            tokens.append(part)
        tokens += ["[]"] * lists
        if keys:
            tokens.append("{keys}")
    if "{keys}" in tokens[:-1]:
        raise AllowlistError(f"{{keys}} must end the path: {path!r}")
    return tokens


def _get(data: Any, tokens: list[str]) -> Any:
    """The projected value at `tokens`, or a sentinel when absent."""
    if not tokens:
        return data if isinstance(data, SCALARS) else _ABSENT
    head, rest = tokens[0], tokens[1:]
    if head == "{keys}":
        return sorted(str(k) for k in data) if isinstance(data, dict) else _ABSENT
    if head == "[]":
        if not isinstance(data, list):
            return _ABSENT
        return [_get(item, rest) for item in data]
    if head == "*":
        if not isinstance(data, dict):
            return _ABSENT
        return {str(k): _get(v, rest) for k, v in data.items()}
    if not isinstance(data, dict) or head not in data:
        return _ABSENT
    return _get(data[head], rest)


class _Absent:
    def __repr__(self) -> str:
        return "<absent>"


_ABSENT = _Absent()


def _merge(out: Any, tokens: list[str], value: Any) -> Any:
    if value is _ABSENT:
        return out
    if not tokens or tokens[0] == "{keys}":
        return value
    head, rest = tokens[0], tokens[1:]
    if head == "*":
        out = out if isinstance(out, dict) else {}
        for k, item in value.items():
            merged = _merge(out.get(k), rest, item)
            if merged is not None and merged is not _ABSENT:
                out[k] = merged
        return out
    if head == "[]":
        out = out if isinstance(out, list) else [_ABSENT] * len(value)
        for i, item in enumerate(value):
            out[i] = _merge(out[i] if out[i] is not _ABSENT else None, rest, item)
        return out
    out = out if isinstance(out, dict) else {}
    merged = _merge(out.get(head), rest, value)
    if merged is not None or not rest:
        out[head] = merged
    return out


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if v is not _ABSENT}
    if isinstance(value, list):
        return [_clean(v) for v in value if v is not _ABSENT]
    return value


def project(data: Any, paths: tuple[str, ...]) -> Any:
    out: Any = None
    for path in paths:
        tokens = _parse(path)
        out = _merge(out, tokens, _get(data, tokens))
    return _clean(out)
