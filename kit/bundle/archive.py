"""Review, export, and untrusted import of diagnostic bundles (RC1-642, ADR 0008).

`review` is the customer's look before anything leaves: every file, why it
is there, what was dropped, what was unavailable or withheld.

`export` writes a deterministic `.tar.gz` (sorted members, zeroed times and
owners) so the same bundle always archives to the same bytes.

`inspect` is the vendor side, and it treats the archive as hostile input: a
size cap before reading, members read into memory (never extracted to disk),
only regular files at the exact names a bundle may hold, every size bounded,
the manifest signature checked, every file's sha256 checked against the
manifest, and no file left unlisted. Nothing in a bundle is ever executed.
"""

import gzip
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kit.bundle import collect
from kit.bundle.allowlist import KNOWN_VERSIONS, Allowlist
from kit.bundle.allowlist import load as load_allowlist
from kit.verify import signing

MEMBER = re.compile(
    r"^(manifest\.signed\.json|report-key\.pub\.json|files/[a-z][a-z0-9_]{0,39}\.json)$")
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
POINTER_TOKEN = re.compile(r"^(0|[1-9]\d*)$")


class BundleRefused(Exception):
    """The bundle is not one to trust. Say why; read nothing further."""


# -- review (customer) ---------------------------------------------------------


def load_local(bundle_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    envelope = json.loads((bundle_dir / collect.MANIFEST).read_text())
    return envelope, json.loads(envelope["payload"])


def review_lines(bundle_dir: Path) -> list[str]:
    envelope, m = load_local(bundle_dir)
    lines = [
        f"bundle {m['bundle_id']}  install {m['install_id']}  app {m['app']}"
        + (f"  case {m['case']}" if m.get("case") else ""),
        f"digest {collect.bundle_digest(envelope)}",
        f"release {m['versions']['release']}  allowlist v{m['versions']['allowlist']}  "
        f"registry v{m['versions']['check_registry']}  "
        f"event schemas {m['versions']['error_event_schemas']}",
        f"collected {m['collected_started_at']} .. {m['collected_finished_at']}",
        "",
        "What would leave, file by file:",
    ]
    for e in m["sources"]:
        status = e["status"]
        head = f"  [{status}] {e['source']}"
        if status == "included":
            head += f"  {e['file']}  {e['bytes']} bytes"
        else:
            head += f"  ({e['reason']})"
        lines.append(head)
        lines.append(f"      {e['purpose']}")
        if e.get("counts"):
            lines.append(f"      kept: {e['counts']}")
        if e.get("dropped"):
            lines.append(f"      dropped (non-conforming, counted not kept): {e['dropped']}")
        for f in e.get("findings", []):
            lines.append(f"      scanner: {f['rule']} ({f['kind']}) at {f['path']}")
    lines += [
        "",
        f"Read any file in {bundle_dir / collect.FILES_DIR} before exporting.",
        "Nothing has been sent. `export` writes an archive; you choose where it goes.",
        m["scanner"]["claim"],
    ]
    return lines


def _tarinfo(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = size, 0, 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.type = tarfile.REGTYPE
    return info


def export(bundle_dir: Path, out: Path) -> Path:
    if out.exists():
        raise FileExistsError(f"{out} exists; export writes a new file")
    _, m = load_local(bundle_dir)
    names = [collect.MANIFEST, collect.PUBLIC_KEY_FILE] + sorted(
        e["file"] for e in m["sources"] if e["status"] == "included")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in names:
            data = (bundle_dir / name).read_bytes()
            tar.addfile(_tarinfo(name, len(data)), io.BytesIO(data))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as fh, gzip.GzipFile(fileobj=fh, mode="wb", mtime=0,
                                             filename="") as gz:
        gz.write(raw.getvalue())
    return out


# -- inspect (vendor; untrusted input) ----------------------------------------------


@dataclass
class Inspected:
    manifest: dict[str, Any]
    digest: str
    fingerprint: str
    files: dict[str, Any]


def _read_members(archive: Path, allow: Allowlist) -> dict[str, bytes]:
    size = archive.stat().st_size
    if size > MAX_ARCHIVE_BYTES:
        raise BundleRefused(f"archive is {size} bytes; the cap is {MAX_ARCHIVE_BYTES}")
    b = allow.bounds
    max_members = b.max_files + 2
    per_member = max(b.max_file_bytes, 64 * 1024)
    budget = b.max_bundle_bytes + 2 * per_member
    raw = archive.read_bytes()
    try:
        # Bounded decompression: a gzip bomb stops at the budget, not at EOF.
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            plain = gz.read(budget + 1024 * 1024 + 1)
    except (OSError, EOFError) as exc:
        raise BundleRefused(f"not a gzip archive ({type(exc).__name__})") from exc
    if len(plain) > budget + 1024 * 1024:
        raise BundleRefused("archive expands past the bundle bound")
    members: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as tar:
            for info in tar:
                if len(members) >= max_members:
                    raise BundleRefused(f"more than {max_members} members")
                if not info.isreg():
                    raise BundleRefused(f"member {info.name!r} is not a regular file")
                if not MEMBER.match(info.name):
                    raise BundleRefused(f"member name {info.name!r} is not one a bundle holds")
                if info.name in members:
                    raise BundleRefused(f"duplicate member {info.name!r}")
                if info.size > per_member:
                    raise BundleRefused(f"member {info.name!r} is {info.size} bytes")
                total += info.size
                if total > budget:
                    raise BundleRefused("members exceed the bundle bound")
                fh = tar.extractfile(info)
                data = fh.read(per_member + 1) if fh else b""
                if len(data) != info.size:
                    raise BundleRefused(f"member {info.name!r} size mismatch")
                members[info.name] = data
    except tarfile.TarError as exc:
        raise BundleRefused(f"not a valid tar ({type(exc).__name__})") from exc
    return members


def _json(name: str, data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleRefused(f"{name} is not JSON") from exc


def inspect(archive: Path, expect_fingerprint: str | None = None,
            allow: Allowlist | None = None) -> Inspected:
    allow = allow or load_allowlist()
    members = _read_members(archive, allow)
    for need in (collect.MANIFEST, collect.PUBLIC_KEY_FILE):
        if need not in members:
            raise BundleRefused(f"missing {need}")
    pub = _json(collect.PUBLIC_KEY_FILE, members[collect.PUBLIC_KEY_FILE])
    envelope = _json(collect.MANIFEST, members[collect.MANIFEST])
    if not isinstance(pub, dict) or not isinstance(envelope, dict):
        raise BundleRefused("manifest or key is not a JSON object")
    try:
        public, fp = signing.trusted_key(pub)
        if expect_fingerprint and fp != expect_fingerprint:
            raise BundleRefused(f"signed by {fp}, not the expected {expect_fingerprint}")
        manifest = signing.verify(envelope, public, fp)
    except (signing.SignatureInvalid, KeyError, ValueError, TypeError) as exc:
        raise BundleRefused(f"signature: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != collect.SCHEMA:
        raise BundleRefused(f"manifest schema {manifest.get('schema')!r} is not {collect.SCHEMA}")
    if manifest.get("versions", {}).get("allowlist") not in KNOWN_VERSIONS:
        raise BundleRefused("allowlist version is not one this kit knows")
    listed: dict[str, str] = {}
    for e in manifest.get("sources", []):
        if e.get("status") == "included":
            listed[e["file"]] = e["sha256"]
    present = {n for n in members if n.startswith(f"{collect.FILES_DIR}/")}
    if present != set(listed):
        extra, missing = sorted(present - set(listed)), sorted(set(listed) - present)
        raise BundleRefused(f"files do not match the manifest (extra {extra}, missing {missing})")
    files: dict[str, Any] = {}
    for name, digest in listed.items():
        if collect.sha256_hex(members[name]) != digest:
            raise BundleRefused(f"{name} does not match its manifest hash")
        body = _json(name, members[name])
        if not isinstance(body, dict) or body.get("schema") != collect.FILE_SCHEMA:
            raise BundleRefused(f"{name} is not a {collect.FILE_SCHEMA} file")
        files[name] = body
    return Inspected(manifest, collect.bundle_digest(envelope), fp, files)


def resolve(inspected: Inspected, reference: str) -> Any:
    """The value an evidence reference points at, checked against this bundle."""
    if not reference.startswith(collect.REF_PREFIX):
        raise BundleRefused(f"not an evidence reference: {reference!r}")
    body = reference[len(collect.REF_PREFIX):]
    digest, _, rest = body.partition("/")
    file, _, pointer = rest.partition("#")
    if digest != inspected.digest:
        raise BundleRefused("reference names another bundle")
    if file == collect.MANIFEST:
        node: Any = inspected.manifest  # the signed payload: source status, drop counts
    elif file in inspected.files:
        node = inspected.files[file]
    else:
        raise BundleRefused(f"no file {file!r} in this bundle")
    for token in [t for t in pointer.split("/")[1:]] if pointer else []:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list) and POINTER_TOKEN.match(token) and int(token) < len(node):
            node = node[int(token)]
        elif isinstance(node, dict) and token in node:
            node = node[token]
        else:
            raise BundleRefused(f"pointer {pointer!r} does not resolve")
    return node
