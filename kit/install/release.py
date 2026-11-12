"""Fetch and verify a signed ESP release (RC1-640, ADR 0003, ADR 0006).

A release is three public files on the vendor repo's GitHub release:
`release.json` (the manifest), `release.json.sigstore.json` (its Sigstore
bundle) and `sbom.spdx.json`. Verification is all-or-nothing:

1. The bundle verifies the manifest's exact bytes against Sigstore's public
   trust root, with the signer pinned to the vendor's release workflow AT
   THIS TAG and GitHub's OIDC issuer. Any other signer is untrusted, even a
   validly signed one.
2. The manifest names the same version, tag and repository the operator
   asked for, a bare GHCR repository, and a sha256 digest.
3. The SBOM's sha256 matches the manifest.

The installer then deploys by the digest inside the verified manifest, so
what runs is exactly what the vendor's CI built and signed.
"""

import hashlib
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sigstore.errors import Error as SigstoreError
from sigstore.errors import TUFError
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity

# The documented trusted publisher (docs/install.md). Changing any of these
# is a trust decision, not a refactor.
TRUSTED_REPOSITORY = "snacksnack/esp-migration-agent"
TRUSTED_WORKFLOW = ".github/workflows/release.yml"
TRUSTED_ISSUER = "https://token.actions.githubusercontent.com"
TRUSTED_IMAGE = "ghcr.io/snacksnack/esp-migration-agent"
MANIFEST_SCHEMA = "esp.release/1"

MANIFEST = "release.json"
BUNDLE = "release.json.sigstore.json"
SBOM = "sbom.spdx.json"
FILES = (MANIFEST, BUNDLE, SBOM)

VERSION = re.compile(r"^\d+\.\d+\.\d+$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DOWNLOAD_TIMEOUT_S = 30


class ReleaseRejected(Exception):
    """The artifact is not a trusted, intact release. Never install it."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


@dataclass(frozen=True)
class Release:
    version: str
    commit: str
    image_digest: str
    sbom_sha256: str
    manifest_sha256: str
    schema_version: int
    schema_compatible_with: int

    @property
    def image_ref(self) -> str:
        return f"{TRUSTED_IMAGE}@{self.image_digest}"

    def to_json(self) -> dict:
        return {
            "version": self.version,
            "commit": self.commit,
            "image": self.image_ref,
            "sbom_sha256": self.sbom_sha256,
            "manifest_sha256": self.manifest_sha256,
            "db_schema": {
                "version": self.schema_version,
                "compatible_with": self.schema_compatible_with,
            },
        }


def signer_identity(version: str) -> str:
    return (
        f"https://github.com/{TRUSTED_REPOSITORY}/{TRUSTED_WORKFLOW}@refs/tags/v{version}"
    )


def _check_version(version: str) -> None:
    if not VERSION.match(version):
        raise ReleaseRejected("bad_version", f"expected MAJOR.MINOR.PATCH, got {version!r}")


def download(version: str, dest: Path) -> Path:
    """Download the release files into dest/<version>/. Overwrites, never
    trusts what is already there: verification always runs on fresh bytes."""
    _check_version(version)
    target = dest / version
    target.mkdir(parents=True, exist_ok=True)
    base = f"https://github.com/{TRUSTED_REPOSITORY}/releases/download/v{version}"
    for name in FILES:
        try:
            with urllib.request.urlopen(f"{base}/{name}", timeout=DOWNLOAD_TIMEOUT_S) as resp:
                (target / name).write_bytes(resp.read())
        except urllib.error.HTTPError as exc:
            raise ReleaseRejected("not_published", f"v{version} {name}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ReleaseRejected("unreachable", f"v{version} {name}: {exc}") from exc
    return target


def _sigstore_verify(manifest: bytes, bundle_json: bytes, version: str) -> None:
    bundle = Bundle.from_json(bundle_json)
    policy = Identity(identity=signer_identity(version), issuer=TRUSTED_ISSUER)
    Verifier.production().verify_artifact(manifest, bundle, policy)


SignatureCheck = Callable[[bytes, bytes, str], None]


def verify(directory: Path, version: str, check: SignatureCheck = _sigstore_verify) -> Release:
    """Verify a downloaded release. Raises ReleaseRejected on any doubt."""
    _check_version(version)
    missing = [n for n in FILES if not (directory / n).is_file()]
    if missing:
        raise ReleaseRejected("incomplete", f"missing {', '.join(missing)}")
    manifest_bytes = (directory / MANIFEST).read_bytes()
    try:
        check(manifest_bytes, (directory / BUNDLE).read_bytes(), version)
    except TUFError as exc:
        # Fail closed, but say why: no trust root means nothing was verified,
        # which is different from a signature that failed verification.
        raise ReleaseRejected("trust_root_unavailable", str(exc)) from exc
    except (SigstoreError, ValueError) as exc:
        # sigstore raises VerificationError (an Error) for a bad signature or
        # an identity mismatch, and ValueError-family errors for a malformed
        # bundle; both mean the same thing to a customer.
        raise ReleaseRejected("signature", f"{type(exc).__name__}: {exc}") from exc

    try:
        m = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise ReleaseRejected("manifest", "signed manifest is not JSON") from exc
    expect = {
        "schema": MANIFEST_SCHEMA,
        "version": version,
        "source.repository": TRUSTED_REPOSITORY,
        "source.tag": f"v{version}",
        "image.repository": TRUSTED_IMAGE,
        "image.platform": "linux/amd64",
        "sbom.file": SBOM,
    }
    for path, wanted in expect.items():
        got = m
        for part in path.split("."):
            got = got.get(part) if isinstance(got, dict) else None
        if got != wanted:
            raise ReleaseRejected("manifest", f"{path} is {got!r}, expected {wanted!r}")
    digest = m["image"].get("digest", "")
    commit = m["source"].get("commit", "")
    if not DIGEST.match(digest) or not COMMIT.match(commit):
        raise ReleaseRejected("manifest", "image digest or commit is not an exact reference")
    schema = m.get("db_schema") or {}
    sv, sc = schema.get("version"), schema.get("compatible_with")
    if not (isinstance(sv, int) and isinstance(sc, int) and 1 <= sc <= sv):
        raise ReleaseRejected("manifest", f"db_schema is not coherent: {schema!r}")

    sbom_sha = hashlib.sha256((directory / SBOM).read_bytes()).hexdigest()
    if sbom_sha != m["sbom"].get("sha256"):
        raise ReleaseRejected("sbom", "SBOM does not match the signed manifest")
    return Release(
        version=version,
        commit=commit,
        image_digest=digest,
        sbom_sha256=sbom_sha,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        schema_version=sv,
        schema_compatible_with=sc,
    )


def fetch_and_verify(version: str, dest: Path) -> Release:
    return verify(download(version, dest), version)
