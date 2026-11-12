"""Release verification rejects anything but the trusted, intact release
(RC1-640). The signature seam is faked here; tests/test_release_live.py
verifies a real published bundle against Sigstore."""

import hashlib
import json

import pytest

from kit.install import release as rel

DIGEST = "sha256:" + "d" * 64


def write_release(tmp_path, version="0.1.1", **overrides):
    sbom = b'{"spdxVersion": "SPDX-2.3"}'
    m = {
        "schema": rel.MANIFEST_SCHEMA, "version": version,
        "source": {"repository": rel.TRUSTED_REPOSITORY, "tag": f"v{version}", "commit": "c" * 40},
        "image": {"repository": rel.TRUSTED_IMAGE, "digest": DIGEST, "platform": "linux/amd64"},
        "sbom": {"file": rel.SBOM, "format": "spdx-json",
                 "sha256": hashlib.sha256(sbom).hexdigest()},
        "db_schema": {"version": 1, "compatible_with": 1},
    }
    for path, value in overrides.items():
        node = m
        *parents, leaf = path.split(".")
        for p in parents:
            node = node[p]
        node[leaf] = value
    (tmp_path / rel.MANIFEST).write_text(json.dumps(m))
    (tmp_path / rel.BUNDLE).write_text("{}")
    (tmp_path / rel.SBOM).write_bytes(sbom)
    return tmp_path


def trusting(manifest, bundle, version):
    return None


def test_intact_release_verifies_and_pins_the_digest(tmp_path):
    r = rel.verify(write_release(tmp_path), "0.1.1", check=trusting)
    assert r.image_ref == f"{rel.TRUSTED_IMAGE}@{DIGEST}"
    assert (r.schema_version, r.schema_compatible_with) == (1, 1)


def test_signer_identity_is_pinned_to_the_tag():
    assert rel.signer_identity("0.1.2") == (
        "https://github.com/snacksnack/esp-migration-agent/.github/workflows/release.yml"
        "@refs/tags/v0.1.2")


def test_a_signature_failure_is_a_rejection(tmp_path):
    def bad(manifest, bundle, version):
        raise rel.SigstoreError("bad signature")
    with pytest.raises(rel.ReleaseRejected) as exc:
        rel.verify(write_release(tmp_path), "0.1.1", check=bad)
    assert exc.value.reason == "signature"


@pytest.mark.parametrize("path,value,reason", [
    ("version", "0.1.2", "manifest"),            # signed for another version
    ("source.repository", "evil/fork", "manifest"),
    ("image.repository", "ghcr.io/evil/esp", "manifest"),
    ("image.digest", "latest", "manifest"),
    ("image.platform", "linux/arm64", "manifest"),
    ("db_schema.compatible_with", 5, "manifest"),
    ("sbom.sha256", "0" * 64, "sbom"),
])
def test_manifest_contents_are_checked_after_the_signature(tmp_path, path, value, reason):
    with pytest.raises(rel.ReleaseRejected) as exc:
        rel.verify(write_release(tmp_path, **{path: value}), "0.1.1", check=trusting)
    assert exc.value.reason == reason


def test_a_swapped_sbom_is_rejected(tmp_path):
    d = write_release(tmp_path)
    (d / rel.SBOM).write_text('{"spdxVersion": "SPDX-2.3", "packages": []}')
    with pytest.raises(rel.ReleaseRejected, match="SBOM"):
        rel.verify(d, "0.1.1", check=trusting)


def test_missing_files_and_bad_versions_are_rejected(tmp_path):
    d = write_release(tmp_path)
    (d / rel.BUNDLE).unlink()
    with pytest.raises(rel.ReleaseRejected, match="missing"):
        rel.verify(d, "0.1.1", check=trusting)
    with pytest.raises(rel.ReleaseRejected, match="MAJOR"):
        rel.verify(d, "latest", check=trusting)
