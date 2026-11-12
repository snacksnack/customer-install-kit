"""Real Sigstore verification of the published v0.1.2 release (RC1-640).

The fixtures are the public files from the GitHub release, unmodified
(the SBOM gzipped for size; decompressed byte-for-byte before use).
Verification fetches Sigstore's trust root, so these need network; that is
the same dependency a customer install has.
"""

import gzip
import shutil
from pathlib import Path

import pytest

from kit.install import release as rel

FIXTURE = Path(__file__).parent / "fixtures" / "release-0.1.2"
DIGEST = "sha256:638215c5b692ca81308220879035e4d3c9ebfe27a7124ff1424f07622f2b5ffd"


@pytest.fixture()
def copy(tmp_path):
    for f in FIXTURE.iterdir():
        if f.suffix == ".gz":  # the SBOM, stored compressed (5.6 MB raw)
            (tmp_path / f.stem).write_bytes(gzip.decompress(f.read_bytes()))
        else:
            shutil.copy(f, tmp_path / f.name)
    return tmp_path


def test_the_published_release_verifies(copy):
    r = rel.verify(copy, "0.1.2")
    assert r.image_digest == DIGEST
    assert r.commit == "8b50bea107eea550448170fbce7b4f5c2a44646d"


def test_one_changed_byte_in_the_manifest_is_refused(copy):
    m = copy / rel.MANIFEST
    m.write_text(m.read_text().replace(DIGEST[-6:], "000000"))  # point at another image
    with pytest.raises(rel.ReleaseRejected) as exc:
        rel.verify(copy, "0.1.2")
    assert exc.value.reason == "signature"


def test_a_genuine_signature_for_another_tag_is_refused(copy):
    # Same bytes, same valid signature, but the operator asked for 0.1.3: the
    # signer identity is pinned to the tag, so this is an untrusted publisher.
    with pytest.raises(rel.ReleaseRejected) as exc:
        rel.verify(copy, "0.1.3")
    assert exc.value.reason == "signature"


def test_a_bundle_from_elsewhere_is_refused(copy):
    (copy / rel.BUNDLE).write_text('{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}')
    with pytest.raises(rel.ReleaseRejected) as exc:
        rel.verify(copy, "0.1.2")
    assert exc.value.reason == "signature"
