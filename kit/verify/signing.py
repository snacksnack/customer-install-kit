"""Report integrity: a signed envelope over canonical JSON (RC1-641, ADR 0003/0007).

The install's Ed25519 key (generated at install, private half mode 600 on
the customer workstation) signs the exact payload bytes. The envelope
carries the payload as a string so a verifier checks the bytes that were
signed, never a re-serialization of them.

What a valid signature proves: the payload is unmodified since signing, and
the holder of this install's private key signed it. What it does NOT prove:
that the observations are true. The customer controls the environment and
the key and could sign anything (ADR 0003's non-claim).
"""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ENVELOPE = "cik.signed/1"
ALGORITHM = "ed25519"
NON_CLAIM = (
    "A valid signature shows this report is unmodified and was signed with the "
    "install's report key. It does not show the observations are true: the "
    "customer controls the environment and the key."
)


class SignatureInvalid(Exception):
    """The envelope does not verify against the trusted key. Refuse it."""


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(raw_public: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw_public).hexdigest()


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureInvalid(f"{path} is not an Ed25519 private key")
    return key


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def sign(payload: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = canonical(payload)
    return {
        "envelope": ENVELOPE,
        "algorithm": ALGORITHM,
        "key_fingerprint": fingerprint(raw_public(key)),
        "payload": body,
        "signature": base64.b64encode(key.sign(body.encode())).decode(),
    }


def trusted_key(record_key: dict[str, Any]) -> tuple[Ed25519PublicKey, str]:
    """The public key from an install record's `report_key`, checked against
    its own fingerprint so a hand-edited record cannot pair one with another."""
    if record_key.get("algorithm") != ALGORITHM:
        raise SignatureInvalid(f"report key algorithm {record_key.get('algorithm')!r}")
    raw = base64.b64decode(record_key["public_key"], validate=True)
    fp = fingerprint(raw)
    if fp != record_key.get("fingerprint"):
        raise SignatureInvalid("install record's report key does not match its fingerprint")
    return Ed25519PublicKey.from_public_bytes(raw), fp


def verify(envelope: dict[str, Any], public: Ed25519PublicKey, fp: str) -> dict[str, Any]:
    """The payload, only if the envelope verifies against the trusted key."""
    if envelope.get("envelope") != ENVELOPE or envelope.get("algorithm") != ALGORITHM:
        raise SignatureInvalid("not a cik.signed/1 ed25519 envelope")
    if envelope.get("key_fingerprint") != fp:
        raise SignatureInvalid(
            f"signed by key {envelope.get('key_fingerprint')}, not the trusted {fp} "
            "(another install, or a re-keyed one: compare fingerprints out of band)"
        )
    body = envelope.get("payload")
    if not isinstance(body, str):
        raise SignatureInvalid("payload is not a string")
    try:
        public.verify(base64.b64decode(envelope["signature"], validate=True), body.encode())
    except (InvalidSignature, KeyError, ValueError) as exc:
        raise SignatureInvalid("signature does not match the payload (modified after signing)") \
            from exc
    return json.loads(body)
