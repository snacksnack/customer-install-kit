"""The independent scan every bundle file passes before it is written (RC1-642, ADR 0008).

The allowlist is the control: a bundle is built only from listed fields.
This scan is the check behind it, and it is deliberately not the same code.
It reuses compatlab's redaction scanner (api-compatibility-lab, pinned by
commit) for value shapes (emails, cards, phones, SSNs, IPs, bearer tokens,
base64-wrapped versions of any of them), adds the secret shapes this kit's
install actually holds, and searches for the install's own secret values in
the encodings a value picks up on its way through logs and JSON.

A file with any finding is withheld from the bundle. The manifest records
that it was withheld and which detectors fired, by path and detector name;
it never carries a preview of the matched value.

What a clean scan means: none of these detectors fired on these bytes. It is
bounded coverage, not proof that nothing sensitive is present.
"""

import base64
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, quote_plus

from compatlab.redaction import BASE_POLICY, DROP, SECRET, Detector, Policy
from compatlab.redaction.detectors import STRING

SCANNER = "compatlab.redaction BASE_POLICY + cik kit detectors + install secret values"

KIT_DETECTORS: tuple[Detector, ...] = (
    Detector("postgres_url_with_password", SECRET, DROP, STRING,
             re.compile(r"postgres(?:ql)?://[^\s:/@]+:[^\s@]+@[^\s/]+")),
    Detector("brevo_api_key", SECRET, DROP, STRING,
             re.compile(r"xkeysib-[A-Za-z0-9]{16,}(?:-[A-Za-z0-9]{8,})?")),
    Detector("anthropic_api_key", SECRET, DROP, STRING,
             re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    Detector("fly_token", SECRET, DROP, STRING,
             re.compile(r"(?:FlyV1\s+)?fm[12]_[A-Za-z0-9+/=_-]{16,}|\bfo1_[A-Za-z0-9_-]{16,}")),
    Detector("private_key_block", SECRET, DROP, STRING,
             re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)

POLICY: Policy = Policy(
    name="cik-bundle",
    detectors=KIT_DETECTORS + BASE_POLICY.detectors,
    allow_values=BASE_POLICY.allow_values,
)

MIN_SECRET_LENGTH = 8


@dataclass(frozen=True)
class Hit:
    """Where a detector fired: a JSON path and a detector name. No value."""

    path: str
    rule: str
    kind: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "rule": self.rule, "kind": self.kind}


def _b64_cores(secret: bytes) -> set[str]:
    """Base64 runs that appear wherever `secret` is encoded inside a longer
    value, at any of the three byte alignments: only whole 3-byte groups
    encode independently of their neighbors."""
    out = set()
    for k in range(3):
        part = secret[k:]
        whole = len(part) // 3 * 3
        if whole < 6:
            continue
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            out.add(enc(part[:whole]).decode())
    return out


def variants(secret: str) -> set[str]:
    """The secret as it may appear after common transformations."""
    raw = secret.encode()
    forms = {
        secret,
        secret.lower(),
        secret.upper(),
        quote(secret, safe=""),
        quote_plus(secret),
        json.dumps(secret)[1:-1],
        raw.hex(),
        raw.hex().upper(),
    }
    forms |= _b64_cores(raw)
    return {f for f in forms if len(f) >= MIN_SECRET_LENGTH}


class Scanner:
    def __init__(self, secret_values: Iterable[str] = ()):
        self._needles: list[str] = sorted({
            v for s in secret_values if len(s) >= MIN_SECRET_LENGTH for v in variants(s)
        }, key=len, reverse=True)

    @property
    def secret_value_count(self) -> int:
        return len(self._needles)

    def scan(self, data: Any, text: str) -> list[Hit]:
        """Findings in a file: the structured scan over `data`, and the
        install's secret values (in every variant) over the serialized
        `text` that would actually be written."""
        hits = [Hit(f.path, f.rule, f.kind) for f in POLICY.scan(data)]
        folded = text.lower()
        for needle in self._needles:
            if needle in text or needle.lower() in folded:
                hits.append(Hit("$", "install_secret_value", SECRET))
                break
        return hits

    def detector_names(self) -> list[str]:
        return [d.name for d in POLICY.detectors] + ["encoded_*", "install_secret_value"]
