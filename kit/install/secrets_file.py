"""The customer-held secrets file (RC1-640, ADR 0006).

One KEY=value file, mode 600, on the operator workstation. It holds the
database owner URL (operator-only, never pushed) and the app's secrets.
The kit reads it, adds generated values, and pushes an allowlisted subset
to the customer's Fly app. Values never reach the install record, the
terminal, or any vendor-side workflow.
"""

import os
import stat
from pathlib import Path

OWNER_URL = "ESP_DATABASE_OWNER_URL"
# Exactly what the app receives. The owner URL is absent on purpose: it is
# install-time only and stays on the workstation (ADR 0005).
APP_SECRETS = (
    "ESP_REVIEW_PASSWORD",
    "ESP_REVIEW_SESSION_SECRET",
    "ESP_DATABASE_URL",
    "ESP_SESSION_TOKEN_KEY",
    "ESP_BREVO_API_KEY",
    "ESP_ANTHROPIC_API_KEY",
)


class SecretsFileError(Exception):
    pass


def read(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SecretsFileError(f"{path} is mode {mode:o}; it must be 600 (chmod 600 {path})")
    values = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def update(path: Path, updates: dict[str, str]) -> None:
    """Set keys, keeping every other line and comment; created mode 600."""
    lines = path.read_text().splitlines() if path.exists() else []
    seen = set()
    for i, line in enumerate(lines):
        key = line.partition("=")[0].strip()
        if key in updates:
            lines[i] = f"{key}={updates[key]}"
            seen.add(key)
    lines += [f"{k}={v}" for k, v in updates.items() if k not in seen]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    path.chmod(0o600)


def app_subset(values: dict[str, str]) -> dict[str, str]:
    return {k: values[k] for k in APP_SECRETS if values.get(k)}
