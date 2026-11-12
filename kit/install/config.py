"""install.toml: the customer's install configuration (no secrets).

    [install]
    profile = "v1"
    release = "0.1.1"
    fly_org = "acme-esp"
    app = "acme-esp"
    region = "iad"
    volume = "esp_data"
    volume_size_gb = 1
    secrets_file = ".env.cik"        # relative to this file; mode 600

Everything an install does is derived from this file plus the secrets file,
so a repeated install with the same inputs converges on the same state.
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
VOLUME = re.compile(r"^[a-z0-9_]{1,30}$")
PROFILES = ("v1",)


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class InstallConfig:
    path: Path
    profile: str
    release: str
    fly_org: str
    app: str
    region: str
    volume: str
    volume_size_gb: int
    secrets_file: Path

    @property
    def workdir(self) -> Path:
        return self.path.parent

    @property
    def public_url(self) -> str:
        return f"https://{self.app}.fly.dev"

    @property
    def record_path(self) -> Path:
        return self.workdir / "install-record.json"


def load(path: Path) -> InstallConfig:
    try:
        raw = tomllib.loads(path.read_text())["install"]
    except FileNotFoundError as exc:
        raise ConfigError(f"no install config at {path}") from exc
    except (tomllib.TOMLDecodeError, KeyError) as exc:
        raise ConfigError(f"{path}: needs an [install] table ({exc})") from exc
    required = ("release", "fly_org", "app", "region", "volume")
    missing = [k for k in required if not raw.get(k)]
    if missing:
        raise ConfigError(f"{path}: missing {', '.join(missing)}")
    profile = raw.get("profile", "v1")
    if profile not in PROFILES:
        raise ConfigError(f"profile {profile!r} is not supported (supported: {PROFILES})")
    for key in ("fly_org", "app"):
        if not NAME.match(raw[key]):
            raise ConfigError(f"{key} {raw[key]!r} is not a valid Fly name")
    if not VOLUME.match(raw["volume"]):
        raise ConfigError(f"volume {raw['volume']!r}: lowercase letters, digits, _ only")
    size = raw.get("volume_size_gb", 1)
    if not isinstance(size, int) or not 1 <= size <= 10:
        raise ConfigError("volume_size_gb must be an integer from 1 to 10")
    return InstallConfig(
        path=path.resolve(),
        profile=profile,
        release=str(raw["release"]),
        fly_org=raw["fly_org"],
        app=raw["app"],
        region=raw["region"],
        volume=raw["volume"],
        volume_size_gb=size,
        secrets_file=(path.parent / raw.get("secrets_file", ".env.cik")).resolve(),
    )
