"""Run ESP's own db_setup from the verified image, on the operator
workstation (RC1-640, ADR 0006).

The database owner URL stays on the workstation (ADR 0005): it reaches the
container by NAME (`-e ESP_DATABASE_OWNER_URL`, value inherited from this
process), never on argv, and the container is removed when the command
ends. The image is always the verified digest, so the schema applied is the
schema that release ships. create-app-role writes .env.neon into a private
scratch directory the kit merges into the customer's secrets file and then
deletes.
"""

import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from kit.install import secrets_file

Runner = Callable[[list[str], dict[str, str]], subprocess.CompletedProcess]
TIMEOUT_S = 900


class ImageError(Exception):
    pass


def subprocess_runner(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=TIMEOUT_S)


DOCKER_HOST_ALIAS = "@host.docker.internal:"
LOCAL_HOSTS = ("@localhost:", "@127.0.0.1:")


def localize(url: str) -> str:
    """Docker Desktop cannot reach the host as localhost; tests use a local
    Postgres, customers use a hosted one, and only the former is rewritten."""
    for local in LOCAL_HOSTS:
        url = url.replace(local, DOCKER_HOST_ALIAS)
    return url


class EspImage:
    def __init__(self, image_ref: str, owner_url: str, runner: Runner = subprocess_runner):
        self.image_ref = image_ref
        self.owner_url = owner_url
        self.runner = runner

    def _db_setup(self, command: str, workdir: Path | None = None) -> str:
        args = [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "-e", secrets_file.OWNER_URL, "-e", "PYTHONPATH=/app",
        ]
        if workdir:
            args += ["-v", f"{workdir}:/work", "-w", "/work"]
        args += [self.image_ref, "/app/.venv/bin/python", "-m", "review_ui.db_setup", command]
        env = {**os.environ, secrets_file.OWNER_URL: localize(self.owner_url)}
        proc = self.runner(args, env)
        if proc.returncode != 0:
            # db_setup prints "error: <psycopg message>"; the message can
            # name the host or role but never the password, and the caller
            # still scans it before it is shown.
            raise ImageError(f"db_setup {command} exited {proc.returncode}: "
                             f"{proc.stderr.strip()[-300:]}")
        return proc.stdout

    def schema_marker(self) -> tuple[int, int] | None:
        """(version, compatible_with) as the database records it, or None
        for a database no marker-writing release has migrated."""
        out = self._db_setup("schema-version").strip().splitlines()[-1]
        data = json.loads(out)
        return (data["version"], data["compatible_with"]) if data else None

    def migrate(self) -> str:
        return self._db_setup("migrate").strip()

    def create_app_role(self, session_token_key: str | None = None) -> dict[str, str]:
        """(Re)create esp_app with a fresh password; returns ESP_DATABASE_URL
        and ESP_SESSION_TOKEN_KEY. Re-passwords an existing role, so the
        installer calls it only when the stored app URL does not work. An
        existing token key is passed through so a retry does not rotate it."""
        with tempfile.TemporaryDirectory(prefix="cik-") as tmp:
            work = Path(tmp)
            work.chmod(0o700)
            if session_token_key:
                secrets_file.update(work / ".env.neon",
                                    {"ESP_SESSION_TOKEN_KEY": session_token_key})
            self._db_setup("create-app-role", workdir=work)
            produced = work / ".env.neon"
            values = {}
            for line in produced.read_text().splitlines():
                key, _, value = line.partition("=")
                if key.strip():
                    values[key.strip()] = value.strip()
            produced.unlink()
        if any(h in self.owner_url for h in LOCAL_HOSTS) and "ESP_DATABASE_URL" in values:
            host = next(h for h in LOCAL_HOSTS if h in self.owner_url)
            values["ESP_DATABASE_URL"] = values["ESP_DATABASE_URL"].replace(DOCKER_HOST_ALIAS, host)
        return values
