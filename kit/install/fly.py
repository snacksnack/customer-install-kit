"""The customer's Fly CLI, run as the customer operator (RC1-640).

Every call goes through one runner so tests can replace Fly, and so no
secret ever reaches argv: values travel on stdin (`fly secrets import`).
The kit uses whatever identity flyctl already has on the workstation (the
operator's login or FLY_API_TOKEN); it never asks for, stores or prints a
Fly credential.
"""

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

Runner = Callable[[list[str], str | None], "Result"]
TIMEOUT_S = 600


@dataclass(frozen=True)
class Result:
    code: int
    stdout: str
    stderr: str


class FlyError(Exception):
    def __init__(self, args: list[str], result: Result):
        tail = (result.stderr or result.stdout).strip().splitlines()[-3:]
        super().__init__(f"fly {' '.join(args[:3])} failed ({result.code}): {' | '.join(tail)}")
        self.result = result


def subprocess_runner(args: list[str], stdin: str | None) -> Result:
    proc = subprocess.run(
        ["flyctl", *args], input=stdin, capture_output=True, text=True, timeout=TIMEOUT_S
    )
    return Result(proc.returncode, proc.stdout, proc.stderr)


class Fly:
    def __init__(self, runner: Runner = subprocess_runner):
        self.runner = runner

    def run(self, *args: str, stdin: str | None = None, check: bool = True) -> Result:
        result = self.runner(list(args), stdin)
        if check and result.code != 0:
            raise FlyError(list(args), result)
        return result

    def json(self, *args: str):
        return json.loads(self.run(*args, "--json").stdout or "null")

    # -- reads -----------------------------------------------------------

    def app_org(self, app: str) -> str | None:
        """The org slug that owns `app`, or None if this identity cannot see
        it. App-scoped: an app deploy token can answer it, unlike `apps list
        --org`. Under a scoped token "not found" also covers "not yours", so
        callers treat None as "try to create", which such a token cannot do."""
        result = self.run("status", "-a", app, "--json", check=False)
        if result.code != 0:
            if "Could not find App" in result.stderr:
                return None
            raise FlyError(["status", "-a", app], result)
        return ((json.loads(result.stdout) or {}).get("Organization") or {}).get("Slug")

    def volumes(self, app: str, name: str) -> list[dict]:
        return [v for v in self.json("volumes", "list", "-a", app) or [] if v.get("name") == name]

    def machines(self, app: str) -> list[dict]:
        return self.json("machines", "list", "-a", app) or []

    def secret_status(self, app: str) -> dict[str, str]:
        listed = self.json("secrets", "list", "-a", app) or []
        return {s["name"]: s.get("status", "") for s in listed}

    # -- writes ----------------------------------------------------------

    def create_app(self, org: str, app: str) -> None:
        self.run("apps", "create", app, "--org", org)

    def create_volume(self, app: str, name: str, size_gb: int, region: str) -> str:
        vol = self.json(
            "volumes", "create", name, "-a", app, "--size", str(size_gb),
            "--region", region, "--yes",
        )
        return vol["id"]

    def stage_secrets(self, app: str, values: dict[str, str]) -> None:
        body = "".join(f"{k}={v}\n" for k, v in values.items())
        self.run("secrets", "import", "-a", app, "--stage", stdin=body)

    def deploy(self, app: str, config: str, image: str) -> None:
        # --ha=false: Fly's default is two machines on first deploy even at
        # min_machines_running = 0 (Phase 0 spike); the profile is one.
        self.run(
            "deploy", "-a", app, "-c", config, "--image", image, "--ha=false",
            "--strategy", "immediate", "--wait-timeout", "5m", "--yes",
        )

    def destroy_volume(self, app: str, volume_id: str) -> None:
        self.run("volumes", "destroy", volume_id, "-a", app, "--yes")

    def destroy_app(self, app: str) -> None:
        self.run("apps", "destroy", app, "--yes")
