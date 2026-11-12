"""db_setup runs from the verified image with the owner URL passed by name,
never on argv (RC1-640)."""

import subprocess

from kit.install.esp_image import EspImage

OWNER = "postgresql://owner:hunter2-secret@localhost:5432/esp"
REF = "ghcr.io/snacksnack/esp-migration-agent@sha256:" + "a" * 64


def test_owner_url_travels_by_name_and_localhost_is_mapped():
    seen = {}

    def runner(args, env):
        seen["args"], seen["env"] = args, env
        return subprocess.CompletedProcess(args, 0, '{"version": 1, "compatible_with": 1}\n', "")

    assert EspImage(REF, OWNER, runner).schema_marker() == (1, 1)
    assert "hunter2-secret" not in " ".join(seen["args"])
    assert "ESP_DATABASE_OWNER_URL" in seen["args"]
    assert REF in seen["args"] and "--platform" in seen["args"]
    assert seen["env"]["ESP_DATABASE_OWNER_URL"].endswith("@host.docker.internal:5432/esp")


def test_unmigrated_database_has_no_marker():
    def runner(args, env):
        return subprocess.CompletedProcess(args, 0, "null\n", "")
    assert EspImage(REF, OWNER, runner).schema_marker() is None
