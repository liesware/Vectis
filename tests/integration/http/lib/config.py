"""Configuration snapshots and deterministic cleanup for HTTP suites."""

import atexit
import copy
import json
import subprocess
from pathlib import Path

from .client import StatusClient, WorkflowError

CONFIG_PATH = Path("config.json")
CONFIG_SIGN_PATH = Path("config_sign.json")

# The nine config sections a negative case isolates when it puts deliberately bad
# data in one of them (the unified reload validates every section at once).
CONFIG_SECTIONS = (
    "routes",
    "remote_routes",
    "permissions",
    "fpe_profiles",
    "tokenization_profiles",
    "mac_profiles",
    "masking_profiles",
    "commitment_profiles",
    "sharing_profiles",
)


def sign_config():
    result = subprocess.run(
        ["cargo", "run", "--", "config", "sign", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise WorkflowError(
            f"vectis config sign failed: stdout={result.stdout} stderr={result.stderr}"
        )


def write_config_file(config_data, sign=True):
    CONFIG_PATH.write_text(json.dumps(config_data, indent=2), encoding="utf-8")
    if sign:
        sign_config()


DEFAULT_CONFIG = {
    "version": "v1",
    "routes": [],
    "remote_routes": [],
    "permissions": [],
    "fpe_profiles": [],
    "tokenization_profiles": [],
    "mac_profiles": [],
    "masking_profiles": [],
    "commitment_profiles": [],
    "sharing_profiles": [],
}


def new_config_state():
    return copy.deepcopy(DEFAULT_CONFIG)


class ConfigTransaction:
    def __init__(self, config_path=Path("config.json"), sign_path=Path("config_sign.json")):
        self.config_path = config_path
        self.sign_path = sign_path
        self._config_snapshot = None
        self._sign_snapshot = None
        self._captured = False
        self._closed = False

    @staticmethod
    def _read(path):
        return path.read_text(encoding="utf-8") if path.exists() else None

    @staticmethod
    def _restore(path, value):
        if value is None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        else:
            path.write_text(value, encoding="utf-8")

    def capture(self):
        if self._captured:
            return
        self._config_snapshot = self._read(self.config_path)
        self._sign_snapshot = self._read(self.sign_path)
        self._captured = True
        atexit.register(self.restore_files)

    def restore_files(self):
        if not self._captured or self._closed:
            return
        try:
            self._restore(self.config_path, self._config_snapshot)
            self._restore(self.sign_path, self._sign_snapshot)
        except FileNotFoundError:
            # A temporary test directory may legitimately be gone during atexit.
            return

    def restore_runtime(self, base_url, apikey):
        self.restore_files()
        status, body = StatusClient(base_url, apikey).post("/config/reload", {}, auth=True)
        if status != 200:
            raise WorkflowError(f"restored config reload failed with {status}: {body}")

    def close(self):
        self._closed = True
        atexit.unregister(self.restore_files)
