"""Per-process state explicitly shared by ordered HTTP cases."""

from dataclasses import dataclass, field

from .client import Client, StatusClient, WorkflowError
from .config import (
    CONFIG_SECTIONS,
    ConfigTransaction,
    new_config_state,
    write_config_file,
)
from .fixtures import Fixtures


@dataclass
class HttpTestContext:
    base_url: str
    apikey: str
    final_app_addr: str | None = None
    client: Client = field(init=False)
    config: ConfigTransaction = field(default_factory=ConfigTransaction)
    config_data: dict = field(default_factory=new_config_state)
    artifacts: dict = field(default_factory=dict)
    fixtures: Fixtures = field(default_factory=Fixtures)
    current_case: str | None = None
    final_app: object | None = None
    _http: StatusClient | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        self.client = Client(self.base_url, self.apikey)
        self.config.capture()

    # --- Ergonomic surface for decorator-style cases (ctx.*) -----------------
    @property
    def http(self) -> StatusClient:
        """Status-preserving client for negative contract checks (keeps 4xx/5xx)."""
        if self._http is None:
            self._http = StatusClient(self.base_url, self.apikey)
        return self._http

    def post(self, path, body, auth=True):
        return self.http.post(path, body, auth=auth)

    def get(self, path, auth=False):
        return self.http.get(path, auth=auth)

    def require(self, condition, message):
        if not condition:
            raise WorkflowError(message)

    def expect(self, actual, expected, label="request"):
        self.require(
            actual == expected,
            f"{label} expected HTTP {expected}, got HTTP {actual}",
        )

    # --- Explicit config surface (replaces the former global `config`) --------
    def write_config(self, sign=True):
        write_config_file(self.config_data, sign=sign)

    def write_unsigned_config(self):
        write_config_file(self.config_data, sign=False)

    def _isolate_section(self, section, value, sign=True):
        # Put bad/valid data in exactly one section and clear the rest, so the
        # unified reload validates the section under test in isolation.
        for name in CONFIG_SECTIONS:
            self.config_data[name] = []
        self.config_data[section] = value
        self.write_config(sign=sign)

    def set_permissions(self, clients, sign=True):
        self._isolate_section("permissions", clients, sign=sign)

    def set_routes(self, routes, sign=True):
        self._isolate_section("routes", routes, sign=sign)

    def set_remote_routes(self, routes, sign=True):
        self._isolate_section("remote_routes", routes, sign=sign)

    def only_fpe_profiles(self, profiles, sign=True):
        self._isolate_section("fpe_profiles", profiles, sign=sign)

    def only_tokenization_profiles(self, profiles, sign=True):
        self._isolate_section("tokenization_profiles", profiles, sign=sign)

    def only_mac_profiles(self, profiles, sign=True):
        self._isolate_section("mac_profiles", profiles, sign=sign)

    def only_masking_profiles(self, profiles, sign=True):
        self._isolate_section("masking_profiles", profiles, sign=sign)

    def reload_config(self):
        status, response = self.http.post("/config/reload", {}, auth=True)
        self.expect(status, 200, "POST /config/reload")
        self.require(response.get("status") == "reloaded", "config reload status must be reloaded")
        for key in (f"{section}_loaded" for section in ("routes", "remote_routes")):
            self.require(isinstance(response.get(key), int), f"config {key} must be int")
        self.require(isinstance(response.get("clients_loaded"), int), "config clients_loaded must be int")
        for section in CONFIG_SECTIONS:
            if section in ("routes", "remote_routes", "permissions"):
                continue
            self.require(
                isinstance(response.get(f"{section}_loaded"), int),
                f"config {section}_loaded must be int",
            )
        return response

    def cleanup(self):
        cleanup_error = None
        if self.final_app is not None:
            self.final_app.shutdown()
            self.final_app.server_close()
            self.final_app = None
        try:
            self.config.restore_runtime(self.base_url, self.apikey)
        except Exception as err:
            cleanup_error = err
        finally:
            self.config.close()
        if cleanup_error is not None:
            raise cleanup_error
