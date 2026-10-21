"""Own the private SQLite lab, fixture preparation and server/audit lifecycle."""

import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

from processes import command, stop_process

HERE = Path(__file__).resolve().parent


def request(url, key=None, body=None, method="GET", expected=200):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["X-API-Key"] = key
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=40) as response:
            if response.status != expected:
                raise RuntimeError("unexpected preflight status")
            raw = response.read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"preflight HTTP {error.code}") from None
    return json.loads(raw) if not url.endswith("/metrics") else raw.decode()


def wait_ready(process, base):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Vectis exited during startup")
        try:
            if request(base + "/healthz/ready").get("status") == "ready":
                return
        except (OSError, ValueError, RuntimeError):
            pass
        time.sleep(.1)
    raise RuntimeError("Vectis readiness deadline exceeded")


def database_sizes(site):
    return {suffix or "db": (site / f"db/data.db{suffix}").stat().st_size
            if (site / f"db/data.db{suffix}").exists() else 0 for suffix in ("", "-wal", "-shm")}


class Laboratory:
    def __init__(self, site, binary, environment, profile):
        self.site = site
        self.binary = binary
        self.profile = profile
        self.environment = environment
        self.server = None
        self.log = None
        self._closed = False
        self._close_result = None
        self.fixture_path = site / "fixtures.json"

    def prepare(self):
        self.site.parent.mkdir(parents=True, exist_ok=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.env = {**self.environment, "K6_SITE_DIR": str(self.site),
                    "K6_BINARY": str(self.binary), "K6_PORT": str(port),
                    "K6_PROFILE": self.profile}
        for script in ("setup.sh", "create-keys.sh", "configure-config.sh"):
            with (self.site.parent / f"{self.site.name}-{script}.log").open("w") as log:
                command(["bash", str(HERE / script)], env=self.env, stdout=log)
        self.fixtures = json.loads(self.fixture_path.read_text())
        if self.fixtures.get("version") != 1:
            raise RuntimeError("unsupported performance fixture version")

    def start(self):
        self.log = (self.site / "logs/runner.log").open("w")
        self.server = subprocess.Popen(["bash", str(HERE / "start-vectis.sh")], env=self.env,
                                       cwd=self.site, stdout=self.log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        wait_ready(self.server, self.fixtures["url"])
        for state in ("startup", "live", "ready"):
            request(self.fixtures["url"] + f"/healthz/{state}")
        # Only the measured profile is provisioned in this laboratory.
        for name in self.fixtures["profiles"]:
            fixture = self.selected(name)
            kid = fixture["kid"]
            public = request(self.fixtures["url"] + f"/pub/{kid}")
            if not all(public.get("keys", {}).get(name) for name in ("eddsa", "xecdh", "ml-dsa", "ml-kem")):
                raise RuntimeError("public key preflight shape mismatch")
            tested = request(self.fixtures["url"] + f"/self-test/keys/{kid}", self.fixtures["apikey"])
            if not all(tested.get(name, {}).get("valid") is True
                       for name in ("symmetric", "eddsa", "xecdh", "ml-dsa", "ml-kem")):
                raise RuntimeError("key preflight failed")
            subject = request(self.fixtures["url"] + f"/subject/{kid}", self.fixtures["apikey"],
                              {"profile": fixture["profiles"]["token"]["stored"],
                               "subject_name": "k6-synthetic-subject"}, method="POST", expected=201)
            fixture["subject"] = subject["subject"]
        self.fixture_path.write_text(json.dumps(self.fixtures, indent=2))
        self.fixture_path.chmod(0o600)

    def selected(self, profile):
        return self.fixtures["profiles"][profile]

    @property
    def pid(self):
        return self.server.pid

    def sizes(self):
        return database_sizes(self.site)

    def check(self):
        if self.server.poll() is not None:
            raise RuntimeError("server exited during measurement")
        metrics = request(self.fixtures["url"] + "/metrics", self.fixtures["apikey"])
        if "vectis_crypto_operation_total" not in metrics:
            raise RuntimeError("final metrics preflight failed")

    def close(self):
        if self._closed:
            return self._close_result
        self._closed = True
        result = {"audit_exit": None, "cleanup_errors": []}
        self._close_result = result
        try:
            stop_process(self.server)
        except (Exception, KeyboardInterrupt):
            result["cleanup_errors"].append("could not stop laboratory server")
        finally:
            if self.log:
                try:
                    self.log.close()
                except (Exception, KeyboardInterrupt):
                    result["cleanup_errors"].append("could not close laboratory log")
        if (self.site / "logs/audit.jsonl").exists():
            try:
                with (self.site / "logs/audit-verify.log").open("w") as audit:
                    result["audit_exit"] = command(
                        [str(self.site / "bin/vectis"), "audit", "verify", "--file", "logs/audit.jsonl"],
                        cwd=self.site, env=self.env, stdout=audit, check=False)
                if result["audit_exit"]:
                    result["cleanup_errors"].append("offline audit verification failed")
            except (Exception, KeyboardInterrupt):
                result["cleanup_errors"].append("offline audit verification could not complete")
        elif self.server is not None:
            result["cleanup_errors"].append("audit log missing")
        return result
