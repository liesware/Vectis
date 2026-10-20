"""Private, disposable SQLite process lifecycle for the manual walkthrough."""

import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request

from happy_transport import require

ROOT = Path(__file__).resolve().parents[2]
KEY_ACTIONS = [
    "keys", "lifecycle", "self-test", "sign", "symmetric", "fpe-encrypt", "fpe-decrypt",
    "token-encode", "token-decode", "token-delete", "token-deterministic-encode",
    "token-deterministic-decode", "subject-create", "subject-delete", "mac-create",
    "mac-verify", "index-create", "index-verify", "mask", "commit-create",
    "commit-verify", "share-split", "share-combine",
]


def configuration(kid, api_hash):
    context = "tenant=manual;purpose=happy-path;version=v1"
    config = {
        "version": "v1", "routes": [], "remote_routes": [],
        "permissions": [{"client": "manual", "apikey_hash": api_hash, "status": "active",
                         "permissions": [{"kid": kid, "actions": KEY_ACTIONS},
                                         {"kid": "*", "actions": ["time-attest"]}]}],
        "fpe_profiles": [], "tokenization_profiles": [], "deterministic_tokenization_profiles": [],
        "mac_profiles": [{"name": "manual-mac", "kid": kid, "context": context}],
        "masking_profiles": [{"name": "manual-mask", "kid": kid, "visible_first": 0,
                              "visible_last": 4, "mask_char": "*", "min_len": 6, "max_len": 32}],
        "commitment_profiles": [{"name": "manual-commit", "kid": kid, "context": context,
                                 "max_plaintext_len": 128, "opening_len": 32}],
        "sharing_profiles": [{"name": "manual-share", "kid": kid, "context": context,
                              "threshold": 3, "shares": 5, "max_secret_len": 128}],
    }
    for mode in ("none", "stored"):
        common = {"name": f"manual-fpe-{mode}", "kid": kid, "subject_mode": mode,
                  "fpe_version": "fpe-ff1-2025", "alphabet_preset": "num",
                  "preserve_characters": "-", "authenticated": True,
                  "min_len": 6, "max_len": 32, "tweak_aad": context}
        config["fpe_profiles"].append(common)
        config["tokenization_profiles"].append({
            "name": f"manual-token-{mode}", "kid": kid, "subject_mode": mode,
            "token_prefix": "manual", "token_len": 32, "max_plaintext_len": 128, "one_time": False})
        config["deterministic_tokenization_profiles"].append({
            "name": f"manual-det-{mode}", "kid": kid, "subject_mode": mode,
            "context": context, "min_plaintext_len": 1, "max_plaintext_len": 128})
    return config


class Laboratory:
    def __init__(self, binary, out, keep=False):
        self.binary = Path(binary).resolve()
        self.out = out
        self.keep = keep
        self.process = None
        self.log = None
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("VECTIS_")}
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.path = Path(tempfile.mkdtemp(prefix="vectis-happy-"))
        self.path.chmod(0o700)
        self.url = f"http://127.0.0.1:{port}"
        self.env.update({
            "VECTIS_HTTP_BIND_ADDR": f"127.0.0.1:{port}",
            "VECTIS_PUBLIC_ADDR": f"127.0.0.1:{port}", "VECTIS_MODE": "dev",
            "VECTIS_STORAGE": "sqlite", "VECTIS_SQLITE_PATH": str(self.path / "vectis.db"),
            "VECTIS_CONFIG_PATH": str(self.path / "config.json"),
            "VECTIS_CONFIG_SIGN_PATH": str(self.path / "config_sign.json"),
            "VECTIS_INIT_KEYS_FILE": str(self.path / "init.json"),
            "VECTIS_INIT_PUBLIC_KEYS_FILE": str(self.path / "init_pub.json"),
            "VECTIS_UNSEAL_KEY_FILE": str(self.path / ".unseal_key"),
            "VECTIS_METRICS_ENABLED": "true", "VECTIS_LOG_TARGET": "file",
            "VECTIS_MAX_CONCURRENT_CRYPTO": "2",
        })

    def command(self, *args):
        result = subprocess.run([str(self.binary), *args], cwd=self.path, env=self.env,
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            # Init output can contain secrets even on failure; never echo it.
            details = "output suppressed for init" if args == ("init",) else self.out.redact(result.stderr + result.stdout)
            with (self.path / "command.log").open("a") as log:
                log.write(f"vectis {' '.join(args)}: exit {result.returncode}\n{details}\n")
            raise RuntimeError(f"vectis {' '.join(args)} failed (exit {result.returncode}); see command.log")
        return result.stdout

    def initialize(self):
        with sqlite3.connect(self.path / "vectis.db") as connection:
            connection.executescript((ROOT / "src/db/sqlite_schema.sql").read_text())
        output = self.command("init")
        credentials = dict(line.split("=", 1) for line in output.splitlines()
                           if line.startswith(("VECTIS_UNSEAL_KEY=", "VECTIS_APIKEY=", "VECTIS_APIKEY_HASH=")))
        require(len(credentials) == 3, "init did not produce required credentials")
        self.out.secrets.extend(credentials.values())
        self.api_key = credentials["VECTIS_APIKEY"]
        self.api_hash = credentials["VECTIS_APIKEY_HASH"]
        self.env.update(credentials)
        (self.path / ".unseal_key").write_text(credentials["VECTIS_UNSEAL_KEY"])
        (self.path / ".unseal_key").chmod(0o600)
        self.write_config({"version": "v1", "routes": [], "remote_routes": [], "permissions": []})

    def write_config(self, value):
        (self.path / "config.json").write_text(json.dumps(value, indent=2))
        self.command("config", "sign")

    def start(self):
        require(self.process is None, "server already running")
        self.log = (self.path / "server.log").open("a")
        self.process = subprocess.Popen([str(self.binary), "serve"], cwd=self.path,
                                        env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            require(self.process.poll() is None, "Vectis exited during startup; see server.log")
            try:
                with opener.open(self.url + "/healthz/ready", timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("Vectis readiness deadline exceeded; see server.log")

    def stop(self):
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=35)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait()
        finally:
            self.process = None
            if self.log is not None:
                self.log.close()
                self.log = None

    def close(self, success):
        self.stop()
        if not success or self.keep:
            self.out.write(f"\nLaboratory retained: {self.path}\nServer log: {self.path / 'server.log'}")
        else:
            shutil.rmtree(self.path)
