"""CLI runtime token/subject coverage against an independently provisioned server."""

import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .cli_support import ROOT, isolated_env, run_cli, run_cli_json, require, write_config, empty_config


def token_subject_runtime_case():
    with tempfile.TemporaryDirectory(prefix="vectis-cli-subject-") as directory:
        env = isolated_env(directory)
        with socket.socket() as socket_handle:
            socket_handle.bind(("127.0.0.1", 0))
            port = socket_handle.getsockname()[1]
        env.update(VECTIS_MODE="dev", VECTIS_HTTP_BIND_ADDR=f"127.0.0.1:{port}",
                   VECTIS_API_URL=f"http://127.0.0.1:{port}", VECTIS_LOG_DIR=str(Path(directory) / "log"),
                   VECTIS_CRYPTO_POLICY="profile-only")
        initialized = run_cli(["init"], env)
        for line in initialized.stdout.splitlines():
            if line.startswith("VECTIS_") and "=" in line:
                key, value = line.split("=", 1)
                env[key] = value
        configuration = empty_config()
        write_config(env, configuration)
        run_cli(["config", "sign"], env)
        from support.vectis import vectis_command
        with (Path(directory) / "server.log").open("w") as log:
            server = subprocess.Popen(vectis_command(["serve"], env=env, quiet=True), cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True)
            try:
                for _ in range(60):
                    if server.poll() is not None:
                        raise RuntimeError("isolated CLI server exited before readiness")
                    ready = subprocess.run(
                        vectis_command(["health", "ready", "--output", "json"], env=env, quiet=True),
                        cwd=ROOT, env=env, capture_output=True, text=True)
                    if ready.returncode == 0:
                        break
                    time.sleep(.2)
                else:
                    raise RuntimeError("isolated CLI server readiness timed out")
                _runtime_contracts(env, configuration, directory)
            finally:
                if server.poll() is None:
                    os.killpg(server.pid, signal.SIGINT)
                try:
                    server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid, signal.SIGKILL)
                    server.wait()


def _runtime_contracts(env, configuration, directory):
    kid = run_cli_json(["keys", "create", "--tag", "cli-subject", "--profile", "hybrid-performance-v1"], env)["kid"]
    credentials = {}
    for action in ["subject-create", "subject-delete", "token-delete"]:
        key = run_cli_json(["apikey", "create"], env)
        credentials[action] = dict(env, VECTIS_APIKEY=key["VECTIS_APIKEY"])
        configuration["permissions"].append({"client": action, "apikey_hash": key["VECTIS_APIKEY_HASH"],
            "status": "active", "permissions": [{"kid": kid, "actions": [action]}]})
    for mode in ["none", "stored"]:
        configuration["tokenization_profiles"].append({"name": f"cli-{mode}", "kid": kid,
            "token_prefix": "cli_token", "token_len": 32, "max_plaintext_len": 128,
            "one_time": False, "subject_mode": mode})
    write_config(env, configuration)
    run_cli(["config", "sign"], env)
    run_cli(["config", "reload"], env)
    source = Path(directory) / "request.json"

    def json_command(command, body, credential=env, file=False):
        if file:
            source.write_text(json.dumps(body), encoding="utf-8")
            options = ["--file", str(source)]
        else:
            options = ["--json", json.dumps(body)]
        return run_cli_json([*command, *options], credential)

    create_body = {"profile": "cli-stored", "subject_name": "synthetic-person"}
    created = json_command(["subject", "create", kid], create_body, credentials["subject-create"], file=True)
    subject = created["subject"]
    require(created["kid"] == kid, "subject create returns the requested KID")
    for mode in ["none", "stored"]:
        profile = f"cli-{mode}"
        route = ["--subject", subject] if mode == "stored" else []
        scope = {"subject": subject} if route else {}
        encoded = json_command(["token", "encode", kid, *route], {"ref": "single", "profile": profile, "plaintext": "synthetic"})
        decode = {"ref": "single", "kid": kid, "profile": profile, "token": encoded["token"], **scope}
        require(json_command(["token", "decode"], decode, file=True)["plaintext"] == "synthetic", "single decode round-trip")
        yaml_output = run_cli(["token", "decode", "--json", json.dumps(decode), "--output", "yaml"], env)
        require("plaintext: synthetic" in yaml_output.stdout, "YAML output remains available")
        denied = run_cli(["token", "delete", "--json", json.dumps(decode)], credentials["subject-create"], expect_success=False)
        require("403" in denied.stderr, "subject-create does not grant token-delete")
        invalid = run_cli(["token", "delete", "--json", json.dumps(decode)], dict(env, VECTIS_APIKEY="0" * 64), expect_success=False)
        require("401" in invalid.stderr, "invalid API key is rejected")
        require(json_command(["token", "delete"], decode, credentials["token-delete"])["deleted"] is True, "token-delete grant works independently")
        require("404" in run_cli(["token", "decode", "--json", json.dumps(decode)], env, expect_success=False).stderr, "deleted token is unavailable")
        encoded_batch = json_command(["token", "encode-batch", kid, *route], {"profile": profile, "items": [
            {"ref": "a", "plaintext": "first"}, {"ref": "b", "plaintext": "second"}]}, file=True)
        batch = {"kid": kid, "profile": profile, "items": [{"ref": item["ref"], "token": item["token"]} for item in encoded_batch["items"]], **scope}
        output = json_command(["token", "decode-batch"], batch)
        require([(item["ref"], item["plaintext"]) for item in output["items"]] == [("a", "first"), ("b", "second")], "batch round-trip order")
        if mode == "stored":
            stored_batch = batch
    denied = run_cli(["subject", "delete", kid, subject], credentials["subject-create"], expect_success=False)
    require("403" in denied.stderr, "subject-create does not grant subject-delete")
    deleted = run_cli(["subject", "delete", kid, subject, "--output", "json"], credentials["subject-delete"])
    require(deleted.stdout == "", "204 must leave stdout empty")
    require("404" in run_cli(["subject", "delete", kid, subject], env, expect_success=False).stderr, "second subject delete fails")
    require("404" in run_cli(["token", "decode-batch", "--json", json.dumps(stored_batch)], env, expect_success=False).stderr, "deleted subject prevents recovery")
