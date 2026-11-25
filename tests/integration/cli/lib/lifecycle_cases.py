import hashlib
import json
from pathlib import Path

from .cli_support import require, run_cli, run_cli_json


def lifecycle_runtime_contracts(env):
    transitions = (
        ("disabled", "retired"),
        ("disabled", "compromised"),
        ("disabled", "destroyed"),
        ("retired", "compromised"),
        ("retired", "destroyed"),
        ("compromised", "destroyed"),
    )
    sign_body = {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(b"lifecycle").hexdigest()}}
    plaintext = {"plaintext": "CLI lifecycle recovery"}
    transitioned_kids = []
    rejected_kids = []

    def update(kid, status):
        reason = f"CLI containment {status}"
        response = run_cli_json(["lifecycle", kid, "--status", status, "--reason", reason], env)
        require(response["kid"] == kid, "lifecycle response KID")
        require(response["lifecycle"]["status"] == status, "lifecycle response status")
        require(response["lifecycle"]["reason"] == reason, "lifecycle response reason")
        require(bool(response["lifecycle"]["changed_at"]), "lifecycle response timestamp")

    def denied(command, status=403, message=None):
        result = run_cli(command, env, expect_success=False)
        require(str(status) in result.stderr, f"CLI must report HTTP {status}")
        if message:
            require(message in result.stderr, "CLI must preserve transition error")

    for current, destination in transitions:
        kid = run_cli_json(["keys", "create", "--tag", f"cli-life-{current}-{destination}",
                            "--profile", "hybrid-performance-v1"], env)["kid"]
        signature = run_cli_json(["sign", kid, "--json", json.dumps(sign_body)], env)
        envelope = run_cli_json(["symmetric", "encrypt", kid, "--json", json.dumps(plaintext)], env)
        decrypt = ["symmetric", "decrypt", "--json", json.dumps(envelope)]
        verify = ["sign", "verify", "--json", json.dumps(signature)]

        def recovery(allowed):
            if allowed:
                require(run_cli_json(decrypt, env) == plaintext, "CLI historical plaintext")
                require(run_cli_json(verify, env)["valid"] == "ok", "CLI historical signature")
            else:
                denied(decrypt)
                denied(verify)

        recovery(True)
        update(kid, current)
        recovery(current == "retired")
        denied(["sign", kid, "--json", json.dumps(sign_body)])
        update(kid, destination)
        recovery(destination == "retired")
        denied(["sign", kid, "--json", json.dumps(sign_body)])
        denied(["symmetric", "encrypt", kid, "--json", json.dumps(plaintext)])
        denied(["pub", kid])
        run_cli(["keys", "reload"], env)
        properties = run_cli_json(["keys", "properties", kid], env)
        require(properties["properties"]["lifecycle"]["status"] == destination, "CLI lifecycle survives reload")
        recovery(destination == "retired")
        transitioned_kids.append(kid)
        print(f"- lifecycle {current} -> {destination}: OK", flush=True)

    forbidden = {
        "active": ("active",),
        "disabled": ("disabled",),
        "retired": ("active", "disabled", "retired"),
        "compromised": ("active", "disabled", "retired", "compromised"),
        "destroyed": ("active", "disabled", "retired", "compromised", "destroyed"),
    }
    for current, destinations in forbidden.items():
        kid = run_cli_json(["keys", "create", "--tag", f"cli-life-forbidden-{current}",
                            "--profile", "hybrid-performance-v1"], env)["kid"]
        if current != "active":
            update(kid, current)
        for destination in destinations:
            denied(["lifecycle", kid, "--status", destination, "--reason", "forbidden"], 400,
                   f"invalid lifecycle transition: {current} -> {destination}")
        rejected_kids.append((kid, len(destinations)))

    records = [json.loads(line) for line in (Path(env["VECTIS_LOG_DIR"]) / "audit.log").read_text(encoding="utf-8").splitlines()]
    for kid in transitioned_kids:
        changes = [r for r in records if r.get("event") == "key.lifecycle.changed" and r.get("kid") == kid]
        require(len(changes) == 2, "each containment scenario must audit both lifecycle changes")
        require(all(r["outcome"] == "success" and r["action"] == "lifecycle" for r in changes),
                "lifecycle audit event contract")
    for kid, count in rejected_kids:
        failures = [r for r in records if r.get("event") == "key.lifecycle.failed" and r.get("kid") == kid]
        require(len(failures) == count, "each rejected transition must be audited")
