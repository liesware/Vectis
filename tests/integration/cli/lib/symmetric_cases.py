"""Symmetric CLI and retired HTTP interface contracts on the suite's isolated node."""

import json
import urllib.error
import urllib.request
from pathlib import Path

from .cli_support import require, run_cli, run_cli_json, write_config


def symmetric_runtime_contracts(env, configuration, directory):
    kid = run_cli_json(["keys", "create", "--tag", "cli-symmetric", "--profile", "hybrid-performance-v1"], env)["kid"]
    credentials = {}
    for action in ["message", "symmetric"]:
        key = run_cli_json(["apikey", "create"], env)
        credentials[action] = dict(env, VECTIS_APIKEY=key["VECTIS_APIKEY"])
        configuration["permissions"].append({"client": f"cli-{action}", "apikey_hash": key["VECTIS_APIKEY_HASH"],
            "status": "active", "permissions": [{"kid": kid, "actions": [action]}]})
    write_config(env, configuration)
    run_cli(["config", "sign"], env)
    run_cli(["config", "reload"], env)
    plaintext = {"plaintext": "synthetic symmetric data"}
    source = Path(directory) / "symmetric-input.json"
    envelope_file = Path(directory) / "symmetric-envelope.json"
    source.write_text(json.dumps(plaintext), encoding="utf-8")
    envelope = run_cli_json(["symmetric", "encrypt", kid, "--file", str(source)], credentials["symmetric"])
    require(envelope["kid"] == kid and "type=internal-message;" in envelope["message"]["aad"], "unchanged envelope and AAD")
    envelope_file.write_text(json.dumps(envelope), encoding="utf-8")
    require(run_cli_json(["symmetric", "decrypt", "--file", str(envelope_file)], credentials["symmetric"]) == plaintext,
            "symmetric file round trip")
    encoded = run_cli_json(["symmetric", "encrypt", kid, "--json", json.dumps(plaintext)], credentials["symmetric"])
    require(run_cli_json(["symmetric", "decrypt", "--json", json.dumps(encoded)], credentials["symmetric"]) == plaintext,
            "symmetric JSON round trip")
    yaml = run_cli(["symmetric", "decrypt", "--file", str(envelope_file), "--output", "yaml"], credentials["symmetric"])
    require("plaintext: synthetic symmetric data" in yaml.stdout, "symmetric YAML output")
    for operation in [["encrypt", kid, "--json", json.dumps(plaintext)], ["decrypt", "--file", str(envelope_file)]]:
        denied = run_cli(["symmetric", *operation], credentials["message"], expect_success=False)
        require("403" in denied.stderr, "message grant cannot authorize symmetric")
        invalid = run_cli(["symmetric", *operation], dict(env, VECTIS_APIKEY="0" * 64), expect_success=False)
        require("401" in invalid.stderr, "symmetric rejects invalid credentials")
    require("403" in run_cli(["message", "send", kid, "--json", json.dumps({"recipient_kid": kid, "message": "synthetic"})],
                              credentials["symmetric"], expect_success=False).stderr, "symmetric grant cannot authorize messaging")
    for args in [["message", "internal", "encrypt", kid, "--file", str(source)],
                 ["message", "internal", "decrypt", "--file", str(envelope_file)]]:
        result = run_cli(args, dict(env, VECTIS_API_URL="http://127.0.0.1:1"), expect_success=False)
        require("unknown message command: internal" in result.stderr, "retired CLI fails before contacting a server")
    for path, body in [(f"/message/internal/encrypt/{kid}", plaintext), ("/message/internal/decrypt", envelope)]:
        request = urllib.request.Request(env["VECTIS_API_URL"] + path, data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json", "X-API-Key": env["VECTIS_APIKEY"]})
        try:
            with urllib.request.urlopen(request, timeout=10):
                raise AssertionError("retired HTTP route must not succeed")
        except urllib.error.HTTPError as error:
            require(error.code == 404, "retired HTTP route returns 404")
    require("symmetric" in run_cli(["--help"], env).stdout, "root help advertises symmetric")
    require("vectis symmetric encrypt" in run_cli(["symmetric", "--help"], env).stdout, "symmetric help is available")
    require("internal" not in run_cli(["message", "--help"], env).stdout, "message help retires internal")
    for args in [["symmetric", "decrypt", kid, "--file", str(envelope_file)],
                 ["symmetric", "encrypt", kid, "--json", json.dumps(plaintext), "--file", str(source)]]:
        run_cli(args, env, expect_success=False)
    configuration["tokenization_profiles"].append({
        "name": "cli-symmetric-subject", "kid": kid, "token_prefix": "cli_sym_seed",
        "token_len": 32, "max_plaintext_len": 128, "one_time": False, "subject_mode": "stored",
    })
    write_config(env, configuration)
    run_cli(["config", "sign"], env)
    run_cli(["config", "reload"], env)
    create = {"profile": "cli-symmetric-subject", "subject_name": "synthetic-person"}
    subject = run_cli_json(["subject", "create", kid, "--json", json.dumps(create)], env)["subject"]
    subject_envelope = run_cli_json(["symmetric", "encrypt", kid, "--subject", subject, "--file", str(source)], credentials["symmetric"])
    require(subject_envelope["subject"] == subject, "subject included in symmetric envelope")
    require(run_cli_json(["symmetric", "decrypt", "--json", json.dumps(subject_envelope)], credentials["symmetric"]) == plaintext,
            "symmetric subject JSON round trip")
    envelope_file.write_text(json.dumps(subject_envelope), encoding="utf-8")
    require("plaintext: synthetic symmetric data" in run_cli(["symmetric", "decrypt", "--file", str(envelope_file), "--output", "yaml"], credentials["symmetric"]).stdout,
            "subject symmetric file/YAML round trip")
    for args in [["symmetric", "encrypt", kid, "--subject", subject.upper(), "--file", str(source)],
                 ["symmetric", "encrypt", kid, "--subject", subject, "--subject", subject, "--file", str(source)],
                 ["symmetric", "decrypt", "--subject", subject, "--file", str(envelope_file)]]:
        run_cli(args, credentials["symmetric"], expect_success=False)
    run_cli(["subject", "delete", kid, subject], env)
    require("404" in run_cli(["symmetric", "decrypt", "--file", str(envelope_file)], credentials["symmetric"], expect_success=False).stderr,
            "deleted subject blocks symmetric")
    run_cli_json(["subject", "create", kid, "--json", json.dumps(create)], env)
    require("message authentication failed" in run_cli(["symmetric", "decrypt", "--file", str(envelope_file)], credentials["symmetric"], expect_success=False).stderr,
            "recreated subject cannot recover old envelope")
    envelope_file.write_text(json.dumps(envelope), encoding="utf-8")
    run_cli(["lifecycle", kid, "--status", "retired", "--reason", "symmetric test"], env)
    require(run_cli_json(["symmetric", "decrypt", "--file", str(envelope_file)], env) == plaintext, "retired key decrypts")
    require("403" in run_cli(["symmetric", "encrypt", kid, "--file", str(source)], env, expect_success=False).stderr,
            "retired key cannot encrypt")
