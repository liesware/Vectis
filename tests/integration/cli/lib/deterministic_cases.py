"""Deterministic token CLI configuration and single/batch contracts."""
import json
from pathlib import Path

from .cli_support import require, run_cli, run_cli_json


def deterministic_runtime_contracts(env, directory):
    kid = run_cli_json(["keys", "create", "--tag", "cli-deterministic", "--profile", "hybrid-performance-v1"], env)["kid"]
    profile = "cli-deterministic-v1"
    config = Path(env["VECTIS_CONFIG_PATH"])
    flags = ["--name", profile, "--kid", kid, "--context", "tenant=cli;field=email;version=1",
             "--min-plaintext-len", "1", "--max-plaintext-len", "16384"]
    run_cli(["config", "token-deterministic", "add", *flags], env)
    definition = run_cli_json(["config", "token-deterministic", "get", profile], env)
    require(definition["context"] == "tenant=cli;field=email;version=1", "signed context preserved")
    for invalid in [["--min-plaintext-len", "0"], ["--max-plaintext-len", "16385"],
                    ["--context", "invalid"], ["--subject-mode", "optional"],
                    ["--subject-mode", "none", "--subject-mode", "stored"],
                    ["--context", "tenant=a", "--context", "tenant=b"]]:
        before = config.read_bytes()
        run_cli(["config", "token-deterministic", "update", profile, *invalid], env, expect_success=False)
        require(config.read_bytes() == before, "invalid deterministic edit cannot write config")
    stored_profile = profile + "-stored"
    stored_flags = list(flags)
    stored_flags[1] = stored_profile
    run_cli(["config", "token-deterministic", "add", *stored_flags, "--subject-mode", "stored"], env)
    run_cli(["config", "token-deterministic", "update", stored_profile, "--max-plaintext-len", "16384"], env)
    require(run_cli_json(["config", "token-deterministic", "get", stored_profile], env)["subject_mode"] == "stored", "omitted flag preserves mode")
    run_cli(["config", "token-deterministic", "update", stored_profile, "--subject-mode", "none"], env)
    require("subject_mode" not in run_cli_json(["config", "token-deterministic", "get", stored_profile], env), "none removes field")
    run_cli(["config", "token-deterministic", "update", stored_profile, "--subject-mode", "stored"], env)
    require("subject_mode" not in definition, "default none is omitted")
    run_cli(["config", "token", "add", "--name", "cli-det-origin", "--kid", kid,
             "--token-prefix", "cli_origin", "--token-len", "32", "--max-plaintext-len", "128",
             "--one-time", "false", "--subject-mode", "stored"], env)
    run_cli(["config", "sign"], env)
    run_cli(["config", "reload"], env)
    subject = run_cli_json(["subject", "create", kid, "--json", json.dumps({"profile": "cli-det-origin", "subject_name": "cli-user"})], env)["subject"]
    for route in [[], ["--subject", subject]]:
        selected_profile = stored_profile if route else profile
        scope = {"subject": subject} if route else {}
        body = {"ref": "r", "profile": selected_profile, "plaintext": "synthetic \u00e9\U0001f600"}
        encoded = run_cli_json(["token", "deterministic", "encode", kid, *route, "--json", json.dumps(body)], env)
        require(run_cli_json(["token", "deterministic", "encode", kid, *route, "--json", json.dumps(dict(body, ref="other"))], env)["token"] == encoded["token"], "CLI deterministic output")
        inverse = {"ref": "d", "kid": kid, "profile": selected_profile, "token": encoded["token"], **scope}
        source = Path(directory) / "deterministic.json"
        source.write_text(json.dumps(inverse), encoding="utf-8")
        require(run_cli_json(["token", "deterministic", "decode", "--file", str(source)], env)["plaintext"] == body["plaintext"], "CLI file decode")
        require("plaintext:" in run_cli(["token", "deterministic", "decode", "--file", str(source), "--output", "yaml"], env).stdout, "CLI YAML output")
        batch = {"profile": selected_profile, "items": [{"ref": "a", "plaintext": "first"}, {"ref": "b", "plaintext": "second"}]}
        source.write_text(json.dumps(batch), encoding="utf-8")
        output = run_cli_json(["token", "deterministic", "encode-batch", kid, *route, "--file", str(source)], env)
        inverse = {"kid": kid, "profile": selected_profile, "items": output["items"], **scope}
        result = run_cli_json(["token", "deterministic", "decode-batch", "--json", json.dumps(inverse)], env)
        require([i["plaintext"] for i in result["items"]] == ["first", "second"], "CLI batch order")
        wrong_route = [] if route else ["--subject", subject]
        for command, payload in [("encode", body), ("encode-batch", batch)]:
            run_cli(["token", "deterministic", command, kid, *wrong_route, "--json", json.dumps(payload)], env, expect_success=False)
        for command, payload in [("decode", {"ref": "d", "kid": kid, "profile": selected_profile, "token": encoded["token"]}),
                                 ("decode-batch", {"kid": kid, "profile": selected_profile, "items": output["items"]})]:
            if not route:
                payload["subject"] = subject
            run_cli(["token", "deterministic", command, "--json", json.dumps(payload)], env, expect_success=False)
    require("AES-256-SIV" in run_cli(["token", "deterministic", "--help"], env).stdout, "deterministic help")
    run_cli(["token", "deterministic", "delete", "--json", "{}"], env, expect_success=False)
    run_cli(["config", "token-deterministic", "delete", profile], env)
    run_cli(["config", "token-deterministic", "delete", stored_profile], env)
