"""Signed FPE format edits and runtime round trips on an isolated CLI node."""
import json
from pathlib import Path

from .cli_support import require, run_cli, run_cli_json


def fpe_runtime_contracts(env, directory):
    kid = run_cli_json(["keys", "create", "--tag", "cli-fpe", "--profile", "hybrid-performance-v1"], env)["kid"]
    config = Path(env["VECTIS_CONFIG_PATH"])
    common = ["--kid", kid, "--min-len", "6", "--max-len", "32", "--tweak-aad", "tenant=cli;field=fpe;version=1"]
    for literal in ["num", "alpha", "alphanum"]:
        before = config.read_bytes()
        error = run_cli(["config", "fpe", "add", "--name", "literal-fpe", *common, "--alphabet", literal], env, expect_success=False)
        require(f'alphabet_preset: "{literal}"' in error.stderr, "literal preset confusion has an actionable hint")
        if literal != "num":
            require("duplicate characters" in error.stderr and "letter_case" in error.stderr, "duplicate reason and required case are retained")
        require(config.read_bytes() == before, "hinted failure does not write config")
    run_cli(["config", "fpe", "add", "--name", "literal-num-cli", "--kid", kid, "--alphabet", "num",
             "--min-len", "13", "--max-len", "32", "--tweak-aad", "tenant=cli;field=literal;version=1"], env)
    for selector in [[], ["--alphabet-preset", "alpha"], ["--alphabet-preset", "num", "--letter-case", "mixed"],
                     ["--alphabet", "0123456789", "--alphabet-preset", "num"], ["--alphabet-preset", "NUM"],
                     ["--alphabet-preset", "num", "--preserve-characters", "00"],
                     ["--alphabet-preset", "num", "--preserve-characters", "0"]]:
        before = config.read_bytes()
        run_cli(["config", "fpe", "add", "--name", "invalid-fpe", *common, *selector], env, expect_success=False)
        require(config.read_bytes() == before, "invalid FPE add does not write")
    run_cli(["config", "fpe", "add", "--name", "formatted-cli", *common,
             "--alphabet-preset", "num", "--preserve-characters", "-"], env)
    definition = run_cli_json(["config", "fpe", "get", "formatted-cli"], env)
    # The editor wraps the stored definition in the section response.
    definition = definition.get("item", definition)
    require(definition["alphabet_preset"] == "num" and "alphabet" not in definition, "preset stays declared as a preset")
    run_cli(["config", "sign"], env)
    run_cli(["config", "reload"], env)
    literal_input = {"ref": "literal", "profile": "literal-num-cli", "plaintext": "num" * 4 + "n"}
    literal = run_cli_json(["fpe", "encrypt", kid, "--json", json.dumps(literal_input)], env)
    require(set(literal["ciphertext"]) <= set("num"), "valid literal alphabet is not converted to digits")
    literal_inverse = {"ref": "literal", "profile": "literal-num-cli", "kid": kid, "ciphertext": literal["ciphertext"]}
    require(run_cli_json(["fpe", "decrypt", "--json", json.dumps(literal_inverse)], env)["plaintext"] == literal_input["plaintext"], "literal num round trip")
    request = Path(directory) / "formatted-fpe.json"
    request.write_text(json.dumps({"ref": "formatted", "profile": "formatted-cli", "plaintext": "001-234-567"}), encoding="utf-8")
    encrypted = run_cli_json(["fpe", "encrypt", kid, "--file", str(request)], env)
    require(encrypted["ciphertext"][3] == "-" and encrypted["ciphertext"][7] == "-", "CLI preserves separator positions")
    inverse = {"ref": "formatted", "profile": "formatted-cli", "kid": kid, "ciphertext": encrypted["ciphertext"]}
    require(run_cli_json(["fpe", "decrypt", "--json", json.dumps(inverse)], env)["plaintext"] == "001-234-567", "CLI exact formatted round trip")
    for flags in [["--alphabet-preset", "alpha"], ["--letter-case", "uppercase"], ["--preserve-characters", "0"]]:
        before = config.read_bytes()
        run_cli(["config", "fpe", "update", "formatted-cli", *flags], env, expect_success=False)
        require(config.read_bytes() == before, "invalid FPE update does not write")
    run_cli(["config", "fpe", "update", "formatted-cli", "--alphabet-preset", "alpha", "--letter-case", "mixed"], env)
    run_cli(["config", "fpe", "update", "formatted-cli", "--alphabet-preset", "alphanum"], env)
    item = run_cli_json(["config", "fpe", "get", "formatted-cli"], env)
    require(item["letter_case"] == "mixed", "letter case inherited for compatible presets")
    run_cli(["config", "fpe", "update", "formatted-cli", "--alphabet-preset", "num"], env)
    item = run_cli_json(["config", "fpe", "get", "formatted-cli"], env)
    require("letter_case" not in item, "num drops inherited letter case")
    run_cli(["config", "fpe", "update", "formatted-cli", "--alphabet", "0123456789", "--preserve-characters", ""], env)
    item = run_cli_json(["config", "fpe", "get", "formatted-cli"], env)
    require("alphabet_preset" not in item and "letter_case" not in item and item["preserve_characters"] == "", "custom selector replaces preset and retains explicit empty")
    for invalid in ["null", "True", "1", "yes"]:
        before=config.read_bytes()
        run_cli(["config","fpe","update","formatted-cli","--authenticated",invalid],env,expect_success=False)
        require(config.read_bytes()==before,"invalid authenticated flag does not write")
    run_cli(["config","fpe","add","--name","auth-cli",*common,"--alphabet-preset","num","--preserve-characters","-","--authenticated","true"],env)
    run_cli(["config","fpe","update","auth-cli","--max-len","40"],env)
    require(run_cli_json(["config","fpe","get","auth-cli"],env)["authenticated"] is True,"update omission preserves auth")
    run_cli(["config","sign"],env); run_cli(["config","reload"],env)
    body={"ref":"auth","profile":"auth-cli","plaintext":"001-234"}
    encrypted=run_cli_json(["fpe","encrypt",kid,"--json",json.dumps(body)],env)
    require(len(encrypted["tag"])==64,"CLI transports authentication tag")
    inverse={"ref":"new-ref","profile":"auth-cli","kid":kid,"ciphertext":encrypted["ciphertext"],"tag":encrypted["tag"]}
    source=Path(directory)/"authenticated-fpe.json"; source.write_text(json.dumps(inverse),encoding="utf-8")
    require(run_cli_json(["fpe","decrypt","--file",str(source)],env)["plaintext"]==body["plaintext"],"CLI authenticated file round trip")
    require("plaintext: 001-234" in run_cli(["fpe","decrypt","--file",str(source),"--output","yaml"],env).stdout,"authenticated YAML output")
    wrong=dict(inverse,tag="0"*64)
    require("fpe authentication failed" in run_cli(["fpe","decrypt","--json",json.dumps(wrong)],env,expect_success=False).stderr,"CLI reports fixed authentication error")
    run_cli(["config","token","add","--name","fpe-seed-origin-cli","--kid",kid,"--token-prefix","fpe_seed","--token-len","32","--max-plaintext-len","128","--one-time","false","--subject-mode","stored"],env)
    run_cli(["config","fpe","add","--name","subject-fpe-cli",*common,"--alphabet-preset","num","--preserve-characters","-","--authenticated","true","--subject-mode","stored"],env)
    run_cli(["config","sign"],env); run_cli(["config","reload"],env)
    created=run_cli_json(["subject","create",kid,"--json",json.dumps({"profile":"fpe-seed-origin-cli","subject_name":"shared-cli-user"})],env)
    subject=created["subject"]
    body={"ref":"subject","profile":"subject-fpe-cli","plaintext":"001-234"}
    source.write_text(json.dumps(body),encoding="utf-8")
    encoded=run_cli_json(["fpe","encrypt",kid,"--subject",subject,"--file",str(source)],env)
    require(encoded["subject"]==subject,"CLI selects subject route and preserves input")
    inverse={"ref":"subject","kid":kid,"profile":body["profile"],"subject":subject,"ciphertext":encoded["ciphertext"],"tag":encoded["tag"]}
    require(run_cli_json(["fpe","decrypt","--json",json.dumps(inverse)],env)["plaintext"]==body["plaintext"],"CLI subject round trip")
    for options in [["--subject"],["--subject","A"*64],["--subject",subject,"--subject",subject]]:
        run_cli(["fpe","encrypt",kid,*options,"--json",json.dumps(body)],env,expect_success=False)
    run_cli(["fpe","decrypt","--subject",subject,"--json",json.dumps(inverse)],env,expect_success=False)
    run_cli(["subject","delete",kid,subject],env)
    require("404" in run_cli(["fpe","decrypt","--json",json.dumps(inverse)],env,expect_success=False).stderr,"CLI deleted seed prevents recovery")
