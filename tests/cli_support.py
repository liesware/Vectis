#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NEXT_REMINDER = "run `vectis config sign`, then `vectis config reload`"
KID_A = "a" * 64
KID_B = "b" * 64
KID_C = "c" * 64
APIKEY_HASH_A = "d" * 64
APIKEY_HASH_B = "e" * 64


class CliTestError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CliTestError(message)


def isolated_env(tmpdir):
    tmpdir = Path(tmpdir)
    env = os.environ.copy()
    env["VECTIS_CONFIG_PATH"] = str(tmpdir / "config.json")
    env["VECTIS_CONFIG_SIGN_PATH"] = str(tmpdir / "config_sign.json")
    env["VECTIS_INIT_KEYS_FILE"] = str(tmpdir / "init.json")
    env["VECTIS_UNSEAL_KEY_FILE"] = str(tmpdir / ".unseal_key")
    return env


def run_cli(args, env, expect_success=True):
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    if expect_success and result.returncode != 0:
        raise CliTestError(
            f"vectis {' '.join(args)} failed: stdout={result.stdout} stderr={result.stderr}"
        )
    if not expect_success and result.returncode == 0:
        raise CliTestError(
            f"vectis {' '.join(args)} must fail but succeeded: stdout={result.stdout}"
        )

    return result


def run_cli_json(args, env):
    result = run_cli([*args, "--output", "json"], env)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as err:
        raise CliTestError(f"CLI returned invalid JSON: {result.stdout}") from err


def init_config(env):
    return run_cli_json(["config", "init"], env)


def config_path(env):
    return Path(env["VECTIS_CONFIG_PATH"])


def read_config(env):
    path = config_path(env)
    require(path.exists(), "config file must exist")
    return json.loads(path.read_text(encoding="utf-8"))


def write_config(env, value):
    path = config_path(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def config_bytes(env):
    path = config_path(env)
    if not path.exists():
        return None
    return path.read_bytes()


def assert_config_unchanged(env, before):
    require(config_bytes(env) == before, "config file must remain unchanged")


def require_next(payload):
    require(payload.get("next") == NEXT_REMINDER, "mutating command must print next reminder")


def require_summary(name, passed, failed):
    print(f"SUMMARY {name} passed={passed} failed={failed}")


def run_case(counters, name, func):
    func()
    counters["passed"] += 1
    print(f"- {name}: OK", flush=True)


def empty_config():
    return {
        "version": "v1",
        "routes": [],
        "remote_routes": [],
        "permissions": [],
        "fpe_profiles": [],
    }
