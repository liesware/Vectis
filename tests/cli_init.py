#!/usr/bin/env python3
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECRET_MARKERS = ("VECTIS_UNSEAL_KEY=", "VECTIS_APIKEY=", "VECTIS_APIKEY_HASH=")


def run_init(init_keys_file):
    env = os.environ.copy()
    env["VECTIS_INIT_KEYS_FILE"] = str(init_keys_file)
    return subprocess.run(
        ["cargo", "run", "--quiet", "--", "init"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def run_apikey_create(init_keys_file, unseal_key):
    env = os.environ.copy()
    env["VECTIS_INIT_KEYS_FILE"] = str(init_keys_file)
    env["VECTIS_UNSEAL_KEY"] = unseal_key
    return subprocess.run(
        ["cargo", "run", "--quiet", "--", "apikey", "create"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def output_value(stdout, key):
    prefix = f"{key}="
    for line in stdout.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    raise RuntimeError(f"missing {key} in init stdout")


def test_existing_init_file_blocks_overwrite(tmpdir):
    init_keys_file = Path(tmpdir) / "existing-init.json"
    original = "existing init material\n"
    init_keys_file.write_text(original, encoding="utf-8")

    result = run_init(init_keys_file)

    require(result.returncode != 0, "init must fail when init keys file already exists")
    require(
        init_keys_file.read_text(encoding="utf-8") == original,
        "init must not overwrite an existing init keys file",
    )
    for marker in SECRET_MARKERS:
        require(marker not in result.stdout, f"init stdout must not contain {marker}")
    require(
        "refusing to overwrite existing init material" in result.stderr,
        "init error must explain that existing init material is protected",
    )


def test_custom_init_file_is_created(tmpdir):
    init_keys_file = Path(tmpdir) / "custom-init.json"

    result = run_init(init_keys_file)

    require(result.returncode == 0, f"init must succeed for a missing custom file: {result.stderr}")
    require(init_keys_file.exists(), "init must create VECTIS_INIT_KEYS_FILE")
    require(
        init_keys_file.stat().st_mode & 0o777 == 0o600,
        "init keys file must be created with 0600 permissions",
    )
    require(f"created {init_keys_file}" in result.stdout, "init must report the custom path")
    for marker in SECRET_MARKERS:
        require(marker in result.stdout, f"init stdout must contain {marker}")


def test_init_file_permissions_are_validated_on_load(tmpdir):
    init_keys_file = Path(tmpdir) / "load-permissions-init.json"
    init_result = run_init(init_keys_file)
    require(init_result.returncode == 0, f"init must succeed before load test: {init_result.stderr}")
    unseal_key = output_value(init_result.stdout, "VECTIS_UNSEAL_KEY")

    init_keys_file.chmod(0o644)
    result = run_apikey_create(init_keys_file, unseal_key)

    require(result.returncode != 0, "loading init state must fail for too-open init keys file")
    require(
        "init keys file permissions are too open" in result.stderr,
        "load error must explain that init keys file permissions are too open",
    )


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_existing_init_file_blocks_overwrite(tmpdir)
        test_custom_init_file_is_created(tmpdir)
        test_init_file_permissions_are_validated_on_load(tmpdir)

    print("CLI init: OK")
    print("SUMMARY cli_init passed=3 failed=0")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"ERROR: {err}")
        raise SystemExit(1)
