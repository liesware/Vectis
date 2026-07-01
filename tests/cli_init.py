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


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


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
    require(f"created {init_keys_file}" in result.stdout, "init must report the custom path")
    for marker in SECRET_MARKERS:
        require(marker in result.stdout, f"init stdout must contain {marker}")


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_existing_init_file_blocks_overwrite(tmpdir)
        test_custom_init_file_is_created(tmpdir)

    print("CLI init: OK")
    print("SUMMARY cli_init passed=2 failed=0")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"ERROR: {err}")
        raise SystemExit(1)
