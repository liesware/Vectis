#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_APIKEY = "20e446d000498e82b056f54e68216d4c8c9bda089a6812d0aa9d82d59f918018"


def run_script(script, base_url, apikey):
    subprocess.run(
        [
            sys.executable,
            str(script),
            "--base-url",
            base_url,
            "--apikey",
            apikey,
        ],
        check=True,
    )


def main():
    parser = argparse.ArgumentParser(description="Run positive and negative HTTP workflows.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey", default=DEFAULT_APIKEY)
    args = parser.parse_args()

    tests_dir = Path(__file__).resolve().parent
    run_script(tests_dir / "http_positive.py", args.base_url, args.apikey)
    run_script(tests_dir / "http_negative.py", args.base_url, args.apikey)


if __name__ == "__main__":
    main()
