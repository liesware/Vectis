#!/usr/bin/env python3
"""CLI entry point for the Vectis HTTP fuzz suite."""

import argparse
import random
import sys
from pathlib import Path

INTEGRATION_ROOT = Path(__file__).resolve().parents[2] / "integration"
sys.path.insert(0, str(INTEGRATION_ROOT))

from support.test_config import require_apikey

from client import FuzzClient
from config import DEFAULT_BASE_URL, UNSEAL_KEY_FILE
from reporting import print_target_done, print_target_start
from self_check import self_check
from targets import TARGET_NAMES, TARGETS


def main():
    parser = argparse.ArgumentParser(description="Fuzz the Vectis HTTP surface.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--target", choices=["all", *TARGET_NAMES], default="all")
    parser.add_argument("--liveness-every", type=int, default=1)
    parser.add_argument(
        "--progress-every",
        type=int,
        default=0,
        help="print per-target progress every N cases; 0 disables periodic progress",
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="run offline self-tests of the semantic oracle and exit",
    )
    args = parser.parse_args()

    if args.self_check:
        sys.exit(self_check())

    apikey = require_apikey(args.apikey)
    client = FuzzClient(args.base_url, apikey)
    rng = random.Random(args.seed)

    if client.get_status("/healthz/ready") != 200:
        print("Vectis is not ready; start the server first", file=sys.stderr)
        sys.exit(1)

    unseal = (
        UNSEAL_KEY_FILE.read_text(encoding="utf-8").strip()
        if UNSEAL_KEY_FILE.exists()
        else ""
    )
    secrets = (apikey, unseal)

    print("HTTP fuzz:", flush=True)
    print(
        f"seed={args.seed} iterations={args.iterations} target={args.target}",
        flush=True,
    )

    passed = 0
    failed = 0
    for target in TARGETS:
        if args.target not in ("all", target["name"]):
            continue
        print_target_start(target["name"], args)
        counters = target["runner"](target, client, rng, args, secrets)
        print_target_done(target["name"], counters)
        passed += counters["passed"]
        failed += counters["failed"]

    if client.get_status("/healthz/ready") != 200:
        print("Vectis is not healthy after fuzzing", file=sys.stderr)
        failed += 1

    print(f"SUMMARY fuzz passed={passed} failed={failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
