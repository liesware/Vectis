#!/usr/bin/env python3
"""CLI entry point for the Vectis HTTP fuzz suite. See doc/Test.md."""

import argparse
import sys

from campaign import RunSummary, TargetMetrics, resolve_seed, select_targets, target_rng
from client import FuzzClient
from config import DEFAULT_BASE_URL, UNSEAL_KEY_FILE
from credentials import require_apikey
from reporting import print_target_done, print_target_start
from self_check import self_check
from targets import TARGET_NAMES, TARGETS


def main():
    parser = argparse.ArgumentParser(description="Fuzz the Vectis HTTP surface.")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="base URL of the running Vectis instance",
    )
    parser.add_argument(
        "--apikey",
        help="API key; falls back to the environment or .env credential helper",
    )
    seed_options = parser.add_mutually_exclusive_group()
    seed_options.add_argument(
        "--seed",
        type=int,
        help="root RNG seed; repeats mutation decisions with identical fixtures (default 1337)",
    )
    seed_options.add_argument(
        "--random-seed", action="store_true", help="generate and print a fresh 64-bit root seed"
    )
    parser.add_argument(
        "--mutation-only", action="store_true",
        help="run body, path, headers and config mutations only",
    )
    parser.add_argument("--summary-json", help="write an aggregate report without request data")
    parser.add_argument(
        "--iterations",
        type=int,
        default=300,
        help="mutation cases run per target (default 300)",
    )
    parser.add_argument(
        "--target",
        choices=["all", *TARGET_NAMES],
        default="all",
        help="run a single target by name, or 'all' (default)",
    )
    parser.add_argument(
        "--liveness-every",
        type=int,
        default=1,
        help="probe /healthz/live every N cases to catch a crash mid-run (default 1)",
    )
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

    if args.iterations < 1 or args.liveness_every < 1 or args.progress_every < 0:
        parser.error("iterations and liveness-every must be positive; progress-every must be nonnegative")
    try:
        selected = select_targets(TARGETS, args.target, args.mutation_only)
    except ValueError as error:
        parser.error(str(error))
    args.seed = resolve_seed(args.seed, args.random_seed)
    print("HTTP fuzz:", flush=True)
    print(
        f"seed={args.seed} iterations={args.iterations} target={args.target} "
        f"mutation_only={args.mutation_only}", flush=True,
    )
    summary = RunSummary(args)
    try:
        exit_code = run(args, selected, summary)
    finally:
        if args.summary_json:
            summary.write(args.summary_json)
    sys.exit(exit_code)


def run(args, selected, summary):
    apikey = require_apikey(args.apikey)
    client = FuzzClient(args.base_url, apikey)
    if client.get_status("/healthz/ready") != 200:
        print("Vectis is not ready; start the server first", file=sys.stderr)
        return 1

    unseal = (
        UNSEAL_KEY_FILE.read_text(encoding="utf-8").strip()
        if UNSEAL_KEY_FILE.exists()
        else ""
    )
    secrets = (apikey, unseal)

    passed = 0
    failed = 0
    for target in selected:
        args.metrics = TargetMetrics(target, args.seed)
        print_target_start(target["name"], args)
        completed = False
        try:
            counters = target["runner"](
                target, client, target_rng(args.seed, target["name"]), args, secrets
            )
            completed = True
        finally:
            measured = args.metrics.summary(completed)
            summary.targets.append(measured)
            del args.metrics
        print_target_done(target["name"], counters)
        if "unique_inputs" in measured:
            print(
                f"[{target['name']}] diversity unique={measured['unique_inputs']} "
                f"duplicates={measured['duplicate_inputs']}", flush=True,
            )
        passed += counters["passed"]
        failed += counters["failed"]

    if client.get_status("/healthz/ready") != 200:
        print("Vectis is not healthy after fuzzing", file=sys.stderr)
        failed += 1

    print(f"SUMMARY fuzz passed={passed} failed={failed}")
    summary.result = "failed" if failed else "passed"
    return 1 if failed else 0


if __name__ == "__main__":
    main()
