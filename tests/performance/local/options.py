"""Validated public options, independent of subprocesses and lab mutation."""

import argparse
import math
import os
import re
import sys
from catalog import PROFILES, TARGETS, TARGET_SPECS


def positive_integer(value):
    if not re.fullmatch(r"[0-9]+", str(value)) or int(value) < 1:
        raise ValueError("must be a positive integer")
    return int(value)


def duration_seconds(value):
    units = {"ns": 1e-9, "us": 1e-6, "ms": .001, "s": 1, "m": 60, "h": 3600}
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s|m|h)", value)
    if not parts or "".join(n + u for n, u in parts) != value:
        raise ValueError("duration must use positive k6 units, e.g. 30s or 1m30s")
    seconds = sum(float(n) * units[u] for n, u in parts)
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("duration must be positive")
    return seconds


def parse_options(argv=None, environ=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description="Selective SQLite/k6 happy paths and reproducible measurements",
                                     allow_abbrev=False)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--subject", action="store_true", default=None)
    parser.add_argument("--authenticated", action="store_true", default=None)
    parser.add_argument("--batch-size")
    parser.add_argument("--vusr", help="Concurrent virtual users (k6 VUs)")
    parser.add_argument("--save-results", action="store_true",
                        help="Save JSON/TSV reports and CPU/RSS samples (off by default)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--duration")
    group.add_argument("--iterations")
    parser.add_argument("--crypto-profile", choices=("all", *PROFILES))
    seen = set()
    for arg in argv:
        if arg.startswith("--"):
            name = arg.split("=", 1)[0]
            if name in seen:
                parser.error(f"duplicate option: {name}")
            seen.add(name)
    args = parser.parse_args(argv)

    def boolean(name):
        value = env.get(name, "false")
        if value not in ("true", "false", "1", "0"):
            raise ValueError(f"{name} must be true/false or 1/0")
        return value in ("true", "1")

    try:
        args.target = args.target or env.get("K6_TARGET", "all")
        args.crypto_profile = args.crypto_profile or env.get("K6_CRYPTO_PROFILE", "all")
        if args.target not in TARGETS or args.crypto_profile not in ("all", *PROFILES):
            raise ValueError("unknown target or crypto profile")
        args.subject = args.subject if args.subject is not None else boolean("K6_SUBJECT")
        args.authenticated = args.authenticated if args.authenticated is not None else boolean("K6_AUTHENTICATED")
        explicit_batch = args.batch_size is not None or "K6_BATCH_SIZE" in env
        args.batch_size = positive_integer(args.batch_size if args.batch_size is not None else env.get("K6_BATCH_SIZE", "3"))
        args.vusr = positive_integer(args.vusr if args.vusr is not None else env.get("K6_VUS", "1"))
        if args.batch_size > 128:
            raise ValueError("batch size must be in 1..128")
        spec = TARGET_SPECS.get(args.target, {})
        if args.subject and not spec.get("subject"):
            raise ValueError("--subject is incompatible with this target")
        if args.authenticated and not spec.get("authenticated"):
            raise ValueError("--authenticated is only supported by fpe/fpe-batch")
        if explicit_batch and not spec.get("batch"):
            raise ValueError("--batch-size requires a concrete batch target")
        if args.duration is None and args.iterations is None:
            args.duration = env.get("K6_DURATION")
            args.iterations = env.get("K6_ITERATIONS")
        if args.duration is not None and args.iterations is not None:
            raise ValueError("duration and iterations are mutually exclusive")
        if args.duration is not None:
            args.duration_seconds = duration_seconds(args.duration)
            args.iterations = None
        else:
            args.duration_seconds = None
            args.iterations = positive_integer(args.iterations if args.iterations is not None else "4")
            if args.vusr > args.iterations:
                # k6 shared iterations need at least one iteration per VU; fail before any build.
                raise ValueError("--vusr cannot exceed --iterations; raise --iterations or use --duration")
        args.p95_ms = None
        if "K6_P95_MS" in env:
            args.p95_ms = float(env["K6_P95_MS"])
            if not math.isfinite(args.p95_ms) or args.p95_ms <= 0:
                raise ValueError("K6_P95_MS must be positive and finite")
    except ValueError as error:
        parser.error(str(error))
    return args
