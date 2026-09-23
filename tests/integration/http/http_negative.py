#!/usr/bin/env python3
"""Run the ordered negative HTTP integration workflow."""

import argparse
import sys
from pathlib import Path

INTEGRATION_ROOT = Path(__file__).resolve().parents[1]
HTTP_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(INTEGRATION_ROOT))
sys.path.insert(0, str(HTTP_ROOT))

from cases.registry import NEGATIVE_CASES
from lib import HttpTestContext, run_cases
from lib.credentials import require_apikey
from lib.positive_support import DEFAULT_BASE_URL


def print_case_complete(case, _case_passed, _total_passed):
    print(f"- {case.name}: OK", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Run negative HTTP contract tests.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    args = parser.parse_args()

    context = HttpTestContext(args.base_url, require_apikey(args.apikey))
    failed = False
    passed = 0
    try:
        passed = run_cases(context, NEGATIVE_CASES, on_case_complete=print_case_complete)
    except Exception as err:
        print(f"ERROR [{context.current_case or 'setup'}]: {err}", file=sys.stderr)
        failed = True
    try:
        context.cleanup()
    except Exception as err:
        print(f"ERROR [cleanup]: {err}", file=sys.stderr)
        failed = True

    if failed:
        return 1
    print(f"SUMMARY negative passed={passed} failed=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
