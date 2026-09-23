#!/usr/bin/env python3
"""Run the ordered positive HTTP integration workflow."""

import argparse
import sys
from pathlib import Path

INTEGRATION_ROOT = Path(__file__).resolve().parents[1]
HTTP_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(INTEGRATION_ROOT))
sys.path.insert(0, str(HTTP_ROOT))

from cases.registry import POSITIVE_CASES
from lib import HttpTestContext, run_cases
from lib.client import WorkflowError
from lib.credentials import require_apikey
from lib.positive_support import DEFAULT_BASE_URL, DEFAULT_FINAL_APP_ADDR


def main():
    parser = argparse.ArgumentParser(description="Run the standard HTTP workflow.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    parser.add_argument("--final-app-addr", default=DEFAULT_FINAL_APP_ADDR)
    args = parser.parse_args()

    context = HttpTestContext(args.base_url, require_apikey(args.apikey), args.final_app_addr)
    failed = False
    passed = 0
    try:
        passed = run_cases(context, POSITIVE_CASES, require_result=True)
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
    print(f"SUMMARY positive passed={passed} failed=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
