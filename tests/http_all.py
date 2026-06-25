#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
from pathlib import Path


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_APIKEY = "20e446d000498e82b056f54e68216d4c8c9bda089a6812d0aa9d82d59f918018"
SUMMARY_RE = re.compile(r"^SUMMARY (?P<name>\w+) passed=(?P<passed>\d+) failed=(?P<failed>\d+)$")


def run_script(script, base_url, apikey):
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--base-url",
            base_url,
            "--apikey",
            apikey,
        ],
        capture_output=True,
        text=True,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    summary = parse_summary(result.stdout)
    if result.returncode != 0:
        if summary is None:
            summary = (script.stem.replace("http_", ""), 0, 1)
        print_summary({summary[0]: summary})
        raise subprocess.CalledProcessError(result.returncode, result.args)

    if summary is None:
        raise RuntimeError(f"{script.name} did not print a SUMMARY line")

    return summary


def parse_summary(output):
    for line in reversed(output.splitlines()):
        match = SUMMARY_RE.match(line.strip())
        if match:
            return (
                match.group("name"),
                int(match.group("passed")),
                int(match.group("failed")),
            )

    return None


def print_summary(summaries):
    positive = summaries.get("positive", ("positive", 0, 0))
    negative = summaries.get("negative", ("negative", 0, 0))
    total_passed = positive[1] + negative[1]
    total_failed = positive[2] + negative[2]

    print("HTTP test summary")
    print(f"- positive: {positive[1]} passed, {positive[2]} failed")
    print(f"- negative: {negative[1]} passed, {negative[2]} failed")
    print(f"- total: {total_passed} passed, {total_failed} failed")


def main():
    parser = argparse.ArgumentParser(description="Run positive and negative HTTP workflows.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey", default=DEFAULT_APIKEY)
    args = parser.parse_args()

    tests_dir = Path(__file__).resolve().parent
    summaries = {}
    for script in (tests_dir / "http_positive.py", tests_dir / "http_negative.py"):
        name, passed, failed = run_script(script, args.base_url, args.apikey)
        summaries[name] = (name, passed, failed)

    print_summary(summaries)


if __name__ == "__main__":
    main()
