#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
from pathlib import Path


SUMMARY_RE = re.compile(r"^SUMMARY (?P<name>\w+) passed=(?P<passed>\d+) failed=(?P<failed>\d+)$")


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


def run_script(script, extra_args=None):
    args = [sys.executable, "-u", str(script)]
    if extra_args:
        args.extend(extra_args)

    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    output_lines = []
    assert process.stdout is not None
    for line in process.stdout:
        output_lines.append(line)
        print(line, end="", flush=True)

    returncode = process.wait()
    output = "".join(output_lines)
    summary = parse_summary(output)

    if returncode != 0:
        if summary is None:
            summary = (script.stem.replace("cli_", ""), 0, 1)
        print_summary({summary[0]: summary})
        raise subprocess.CalledProcessError(returncode, args)

    if summary is None:
        raise RuntimeError(f"{script.name} did not print a SUMMARY line")

    return summary


def print_summary(summaries):
    init = summaries.get("cli_init", ("cli_init", 0, 0))
    positive = summaries.get("cli_positive", ("cli_positive", 0, 0))
    negative = summaries.get("cli_negative", ("cli_negative", 0, 0))
    total_passed = init[1] + positive[1] + negative[1]
    total_failed = init[2] + positive[2] + negative[2]

    print("CLI test summary")
    print(f"- init: {init[1]} passed, {init[2]} failed")
    print(f"- positive: {positive[1]} passed, {positive[2]} failed")
    print(f"- negative: {negative[1]} passed, {negative[2]} failed")
    print(f"- total: {total_passed} passed, {total_failed} failed")


def main():
    parser = argparse.ArgumentParser(description="Run Vectis CLI test workflows.")
    parser.add_argument("--base-url")
    parser.add_argument("--apikey")
    args = parser.parse_args()

    tests_dir = Path(__file__).resolve().parent
    summaries = {}

    scripts = [
        (tests_dir / "cli_init.py", []),
        (
            tests_dir / "cli_positive.py",
            ["--base-url", args.base_url, "--apikey", args.apikey]
            if args.base_url and args.apikey
            else [],
        ),
        (tests_dir / "cli_negative.py", []),
    ]

    for script, extra_args in scripts:
        name, passed, failed = run_script(script, extra_args)
        summaries[name] = (name, passed, failed)

    print_summary(summaries)


if __name__ == "__main__":
    main()
