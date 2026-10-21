"""Owned subprocess groups used by the laboratory and k6 coordinator."""

import os
from pathlib import Path
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def stop_process(process, grace=35):
    if process is None:
        return
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def command(args, *, env=None, cwd=ROOT, stdout=None, check=True):
    process = subprocess.Popen(args, cwd=cwd, env=env, stdout=stdout,
                               stderr=subprocess.STDOUT if stdout else None, start_new_session=True)
    try:
        code = process.wait()
    finally:
        stop_process(process)
    if code and check:
        # No child output/credentials are incorporated into public errors.
        raise RuntimeError(f"{Path(args[0]).name} command failed (exit {code}); inspect laboratory logs")
    return code
