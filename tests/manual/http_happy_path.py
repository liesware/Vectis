#!/usr/bin/env python3
"""Run and display a disposable, single-client Vectis happy-path laboratory."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from happy_flows import prepare, run
from happy_lab import Laboratory, ROOT
from happy_transport import Client, Transcript


def resolve_binary(binary):
    if binary:
        candidate = Path(binary).expanduser().resolve()
    else:
        subprocess.run(["cargo", "build", "--locked", "--bin", "vectis"], cwd=ROOT, check=True)
        metadata = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"],
                                  cwd=ROOT, check=True, capture_output=True, text=True)
        candidate = Path(json.loads(metadata.stdout)["target_directory"]) / "debug" / "vectis"
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise RuntimeError(f"executable not found: {candidate}")
    return candidate


def execute(binary, keep=False, stream=None):
    out = Transcript(stream or sys.stdout)
    lab = Laboratory(binary, out, keep)
    client = None
    success = False
    previous_umask = os.umask(0o077)
    try:
        out.write(f"# Vectis HTTP happy path\n\nSQLite laboratory: {lab.path}\nBase URL: {lab.url}")
        lab.initialize()
        client = Client(lab.url, lab.api_key, out)
        lab.start()
        kid = prepare(lab, client)
        run(client, kid)
        success = True
        return 0
    except (Exception, KeyboardInterrupt) as error:
        out.write(f"\nERROR [{client.current if client else 'preparation'}]: {error}")
        return 1
    finally:
        try:
            lab.close(success)
        finally:
            os.umask(previous_umask)
        out.write(f"\n## Summary\nCompleted requests: {client.completed if client else 0}\n"
                  f"Distinct method/path pairs: {len(client.visited) if client else 0}\n"
                  f"Result: {'OK' if success else 'FAILED'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="Existing Vectis executable; otherwise build the development binary")
    parser.add_argument("--keep-lab", action="store_true", help="Keep SQLite, config, init material and logs after success")
    args = parser.parse_args()
    try:
        return execute(resolve_binary(args.binary), args.keep_lab)
    except (Exception, KeyboardInterrupt) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
