"""Resolve an explicit test binary without changing subprocess behavior."""

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def configured_binary(env=None):
    environment = os.environ if env is None else env
    if "VECTIS_BIN" not in environment:
        return None
    value = environment["VECTIS_BIN"]
    if not value:
        raise RuntimeError("VECTIS_BIN must name an executable file")
    binary = Path(value).expanduser()
    if not binary.is_absolute():
        binary = ROOT / binary
    binary = binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("VECTIS_BIN must name an executable file")
    return binary


def vectis_command(args, *, env=None, quiet=False):
    binary = configured_binary(env)
    if binary is not None:
        return [str(binary), *args]
    return ["cargo", "run", *(["--quiet"] if quiet else []), "--", *args]
