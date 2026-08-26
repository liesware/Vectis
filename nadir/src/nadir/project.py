"""The explicit project integration boundary."""

from __future__ import annotations

from contextlib import AbstractContextManager
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import os
import re
from typing import Mapping, Protocol

from .workflows import Finding, HttpStep, Target


class Project(Protocol):
    name: str

    def target_names(self) -> tuple[str, ...]: ...

    def fixture(self, options: Mapping[str, object]) -> AbstractContextManager[object]: ...

    def targets(self) -> tuple[Target, ...]: ...

    def healthcheck_step(self) -> HttpStep: ...

    def redaction_values(self, fixture: object) -> tuple[bytes, ...]: ...

    def self_check(self) -> tuple[Finding, ...]: ...


def load_project(path: Path) -> Project:
    resolved = path.resolve()
    if not resolved.is_file():
        raise ValueError("project module path is not a file")
    spec = spec_from_file_location(f"nadir_project_{resolved.stem}", resolved)
    if spec is None or spec.loader is None:
        raise ValueError("project module could not be loaded")
    module = module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, SyntaxError) as error:
        raise ValueError("project module could not be loaded") from error
    project = getattr(module, "PROJECT", None)
    required = ("name", "target_names", "fixture", "targets", "healthcheck_step", "redaction_values", "self_check")
    if project is None or any(not hasattr(project, attribute) for attribute in required):
        raise ValueError("project module does not expose a valid PROJECT")
    return project


_ENVIRONMENT_NAME = re.compile(r"NADIR_[A-Z0-9_]+\Z")


def load_project_environment(project_path: Path) -> dict[str, str]:
    """Load the project's declared Nadir environment and apply process overrides."""

    environment_path = project_path.resolve().parent / "env.dist"
    if not environment_path.is_file():
        raise ValueError("project environment file env.dist is missing")
    try:
        lines = environment_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError("project environment file env.dist could not be read") from error

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid env.dist line {line_number}")
        name, value = line.split("=", maxsplit=1)
        if not _ENVIRONMENT_NAME.fullmatch(name):
            raise ValueError(f"env.dist line {line_number} must declare a NADIR_* variable")
        if name in values:
            raise ValueError(f"env.dist declares {name} more than once")
        values[name] = value

    for name, value in os.environ.items():
        if _ENVIRONMENT_NAME.fullmatch(name):
            values[name] = value
    return values
