"""Explicit, declarative Nadir integration for Vectis.

Targets are defined as data in ``targets.yaml``. This module only wires the
fixture, the redaction values, and the registry of Python invariants that the
YAML references by name. Adding a shallow endpoint is a YAML block; a deep one
adds a pure oracle function here and names it from the YAML.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
import sys
from typing import Mapping

from nadir.spec import load_targets
from nadir.workflows import ExpectStatus, Finding, HttpStep, Target

_PROJECT_DIRECTORY = Path(__file__).resolve().parent
if str(_PROJECT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_PROJECT_DIRECTORY))

from fixture import VectisFixture
import invariants

_TARGETS_FILE = _PROJECT_DIRECTORY / "targets.yaml"
_INVARIANTS = {
    "public_keys_output": invariants.public_keys_output,
    "verification_success": invariants.verification_success,
    "verification_failure": invariants.verification_failure,
}


class VectisProject:
    name = "vectis"

    def targets(self) -> tuple[Target, ...]:
        return load_targets(_TARGETS_FILE, invariants=_INVARIANTS)

    def target_names(self) -> tuple[str, ...]:
        return tuple(target.name for target in self.targets())

    def fixture(self, options: Mapping[str, object]) -> AbstractContextManager[object]:
        return VectisFixture.from_options(options)

    def healthcheck_step(self) -> HttpStep:
        return HttpStep("ready", "GET", "{base_url}/healthz/ready", expectation=ExpectStatus(frozenset({200})))

    def redaction_values(self, fixture: object) -> tuple[bytes, ...]:
        if not isinstance(fixture, VectisFixture) or fixture.api_key is None:
            return ()
        return (fixture.api_key.encode("utf-8"),)

    def self_check(self) -> tuple[Finding, ...]:
        return ()


PROJECT = VectisProject()
