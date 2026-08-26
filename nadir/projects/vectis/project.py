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
    "compact_signature_output": invariants.compact_signature_output,
    "fpe_encrypt_output": invariants.fpe_encrypt_output,
    "fpe_round_trip": invariants.fpe_round_trip,
    "retired_fpe_round_trip": invariants.retired_fpe_round_trip,
    "fpe_ciphertext_integrity": invariants.fpe_ciphertext_integrity,
    "mac_create_output": invariants.mac_create_output,
    "mac_verification_failure": invariants.mac_verification_failure,
    "mac_verification_success": invariants.mac_verification_success,
    "masking_output": invariants.masking_output,
    "masking_policy_output": invariants.masking_policy_output,
    "public_keys_output": invariants.public_keys_output,
    "token_round_trip": invariants.token_round_trip,
    "token_once_round_trip": invariants.token_once_round_trip,
    "token_distinct_output": invariants.token_distinct_output,
    "token_once_output": invariants.token_once_output,
    "one_time_token_race": invariants.one_time_token_race,
    "one_time_token_batch_round_trip": invariants.one_time_token_batch_round_trip,
    "token_output": invariants.token_output,
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
        if not isinstance(fixture, VectisFixture):
            return ()
        return tuple(key.encode("utf-8") for key in (fixture.api_key, fixture.denied_api_key, fixture.scoped_api_key) if key is not None)

    def primary_api_key(self, fixture: object) -> bytes | None:
        # The full-privilege key. A finding whose request used the scoped or denied
        # key is not replayed with this one; it is recorded as unreplayable.
        if not isinstance(fixture, VectisFixture) or fixture.api_key is None:
            return None
        return fixture.api_key.encode("utf-8")

    def self_check(self) -> tuple[Finding, ...]:
        return ()


PROJECT = VectisProject()
