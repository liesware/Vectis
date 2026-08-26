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
    "blind_index_batch_atomicity": invariants.blind_index_batch_atomicity,
    "blind_index_batch_membership": invariants.blind_index_batch_membership,
    "blind_index_batch_nonmembership": invariants.blind_index_batch_nonmembership,
    "blind_index_create_output": invariants.blind_index_create_output,
    "blind_index_membership": invariants.blind_index_membership,
    "blind_index_nonmembership": invariants.blind_index_nonmembership,
    "blind_index_verify_nonmembership": invariants.blind_index_verify_nonmembership,
    "compact_signature_output": invariants.compact_signature_output,
    "fpe_encrypt_output": invariants.fpe_encrypt_output,
    "fpe_round_trip": invariants.fpe_round_trip,
    "retired_fpe_round_trip": invariants.retired_fpe_round_trip,
    "fpe_ciphertext_integrity": invariants.fpe_ciphertext_integrity,
    "internal_message_encrypt_output": invariants.internal_message_encrypt_output,
    "internal_message_round_trip": invariants.internal_message_round_trip,
    "internal_message_tamper_rejected": invariants.internal_message_tamper_rejected,
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
        values = [key.encode("utf-8") for key in (fixture.api_key, fixture.denied_api_key, fixture.scoped_api_key) if key is not None]
        extra = dict(fixture.extra)
        for name in (
            "index_plaintext",
            "index_mutated_plaintext",
            "index_verify_plaintext",
            "index_batch_plaintext_zero",
            "index_batch_plaintext_one",
            "index_atomic_plaintext_zero",
            "index_atomic_plaintext_one",
        ):
            value = extra.get(name)
            if isinstance(value, str) and value:
                values.append(value.encode("utf-8"))
        return tuple(values)

    def artifact_redaction_values(self, fixture: object) -> tuple[bytes, ...]:
        values = list(self.redaction_values(fixture))
        if not isinstance(fixture, VectisFixture):
            return tuple(values)
        plaintext = dict(fixture.extra).get("internal_message_plaintext")
        if plaintext:
            values.append(plaintext.encode("utf-8"))
        return tuple(values)

    def primary_api_key(self, fixture: object) -> bytes | None:
        # The full-privilege key. A finding whose request used the scoped or denied
        # key is not replayed with this one; it is recorded as unreplayable.
        if not isinstance(fixture, VectisFixture) or fixture.api_key is None:
            return None
        return fixture.api_key.encode("utf-8")

    def self_check(self) -> tuple[Finding, ...]:
        return ()


PROJECT = VectisProject()
