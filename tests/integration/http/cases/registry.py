
from . import (
    negative_auth,
    negative_authz,
    negative_config,
    negative_fpe,
    negative_internal_messages,
    negative_lifecycle,
    negative_mac_index,
    negative_masking,
    negative_messages,
    negative_protocol,
    negative_sharing,
    negative_signatures,
    negative_tokenization,
    negative_subjects,
    positive_commitments,
    positive_fpe,
    positive_fpe_subjects,
    positive_symmetric_subjects,
    positive_health,
    positive_keys,
    positive_lifecycle,
    positive_mac_index,
    positive_masking,
    positive_messages,
    positive_permissions,
    positive_sharing,
    positive_signatures,
    positive_tokenization,
    positive_token_delete,
    positive_subjects,
    positive_deterministic_tokenization,
    positive_token_budget,
)


POSITIVE_CASES = (
    *positive_health.CASES[:3],
    *positive_keys.CASES,
    *positive_fpe.CASES,
    *positive_tokenization.CASES,
    *positive_token_delete.CASES,
    *positive_subjects.CASES,
    *positive_deterministic_tokenization.CASES,
    *positive_fpe_subjects.CASES,
    *positive_symmetric_subjects.CASES,
    *positive_token_budget.CASES,
    *positive_mac_index.CASES,
    *positive_commitments.CASES,
    *positive_sharing.CASES,
    *positive_masking.CASES,
    *positive_lifecycle.CASES,
    *positive_permissions.CASES,
    *positive_messages.CASES,
    *positive_signatures.CASES,
    positive_health.CASES[3],
)

NEGATIVE_CASES = (
    *negative_protocol.CASES,
    *negative_authz.CASES,
    *negative_auth.CASES,
    *negative_config.CASES,
    *negative_lifecycle.CASES,
    *negative_messages.CASES,
    *negative_internal_messages.CASES,
    *negative_fpe.CASES,
    *negative_tokenization.CASES,
    *negative_subjects.CASES,
    *negative_mac_index.CASES,
    *negative_masking.CASES,
    *negative_sharing.CASES,
    *negative_signatures.CASES,
)


def _assert_unique_names(cases):
    names = [case.name for case in cases]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise RuntimeError(f"duplicate HTTP case names in the registry: {duplicates}")


_assert_unique_names(POSITIVE_CASES)
_assert_unique_names(NEGATIVE_CASES)
