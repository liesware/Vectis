"""Explicit HTTP case registries. Keep order stable; do not auto-discover modules."""

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
    positive_commitments,
    positive_fpe,
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
)


# Explicit, ordered composition of the positive workflow. Each capability module
# owns its own cases; the registry fixes the order they execute in. runtime-metrics
# lives in positive_health but must run last, after every capability has emitted the
# metrics it asserts on.
POSITIVE_CASES = (
    *positive_health.CASES[:3],  # health, metrics, init
    *positive_keys.CASES,  # keys.create, inventory, lifecycle, routes, remote-public-keys
    *positive_fpe.CASES,  # fpe (profile load + stale-config warning + round-trips)
    *positive_tokenization.CASES,  # tokenization, tokenization.one-time
    *positive_mac_index.CASES,  # mac, index
    *positive_commitments.CASES,  # commit
    *positive_sharing.CASES,  # shares
    *positive_masking.CASES,  # mask
    *positive_lifecycle.CASES,  # lifecycle.retired
    *positive_permissions.CASES,  # permissions
    *positive_messages.CASES,  # messages
    *positive_signatures.CASES,  # signatures
    positive_health.CASES[3],  # runtime-metrics (runs last)
)

# Explicit, ordered composition of the negative suite. Order is load-bearing:
# authz bootstraps the shared key + api-key hashes that later groups reuse, and
# config/lifecycle mutate then restore shared state in sequence.
NEGATIVE_CASES = (
    *negative_protocol.CASES,
    *negative_authz.CASES,
    *negative_auth.CASES,
    *negative_config.CASES,
    *negative_lifecycle.CASES,
    *negative_messages.CASES,
    # negative_operations split by capability, in the original execution order:
    *negative_internal_messages.CASES,
    *negative_fpe.CASES,
    *negative_tokenization.CASES,
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
