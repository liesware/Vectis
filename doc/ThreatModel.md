# Vectis Threat Model

## Scope And Status

Vectis is an experimental cryptographic data protection toolkit for sensitive
data workflows. It is not audited and not production-ready. Do not use it to
protect real sensitive data.

This document describes the design intent of protocol `v1`: the threats Vectis
is built to address, the assumptions it depends on, and the risks it explicitly
does not cover. It is a statement of intent, not a security guarantee.

## System Overview

```text
Application A                       Application B
     |                                    ^
     | plaintext record                   | local decrypt through Vectis B
     v                                    |
Vectis A  ---- protected message ---->  Vectis B
          hybrid KEM + AEAD + dual        verify -> decrypt -> local
          signatures over TLS             re-encrypt -> deliver
```

The core claim: TLS protects the connection, but sensitive data keeps moving
after the transport session ends (queues, workers, logs, storage, internal
APIs). Vectis protects the data object itself as it moves through an application
workflow. The receiving application never gets remote plaintext directly; it
receives a local encrypted delivery and must ask its local Vectis instance to
decrypt it.

The diagram above covers only the inter-instance path. Vectis also provides
**local, single-instance field protection** that never involves a peer or a
protected message: format-preserving encryption (FPE) over field values,
reversible random tokenization, MAC create/verify, blind indexes, display
masking, keyed commitments, and authenticated Shamir secret sharing. These
operations are governed by the same signed config, `kid` binding, permission,
and lifecycle enforcement as the messaging path.

## Assets

In order of importance:

1. **Protected payloads**: the sensitive records moving between instances.
2. **Token vault and blind-index store**: the `tokens` table holds the reversible mapping from a
   token to its original plaintext (plus optional metadata), AEAD-encrypted at
   rest. The database only ever sees `kid`, `hashid`, and encrypted `data`.
   The `indexes` table holds only deterministic `(kid, digest)` membership
   entries; it contains no plaintext or profile data.
3. **Key material**: encrypted init keys (`init.json`), operational keys
   (encrypted at rest in storage), HKDF-derived internal keys, and the per-profile
   keys derived from an operational key for FPE (the field key), tokenization
   (the `hash_key` and `data_key`), MAC/indexes (the MAC key), commitments
   (the commitment key), and secret sharing (share-authentication key material).
4. **Signed configuration**: routes, remote routes, peer public keys, API-key
   permissions, and `fpe_profiles`, `tokenization_profiles`, `mac_profiles`,
   `commitment_profiles`, `sharing_profiles`, and `masking_profiles` in
   `config.json`.
5. **Transient sensitive outputs**: commitment openings and plaintext secrets
   returned by share combination, plus self-contained authenticated shares held
   by callers. Vectis does not persist these values.
6. **Credentials**: the root API key and per-client API keys.

## Trust Model

- **The operator is the root of trust.** The operator signs `config.json` with
  the init keys (`vectis-config` token over the hash of the canonical JSON).
  Everything the config asserts — routes, permissions, peer public keys — is
  trusted because the operator signed it.
- **A `kid` is not self-certifying.** It is a hash of encrypted private key
  material, so possession of a kid proves nothing. Trust in a remote peer's
  public keys is anchored by the operator registering them under
  `remote_routes[].public_keys` inside the signed config.
- **The signed config is the only source of peer public keys.** Vectis never
  fetches peer keys from a remote `/pub` endpoint at runtime. Sending requires
  the recipient route to carry registered `public_keys`; receiving requires the
  sender `kid` to match an active `remote_routes` entry with `public_keys`.
  Unregistered peers are rejected. There is no trust-on-first-use path.
- **The root API key is omnipotent.** Non-root clients are constrained by the
  signed `permissions` section (per-kid actions, global actions, admin).
- **Final applications trust their local Vectis instance.** They authenticate
  with client API keys and receive only locally re-encrypted deliveries.
- **Local profile operations trust signed policy.** Masking reveals only the
  configured visible characters; commitments rely on callers protecting their
  openings; blind indexes intentionally expose deterministic membership; and
  share reconstruction trusts only authenticated, compatible shares meeting the
  configured threshold.

## Threats Addressed

| Threat | Mitigation | Mechanism |
| --- | --- | --- |
| Payload exposure beyond the TLS session (queues, logs, intermediate storage) | Object-level protection independent of transport | Hybrid XECDH + ML-KEM key establishment, AEAD encryption, local re-encryption before final delivery (`ops/message.rs`) |
| Sender impersonation between instances | Dual signatures verified before decryption | EdDSA and ML-DSA over the canonical JSON payload; both must verify (`verify_message_signatures`, verify-then-decrypt order) |
| Cross-protocol and cross-context confusion (token/message type mixing, version downgrade) | Context binding and versioning inside the signed material | For messages, AAD binds `version`, `type`, `created_at`, `sender_host`, `sender_kid`, `recipient_kid`, `kem_alg`, `cipher_alg`, and the protocol version is inside the signed payload and must match the envelope. Each local subsystem binds its signed profile context: FPE derives a field key from profile/KID and uses `tweak_aad`; tokenization binds profile/KID/internal scheme/hashid/cipher in `tokens.data`; MAC and indexes bind profile/KID/context; commitments bind profile/KID/context/opening; sharing authenticates profile/KID/context/set metadata before interpolation |
| "Harvest now, decrypt later" quantum adversary | Hybrid post-quantum cryptography | ML-KEM alongside XECDH for key establishment; ML-DSA alongside EdDSA for signatures; security holds if either component holds |
| Nonce reuse under a long-lived key | Fresh key per message | Ephemeral XECDH key and fresh ML-KEM encapsulation per message; the HKDF-derived message key is used once |
| Configuration tampering (routes, permissions, peer keys) | Mandatory config signature | `vectis-config` timestamp token over canonical JSON, verified on load and on every reload (`ops/sign.rs`, `core/config_file.rs`) |
| Storage theft or row substitution in the database | Encryption at rest with identity binding | Operational keys encrypted with an HKDF-derived key and AAD; the `kid` is re-verified against the hash of the encrypted payload on load (`validate_key_id_matches_keys`). Token vault rows are protected separately: `tokens.data` is AEAD-encrypted with AAD binding `kid`, `profile`, and `hashid`, so a stolen or substituted row cannot decrypt outside its own `(kid, profile, hashid)` context. Blind indexes store only deterministic MAC digests in `indexes` for membership checks |
| API key brute force and timing attacks | Hashed verification with constant-time comparison where credentials are compared | Server stores keyed hashes; root verification compares in constant time, and permission clients are indexed by hash for lookup (`core/permissions.rs`, `crypto::constant_time_eq`) |
| Information leakage through errors and telemetry | Typed error boundary and disciplined observability | `VectisError` variants decide HTTP status and public messages (no internal detail on 5xx); logs and metrics avoid secrets and high-cardinality labels; dedicated audit stream with request ids |
| Use of retired or destroyed keys | Runtime lifecycle enforcement | Lifecycle states (`active`, `disabled`, `retired`, `compromised`, `destroyed`) gate every operation class (`ops/keys.rs`) |

## Explicit Assumptions

These are deliberate design decisions, not oversights. Deployments that cannot
satisfy them need compensating controls.

1. **TLS protects the channel; Vectis does not implement object-level
   anti-replay.** A captured protected message or signed token verifies
   indefinitely: `created_at` is informative, there is no freshness window and
   no nonce ledger. Consumers that require exactly-once semantics must
   implement idempotency or replay tracking themselves.
2. **Vectis runs on a trusted internal network.** Expensive Botan operations are
   isolated from Tokio async workers with blocking tasks, but this is not rate
   limiting. Outbound peer and final-app calls have a bounded internal deadline,
   but there is no built-in request throttling, inbound request execution
   deadline, or CPU budget enforcement. Exposing a Vectis instance publicly
   requires a reverse proxy, gateway, or ingress providing those controls.
3. **Config rollback protection is the operator's responsibility.** The config
   signature proves authenticity and integrity, not freshness. An attacker who
   can replace both `config.json` and `config_sign.json` with an older, validly
   signed pair can restore previous routes or permissions. Operators should
   version and monitor config changes.
4. **The host and process are trusted.** The server stores the root API key
   verifier as `VECTIS_APIKEY_HASH`; clients may store `VECTIS_APIKEY`. The
   unseal key can live in `.unseal_key`, and decrypted key material stays in
   process memory (zeroized on drop, but readable by a host-level attacker).
   Host compromise is out of scope.
5. **The system clock is reasonably correct.** Timestamps in tokens and
   messages are informative and used for audit, not for security decisions.
6. **Lifecycle states are authoritative and final.** `destroyed` is terminal by
   design; there are no guardrails or recovery paths. Managing the business
   consequences of lifecycle transitions belongs to the client.
7. **FPE is deterministic and does not authenticate.** For the same
   key/profile/tweak, equal plaintexts produce equal ciphertexts, so FPE leaks
   equality and frequency and enables correlation of repeated values. The profile
   must also define a large enough domain (the server rejects domains below one
   million). FPE preserves format only; it does not authenticate data and does not
   replace AEAD message encryption. Use it where equality leakage is acceptable
   (for example, values that are already unique), and prefer tokenization when
   unlinkability is required.
8. **Blind indexes deliberately reveal deterministic membership.** The same
   profile/context/plaintext produces the same digest, so an observer with
   access to the `indexes` table can correlate equal indexed values within that
   domain. An index is not encryption and must not be used as a confidentiality
   boundary.
9. **Commitment openings are sensitive.** Random openings prevent equality
   leakage between commitments for the same plaintext, but a party that holds
   the opening and plaintext can verify the commitment. Callers must protect
   openings according to their own disclosure workflow.
10. **Secret-share custody belongs to callers.** Vectis authenticates and
    validates shares before reconstruction but does not store, distribute, or
    revoke them. Any threshold-sized compatible set can reconstruct the secret;
    operators must control which parties receive shares and invoke combine.
11. **Masking is controlled disclosure, not cryptographic protection.** It
    reveals configured prefix/suffix characters and cannot recover a plaintext
    once returned to a caller.

## Out Of Scope / Non-Goals

Vectis is not, and does not replace:

- TLS, KMS, HSMs, secrets managers, database encryption, access control
  systems, or traditional DLP products (see the README);
- protection against a malicious operator (the operator is the root of trust);
- protection against compromise of the host or the process memory;
- a secure channel or a message-encryption substitute for the local field
  operations: FPE, reversible tokenization, MAC, blind indexes, masking,
  commitments, and secret sharing protect or transform values within a single
  instance, not data in transit between instances.
  Tokenization additionally persists a reversible token-to-plaintext mapping
  (FPE, MAC, masking, commitments, and sharing store nothing; blind indexes
  store deterministic digests), so an attacker holding both the `tokens` table
  and the operational key could recover plaintexts — the host and operator
  boundary above applies;
- automatic runtime state propagation between nodes; clustered instances share
  durable storage (PostgreSQL) but not in-memory state, and cross-node changes
  become visible only through explicit reload, restart, or lazy-load (see
  `doc/Clustering.md`);
- Merkle proofs, tamper-evident audit chains, SLH-DSA, Vault/KMS/HSM
  auto-unseal, and mTLS;
- denial-of-service resistance.

## Residual Risks And Known Gaps

| Risk | Status | Recommended operational mitigation |
| --- | --- | --- |
| Object replay (assumption 1) | Accepted for v1 | Idempotent consumers; unique message ids at the application layer |
| Config rollback (assumption 3) | Accepted for v1 | Version-control the signed config; alert on unexpected reloads via the audit log |
| Client-side API key storage | Known gap | Restrict file permissions; use per-client keys for applications; rotate keys when exposure is suspected |
| No key rotation flow | Known gap | Create a successor key, update routes, retire the old key manually |
| FPE equality and frequency leakage (assumption 7) | Accepted for v1 | Apply FPE only where equality leakage is acceptable, such as already-unique identifiers; use reversible tokenization when unlinkability is required |
| Blind-index equality and membership leakage (assumption 8) | Accepted for v1 | Use a narrowly scoped signed MAC profile/context; do not expose the index table or treat its digests as encrypted values |
| Commitment opening exposure (assumption 9) | Caller responsibility | Store and disclose openings only through the intended evidence workflow |
| Threshold share custody or combine misuse (assumption 10) | Caller responsibility | Distribute shares through independent protected channels; restrict `share-combine` to the minimum trusted clients |
| Masked-value disclosure (assumption 11) | Accepted for v1 | Choose conservative visible prefix/suffix counts and treat masked output as sensitive display data |

## Revision

This document reflects the design of protocol `v1` as of 2026-07-24, including
local FPE, tokenization, MAC, blind indexes, masking, commitments, and secret
sharing. Update it whenever the protocol version, trust model, or any explicit
assumption changes.
