# Vectis Threat Model

## Scope And Status

Vectis is an experimental project for Sensitive Data Lifecycle Protection. It is
not audited and not production-ready. Do not use it to protect real sensitive
data.

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
APIs). Vectis protects the data object itself across that lifecycle. The
receiving application never gets remote plaintext directly; it receives a local
encrypted delivery and must ask its local Vectis instance to decrypt it.

## Assets

In order of importance:

1. **Protected payloads**: the sensitive records moving between instances.
2. **Key material**: encrypted init keys (`init.json`), operational keys
   (encrypted at rest in storage), and HKDF-derived internal keys.
3. **Signed configuration**: routes, remote routes, peer public keys, and
   API-key permissions in `config.json`.
4. **Credentials**: the root API key and per-client API keys.

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

## Threats Addressed

| Threat | Mitigation | Mechanism |
| --- | --- | --- |
| Payload exposure beyond the TLS session (queues, logs, intermediate storage) | Object-level protection independent of transport | Hybrid XECDH + ML-KEM key establishment, AEAD encryption, local re-encryption before final delivery (`ops/message.rs`) |
| Sender impersonation between instances | Dual signatures verified before decryption | EdDSA and ML-DSA over the canonical JSON payload; both must verify (`verify_message_signatures`, verify-then-decrypt order) |
| Cross-protocol and cross-context confusion (token/message type mixing, version downgrade) | Context binding and versioning inside the signed material | AAD binds `version`, `type`, `created_at`, `sender_host`, `sender_kid`, `recipient_kid`, `kem_alg`, `cipher_alg`; protocol version is inside the signed payload and must match the envelope |
| "Harvest now, decrypt later" quantum adversary | Hybrid post-quantum cryptography | ML-KEM alongside XECDH for key establishment; ML-DSA alongside EdDSA for signatures; security holds if either component holds |
| Nonce reuse under a long-lived key | Fresh key per message | Ephemeral XECDH key and fresh ML-KEM encapsulation per message; the HKDF-derived message key is used once |
| Configuration tampering (routes, permissions, peer keys) | Mandatory config signature | `vectis-config` timestamp token over canonical JSON, verified on load and on every reload (`ops/sign.rs`, `core/config_file.rs`) |
| Storage theft or row substitution in the database | Encryption at rest with identity binding | Operational keys encrypted with an HKDF-derived key and AAD; the `kid` is re-verified against the hash of the encrypted payload on load (`validate_key_id_matches_enc_keys`) |
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
   limiting. There is no built-in request throttling, timeout policy, or CPU
   budget enforcement. Exposing a Vectis instance publicly requires a reverse
   proxy, gateway, or ingress providing those controls.
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

## Out Of Scope / Non-Goals

Vectis is not, and does not replace:

- TLS, KMS, HSMs, secrets managers, database encryption, access control
  systems, or traditional DLP products (see the README);
- protection against a malicious operator (the operator is the root of trust);
- protection against compromise of the host or the process memory;
- automatic runtime state propagation between nodes; clustered instances share
  durable storage (PostgreSQL) but not in-memory state, and cross-node changes
  become visible only through explicit reload, restart, or lazy-load (see
  `doc/Clustering.md`);
- denial-of-service resistance.

## Residual Risks And Known Gaps

| Risk | Status | Recommended operational mitigation |
| --- | --- | --- |
| Object replay (assumption 1) | Accepted for v1 | Idempotent consumers; unique message ids at the application layer |
| Config rollback (assumption 3) | Accepted for v1 | Version-control the signed config; alert on unexpected reloads via the audit log |
| Client-side API key storage | Known gap | Restrict file permissions; use per-client keys for applications; rotate keys when exposure is suspected |
| No key rotation flow | Known gap | Create a successor key, update routes, retire the old key manually |

## Revision

This document reflects the design of protocol `v1` as of 2026-07-02. Update it
whenever the protocol version, trust model, or any explicit assumption changes.
