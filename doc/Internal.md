# Vectis Internals

## Purpose

This document explains how data moves through the Vectis implementation.

It is for contributors, maintainers, and auditors reading the code. It is not an
API contract, a threat model, a test plan, or a replacement for source code. It
documents the implementation flow and the internal invariants that should not be
broken when changing Vectis.

For system design, read [doc/Reference.md](Reference.md). For HTTP contracts,
read [doc/API.md](API.md). For testing, read [doc/Test.md](Test.md).

## Layer Map

Vectis uses three main code layers:

- `core`: reusable primitives and infrastructure;
- `ops`: Vectis business operations and protocol flows;
- `io`: input/output adapters, currently HTTP and CLI.

The dependency direction is one way:

```text
io -> ops -> core
io -> core
```

`core` should not depend on `ops` or `io`. `ops` should not depend on HTTP or
CLI details. `io/http` and `io/cli` translate external input into internal
operations and map internal results back to the caller.

Important `core` responsibilities:

- configuration loading and validation;
- canonical JSON;
- cryptographic helper functions;
- external input validators;
- signed config loading;
- routes, remote routes, permissions, and FPE profiles;
- storage abstraction and SQLite/PostgreSQL backends;
- HTTP client construction;
- operational logs, audit logs, and metrics;
- blocking-task isolation for CPU-bound crypto.

Important `ops` responsibilities:

- init key material creation and validation;
- HKDF-derived internal keys;
- operational key creation, loading, lifecycle, and storage encryption;
- public key output;
- hybrid timestamp signing and verification;
- protected message send, receive, decrypt, and internal message encryption;
- API key generation.

Important `io/http` responsibilities:

- server startup;
- router construction;
- `HttpState`;
- request context and `X-Request-Id`;
- authentication and permission checks;
- endpoint adapters;
- public error mapping.

Important `io/cli` responsibilities:

- local bootstrap commands such as `init`, `serve`, `apikey create`, and
  `config sign`;
- HTTP client commands for runtime operations;
- local config editing helpers.

Storage is reached through `core/storage/mod.rs`. SQLite and PostgreSQL share
the same logical storage contract.

## Startup Flow

`vectis serve` starts the HTTP service. The high-level flow is:

1. Load process environment and `.env`.
2. Build and validate `AppConfig`.
3. Validate the encrypted init key file path and file permissions.
4. Resolve the unseal key from environment, unseal key file, or hidden prompt.
5. Decrypt and validate init key material.
6. Derive internal keys with HKDF-SHA256.
7. Initialize logging, audit logging, and metrics.
8. Initialize the configured storage backend.
9. Load operational keys from storage into local memory.
10. Load signed config state.
11. Build `HttpState`.
12. Start the HTTP server.

`VECTIS_MODE=dev` starts an HTTP server. `VECTIS_MODE=prod` starts HTTPS and
requires TLS certificate and key paths.

Startup is strict for files that exist and claim to be security state. If
`config.json` exists, it must be valid and signed. If it is missing, the node can
start with empty config state. Runtime reload is explicit.

## HttpState

`HttpState` is the long-lived in-memory state used by HTTP handlers.

It contains:

- loaded `AppConfig`;
- precomputed auth state for the root API key hash;
- validated init key state;
- HKDF-derived internal keys;
- storage backend handle;
- service startup timestamp;
- loaded operational keys;
- signed config runtime state;
- cached peer public key state when needed by the current design;
- optional Prometheus metrics handle.

`HttpState` should not contain plaintext request payloads, plaintext API keys,
unseal key text after unseal, or temporary crypto outputs beyond the operation
that needs them.

Shared runtime state uses `Arc` and `RwLock` where handlers need concurrent
read access and explicit replacement. Loaded operational keys are stored behind
`Arc<LoadedOpsKey>` so handlers can hold a key without deep-cloning private
material.

Reload boundaries are explicit:

- `POST /keys/reload` refreshes loaded key state from storage.
- `POST /config/reload` refreshes signed routes, remote routes, and
  permissions plus FPE profiles.
- missing-key lazy-load loads one key from storage if a request references a
  valid `kid` not present in memory.

The cluster rule applies inside the process too:

> Storage can be shared. Runtime state is local. Reload is explicit.

## HTTP Request Flow

The normal protected endpoint flow is:

1. Request enters Axum router.
2. Middleware creates a `request_id` from a process nonce and atomic counter.
3. Middleware records request context in tracing spans.
4. Handler authorizes `X-API-Key`.
5. Handler checks required permission.
6. Handler validates path/query/body input.
7. Handler delegates business work to `ops`.
8. `ops` uses `core` primitives, storage, and crypto helpers.
9. Handler maps success or failure into a public HTTP response.
10. Middleware records HTTP metrics.
11. Response includes `X-Request-Id`.

Handlers should stay thin. They should deal with transport concerns,
authentication, permission checks, state access, and error mapping. Protocol and
business logic belongs in `ops`.

Audit is emitted for security-relevant decisions and operations. Metrics are
updated with low-cardinality labels. Operational logs can include request
context and non-secret summaries.

## Key Flow

`POST /keys` creates operational key material.

The flow is:

1. Authenticate and require `admin`.
2. Parse and validate the request.
3. Resolve crypto profile and policy.
4. Generate key material.
5. Build encrypted `keys`.
6. Build encrypted `properties`.
7. Store both encrypted blobs in `opskeys`.
8. Load the created key into local `KeysDbState`.
9. Return the new `kid`.

Storage has two encrypted fields:

- `keys`: encrypted operational key material;
- `properties`: encrypted key properties and lifecycle metadata.

Both are bound to context through AAD. The `kid` is tied to the encrypted key
payload. On load, Vectis validates that stored fields still belong together.

Key loading happens at startup, explicit reload, or missing-key lazy-load.
`GET /keys` lists node-local loaded keys, not every row in shared storage.

Lifecycle changes update encrypted `properties`. The update uses
compare-and-swap semantics against the previous encrypted properties blob. This
prevents stale concurrent lifecycle writes from overwriting terminal states.

## Message Flow

### Send

`POST /message/{sender_kid}` sends a protected message to another Vectis
instance.

The flow is:

1. Authenticate and require `message` permission for `sender_kid`.
2. Validate and load the sender key.
3. Parse request body.
4. Resolve recipient route from signed `remote_routes`.
5. Ensure the route is active and allows the local sender KID.
6. Read peer public keys from signed config.
7. Build canonical protected-message payload metadata.
8. Create hybrid KEM material using XECDH and ML-KEM.
9. Derive a message key.
10. Encrypt plaintext with AEAD.
11. Sign the envelope with local EdDSA and ML-DSA keys.
12. Send the envelope to the remote `/message` endpoint.

The caller does not provide a remote host. Remote addresses and peer public keys
come from signed config.

### Receive

`POST /message` receives a protected message from another Vectis instance.

The receiver flow is:

1. Parse the envelope.
2. Load the recipient key.
3. Resolve sender public keys from signed `remote_routes`.
4. Verify signatures before decrypting.
5. Enforce lifecycle for decrypt/verify use.
6. Decapsulate ML-KEM and compute XECDH shared secret.
7. Derive the message key.
8. Decrypt AEAD ciphertext.
9. Re-encrypt plaintext with the local recipient key's symmetric algorithm.
10. Deliver the encrypted internal message to the configured final app route.

Verify-before-decrypt is mandatory. A message must not be decrypted until the
sender identity and signatures have been validated.

### Internal Messages

`POST /message/internal/encrypt/{kid}` encrypts a local plaintext using the
local symmetric key for `kid`.

`POST /message/internal/decrypt` decrypts that internal message.

These are local operations. They use separate audit events:

- `message.internal.encrypt.*`;
- `message.internal.decrypt.*`.

Remote message send uses `message.send.*`. The audit log must be able to tell
local internal encryption from remote delivery.

### FPE Flow

`POST /fpe/encrypt/{kid}` and `POST /fpe/decrypt` are local field operations.
The request selects a profile name, but the profile parameters come from signed
config:

- alphabet;
- minimum and maximum length;
- `tweak_aad`;
- `fpe_version`;
- bound local `kid`.

The FPE key is derived from the loaded key's symmetric key with HKDF-SHA256,
using the profile name, KID, and FPE version as AAD-style info. Encrypt requires
an `active` key. Decrypt allows `active` and `retired`. FPE preserves format but
does not authenticate data and is not part of the remote message protocol.

## Signed Config Flow

Runtime policy is stored in `config.json` and signed in `config_sign.json`.

The signed config contains:

- local final app routes;
- remote Vectis routes and peer public keys;
- API key permission clients.
- FPE field profiles.

The signing flow uses canonical JSON. Vectis signs the canonical config hash
inside a timestamp token using init keys. The signature is not bound to the local
filesystem path; a `config.json` and `config_sign.json` pair can be moved
together between host, container, and Kubernetes-mounted paths.

Startup behavior:

- missing `config.json`: load empty config state;
- present `config.json`: require valid JSON, valid schema, and valid signature.

Reload behavior:

- missing `config.json`: reload to empty config state;
- invalid existing config or invalid signature: reject reload and keep previous
  runtime state.

Config reload is whole-file. There is no partial route, remote route, or
permissions reload.

## Zeroizing And Memory

Vectis uses `zeroize` and `Zeroizing` for secret material that should be cleared
when dropped.

Important secret categories:

- unseal key;
- init symmetric key;
- HKDF-derived internal keys;
- operational private key material;
- shared secrets from XECDH and ML-KEM;
- AEAD message keys;
- decrypted plaintext buffers.

Loaded operational keys live in memory while the server needs them. They are
stored as `Arc<LoadedOpsKey>` to avoid deep clones of private material across
requests. When the last `Arc` is dropped, the key tree is zeroized.

Zeroization is a best-effort memory hygiene tool. It does not protect against:

- a hostile kernel or hypervisor;
- process memory dumps taken before zeroization;
- compiler/runtime copies outside Vectis control;
- secrets already written to logs, metrics, panics, swap, or external systems.

Therefore Vectis also avoids logging secrets and avoids putting secret values in
metric labels or public errors.

## Logging, Audit, And Metrics

Vectis separates three observability channels:

- operational logs;
- audit logs;
- metrics.

`VECTIS_LOG_TARGET=file` writes operational and audit logs to separate files.
`VECTIS_LOG_TARGET=stdout` writes both streams to stdout as JSON lines. Audit
events remain distinguishable by `target: "vectis::audit"`.

Operational logs are for running and debugging the service. They can include
request path, status, request ID, non-secret input summaries, and operational
errors.

Audit logs are for security-relevant events. They use stable event names and
logical identity fields such as:

- `actor`;
- `actor_fp`;
- `root`;
- `admin`;
- `kid`;
- `remote_kid`;
- `action`;
- `outcome`;
- `reason`.

Audit logs must not include plaintext, ciphertext bodies, API keys, unseal keys,
private keys, shared secrets, or full sensitive payloads.

Every HTTP response includes `X-Request-Id`. The same ID is present in request
logs so a caller can report a failing request without exposing payloads.

Metrics are Prometheus-compatible. Labels must stay low-cardinality. Allowed
labels are stable dimensions such as method, endpoint route template, status,
operation, outcome, and result. Labels must not include KIDs, API keys, actors,
remote addresses, free-form errors, plaintext, or ciphertext.

## Error Boundary

Vectis uses `VectisError` as its semantic error boundary.

Operations should return meaningful internal errors. HTTP handlers map those
errors to safe public responses.

General rules:

- validation failures are client errors;
- missing resources are not found;
- permission failures are forbidden;
- authentication failures are unauthorized;
- remote reachability errors are reported as reachability;
- unexpected internal failures are public 5xx responses with sanitized text.

Public errors should be useful but not revealing. Internal logs can keep more
detail, as long as they still avoid secrets.

## Internal Invariants

These invariants are part of the implementation contract:

- Do not decrypt a remote protected message before verifying sender signatures.
- Do not fetch peer public keys at runtime for message exchange.
- Do not accept request-supplied remote hosts for message sending.
- Do not log plaintext, ciphertext bodies, API keys, unseal keys, private keys,
  or shared secrets.
- Do not put KIDs, actors, remote addresses, free-form errors, or secrets in
  metric labels.
- Enforce lifecycle through centralized helpers.
- `retired` keys can decrypt/verify but must not be used for new operations or
  public key exposure.
- `compromised` and `destroyed` keys must not be usable.
- Terminal lifecycle states must remain terminal under concurrent writes.
- Signed config is the source of runtime route, remote peer, and permission
  policy.
- Config reload and key reload are explicit.
- Storage may be shared, but runtime state is local.
- CPU-bound cryptographic work that can block Tokio workers should run through
  blocking-task isolation.
