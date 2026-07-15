# How Vectis Works

## Purpose

This document explains how Vectis works. It is written for new contributors,
maintainers, auditors, and technical project owners who need to understand the
flows, invariants, and boundaries of the system.

The goal is to make Vectis recoverable as a design. If the current codebase were
lost tomorrow, rebuilding it from scratch would still be a large effort, but this
document should preserve the core concepts, flows, invariants, and design
decisions needed to recreate the system deliberately.

This document complements:

- [README.md](../README.md): overview, quick start, and demo entry point.
- [doc/API.md](API.md): HTTP API and CLI mapping.
- [doc/CLI.md](CLI.md): CLI behavior, commands, output, and environment.
- [doc/ENV.md](ENV.md): environment variables and expected values.
- [doc/Clustering.md](Clustering.md): multi-node behavior and shared storage model.
- [doc/HA_DR.md](HA_DR.md): high availability, backups, restore, and recovery limits.
- [doc/Internal.md](Internal.md): implementation flows and internal invariants.
- [doc/openapi.yaml](openapi.yaml): OpenAPI contract.

## What Vectis Does

Vectis is an experimental system for **Sensitive Data Lifecycle Protection**.
TLS protects a network connection, but sensitive data often continues moving
through applications, queues, services, storage, logs, jobs, and final systems
after the TLS session ends. Vectis explores object-level protection: the data
itself is encrypted, signed, routed, verified, re-encrypted, and governed across
its lifecycle.

At the current stage, Vectis provides:

- encrypted local init key material;
- operational key creation and lifecycle management;
- hybrid key establishment with XECDH and ML-KEM;
- EdDSA and ML-DSA signatures;
- authenticated encryption for protected messages;
- local re-encryption before final application delivery;
- a hybrid timestamp/signature protocol;
- signed runtime configuration for routes, remote routes, permissions, FPE profiles, and tokenization profiles;
- local format-preserving encryption for signed field profiles;
- local reversible random tokenization for signed token profiles;
- SQLite/PostgreSQL-backed storage behind a storage abstraction;
- API key authentication using derived verification material;
- startup, liveness, readiness, metrics, structured logs, and audit logs;
- a CLI that mostly behaves as an HTTP client for the runtime service.

Vectis is experimental. It does not replace TLS, KMS, HSMs, mature DLP systems,
secrets managers, or audited cryptographic products.

## Core Model

Vectis is built around four rules.

### Data Should Remain Protected Beyond Transport

The protected unit is not the TCP connection or the HTTP request. The protected
unit is the data object. Vectis therefore produces structured protected
messages that carry metadata, KEM material, cipher material, and signatures.

### A Vectis Instance Owns Local Trust

Each Vectis instance has local init key material and local operational keys. It
can:

- create operational keys;
- publish public keys;
- decrypt messages addressed to local keys;
- re-encrypt data for local final applications;
- enforce local lifecycle and permission policy.

### Remote Communication Is Policy-Driven

Outbound message destinations are not supplied freely by request input. They are
resolved from a signed configuration file. This prevents an API caller from
turning Vectis into an arbitrary relay.

The signed config controls:

- local final app routes;
- authorized remote Vectis routes;
- non-root API key permissions.
- local FPE field profiles.
- local tokenization profiles.

### Cryptographic Material Has Lifecycle

Operational keys are not just bytes. They have encrypted properties, including a
lifecycle status. The lifecycle determines whether a key can be used for new
operations, verification/decryption only, public key exposure, or no operations.

## Repository Architecture

Vectis follows a deliberately simple three-layer architecture:

```text
src/
  core/   reusable infrastructure, validation, crypto, config, storage
  ops/    business operations and protocol flows
  io/     input/output adapters: HTTP and CLI
```

The rule of thumb is:

- `core` knows how to do reusable primitive work.
- `ops` knows how to perform Vectis operations.
- `io` knows how to receive and return data.

HTTP handlers should be thin. They should validate transport concerns such as
authentication, pass input to `ops`, and return structured output. Business
logic should not live in HTTP handlers.

### `core`

Important modules:

- `core/config.rs`: environment loading, defaults, and validation.
- `core/config_file.rs`: signed unified config loading and reload behavior.
- `core/crypto.rs`: reusable cryptographic helper functions.
- `core/validation.rs`: generic validation helpers for external input.
- `core/canonical.rs`: canonical JSON representation for signed payloads.
- `core/protocol.rs`: protocol version validation.
- `core/routes.rs`: final app route validation and lookup.
- `core/remote_routes.rs`: remote Vectis route validation and lookup.
- `core/permissions.rs`: permission model and API key client authorization data.
- `core/tokenization.rs`: reversible tokenization profile validation and token data crypto.
- `core/storage/mod.rs`: storage abstraction.
- `core/storage/sqlite.rs`: SQLite implementation.
- `core/storage/postgres.rs`: PostgreSQL implementation.
- `core/blocking.rs`: helper for isolating CPU-bound crypto from async workers.
- `core/http_client.rs`: outbound HTTP client construction.
- `core/logging.rs`: structured JSON logging and audit log setup.
- `core/audit.rs`: security audit events.
- `core/metrics.rs`: metrics helpers.

### `ops`

Important modules:

- `ops/init.rs`: init key creation, encrypted init file handling, validation.
- `ops/internal_keys.rs`: HKDF-derived internal keys.
- `ops/key_material.rs`: shared key material creation.
- `ops/keys.rs`: operational key creation, loading, storage encryption,
  properties, lifecycle, and key state.
- `ops/key_validation.rs`: validation of generated key material.
- `ops/pubkey.rs`: public key output.
- `ops/sign.rs`: hybrid signing and signature verification.
- `ops/message.rs`: protected message send, receive, decrypt, internal encrypt,
  and internal decrypt flows.
- `ops/tokenization.rs`: reversible token encode/decode flows.
- `ops/apikey.rs`: API key generation and hashing.
- `ops/test.rs`: self-test operations.
- `ops/contracts.rs`: shared request and response contracts.

### `io`

Important modules:

- `io/http/app.rs`: HTTP server startup.
- `io/http/mod.rs`: `HttpState`, router, and shared state helpers.
- `io/http/auth.rs`: API key authentication.
- `io/http/middleware.rs`: request context, metrics, and request-level logging.
- `io/http/error.rs`: public HTTP error mapping.
- `io/http/*.rs`: endpoint-specific adapters.
- `io/cli/init.rs`: local init command.
- `io/cli/apikey.rs`: local API key generation command.
- `io/cli/http.rs`: CLI HTTP client commands.

## Runtime State

`HttpState` is the main in-memory runtime container for the HTTP service.

It holds:

- loaded and validated `AppConfig`;
- precomputed HTTP auth state;
- validated init key material;
- HKDF-derived internal keys;
- storage backend state;
- service startup timestamp;
- loaded operational keys from storage;
- signed config state;
- optional Prometheus metrics handle.

The most important design decision here is that secrets needed by the long-lived
server are intentionally kept in memory for the lifetime of the process. They
are wrapped in `Zeroizing` where appropriate, so memory is cleared when the
state is dropped. For a server, that means zeroization primarily happens at
process shutdown or when a reload replaces a state value.

## Bootstrap Flow

### `vectis init`

`vectis init` creates local encrypted init key material. It writes to
`VECTIS_INIT_KEYS_FILE`, defaulting to `init.json`.

The command must not overwrite existing init material. If the configured init
file already exists, the command aborts before generating or printing secrets.
Reinitialization is intentionally manual: delete the configured file first.

The init material includes fixed internal key families:

- symmetric root key;
- EdDSA key pair;
- XECDH key pair;
- ML-DSA key pair;
- ML-KEM key pair.

The init file itself is encrypted with `INTERNAL_KEYS_CIPHER`, currently
`AES-256/GCM`. The unseal key is printed once and can later be supplied through
the current unseal providers:

1. `env`: `VECTIS_UNSEAL_KEY`;
2. `file`: `VECTIS_UNSEAL_KEY_FILE`, default `.unseal_key`;
3. `prompt`: hidden terminal prompt.

The provider structure is intentionally small for now. Vault, KMS, and HSM
unseal methods are future integrations, not current behavior.

### `vectis serve`

`vectis serve` performs these high-level steps:

1. Load and validate `AppConfig`.
2. Load the unseal key.
3. Decrypt and validate init material.
4. Derive internal keys from the init symmetric key.
5. Initialize storage.
6. Load operational keys from storage into memory.
7. Load and verify signed config, or fall back to empty config sections.
8. Initialize logging, audit logging, and metrics.
9. Start the HTTP server.

In `VECTIS_MODE=dev`, the local server and outbound clients use HTTP. In
`VECTIS_MODE=prod`, the local server and outbound clients use HTTPS, and TLS
certificate/key paths are required for the server. `VECTIS_TLS_SKIP_VERIFY` only
affects outbound HTTPS clients.

## Key Hierarchy

Vectis has two levels of key material.

### Init Key Material

Init material is local root material. It is encrypted in `VECTIS_INIT_KEYS_FILE`
and is required to start the server.

Its symmetric key is treated as a root secret from which internal keys are
derived.

### Internal Derived Keys

`ops/internal_keys.rs` derives separate internal keys using HKDF-SHA256:

- `db_key`: encrypts and decrypts `opskeys.keys`;
- `properties_key`: encrypts and decrypts `opskeys.properties`;
- `api_auth_key`: verifies API keys without storing them in plaintext.

The derivation uses a fixed internal salt and distinct `info` strings. This
separates cryptographic domains even though they start from the same init
symmetric root key.

### Operational Keys

Operational keys are created by `POST /keys` or `vectis keys create`. They are
used for application-level operations:

- signing;
- verification;
- protected messaging;
- public key publication;
- local encryption/decryption.

Operational key material is stored encrypted in `opskeys.keys`.
Lifecycle/properties metadata is stored encrypted in `opskeys.properties`.

## Operational Key Creation

Operational key creation is profile-driven.

Supported profiles:

- `hybrid-performance-v1`;
- `hybrid-high-assurance-v1`;
- `hybrid-long-term-v1`.

`VECTIS_DEFAULT_CRYPTO_PROFILE` selects the default profile. `VECTIS_CRYPTO_POLICY`
controls whether request-level algorithm overrides are accepted:

- `profile-only`: only a profile is accepted;
- `allow-overrides`: individual algorithm fields may override the profile, mainly
  for development and testing.

Each created key gets:

- public/private key material for EdDSA;
- public/private key material for XECDH;
- public/private key material for ML-DSA;
- public/private key material for ML-KEM;
- symmetric key material;
- hash algorithm metadata;
- encrypted properties, including profile, tag, creation time, lifecycle.

The `kid` is derived using `INTERNAL_KEYS_HASH`, currently `BLAKE2b(256)`.

## Lifecycle Model

Operational keys have a lifecycle status:

- `active`: normal use.
- `disabled`: blocked for all cryptographic operations.
- `retired`: allowed only for decrypt and verification; blocked for new
  encryption, signing, sending, and `/pub`.
- `compromised`: blocked for all cryptographic operations.
- `destroyed`: logically destroyed; administrative metadata is retained, but
  cryptographic operations are blocked.

Allowed transitions:

- `active` -> `disabled`, `retired`, `compromised`, `destroyed`
- `disabled` -> `active`
- `retired` -> no transitions
- `compromised` -> no transitions
- `destroyed` -> no transitions

Transitions to the same status are rejected.

Lifecycle enforcement is centralized through helper functions in `ops/keys.rs`,
such as:

- `require_lifecycle_for_new_use`;
- `require_lifecycle_for_decrypt_or_verify`;
- `require_lifecycle_for_public_keys`.

This avoids each operation inventing its own lifecycle interpretation.

## Signed Unified Config

Runtime policy lives in one signed JSON file:

```json
{
  "version": "v1",
  "routes": [],
  "remote_routes": [],
  "permissions": [],
  "fpe_profiles": [],
  "tokenization_profiles": []
}
```

The content is canonicalized before signing. The signature is stored in
`VECTIS_CONFIG_SIGN_PATH`. The config is signed with init keys through
`vectis config sign`.

Vectis rejects config files above 8 MiB and config signature files above 1 MiB
before parsing, canonicalizing, signing, or verifying them.

The unified config exists to keep policy changes explicit, reviewable, and
protected against local tampering.

### Startup Behavior

If the config is missing during startup, Vectis logs a warning and starts with
empty config sections:

- no manual final app routes;
- no remote routes;
- no non-root permission clients;
- no FPE profiles.
- no tokenization profiles.

If the config file exists, it must be valid and its signature must verify.
Invalid existing config is fatal at startup.

### Reload Behavior

Reload endpoints re-read the signed config. If the file is missing, Vectis
reloads to empty config sections. If the file exists but validation or signature
verification fails, the reload fails and the previous in-memory config remains
active.

This prevents a bad runtime reload from erasing a known-good policy.

## Routes

Routes define where locally decrypted and re-encrypted messages are delivered.

Each final app route binds:

- local `kid`;
- human-readable `name`;
- `final_app_addr`;
- `final_app_path`.

If no route exists for a recipient KID, Vectis uses the default final app
destination from environment config.

Every configured route KID must already exist in the loaded key state.

## Remote Routes

Remote routes define which remote Vectis peers may receive outbound messages.

Each remote route contains:

- `remote_kid`: recipient KID on the remote Vectis instance;
- `name`: human-readable peer label;
- `remote_addr`: host:port without scheme;
- `allowed_local_kids`: local sender KIDs allowed to use the route, or `["*"]`;
- `status`: `active` or `disabled`;
- optional `public_keys`: trusted remote public key material.

The endpoint `POST /message/{sender_kid}` does not accept a destination host in
the request. It accepts only a `recipient_kid`; the destination is resolved from
signed remote routes.

This design protects against SSRF and arbitrary relay behavior.

If `public_keys` is present, Vectis validates the material before loading it:

- DER public keys must be loadable by Botan;
- X25519 public keys must be 32 bytes;
- X448 public keys must be 56 bytes;
- ML-KEM public keys must be loadable and usable for encapsulation.

The signed config is the only source of peer public keys. If `public_keys` is
absent, the entry is routing metadata only: sending to that peer returns `403`,
and inbound messages from a sender `kid` without a registered entry are
rejected with `403`. Vectis never fetches peer keys from a remote `/pub`
endpoint at runtime.

## Permissions

Root authentication uses:

- `VECTIS_APIKEY`: client secret sent as `X-API-Key`;
- `VECTIS_APIKEY_HASH`: server-side verifier.

The server does not need to store the root API key in plaintext. It derives an
API auth key from init material and verifies `X-API-Key` by HMAC.

Additional API clients are loaded from the signed config. They have:

- client label;
- API key hash;
- status;
- permission grants.

Supported actions:

- `admin`;
- `keys`;
- `lifecycle`;
- `self-test`;
- `sign`;
- `message`;
- `metrics`.
- `fpe-encrypt`;
- `fpe-decrypt`;
- `token-encode`;
- `token-decode`.

`admin` grants access to all protected endpoints and ignores kid-scoped grants.
`GET /permissions` exposes a redacted administrative view of the effective
permission clients loaded in memory. It requires root or `admin` and never
returns `apikey_hash`.

Permissions are indexed by API key hash in memory for efficient lookup.

## Protected Message Flow

The protected message flow is the central Vectis protocol.

### Sender Flow

For `POST /message/{sender_kid}`:

1. Authenticate the caller.
2. Validate `sender_kid`.
3. Validate request input.
4. Load sender key from memory, or from storage if missing.
5. Enforce lifecycle for new use.
6. Resolve `recipient_kid` through signed remote routes.
7. Ensure `sender_kid` is allowed by the route.
8. Resolve recipient public keys from the route's `public_keys` in the signed
   config; reject with `403` if the route has none.
9. Generate hybrid KEM material using XECDH and ML-KEM.
10. Derive a message key with HKDF.
11. Build AAD binding protocol metadata.
12. Encrypt plaintext.
13. Sign the payload with EdDSA and ML-DSA.
14. Send the protected message to the remote Vectis instance.

### Receiver Flow

For `POST /message`:

1. Validate the protected message schema.
2. Resolve sender public keys from the matching active `remote_routes` entry
   with `public_keys` in the signed config; reject unregistered senders with
   `403`.
3. Verify EdDSA and ML-DSA signatures.
4. Load recipient private key.
5. Enforce lifecycle for decrypt/verify.
6. Decapsulate ML-KEM.
7. Perform XECDH.
8. Derive the same message key with HKDF.
9. Decrypt the ciphertext.
10. Re-encrypt plaintext with the recipient local key material.
11. Deliver encrypted local payload to the final app route.

The final app receives encrypted local delivery, not direct remote plaintext. It
can call `POST /message/decrypt` on its local Vectis instance to recover the
plaintext.

## Internal Message Encryption

Vectis also exposes local internal encryption and decryption endpoints:

- `POST /message/internal/encrypt/{kid}`;
- `POST /message/internal/decrypt`.

These endpoints protect data using a local operational key rather than sending
to a remote Vectis peer. They are useful for local application integration where
an app wants Vectis-managed encryption without cross-instance transport.

## Format-Preserving Encryption

Vectis exposes local FF1 FPE endpoints for fields that must stay inside a
signed alphabet and length range:

- `POST /fpe/encrypt/{kid}`;
- `POST /fpe/decrypt`.

FPE profiles live in signed config under `fpe_profiles`. Requests select a
profile by name; alphabet, length bounds, tweak AAD, FPE version, and bound KID
come from signed config. FPE is deterministic for the same key/profile/tweak and
plaintext. It preserves format, but it does not authenticate data and does not
replace AEAD message encryption.

## Reversible Tokenization

Vectis exposes local reversible tokenization endpoints for applications that
need stable-looking tokens while storing the original value encrypted:

- `POST /token/encode/{kid}`;
- `POST /token/decode`.

Tokenization profiles live in signed config under `tokenization_profiles`.
Requests select a profile by name; token prefix, token length, plaintext length
limit, tokenization version, and bound KID come from signed config. Encode
generates a random visible token, stores encrypted payload data in storage, and
returns only the token. Decode hashes the presented token, looks up the encrypted
payload, decrypts it, and returns the original plaintext plus optional metadata.
Tokenization hash/data keys are derived per profile, KID, and
`tokenization_version`; the encrypted token payload AAD also binds
`tokenization_version`.
Encode metadata must be a JSON object and is capped at 128 characters after
compact JSON serialization.

The database stores only `kid`, `hashid`, and encrypted `data`. It does not see
the profile name, plaintext, metadata, or visible token.

## Hybrid Timestamp And Signing Protocol

`POST /sign/{kid}` signs a supplied message hash. The caller supplies:

```json
{
  "message_hash": {
    "alg": "BLAKE2b(256)",
    "hex": "..."
  }
}
```

Vectis validates that:

- the hash algorithm is supported;
- the hex value is valid;
- the length matches the algorithm.

The output separates:

- `payload`: canonical signed content;
- `signatures`: EdDSA and ML-DSA signatures.

The payload includes:

- protocol version;
- type `vectis-sign`;
- creation timestamp;
- key info/AAD;
- `kid`;
- serial;
- message hash.

Signatures cover canonical JSON for the payload. JSON field order in received
input should not matter, because verification canonicalizes the signed payload.

`POST /sign/verification` verifies the token. It can verify local KIDs and, when
configured, remote KIDs from trusted `remote_routes.public_keys`.

## Canonical JSON

Canonical JSON is used for signed content. Its job is to make signatures stable
when the same logical JSON object is represented with different field ordering.

Any signed object should follow this pattern:

1. Validate the full input schema.
2. Parse into a typed structure.
3. Canonicalize the signed payload.
4. Sign or verify canonical bytes.

This principle applies to:

- config signatures;
- timestamp/sign tokens;
- protected message signatures.

## Storage

The storage abstraction supports SQLite and PostgreSQL. SQLite is the local
default. PostgreSQL is the shared durable backend for multi-node deployments.

Current logical storage operations:

- save operational keys;
- get operational key by ID;
- list operational keys;
- update encrypted properties;
- save tokenization data;
- get tokenization data by KID and hash ID;
- health check.

Current SQLite table:

```sql
CREATE TABLE IF NOT EXISTS opskeys (
    kid VARCHAR(128) PRIMARY KEY,
    keys VARCHAR(10240) NOT NULL,
    properties VARCHAR(10240) NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    kid VARCHAR(128) NOT NULL,
    hashid VARCHAR(128) NOT NULL,
    data VARCHAR(10240) NOT NULL,
    PRIMARY KEY (kid, hashid)
);
```

Current PostgreSQL table:

```sql
CREATE TABLE opskeys (
    kid VARCHAR(128) PRIMARY KEY,
    keys TEXT NOT NULL,
    properties TEXT NOT NULL
);

CREATE TABLE tokens (
    kid VARCHAR(128) NOT NULL,
    hashid VARCHAR(128) NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (kid, hashid)
);
```

Vectis ships SQL reference files under `src/db`. It does not apply migrations
and does not create tables at runtime. The DBA or operator owns database
creation, schema application, backups, permissions, and tuning. Vectis validates
the schema when it connects.

Important invariant:

- `kid`, encrypted key payload, and encrypted properties must stay bound together.

The `kid` is derived from canonical encrypted key payload material using
`INTERNAL_KEYS_HASH`. Properties are encrypted separately with their own
HKDF-derived key.

If a key is not present in memory, Vectis can load that specific key from
storage on demand. This matters for clustered deployments where another node may
have created a key and written it to shared storage.

## Configuration

Configuration resolution order:

1. process environment variables;
2. `.env` file;
3. built-in defaults.

All public environment variables use the `VECTIS_` prefix.

`VECTIS_MODE` controls transport:

- `dev`: HTTP everywhere;
- `prod`: HTTPS for server, remote Vectis calls, and final app delivery.

The legacy per-channel scheme variables are no longer part of the public
contract.

## HTTP API Shape

Vectis exposes these major endpoint groups:

- health: `/healthz/startup`, `/healthz/live`, `/healthz/ready`;
- metrics: `/metrics`;
- keys: `/keys`, `/keys/reload`, `/keys/properties`;
- lifecycle: `/lifecycle/{kid}`;
- config: `/config/reload`;
- routes: `/routes`;
- remote routes: `/remote-routes`;
- public keys: `/pub/{kid}`;
- signing: `/sign/{kid}`, `/sign/verification`;
- messaging: `/message/{sender_kid}`, `/message`, `/message/decrypt`;
- internal messaging: `/message/internal/encrypt/{kid}`,
  `/message/internal/decrypt`;
- FPE: `/fpe/encrypt/{kid}`, `/fpe/decrypt`;
- tokenization: `/token/encode/{kid}`, `/token/decode`;
- self-test: `/self-test/init`, `/self-test/keys/{kid}`.

Public endpoints are intentionally limited. Protected endpoints require
`X-API-Key`.

## CLI Model

The CLI has two personalities.

Local commands:

- `vectis init`;
- `vectis serve`;
- `vectis apikey create`;
- `vectis config sign`;
- `vectis config list`.

HTTP client commands:

- health;
- keys;
- lifecycle;
- routes;
- remote routes;
- config reload;
- public key lookup (`GET /pub`);
- sign;
- message send/decrypt;
- FPE encrypt/decrypt;
- token encode/decode;
- self-test.

The CLI defaults to YAML output for readability, with JSON available for HTTP
client commands.

## Validation Model

The validation rule is simple:

> Any data from outside the current trust boundary must be validated before it
> enters the system.

Examples:

- path config values are non-empty and checked where needed;
- socket addresses and host:port values are validated;
- KIDs are hex and the expected length;
- hash hex lengths match the selected hash algorithm;
- algorithms are checked against explicit allowlists;
- lifecycle statuses and transitions are checked;
- config file versions are explicit;
- public keys are validated structurally and operationally;
- signed config is verified before use;
- request bodies are parsed and validated in `ops`, not only in HTTP.

## Error Handling

HTTP errors should avoid leaking internals while still being useful to callers.

Design principles:

- detailed errors can be logged internally;
- public responses should be stable and safe;
- common integration failures should be clear enough to diagnose;
- HTTP handlers should use centralized error mapping.

Examples:

- missing recipient route should not look like a generic database failure;
- unreachable remote recipient should be reported as recipient reachability;
- final app delivery failure should distinguish final app reachability from
  generic internal errors.

## Logging, Audit, And Metrics

Vectis uses structured JSON logs with configurable level. Logs can be written to
daily rolling files or to stdout with `VECTIS_LOG_TARGET`.

Operational logs should show:

- request start/end;
- endpoint;
- outcome;
- non-secret input summary;
- non-secret output summary;
- lifecycle and config reload events;
- remote communication failures.

Audit logs are separate from operational logs and intended for security-relevant
events. In file mode this separation is physical. In stdout mode both streams go
to stdout and audit is selected by `target: "vectis::audit"`. Audit records
stable security event names such as `auth.success`,
`permission.denied`, `config.reload.failed`, `key.create.success`,
`message.receive.denied`, `message.internal.encrypt.success`, and
`verify.failed`. Remote sends use `message.send.*`; local internal encryption
and decryption use `message.internal.encrypt.*` and
`message.internal.decrypt.*`.

Audit records use logical identity and resource fields (`actor`, `actor_fp`,
`root`, `admin`, `kid`, `remote_kid`, `action`, `outcome`, `reason`) and must not
contain plaintext, ciphertext, API keys, unseal keys, private keys, or full
sensitive payloads.

Metrics are exposed in Prometheus text format and should avoid sensitive labels.
Labels should remain low cardinality. Runtime metrics cover unsealed state,
loaded keys/routes/permissions, auth and permission decisions, config/key
reload results, message send/receive/decrypt results, and cryptographic
sign/verify/encrypt/decrypt/FPE results.

## Security Boundaries And Invariants

Important invariants:

- `init.json` must not be overwritten automatically.
- The unseal key must not be stored in `.env`.
- Root API key is verified by HMAC, not stored as plaintext server-side.
- Signed config must be canonicalized and verified before loading.
- Runtime config reload must keep the previous state if validation fails.
- Remote message destinations must come from signed config, not request input.
- `remote_routes.public_keys`, if present, must be operationally valid.
- Lifecycle must be enforced centrally.
- Retired keys must not expose `/pub`.
- Compromised and destroyed keys must not perform cryptographic operations.
- Secrets kept for server lifetime should be wrapped in `Zeroizing` when
  possible.
- Public discovery endpoints must not leak private material or decrypted
  properties.

## Testing Strategy

Vectis uses layered tests: Rust unit/property tests, Python HTTP workflows,
Schemathesis OpenAPI contract fuzzing, and native `cargo-fuzz` targets.

The canonical testing guide is [doc/Test.md](Test.md). It explains the current
test files, what each layer proves, prerequisites such as `uv` and Rust nightly,
and the recommended commands for local validation.

## Design Decisions

### Three Layers Instead Of A Framework-Heavy Architecture

The project uses `core`, `ops`, and `io` to keep responsibilities obvious. This
is intentionally simpler than a full domain-driven architecture, but it still
prevents HTTP handlers from becoming business logic containers.

### Profiles Instead Of Free Algorithm Selection By Default

Operational key creation is profile-driven because cryptographic combinations
are policy decisions. Individual overrides exist only when
`VECTIS_CRYPTO_POLICY=allow-overrides`.

### Unified Signed Config

Routes, remote routes, and permissions are one signed file. This keeps runtime
policy easy to review and prevents partial policy drift.

### Remote Routes Instead Of User-Supplied Hosts

`POST /message/{sender_kid}` does not accept a remote host. This closes a major
relay/SSRF class of mistakes and makes outbound communication an operator
policy decision.

### Local Re-Encryption Before Final App Delivery

The receiver's final app does not get plaintext directly from the remote sender.
Vectis re-encrypts the data locally, and the final app calls local Vectis to
decrypt. This keeps the final handoff inside the receiver's local trust domain.

### Lifecycle Metadata Is Encrypted

Lifecycle and properties are operationally sensitive. They are stored encrypted,
separate from encrypted key material, using a separate HKDF-derived key.

### API Key Hashing Uses Derived Internal Key Material

The server validates API keys without storing plaintext API keys. The API key
hash is an HMAC using an internal key derived from init material.

## How To Rebuild Vectis From Scratch

This section is the recovery guide. It describes the order in which the system
should be rebuilt if the implementation were lost.

### 1. Define The Protocol Objects

Start with stable data structures:

- KID format;
- public key response;
- signed token envelope;
- protected message envelope;
- config file;
- operational key properties;
- lifecycle update;
- permission grants.

Use explicit protocol versioning from the beginning.

### 2. Implement Canonical JSON

Before implementing signatures, implement canonical JSON. Every signed payload
must serialize to stable bytes independent of input field order.

Test canonicalization before writing signing code.

### 3. Implement Validation Primitives

Build generic validation helpers for:

- non-empty text;
- hex fields and expected sizes;
- hash algorithm output sizes;
- allowed values;
- host:port;
- HTTP paths;
- protocol version;
- symmetric key sizes.

Use these helpers everywhere external data enters the system.

### 4. Implement Crypto Primitives In `core`

Implement reusable functions only:

- hash;
- HKDF-SHA256;
- HMAC-SHA256;
- symmetric encryption/decryption;
- EdDSA key creation/sign/verify/public/private DER export;
- XECDH key creation/shared secret;
- ML-DSA key creation/sign/verify/public/private DER export;
- ML-KEM key creation/encapsulate/decapsulate;
- public key loading and validation helpers.

Do not put business flows in `core`.

### 5. Implement Init Material

Create fixed init key material and encrypt it into `VECTIS_INIT_KEYS_FILE`.

Rules:

- refuse overwrite;
- print unseal material once;
- validate on load;
- wrap secrets in zeroizing containers.

### 6. Implement Internal Key Derivation

Use HKDF-SHA256 from the init symmetric key to derive:

- database encryption key;
- properties encryption key;
- API auth key.

Keep separate `info` labels for each derived key.

### 7. Implement Storage

Start with the storage trait-like abstraction and SQLite backend.

Minimum operations:

- save key;
- get key;
- list keys;
- update properties;
- health check.

Preserve the invariant binding `id`, encrypted key payload, and properties.

### 8. Implement Operational Key Creation

Create profile-driven operational key generation. Store:

- encrypted key payload;
- encrypted properties;
- public material derivable for `/pub`;
- lifecycle status.

Derive KID with `INTERNAL_KEYS_HASH`.

### 9. Implement Lifecycle

Centralize lifecycle checks. Do not scatter status checks through endpoints.

Add tests for every status and transition.

### 10. Implement Public Key Output

Expose public key material only for active keys. Never expose private key
material. Block retired, disabled, compromised, and destroyed keys.

### 11. Implement Signing

Implement the `vectis-sign` token:

- validate input hash;
- build payload;
- canonicalize payload;
- sign with EdDSA and ML-DSA;
- verify local and trusted remote signers.

### 12. Implement Signed Config

Implement config canonicalization, signing, verification, load, and reload.

Sections:

- final app routes;
- remote routes;
- permissions.

Reload must be fail-safe: invalid reload keeps previous state.

### 13. Implement Authentication And Permissions

Implement:

- root API key verification;
- permission clients from signed config;
- action-based permission checks;
- redacted admin-only permission listing endpoint.

Index clients by API key hash.

### 14. Implement Protected Messaging

Implement sender and receiver flows:

- signed route resolution;
- public key resolution;
- hybrid KEM;
- HKDF message key;
- AAD construction;
- authenticated encryption;
- EdDSA and ML-DSA signatures;
- receiver verification;
- receiver decrypt;
- local re-encrypt for final app delivery.

### 15. Implement HTTP Adapters

Keep handlers thin:

- authenticate;
- require permission;
- pass validated input into `ops`;
- map output to JSON;
- map errors centrally.

### 16. Implement CLI

Keep local commands local. Make runtime commands HTTP clients.

Support YAML by default and JSON when requested.

### 17. Add Observability

Add:

- structured logs;
- audit logs;
- request correlation IDs;
- metrics;
- health probes.

Never log secrets.

### 18. Add End-To-End Tests

Rebuild confidence with:

- init;
- key creation;
- public key lookup (`GET /pub`);
- self-test;
- sign/verify;
- message send/receive/decrypt;
- lifecycle blocking;
- config reload failure;
- permissions;
- negative input validation.

## Current Known Boundaries

Vectis is still experimental. Important boundaries:

- SQLite and PostgreSQL storage are implemented; PostgreSQL is schema-managed by
  the operator, not migrated by Vectis;
- no custom CA bundle support yet;
- production TLS policy exists, but deployment hardening still needs more work;
- config reload is whole-file, not per-section transactional;
- message exchange requires peer `public_keys` registered in the signed config;
  there is no runtime key fetch and no trust-on-first-use path;
- cryptographic implementation depends on Botan availability and correctness;
- no formal external security audit has been completed.

## Future Directions

Likely future work:

- additional storage backends if they keep the same storage contract;
- stronger cluster-aware key loading and cache invalidation;
- custom trust store / CA bundle support;
- richer permission model if endpoint-level actions become necessary;
- signed audit event export;
- stronger key rotation workflows;
- explicit backup and disaster recovery guide;
- formal threat model document;
- formal protocol specification separate from implementation docs;
- production deployment guide;
- external security review.

## Reading Order For New Contributors

Recommended onboarding path:

1. Read [README.md](../README.md).
2. Read this document.
3. Read [doc/API.md](API.md).
4. Read [doc/ENV.md](ENV.md).
5. Run the clinical demo in [demo/README.md](../demo/README.md).
6. Read `src/io/http/mod.rs` to understand runtime state and routing.
7. Read `src/ops/keys.rs`, `src/ops/message.rs`, and `src/ops/sign.rs`.
8. Read `src/core/config_file.rs`, `src/core/remote_routes.rs`, and
   `src/core/permissions.rs`.
9. Run the HTTP positive and negative tests.

## Maintainer Checklist

When changing Vectis, check:

- Does the change keep HTTP logic out of business operations?
- Does every external input pass validation before use?
- Does the change preserve canonical signed payload behavior?
- Does it avoid logging secrets?
- Does lifecycle enforcement still happen centrally?
- Does config reload fail safely?
- Does the OpenAPI contract need an update?
- Does `doc/API.md` need an update?
- Does `doc/ENV.md` need an update?
- Do Python positive and negative tests need new coverage?
- Do Rust unit tests need new coverage?

## Glossary

- **AAD**: Authenticated associated data. Metadata bound to ciphertext without
  being encrypted.
- **Config state**: In-memory routes, remote routes, and permissions loaded from
  signed config.
- **Final app**: Local application that receives Vectis-protected delivery.
- **Init material**: Local root key material created by `vectis init`.
- **KID**: Key identifier derived with Vectis internal hash.
- **Lifecycle**: Operational state controlling what a key is allowed to do.
- **Operational key**: Application-level key set created by `POST /keys`.
- **Remote route**: Signed policy entry authorizing outbound messages to a
  remote Vectis peer.
- **Root API key**: API key verified by `VECTIS_APIKEY_HASH`.
- **Signed config**: Canonicalized `config.json` verified by `config_sign.json`.
  The only source of peer public keys; Vectis has no trust-on-first-use path.
