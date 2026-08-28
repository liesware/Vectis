# Vectis From Scratch

This document explains what Vectis is and how it works internally, starting from
zero. It is written for a programmer who is **new to the codebase** — and perhaps
new to the idea of "data protection as a service" — and wants to understand the
architecture well enough to contribute. It does not assume you have read the rest
of the documentation.

If you are looking for the engineering **rules** (why each decision is the way it
is), those live in [Design.md](Design.md), which this text cites often. If you
want the HTTP contract field by field, that is [API.md](API.md). This document is
the mental map that ties it all together before you open `src/`.

All values shown here are synthetic and used only as examples.

## What Problem Vectis Solves

TLS protects the **connection**. An encrypted disk protects **storage**. But
between those two ends, the sensitive value appears in plaintext inside the
application: in payloads, logs, queues, databases, backups, internal APIs.

Vectis protects the **data object itself**, not the channel it travels through.
Its contract is a single sentence:

> **Sensitive input in, safe representation out** — keeping only the properties
> your workflow needs.

Depending on which property you need to keep, you pick a different capability:

- a **format-preserving ciphertext** (a card number still looks like a card) →
  *FPE*;
- a **token reversible under policy** → *tokenization*;
- a **masked value** that shows only the last digits → *masking*;
- an **integrity tag** that proves something did not change → *MAC*;
- a **digest you can search without revealing** the original → *blind index*;
- a **commitment** you can prove later → *commitments*;
- **shares** no single holder can read → *secret sharing*;
- a **protected message** only the registered peer can open → post-quantum
  *messaging*;
- a post-quantum **hybrid signature** → *signing*.

All of this is governed by an **operator-signed configuration**, and served
through a consistent HTTP and CLI interface. What Vectis deliberately does **not**
do — key custody (KMS/HSM), secrets management, transport security, access
control — it leaves to the tools that already do it well (see
[What Vectis Does Not Do](#what-vectis-does-not-do)).

## How It Works: The Mental Model

Six ideas carry everything else. With this section you can already read the code
without getting lost.

- **Every operation is an exchange.** A sensitive value goes in; a safe
  representation that keeps only the requested property comes out. Every capability
  is a variation on that same trade.

- **The operator defines trust; the request only selects.** Policy — peers,
  routes, permissions, algorithms, crypto profiles — lives in a **signed
  configuration**. A request may *select* an approved profile or peer, but it
  **never** defines a host, a key, or an algorithm inline. Client input never
  becomes part of the trust model (Design.md, Rule 31).

- **Three layers, dependencies in one direction only.** `io → ops → core`. The
  input/output adapters depend on the business operations, which depend on the
  generic primitives — **never the other way around**. That direction is law
  (Rule 2).

- **Everything external is validated at the boundary, once.** The pattern is
  *parse, don't validate*: raw input (`*Input`) exists only at the edge and is
  converted once into a validated domain type; the rest of the code never
  re-checks. And **persisted data is untrusted input too**: it is validated when
  read, before it is decrypted (Rules 9, 14).

- **The safe choice is the default.** HTTPS is the only mode (there is no plaintext
  listener), permissions are allowlists (anything not granted is denied), and
  signatures are verified **before** decryption. Any unsafe escape hatch is
  explicit, carries a name that declares its danger, and makes noise while active
  (Rules 30, 34).

- **The CLI is a client of the API, not a second implementation.** Runtime commands
  (`fpe`, `token`, `keys`…) call the same HTTP API the service exposes. Only
  bootstrap (`init`, `apikey`, signed-config editing) runs locally, because it must
  work before the service starts (Rule 5).

Each section below is one of these ideas made concrete.

## The Capabilities At A Glance

Each capability is a vertical slice `io/http → ops → core`. They all share the same
shape; only the primitive changes.

| Capability | What it gives you | Reversible |
|---|---|---|
| **FPE** | encryption that preserves the format (same alphabet and length) | yes, with the key |
| **Tokenization** | a token that replaces the value, reversible under policy | yes, under policy |
| **Masking** | a partial view (e.g. `****1111`) | no |
| **MAC** | a tag that proves integrity/authenticity | verification |
| **Blind index** | a deterministic digest searchable without revealing the value | no |
| **Commitments** | a commitment you can open/prove later | opening |
| **Secret sharing** | N shares; k needed to reconstruct | combination |
| **Messaging** | a post-quantum envelope only the registered peer opens | receive |
| **Signing** | hybrid signature (ML-DSA + EdDSA) and its verification | verification |

## The Life Of An Operation

Let us follow a concrete request — `POST /fpe/encrypt/{kid}` — from start to
finish. It is the pattern **every** capability follows, and it shows the three
layers in action.

| step | where it lives | what happens |
|---|---|---|
| 1 | `io/http` (router + `middleware`) | The request arrives; the router applies the **body size cap** before buffering it (Rule 18). |
| 2 | `io/http/auth` | The middleware validates the **API key** with a constant-time comparison (Rule 33). |
| 3 | `io/http/fpe::encrypt_endpoint` | The handler — thin — extracts the `kid` and the body. No business decisions. |
| 4 | `ops/fpe::parse_encrypt_input` → `validate_encrypt_input` | *Parse, don't validate*: raw input becomes a validated type once (Rule 9). |
| 5 | `ops/fpe::prepare_encrypt` | Resolves the crypto **profile** and the **key** from signed config and the in-memory keys-db — the request does not define crypto (Rule 31). |
| 6 | `core/blocking::spawn_blocking_crypto(ops::fpe::encrypt)` | The crypto (CPU-bound) runs **off** the async thread, over `core/fpe` (Rule 3). |
| 7 | `io/http/error::status_for_error` | The result — or the error — maps to the HTTP response through an exhaustive `match` (Rules 21, 22). |

Why this shape matters: the HTTP handler is **thin** (authenticate, parse,
delegate, map); the operation logic lives in `ops`; the pure crypto lives in
`core`; and the heavy work is offloaded so the event loop keeps serving. Changing
the transport does not touch the crypto, and the crypto can be tested without
starting a server.

## Startup Flow: `vectis serve`

What happens from running the binary until the service is listening, noting which
file each step lives in.

| step Nº | action | result |
|---|---|---|
| 1 | `main.rs` → `real_main`: `tokio::main` starts; logging and the crypto provider (`core::tls::ensure_crypto_provider`) are initialized. | The process is ready to dispatch. |
| 2 | `main.rs` recognizes the `serve` command in its `ROOT_COMMANDS` table and calls `run_serve`. | The server path begins. |
| 3 | `run_serve` → `io::cli::init::load_init_state()`: **validates and decrypts the encrypted `init` file** before starting. | `ValidatedInitState`; if the unseal fails, it aborts (nothing starts without the key). |
| 4 | `io::http::run(init_state)` (in `io/http/app.rs`) → `config::app_config()`: loads the environment config (env → `.env` → defaults). | The app `Config` (Rule 8). |
| 5 | `app.rs`: initializes metrics (if enabled) and `HttpAuthState::from_config` for API-key auth. | Metrics handle and auth state. |
| 6 | `app.rs` → `audit_chain::initialize`: prepares the hash-chained, signed audit log. | The audit chain is ready (Rule 42). |
| 7 | `app.rs` → `StorageState::new`: connects to storage (SQLite/PostgreSQL) and **validates the expected schema**. | Storage state; a missing table fails closed with a named error (Rule 25). |
| 8 | `app.rs` → `InternalDerivedKeysState::from_init_state` and `keys::load_keys_db_state`: derives internal keys (in `Zeroizing`) and **decrypts operational keys** into memory. | The in-memory keys-db. |
| 9 | `app.rs` → `config_file::load_config_state`: loads `config.json`, **verifies its signature**, and resolves profiles (FPE/token/MAC/…). Lenient startup: invalid config → empty state + warning. | The applied config state (Rule 15). |
| 10 | `app.rs`: builds the router, starts over **HTTPS**, and registers shutdown on SIGTERM/Ctrl-C with a bounded grace period. | The service listening; graceful shutdown (Rules 28, 34). |

A **runtime** command (`vectis fpe encrypt …`) follows a different path: `main.rs`
dispatches it to `io::cli::http::run`, which **builds an HTTP request and calls
the service API**, printing the response. It is the same operation code as any
other client: the CLI reimplements nothing (Rule 5).

## The Secure-Handling Lifecycle: How Key Material Lives

This is the most important process in Vectis, and the one a contributor must
understand before touching anything near keys, storage, or config. Everything
Vectis protects hangs off a single **chain of custody**: one operator-held key
unlocks the node's root, the root derives purpose-specific keys, those keys
decrypt the database into memory, and every secret along the way is wiped when it
is dropped. Break a link and either nothing starts, or plaintext leaks.

```
unseal key            32 bytes; from VECTIS_UNSEAL_KEY / .unseal_key file / hidden
  │                   prompt. Held in Zeroizing. Never stored by Vectis.
  │  decrypts (AEAD + AAD)
  ▼
init material         node root: a symmetric root key + EdDSA/ML-DSA signing keys
  │                   + the API-key hash. On disk ONLY as an encrypted envelope
  │                   (init.json). Decrypted to a Zeroizing ValidatedInitState.
  │  derives (per-purpose labels)
  ▼
internal keys         db_key · properties_key · api_auth_key  (all Zeroizing)
  │                   key separation: one purpose, one key.
  │  db_key decrypts
  ▼
DB envelopes          ops keys, tokens, index digests — stored as encrypted Base64
  │                   envelopes in SQLite/PostgreSQL. Validated on EVERY read and
  │                   write, then decrypted into memory.
  │  loaded into
  ▼
live state            keys_db_state · config_state, each Arc<RwLock<Zeroizing<…>>>
  │                   shared across handlers; reload swaps it under the write lock.
  │  dropped
  ▼
zeroized              the memory backing every secret above is overwritten on drop.
```

Each stage and its protection:

| stage | what happens | the protection |
|---|---|---|
| **unseal** | The 32-byte unseal key is read from `VECTIS_UNSEAL_KEY` → the `.unseal_key` file → a hidden prompt (`core/unseal.rs`). The file's permissions are checked (no group write/execute, no access for others). | The key gates the whole node. It lives in `Zeroizing`, and Vectis never writes it to disk — the operator custodies it. Without it, boot fails. |
| **init decrypt** | `ops::init::load_validated_init_state` decrypts the encrypted `init.json` with the unseal key (AEAD), then validates the plaintext against its AAD (`ValidatedInitState`, in `Zeroizing`). | `init.json` on disk is only ciphertext; a stolen file without the unseal key is noise. AAD binding means a swapped or wrong-context envelope fails closed. |
| **key derivation** | `InternalDerivedKeysState::from_init_state` derives `db_key`, `properties_key`, and `api_auth_key` from the init root key, each with a distinct purpose label (`ops/internal_keys.rs`). | Key separation: a leak of one derived key does not expose the others or the root. All held in `Zeroizing`. |
| **bd (database)** | Operational keys, tokens, and index digests are persisted as encrypted Base64 envelopes. `StorageState` validates KIDs, hash-ids, digests, and envelope shape on **every read and write** before decrypting with `db_key` (`core/storage/`). | The DB never holds anything it could read on its own; a database backup without the matching init material decrypts nothing (Rule 14, Rule 26). |
| **load config** | `config_file::load_config_state` reads `config.json`, **verifies its signature** against the init keys before trusting any of it, then resolves the profiles. | Verify before trust: unsigned or tampered config is rejected. Lenient at startup (invalid → empty state + warning), strict at reload (invalid → keep the previous good state) — Rule 15. |
| **state** | The decrypted keys and the signed config live as `Arc<RwLock<Zeroizing<…>>>` in the HTTP state (`io/http/mod.rs`); `init_state` and `internal_keys` are shared `Arc<…Zeroizing…>`. | `RwLock` for safe concurrent access with a short critical section (Rule 3); `Arc` for sharing across handlers; a reload swaps state atomically under the write lock. |
| **zeroizing** | Every secret above — unseal key, init material, derived keys, decrypted keys, config — is wrapped in `Zeroizing`/`SensitiveString`; 180+ uses across the tree. Credential matching uses constant-time comparison. | Secret memory is overwritten on drop, never logged, and never placed in metrics labels (Rule 33). |

Why the design is shaped this way: the unseal key is the **single gate** — one
secret the operator holds, outside Vectis, unlocks everything and nothing works
without it. Everything at rest (init material, the entire database) is ciphertext,
so losing the disk is not losing the data. Trust always flows **from** the
operator-signed inputs (the unseal key, the signed config), never from a request
or a stored row. And no secret outlives its use: it is validated on the way in,
kept in locked memory while live, and zeroized on the way out.

## The Key Hierarchy: Every Key And Where It Comes From

The previous section followed the chain of custody. This one answers the two
questions a contributor asks next: **exactly which keys exist, and how many?**
Vectis never stores a key it can avoid storing — almost every key is *derived*
on demand with HKDF from a parent, using a **domain salt** (which capability)
and an **info context** (which profile / KID / version). Two rules make the tree
safe: **domain separation** (a different salt per purpose means the same parent
never yields the same child twice) and **context binding** (the info ties a
subkey to one exact profile and KID, so it is useless anywhere else).

There are four levels.

```
Level 0   unseal key          1   operator-held, 32 bytes, never derived, never stored
                              │    decrypts init.json (AEAD)
Level 1   node root key       1   the init symmetric key ("master key")
                              │    HKDF salt: vectis/internal-keys/v1
                              ├──► db_key           info: vectis/db-key/v1
Level 2   internal keys       3   ├──► properties_key    info: vectis/properties-key/v1
          (admin side)        │    └──► api_auth_key      info: vectis/api-key-auth/v1
                              │
                              │    (a separate, per-KID tree lives under each operational key)
Level 3   per-KID bundle      5   symmetric · eddsa · xecdh · ml-dsa · ml-kem   (+ hash variant)
          (one KID)          │    the "symmetric" member is the parent for capability subkeys
                              │    HKDF, per-capability salt + info(profile, kid, version)
                              ├──► FPE key
Level 4   per-operation       ├──► MAC key → HMAC subkey        (blind index reuses this)
          subkeys             ├──► tokenization: hash_key + data_key
                              ├──► commitment key → HMAC subkey
                              └──► sharing key → HMAC subkey
```

### Level 1 — the master key (one)

There is exactly **one** master key: the node **root symmetric key**, carried
inside the decrypted `init` material (`ValidatedInitState`). Everything else is
derived from it or from an operational key; nothing above it exists at runtime
except the unseal key that decrypted it. Losing the root (by losing the unseal
key) loses the node — by design, there is no recovery path.

### Level 2 — the internal / admin keys (three)

`InternalDerivedKeysState::from_init_state` ([`ops/internal_keys.rs`](../src/ops/internal_keys.rs))
derives **three** keys from the root, all with the same salt
(`vectis/internal-keys/v1`) but distinct info labels. These are the "admin side"
keys — they protect the database itself, not the user's values:

| internal key | derived with info | what it protects |
|---|---|---|
| `db_key` | `vectis/db-key/v1` | encrypts the operational **key-material bundle** stored in `opskeys.keys` (the envelope the whole per-KID tree lives in) |
| `properties_key` | `vectis/properties-key/v1` | encrypts the **metadata** stored in `opskeys.properties` (state, timestamps, profile bindings), kept under its own key so metadata and key bytes never share one |
| `api_auth_key` | `vectis/api-key-auth/v1` | HMACs presented **API keys** so only the hash is ever compared/stored (constant-time) |

So the mental model "a key per table" is close, but the precise rule is **a key
per purpose**: `db_key` and `properties_key` split the two columns of the
`opskeys` table by sensitivity, and `api_auth_key` guards authentication. The
`tokens` and `indexes` tables are protected by the per-KID keys below, not by a
fourth admin key.

### Level 3 — the operational key bundle (five per KID)

An operational key (a **KID**) is not one key — `create_key_material`
([`ops/key_material.rs`](../src/ops/key_material.rs)) generates a **bundle of
five** freshly random keys, plus a hash-algorithm marker. This whole bundle is
what `db_key` encrypts into `opskeys.keys`:

| member | kind | used by |
|---|---|---|
| `symmetric` | symmetric secret | the **parent** for every Level-4 subkey (FPE, MAC, blind index, tokenization, commitment, sharing) |
| `eddsa` | Ed25519 keypair | classical half of hybrid **signing** |
| `xecdh` | X25519 key-agreement keypair | classical half of post-quantum **messaging** |
| `ml-dsa` | ML-DSA keypair | post-quantum half of hybrid **signing** |
| `ml-kem` | ML-KEM keypair | post-quantum half of **messaging** |

The two signing schemes and the two messaging schemes are used **together**
(hybrid), so one broken assumption — classical *or* post-quantum — does not break
the guarantee.

### Level 4 — the per-operation subkeys (derived on demand)

The symmetric capabilities never use the KID's `symmetric` key directly. Each one
derives its own subkey with HKDF, using a capability-specific salt and an info
that binds the profile, the KID, and a version. This is why the same KID can back
FPE **and** MAC **and** tokenization without any of them sharing key bytes:

| capability | domain salt | subkeys | note |
|---|---|---|---|
| **FPE** | `vectis:fpe:ff1:v1` | 1 (the FF1 key) | info binds `(profile, kid, fpe_version)` |
| **MAC** | `vectis/mac/v1` → `vectis/mac/hmac/v1` | 2 levels (key, then HMAC subkey) | keyed tag via `derive_keyed_tag_subkey` |
| **Blind index** | *(reuses the MAC derivation)* | — | the digest is `mac::compute_digest`; that is why a blind index selects a MAC profile |
| **Tokenization** | `vectis/tokenization/v1` | 2 (`hash_key` + `data_key`) | one to derive the lookup hashid, one to encrypt the token payload |
| **Commitments** | `vectis/commitment/v1` → `vectis/commitment/hmac/v1` | 2 levels | context-bound like MAC |
| **Secret sharing** | `vectis/sharing/v1` → `vectis/sharing/hmac/v1` | 2 levels | authenticates each share |
| **Masking** | *(none)* | 0 | masking is a policy view, not a keyed operation |
| **Signing / Messaging** | *(none — asymmetric)* | 0 | these use the `eddsa`/`ml-dsa` (sign) and `xecdh`/`ml-kem` (messaging) keypairs directly |

The payoff of doing it this way: no capability's key is ever the same as
another's, a subkey cannot be replayed under a different profile or KID, and every
symmetric secret in the system traces back through exactly one derivation path to
the single master key — which itself never leaves the node in the clear.

## The Database And Its Tables

Vectis stores almost nothing, and what it stores is ciphertext. The schema is
**three tables** ([`src/db/sqlite_schema.sql`](../src/db/sqlite_schema.sql),
[`src/db/postgres_schema.sql`](../src/db/postgres_schema.sql)) — and, importantly,
Vectis does **not** create or migrate them: the operator applies the DDL and
Vectis validates the shape at startup, failing closed if a table is missing
(Rule 25). Every row is validated as untrusted input on **every** read and write
before anything is decrypted (Rule 14).

| table | columns | what it holds | protected by |
|---|---|---|---|
| **`opskeys`** | `kid` (PK), `keys`, `properties` | one row per operational key. `keys` is the encrypted Level-3 bundle (the five keys); `properties` is the encrypted metadata (lifecycle state, profile bindings, timestamps). | `keys` ← `db_key`, `properties` ← `properties_key` |
| **`tokens`** | `(kid, hashid)` (PK), `data` | the tokenization vault: one row per tokenized value. `hashid` is the deterministic lookup handle (from the token `hash_key`); `data` is the encrypted original payload (under the token `data_key`). | per-KID tokenization subkeys (Level 4) |
| **`indexes`** | `(kid, digest)` (PK), — | the blind-index set: the mere **presence** of a `(kid, digest)` row is the searchable fact. The digest is a MAC of the value; the value itself is never stored. | per-KID MAC subkey (Level 4) |

Three things about this schema are the whole design in miniature:

- **The composite primary keys are the security model, not just an index.**
  `(kid, hashid)` and `(kid, digest)` mean a token or index entry is only ever
  meaningful *within its KID* — you cannot mix rows across keys, and idempotent
  creation falls out for free (creating the same blind index twice is a no-op by
  the primary key, Rule 24).
- **A blind index stores no value at all** — only a keyed digest. You can ask "is
  there a record whose value MACs to this digest?" and get yes/no, without the
  database ever holding the value or anything reversible to it.
- **A stolen database is inert.** `opskeys.keys` is encrypted under `db_key`,
  which is derived from the root, which is decrypted by the unseal key the
  operator holds outside Vectis. Without that key the three tables are noise —
  which is exactly what the recovery boundary in `HA_DR.md` depends on.

## The Three Layers And The Dependency Graph

Vectis materializes the layers as **directories**. The dependency points inward:

```
        io/                 ops/               core/
   (adapters)     ──►  (operations)   ──►  (primitives)
   http/ + cli/        keys, fpe, sign,    crypto, validation,
                       message, ...        config, storage, ...
```

- **`core`** — reusable primitives: validation, crypto, config, storage, logging.
  **Knows nothing** about business flows.
- **`ops`** — business operations and protocol flows. Depends on `core` only.
- **`io`** — HTTP and CLI adapters. Depends on `ops` and `core`. Handlers are
  **thin**: authenticate, parse, delegate, map.

The rule is law (Design.md, Rule 2): if a lower layer needs a type owned by an
upper one, the type is **mirrored downward** and converted at the boundary — never
imported upward. Real example: `PeerPublicKeys` lives in `core/remote_routes.rs`
and it is `ops` that converts it, so that `core` does not import `ops::contracts`.

In Rust this is enforced with module visibility (`pub(crate)`) and review.

## Reference: The `core` Layer (`src/core/`)

Generic primitives. Table format: **module | what it does | why it is needed**.
Given the size of the system (~40,000 lines), this reference is at the **file**
level, not the function level; for the internal detail, each file has its own
`#[cfg(test)]` tests.

### The security core (read this first)

| module | what it does | why it is needed |
|---|---|---|
| `validation.rs` | validators for names, refs, labels, hex, host/port, keys; `build_validated_aad` | The trust boundary; *parse, don't validate* (Rules 9-13) |
| `crypto.rs` | crypto helpers over the Botan backend (AEAD, derivation, etc.) | The primitives every operation uses |
| `canonical.rs` | deterministic versioned encoding `canonical_json_v1` | Sign canonical bytes; two equal documents sign identically (Rule 29) |
| `protocol.rs` | protocol version and its binding | Closes version downgrades inside the signed payload (Rule 29) |
| `unseal.rs` | handles the unseal key that decrypts the `init` material | The most sensitive point: without the key, nothing starts |
| `sensitive.rs` | `SensitiveString` (a `Zeroizing` wrapper) | Secrets are wiped from memory on drop (Rule 33) |
| `permissions.rs` | permission model (allowlists), `PermissionsState`, constant-time auth | Deny-by-default; separates authorization from authentication (Rules 33, 34) |

### Configuration and storage

| module | what it does | why it is needed |
|---|---|---|
| `config.rs` | settings precedence (env → `.env` → defaults), `VECTIS_` prefix, limits as constants | One settings source; named bounds (Rules 8, 18) |
| `config_file.rs` | **the only** loader of signed `config.json`; lenient load vs strict reload; size caps | One config, one signature, one loader (Rules 6, 15, 18) |
| `routes.rs` | local routes from the signed config | Routing governed by the operator |
| `remote_routes.rs` | peers and their public keys from the signed config (`RemoteRouteInput` → `RemoteRoute`, `PeerPublicKeys`) | Peer trust comes only from signed config (Rules 7, 31) |
| `storage/mod.rs` | `StorageState`, rows (`OpsKeyRow`, `TokenRow`, `IndexRow`); validates on every read/write | Persisted data is untrusted input (Rule 14) |
| `storage/sqlite.rs`, `storage/postgres.rs` | the concrete storage backends | One node (SQLite) or many (PostgreSQL) with the same contract |
| `files.rs` | bounded operator-file reads (`metadata` before reading) | Bound everything before expensive work (Rule 18) |

### The capability primitives

| module | what it does | why it is needed |
|---|---|---|
| `fpe.rs` | format-preserving encryption + profiles | The FPE capability primitive |
| `tokenization.rs` | reversible tokenization + key derivation | The tokenization primitive |
| `masking.rs` | masking under policy | The masking primitive |
| `mac.rs` | message authentication codes | The MAC primitive |
| `commitments.rs` | cryptographic commitments | The commitments primitive |
| `sharing.rs` | secret sharing (split/combine) | The secret-sharing primitive |
| `time_attestation.rs` | time attestation | The time-attestation primitive |

### Observability and infrastructure

| module | what it does | why it is needed |
|---|---|---|
| `blocking.rs` | `spawn_blocking_crypto`: offloads CPU-bound crypto off the async runtime | So the event loop never stalls (Rule 3) |
| `audit.rs` | audit events (actor, resource, action, outcome), no secrets | Security evidence separate from logs (Rule 42) |
| `audit_chain.rs` | hash-chained audit log + signed checkpoints | Detects local record tampering (Rule 42) |
| `logging.rs` | operational log init (JSON) | Operational channel separate from audit (Rule 42) |
| `metrics.rs` | Prometheus metrics with low-cardinality labels | Runtime health without leaking content (Rule 42) |
| `http_client.rs` | outbound HTTP client with a deadline and no automatic retries | Every outbound call has a deadline (Rule 27) |
| `tls.rs` | crypto / TLS provider | HTTPS as the only mode (Rule 34) |
| `project.rs` | identity constants (name, version, license, capabilities) | Binary metadata in one place |
| `mod.rs` | declares the `core` submodules | Assembles the layer |

## Reference: The `ops` Layer (`src/ops/`)

Business operations. Each takes validated input, resolves policy/keys, and uses the
`core` primitives. The per-capability files expose entry points shaped
`parse → validate → prepare → execute`.

| module | what it does | why it is needed |
|---|---|---|
| `keys.rs` | operational keys and their **lifecycle** (`active`/`disabled`/`retired`/`compromised`/`destroyed`) | The central resource; the lifecycle is decided in one place (Rule 36) |
| `key_material.rs`, `key_validation.rs`, `internal_keys.rs` | key-material types, their validation, and internal keys derived from init | Model and validate keys before use |
| `init.rs` | `init` material (`ValidatedInitState`), bootstrap | The node's root of trust |
| `sign.rs` | hybrid signing (ML-DSA + EdDSA) and verification; verifies the config signature | Verify before trusting; validate encoding before crypto (Rules 29, 32) |
| `slh_dsa.rs` | SLH-DSA signatures (hash-based, stateless) | An alternative post-quantum scheme |
| `message.rs` | post-quantum protected messaging (`send`/`receive`), AAD binding 8 context fields | Verify before decrypt, bound context (Rule 30) |
| `fpe.rs`, `tokenization.rs`, `masking.rs`, `mac.rs`, `commitments.rs`, `sharing.rs` | the operations of each capability over its `core` primitive | The business logic of each capability |
| `indexes.rs` | blind indexes (idempotent creation by `(kid, digest)`) | Search without revealing; idempotency by construction (Rule 24) |
| `pubkey.rs` | public-key exposure (blocked for retired keys) | Discovery governed by the lifecycle (Rule 36) |
| `apikey.rs` | API-key creation/verification | Credential bootstrap |
| `contracts.rs` | the request/response types `ops` exposes | The type boundary `io` translates |
| `batch.rs`, `json.rs` | batch helpers (`ref` correlation) and JSON helpers | Utilities shared across operations (Rule 24) |
| `time_attestation.rs`, `test.rs` | time attestation and self-test | Auxiliary operations |
| `mod.rs` | declares the `ops` submodules | Assembles the layer |

## Reference: The `io` Layer (`src/io/`)

Adapters. `io/http/` serves the API; `io/cli/` is the command line. Both are
**thin**: they make no business decisions.

### `io/http/` — the server

| module | what it does | why it is needed |
|---|---|---|
| `app.rs` | bootstrap: assembles state, router, TLS, and graceful shutdown | The service assembly (Rules 3, 28) |
| `mod.rs` | router construction (routes → handlers) | Wires every endpoint |
| `auth.rs` | API-key authentication state and middleware | The authentication boundary (Rule 33) |
| `middleware.rs` | HTTP middleware (body size cap, etc.) | Bounds input before parsing (Rule 18) |
| `extract.rs` | request extractors (`JsonBody` with a cap) | Bounded, uniform parsing |
| `error.rs` | `status_for_error`: exhaustive error→status `match`; public messages | Map errors without leaking internals (Rules 21, 22) |
| `health.rs`, `metrics.rs` | readiness/liveness endpoints and `/metrics` | Observability and healthchecks |
| `keys.rs`, `sign.rs`, `fpe.rs`, `token.rs`, `mac.rs`, `masking.rs`, `indexes.rs`, `commitments.rs`, `sharing.rs`, `message.rs`, `time.rs`, `pubkey.rs` | thin per-capability handlers | Translate HTTP ↔ `ops`, nothing more |
| `config.rs`, `routes.rs`, `remote_routes.rs`, `permissions.rs` | signed-config management endpoints | Operate policy via API |
| `test.rs` | self-test endpoint | Live verification |

### `io/cli/` — the command line

| module | what it does | why it is needed |
|---|---|---|
| `http.rs` | runtime command dispatch → **client** of the HTTP API | The CLI is a client, not a second implementation (Rule 5) |
| `init.rs` | local `init`: creates/loads the bootstrap material | Must work before the service exists |
| `apikey.rs` | local `apikey` (credential bootstrap) | Create the first credential without a service |
| `config_editor.rs` | signed-config editors (init/list/validate/sign) | Prepare and sign artifacts the service consumes (Rule 17) |
| `audit.rs` | audit-log inspection | Operate the security evidence |
| `slh_dsa.rs` | SLH-DSA commands | Operate that signature scheme |
| `version.rs`, `help_catalog.rs`, `sensitive.rs` | version, help catalog, and sensitive input | Interface utilities |
| `mod.rs` | declares the CLI submodules | Assembles the layer |

## Reference: Top Level And Schema (`src/`, `src/db/`)

| module | what it does | why it is needed |
|---|---|---|
| `main.rs` | root command dispatch and the `serve` path | The binary's entry point |
| `lib.rs` | declares the layers (`core`, `ops`, `io`, `error`) | The crate root |
| `error.rs` | `VectisError` (8 variants = response categories) + constructors + serde-error sanitizing | One semantic error type (Rules 20-22) |
| `db/sqlite_schema.sql`, `db/postgres_schema.sql` | reference DDL (the operator applies the schema) | The operator owns the schema; Vectis does not migrate (Rule 25) |
| `db/data_init.sh`, `db/data.db` | init script and sample DB | Spin up a local lab |

## The Security Spine

A contributor can break a capability by accident if they do not respect these
cross-cutting invariants. They are the heart of Vectis:

- **Verify before decrypt, always.** `receive_message` verifies signatures before
  opening the cipher. Never process unauthenticated bytes with your keys (Rule 30).
- **Bind the context with AAD.** The AEAD binds version, type, sender, recipient,
  algorithms, and timestamp, so a ciphertext is valid only in its exact context.
  Never hand-concatenate AAD: use `build_validated_aad` (Rules 12, 30).
- **Validate encoding before crypto.** First size, alphabet, segment count, and
  non-emptiness; *then* verify signatures or tags over the original bytes (Rule 32).
- **Secrets are radioactive.** `Zeroizing`/`SensitiveString` to wipe them from
  memory; constant-time comparison for secret material; never in logs or metrics
  labels (Rule 33).
- **The request selects policy, it does not define it.** Profiles, peers, and
  algorithms come from signed config or validated storage, never inline (Rule 31).
- **Lenient startup, strict reload.** An invalid config at startup yields a safe
  empty state + warning; at runtime an invalid reload is rejected and the previous
  good state is kept (Rule 15).

## What Vectis Does Not Do

As important as what it does. Vectis does **not** replace:

- TLS, KMS, HSMs, secrets managers, database encryption, access control, or
  traditional DLP tools.

And today it does **not** provide: Merkle proofs, external anchoring for its
audit-chain checkpoints, Vault/KMS/HSM auto-unseal, or mTLS. Every new capability
must answer the scope question (Rule 1): *is this responsibility intrinsic to
Vectis, or are we taking work away from a layer that already solves it well?* Key
rewrap/migration was **rejected** against that boundary.

## Glossary

- **Capability** — one of the protection functions (FPE, tokenization, MAC…).
- **Profile** — a named crypto configuration, approved in the signed config, that a
  request selects (does not define).
- **Signed config** — `config.json` + its signature; contains routes, peers,
  permissions, and profiles, loaded by a single loader.
- **`init` / unseal** — the node's encrypted root material and the key that opens
  it; without the key, the node does not start.
- **AAD** (*Authenticated Associated Data*) — the context bound to a ciphertext so
  it is valid only for its exact sender/recipient/version.
- **KID** — an operational key's identifier.
- **Lifecycle** — a key's states (`active`, `disabled`, `retired`, `compromised`,
  `destroyed`) and their transitions.
- **`ops` / `core` / `io`** — the three layers: operations, primitives, adapters.
- **`VectisError`** — the single semantic error type; its variants are response
  categories.

## Where To Start Reading The Code

In this order, from highest to lowest "aha" density:

1. [`src/main.rs`](../src/main.rs) — command dispatch and the `serve` path. Short,
   and reveals the whole entry structure.
2. [`src/io/http/app.rs`](../src/io/http/app.rs) — server startup: how init,
   config, storage, keys, and router are assembled.
3. A full vertical slice: [`src/io/http/fpe.rs`](../src/io/http/fpe.rs) →
   [`src/ops/fpe.rs`](../src/ops/fpe.rs) → [`src/core/fpe.rs`](../src/core/fpe.rs).
   See the `io → ops → core` pattern end to end.
4. [`src/core/validation.rs`](../src/core/validation.rs) — the trust boundary;
   understand *parse, don't validate*.
5. [`src/error.rs`](../src/error.rs) and
   [`src/io/http/error.rs`](../src/io/http/error.rs) — how an error becomes an HTTP
   status.
6. [Design.md](Design.md) — the 44 rules, each with its "In Vectis" pointer. It is
   the rationale for everything above.
