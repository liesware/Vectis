# Vectis

<p align="left">
  <img width="300" alt="Vectis logo" src="logo.png">
</p>

Vectis is an **open source advanced data protection service**:
format-preserving encryption, reversible tokenization, masking, MACs, blind
indexes, commitments, and post-quantum protected messaging/signing — governed by an
operator-signed configuration, served through a consistent HTTP and CLI
interface.

**TLS protects the connection. Vectis protects the data.** Sensitive data often
continues moving through applications, services, queues, storage, logs, workers,
and final systems after the transport session is over; Vectis protects the data
object or payload itself after it leaves the transport layer.

> In Latin, *vectis* can mean a lever, crowbar, fastening bar, or carrying pole:
> a simple tool used to move something heavy with controlled force.

> **Status: in progress.** Vectis is under active development and has not yet
> completed an external security audit. It is suitable for evaluation, demos,
> and design-partner PoCs, but should not be used as the sole protection layer
> for production sensitive data yet.

## Why Vectis?

Modern systems already use important security controls:

- TLS;
- encrypted disks;
- cloud KMS;
- HSMs;
- secrets managers;
- access control;
- database encryption;
- traditional DLP tools.

Those controls are necessary, but sensitive data can still appear in plaintext
inside application payloads, logs, queues, databases, backups, internal APIs, and
temporary processing steps.

Vectis answers a different question:

> What if sensitive data stayed protected as a data object while it moves
> through an application workflow?

Advanced data protection — tokenization, format-preserving encryption, masking,
encryption as a service — has traditionally shipped as expensive enterprise
licensing. Vectis provides that capability as free, self-hosted, open source
software, and leaves every other job (secrets, transport, key custody) to the
tools that already do it well.

Not sure which primitive solves your problem? See the how-to-choose table in
[doc/UseCases.md](doc/UseCases.md).

## Philosophy

Vectis tries to stay close to the Unix philosophy. Peter H. Salus summarized it
in 1994, crediting Doug McIlroy:

```text
Write programs that do one thing and do it well.
Write programs to work together.
Write programs to handle text streams, because that is a universal interface.
```

Vectis has one narrow job: provide composable cryptographic protection for
sensitive data workflows. It does not try to replace TLS, KMS, HSMs, databases,
access control, or traditional DLP tools. Those systems already have their own
jobs.

Vectis exposes HTTP, CLI commands, JSON, OpenAPI, logs, and metrics because
plain interfaces are easier to inspect, automate, and combine. Future
capabilities such as stronger clustering, HSM/KMS support, mTLS, or additional
distributed storage should exist only when the operating environment requires
them, not as product tiers or decorative complexity.

## What Vectis Does Today

Vectis currently provides an HTTP service and CLI for cryptographic data
protection primitives and workflows.

**Cryptography**

- hybrid post-quantum key establishment with XECDH + ML-KEM;
- dual signatures with EdDSA and ML-DSA, both required to verify;
- authenticated encryption for protected payloads;
- canonical JSON signing with explicit protocol versioning bound to signatures;
- selectable crypto profiles (see [Crypto Profiles](#crypto-profiles)).

**Protocol and trust**

- protected messages between Vectis instances, verified before decryption;
- one operator-signed config file (routes, remote routes, permissions, FPE
  profiles, tokenization profiles, MAC profiles, commitment profiles, and masking profiles); its registered
  `remote_routes` are the only source of peer public keys — no trust-on-first-use
  path;
- local re-encryption before final app delivery: the receiving application
  never gets remote plaintext directly;
- public key publication by `kid`;
- internal encrypt/decrypt endpoints for local protected data;
- local FF1 format-preserving encryption for signed field profiles;
- local reversible random tokenization for signed token profiles;
- local MAC create/verify for signed MAC profiles;
- local keyed cryptographic commitments with random openings;
- local blind indexes that reuse signed MAC profiles and persist deterministic
  membership digests.
- local display masking for signed masking profiles.

**Key management**

- encrypted local init key material;
- HKDF-derived internal keys for storage encryption and API key verification;
- operational key creation and validation;
- encrypted key lifecycle metadata and runtime lifecycle enforcement;
- SQLite/PostgreSQL-backed storage for encrypted operational keys, encrypted
  tokenization payloads, and blind index digests behind a storage abstraction.

**Operations and observability**

- startup, liveness, and readiness health probes;
- a dedicated security audit log stream with per-request correlation ids;
- a Prometheus `/metrics` endpoint for operational observability;
- local CLI commands plus CLI commands that act as an HTTP API client;
- OpenAPI and environment variable documentation.

## High-Level Flow

```text
Application A
    |
    | private record / sensitive payload
    v
Vectis A
    |
    | hybrid KEM + authenticated encryption + signatures
    v
Vectis B
    |
    | verify + decrypt + local re-encrypt
    v
Application B
    |
    | local decrypt through Vectis B
    v
Recovered private record / sensitive payload
```

The receiving application does not receive remote plaintext directly. It receives
a local encrypted delivery and must ask its local Vectis instance to decrypt it.

## Clinical Data Exchange Demo

The repository includes a two-site clinical demo:

- Clinic A reads a patient record JSON file.
- Vectis A protects and sends the record.
- Vectis B verifies, decrypts, and re-encrypts the record for Clinic B.
- Clinic B's final app calls local Vectis to decrypt and print the recovered
  record.

See [demo/message/README.md](demo/message/README.md).

Quick demo setup:

```sh
bash demo/message/setup.sh
bash demo/message/create-keys.sh
bash demo/message/configure-routes.sh
```

Then run the four demo processes:

```sh
bash demo/message/start-vectis-a.sh
bash demo/message/start-vectis-b.sh
bash demo/message/start-app-a.sh
bash demo/message/start-app-b.sh
```

In the Clinic A terminal:

```text
clinic-a file: ../personaldata.json
```

## Local Data Protection Demo

The repository also includes a single-node local demo over SQLite and HTTP. It
shows field-level protection with three synthetic categories: credit card PAN,
SSN, and bank account values.

The demo exercises:

- FPE encrypt/decrypt;
- reversible token encode/decode;
- MAC create/verify;
- blind index create/verify;
- `/message/internal` encrypt/decrypt;
- sign and verification.

See [demo/local/README.md](demo/local/README.md).

Quick local demo setup:

```sh
bash demo/local/setup.sh
bash demo/local/create-keys.sh
bash demo/local/configure-config.sh
```

Then run the local Vectis instance and demo runner:

```sh
bash demo/local/start-vectis.sh
uv run demo/local/run-demo.py
```

## Architecture

Vectis follows a simple three-layer structure:

- `core`: infrastructure and reusable primitives such as configuration,
  validation, crypto helpers, logging, storage, routes, and database access.
- `ops`: application operations and business flows such as init, key creation,
  signing, validation, protected messaging, FPE, tokenization, and tests.
- `io`: input/output adapters such as HTTP endpoints and CLI commands.

The intent is to keep protocol and business logic out of HTTP handlers, and to
keep low-level reusable primitives out of higher-level operation flows.

## Quick Start

Requirements:

- Rust toolchain with `cargo`;
- SQLite CLI (`sqlite3`).

Build the project:

```sh
cargo build
```

Initialize local encrypted key material:

```sh
cargo run -- init
```

The command prints:

- `VECTIS_UNSEAL_KEY`: used to decrypt the configured init keys file;
- `VECTIS_INIT_KEYS_FILE`: encrypted init key material path, default `init.json`;
- `VECTIS_APIKEY`: client secret generated with a cryptographic random number
  generator and sent as `X-API-Key`;
- `VECTIS_APIKEY_HASH`: server-side verifier for protected HTTP endpoints.

For local development, save the unseal key in `.unseal_key`:

```sh
printf '%s\n' '<VECTIS_UNSEAL_KEY>' > .unseal_key
chmod 600 .unseal_key
```

Create a SQLite database file and schema:

```sh
mkdir -p src/db
sqlite3 src/db/data.db < src/db/sqlite_schema.sql
```

Start the HTTP service:

```sh
cargo run -- serve
```

Check readiness:

```sh
cargo run -- health ready
```

Create an operational key:

```sh
cargo run -- keys create --tag payments --profile hybrid-performance-v1
```

List public keys loaded in memory:

```sh
cargo run -- keys list
```

## CLI And API

The CLI is primarily an HTTP client for the local Vectis service.

Examples:

```sh
vectis version
vectis health ready
vectis apikey create
vectis keys create --tag payments --profile hybrid-high-assurance-v1
vectis keys list
vectis pub <kid>
vectis fpe encrypt <kid> --file fpe-encrypt.json
vectis token encode <kid> --file token-encode.json
vectis mac create <kid> --file mac-create.json
vectis mac verify --file mac-verify.json
vectis index create <kid> --file index-create.json
vectis index verify --file index-verify.json
vectis commit create <kid> --file commit-create.json
vectis commit verify --file commit-verify.json
vectis mask <kid> --file mask.json
vectis message send <sender_kid> --file send-message.json
vectis message decrypt --file encrypted-message.json
vectis config sign
vectis config reload
```

See the full API documentation in [doc/API.md](doc/API.md).

## Configuration

Runtime routing, remote peers, API-key permissions, FPE profiles, tokenization
profiles, MAC profiles, commitment profiles, and masking profiles live in a single **signed config file** (`config.json`,
default path `VECTIS_CONFIG_PATH`) with `version`, `routes`, `remote_routes`,
`permissions`, optional `fpe_profiles`, optional `tokenization_profiles`, and
optional `mac_profiles`, `commitment_profiles`, and `masking_profiles` sections. Blind indexes reuse `mac_profiles`; there is
no separate `index_profiles` section. Edit it, then sign it with
`vectis config sign`. The full schema
(every field, allowed values, and the optional peer `public_keys`) is documented
under **Configuration File (`config.json`)** in [doc/API.md](doc/API.md).

Vectis reads process/environment settings from process environment variables
first, then from `.env`, then from built-in defaults.

All Vectis-specific variables use the `VECTIS_` prefix.

The essentials to get a local instance running:

- `VECTIS_HTTP_BIND_ADDR`: listen address, default `127.0.0.1:3000`;
- `VECTIS_MODE`: `dev` (HTTP) or `prod` (HTTPS, requires TLS cert and key);
- `VECTIS_INIT_KEYS_FILE`: encrypted init key material, default `init.json`;
- `VECTIS_UNSEAL_KEY_FILE`: unseal key file, default `.unseal_key`;
- `VECTIS_STORAGE`: `sqlite` by default, or `postgres` for shared storage;
- `VECTIS_SQLITE_PATH`: SQLite operational key storage, default `src/db/data.db`
  in dev builds;
- `VECTIS_POSTGRES_DSN`: PostgreSQL DSN when `VECTIS_STORAGE=postgres`;
- `VECTIS_CONFIG_PATH`: signed config file, default `config.json`.

See [doc/ENV.md](doc/ENV.md) for the full list and expected values.

## Crypto Profiles

`POST /keys` supports crypto profiles:

- `hybrid-performance-v1`;
- `hybrid-standard-v1`;
- `hybrid-high-assurance-v1`;
- `hybrid-long-term-v1`.

By default, Vectis uses profile-only policy:

```text
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-performance-v1
VECTIS_CRYPTO_POLICY=profile-only
```

In development and tests, individual algorithm overrides can be enabled with:

```text
VECTIS_CRYPTO_POLICY=allow-overrides
```

## FPE, Tokenization, MAC, Commitments, Blind Indexes, And Masking

FPE, tokenization, MAC, commitments, blind indexes, and masking are
profile-driven. Profiles are loaded only from signed config, and requests select
a profile by name. Commitments use random openings so repeated commitments for
the same plaintext differ. Blind indexes reuse MAC profiles and persist the
resulting deterministic digest.
Masking is display-only: it reveals configured leading/trailing characters and
replaces the middle with a configured mask character.

FPE currently supports:

```text
fpe-ff1-2025
```

Tokenization currently supports:

```text
token-random-v1
```

MAC currently supports HMAC with the operational key hash algorithm, or
`KMAC-224`, `KMAC-256`, `KMAC-384`, and `KMAC-512` when the operational key
uses the corresponding SHA-3 hash size. MAC profile `context` values use
structured labels such as `tenant=mx;field=pan;purpose=blind-index;version=1`.

The CLI can edit these profile sections locally:

```sh
vectis config fpe add --name patient-id-decimal-v1 --kid <kid> --alphabet 0123456789 --min-len 6 --max-len 32 --tweak-aad 'tenant=acme;field=patient_id;version=1'
vectis config token add --name patient-id-token-v1 --kid <kid> --token-prefix tok_patient --token-len 32 --max-plaintext-len 1024
vectis config mac add --name pan-blind-index-v1 --kid <kid> --context 'tenant=mx;field=pan;purpose=blind-index;version=1'
vectis config commitment add --name pan-commitment-v1 --kid <kid> --context 'tenant=mx;field=pan;purpose=commitment;version=1' --max-plaintext-len 128 --opening-len 32
vectis config masking add --name pan-display-v1 --kid <kid> --visible-first 0 --visible-last 4 --mask-char '*' --min-len 12 --max-len 19
vectis config sign
vectis config reload
```

## Testing

See [doc/Test.md](doc/Test.md) for the full testing strategy, including Rust
checks, Python HTTP workflows with `uv`, Schemathesis OpenAPI fuzzing, and
native `cargo-fuzz` targets.

## Documentation

- [doc/API.md](doc/API.md): HTTP API and CLI mapping.
- [doc/UseCases.md](doc/UseCases.md): real-world use cases per feature.
- [doc/CLI.md](doc/CLI.md): CLI behavior, commands, output, and environment.
- [doc/ENV.md](doc/ENV.md): environment variables and expected values.
- [doc/Test.md](doc/Test.md): testing strategy and test commands.
- [doc/Clustering.md](doc/Clustering.md): multi-node behavior and shared
  storage model.
- [doc/HA_DR.md](doc/HA_DR.md): high availability, backups, restore, and
  recovery limits.
- [doc/openapi.yaml](doc/openapi.yaml): OpenAPI specification.
- [doc/ThreatModel.md](doc/ThreatModel.md): threat model, explicit assumptions,
  and limitations.
- [doc/Reference.md](doc/Reference.md): architecture and design reference.
- [doc/Internal.md](doc/Internal.md): implementation flows and internal invariants.
- [doc/Design.md](doc/Design.md): reusable design principles distilled from this project.
- [demo/message/README.md](demo/message/README.md): clinical data exchange demo.
- [demo/local/README.md](demo/local/README.md): local FPE, tokenization, MAC,
  blind indexes, internal message, and sign demo.
- [charts/vectis/README.md](charts/vectis/README.md): Kubernetes Helm chart.

## What Vectis Is Not

Vectis is not a replacement for:

- TLS;
- KMS;
- HSMs;
- secrets managers;
- database encryption;
- access control;
- traditional DLP products.

Vectis does not currently provide Merkle proofs, tamper-evident audit chains,
SLH-DSA, Vault/KMS/HSM auto-unseal, or mTLS.

Vectis is intended to complement existing security controls by providing
cryptographic protection for sensitive data workflows. It should work with
other tools, not absorb their responsibilities.

## Security Status

Vectis is currently experimental and under active development. It has not yet
completed an external security audit, and its APIs and operational model may
still change as the project matures.

Use Vectis for evaluation, demos, internal testing, and design-partner PoCs. Do
not rely on it as the only protection layer for production patient data,
production secrets, financial records, or other sensitive data yet.

The threat model, explicit assumptions, and known limitations are documented in
[doc/ThreatModel.md](doc/ThreatModel.md).

## License

Licensed under the Apache License, Version 2.0
