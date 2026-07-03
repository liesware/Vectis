# Vectis

<p align="left">
  <img width="300" alt="Vectis logo" src="logo.png">
</p>

Vectis is a personal open source project for **Sensitive Data Lifecycle
Protection**.

The core idea is simple: TLS protects the connection, but sensitive data often
continues moving through applications, services, queues, storage, logs, workers,
and final systems after the transport session is over. Vectis explores how to
protect the data object itself across that lifecycle.

> In Latin, *vectis* can mean a lever, crowbar, fastening bar, or carrying pole:
> a simple tool used to move something heavy with controlled force.

This project is experimental and should be treated as a work in progress.

**Do not use Vectis to protect real sensitive data yet.**

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

Vectis explores a different question:

> What if sensitive data stayed protected as a data object while it moves
> through its lifecycle?

## What Vectis Does Today

Vectis currently provides a small HTTP service and CLI for experimenting with
protected data flows between Vectis instances.

**Cryptography**

- hybrid post-quantum key establishment with XECDH + ML-KEM;
- dual signatures with EdDSA and ML-DSA, both required to verify;
- authenticated encryption for protected payloads;
- canonical JSON signing with explicit protocol versioning bound to signatures;
- selectable crypto profiles (see [Crypto Profiles](#crypto-profiles)).

**Protocol and trust**

- protected messages between Vectis instances, verified before decryption;
- one operator-signed config file (routes, remote routes, permissions) as the
  only source of peer public keys — no trust-on-first-use path;
- local re-encryption before final app delivery: the receiving application
  never gets remote plaintext directly;
- public key publication by `kid`;
- internal encrypt/decrypt endpoints for local protected data.

**Key management**

- encrypted local init key material;
- HKDF-derived internal keys for storage encryption and API key verification;
- operational key creation and validation;
- encrypted key lifecycle metadata and runtime lifecycle enforcement;
- SQLite-backed operational key storage behind a storage abstraction.

**Operations and observability**

- startup, liveness, and readiness health probes;
- a dedicated security audit log stream with per-request correlation ids;
- a Prometheus `/metrics` endpoint for operational observability;
- CLI commands that act as an HTTP API client;
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

See [demo/README.md](demo/README.md).

Quick demo setup:

```sh
bash demo/setup.sh
bash demo/create-keys.sh
bash demo/configure-routes.sh
```

Then run the four demo processes:

```sh
bash demo/start-vectis-a.sh
bash demo/start-vectis-b.sh
bash demo/start-app-a.sh
bash demo/start-app-b.sh
```

In the Clinic A terminal:

```text
clinic-a file: ../personaldata.json
```

## Architecture

Vectis follows a simple three-layer structure:

- `core`: infrastructure and reusable primitives such as configuration,
  validation, crypto helpers, logging, storage, routes, and database access.
- `ops`: application operations and business flows such as init, key creation,
  signing, validation, protected messaging, and tests.
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
- `VECTIS_APIKEY`: client secret generated with a cryptographic random number generator and sent as `X-API-Key`;
- `VECTIS_APIKEY_HASH`: server-side verifier for protected HTTP endpoints.

For local development, save the unseal key in `.unseal_key`:

```sh
printf '%s\n' '<VECTIS_UNSEAL_KEY>' > .unseal_key
chmod 600 .unseal_key
```

Create a SQLite database file and schema:

```sh
mkdir -p src/db
sqlite3 src/db/data.db < src/db/data_schema.sql
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
vectis health ready
vectis apikey create
vectis keys create --tag payments --profile hybrid-high-assurance-v1
vectis keys list
vectis pub <kid>
vectis message send <sender_kid> --file send-message.json
vectis message decrypt --file encrypted-message.json
vectis config sign
vectis config reload
```

See the full API documentation in [doc/API.md](doc/API.md).

## Configuration

Runtime routing, remote peers, and API-key permissions live in a single **signed
config file** (`config.json`, default path `VECTIS_CONFIG_PATH`) with `version`,
`routes`, `remote_routes`, and `permissions` sections. Edit it, then sign it with
`vectis config sign`. The full schema (every field, allowed values, and the
optional peer `public_keys`) is documented under **Configuration File
(`config.json`)** in [doc/API.md](doc/API.md).

Vectis reads process/environment settings from process environment variables
first, then from `.env`, then from built-in defaults.

All Vectis-specific variables use the `VECTIS_` prefix.

The essentials to get a local instance running:

- `VECTIS_HTTP_BIND_ADDR`: listen address, default `127.0.0.1:3000`;
- `VECTIS_MODE`: `dev` (HTTP) or `prod` (HTTPS, requires TLS cert and key);
- `VECTIS_INIT_KEYS_FILE`: encrypted init key material, default `init.json`;
- `VECTIS_UNSEAL_KEY_FILE`: unseal key file, default `.unseal_key`;
- `VECTIS_SQLITE_PATH`: operational key storage, default `src/db/data.db` in
  dev builds;
- `VECTIS_CONFIG_PATH`: signed config file, default `config.json`.

See [doc/ENV.md](doc/ENV.md) for the full list and expected values.

## Crypto Profiles

`POST /keys` supports crypto profiles:

- `hybrid-performance-v1`;
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

## Testing

See [doc/Test.md](doc/Test.md) for the full testing strategy, including Rust
checks, Python HTTP workflows with `uv`, Schemathesis OpenAPI fuzzing, and
native `cargo-fuzz` targets.

## Documentation

- [doc/API.md](doc/API.md): HTTP API and CLI mapping.
- [doc/ENV.md](doc/ENV.md): environment variables and expected values.
- [doc/Test.md](doc/Test.md): testing strategy and test commands.
- [doc/openapi.yaml](doc/openapi.yaml): OpenAPI specification.
- [doc/ThreatModel.md](doc/ThreatModel.md): threat model, explicit assumptions, and limitations.
- [doc/Reference.md](doc/Reference.md): architecture and design reference.
- [doc/Design.md](doc/Design.md): reusable design principles distilled from this project.
- [demo/README.md](demo/README.md): clinical data exchange demo.

## What Vectis Is Not

Vectis is not a replacement for:

- TLS;
- KMS;
- HSMs;
- secrets managers;
- database encryption;
- access control;
- traditional DLP products.

Vectis is intended to complement existing security controls by exploring
object-level protection for sensitive data flows.

## Security Status

Vectis is currently:

- experimental;
- incomplete;
- not audited;
- not production-ready;
- subject to major design changes.

Do not use Vectis with real patient data, production secrets, financial records,
or any other real sensitive data.

The threat model, explicit assumptions, and known limitations are documented in
[doc/ThreatModel.md](doc/ThreatModel.md).

## License

Apache-2.0.
