# Vectis

Vectis is a personal open source project for **Sensitive Data Lifecycle
Protection**.

The core idea is simple: TLS protects the connection, but sensitive data often
continues moving through applications, services, queues, storage, logs, workers,
and final systems after the transport session is over. Vectis explores how to
protect the data object itself across that lifecycle.

This project is experimental and should be treated as a work in progress.

**Do not use Vectis to protect real sensitive data yet.**
<p align="left">
  <img width="300" alt="OpenBao Mascot" src="logo.png">
</p>

> In Latin, *vectis* can mean a lever, crowbar, fastening bar, or carrying pole:
> a simple tool used to move something heavy with controlled force.

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

Current capabilities include:

- encrypted local init key material;
- HKDF-derived internal keys for storage encryption and API key verification;
- operational key creation and validation;
- encrypted key lifecycle metadata and runtime lifecycle enforcement;
- public key publication by `kid`;
- protected messages between Vectis instances;
- hybrid key establishment with XECDH + ML-KEM;
- EdDSA and ML-DSA signatures;
- authenticated encryption for protected payloads;
- local re-encryption before final app delivery;
- internal encrypt/decrypt endpoints for local protected data;
- signed route files for per-key final app delivery;
- SQLite-backed operational key storage;
- storage abstraction designed for future backends;
- startup, liveness, and readiness health probes;
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

- `VECTIS_UNSEAL_KEY`: used to decrypt `init.json`;
- `VECTIS_APIKEY`: client secret sent as `X-API-Key`;
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
vectis routes sign
```

See the full API documentation in [Doc/API.md](Doc/API.md).

## Configuration

Vectis reads configuration from process environment variables first, then from
`.env`, then from built-in defaults.

All Vectis-specific variables use the `VECTIS_` prefix.

Important variables include:

- `VECTIS_HTTP_BIND_ADDR`;
- `VECTIS_SERVER_SCHEME`;
- `VECTIS_REMOTE_SCHEME`;
- `VECTIS_FINAL_APP_SCHEME`;
- `VECTIS_TLS_CERT_PATH`;
- `VECTIS_TLS_KEY_PATH`;
- `VECTIS_TLS_SKIP_VERIFY`;
- `VECTIS_PUBLIC_ADDR`;
- `VECTIS_API_URL`;
- `VECTIS_APIKEY`;
- `VECTIS_APIKEY_HASH`;
- `VECTIS_UNSEAL_KEY`;
- `VECTIS_UNSEAL_KEY_FILE`;
- `VECTIS_SQLITE_PATH`;
- `VECTIS_ROUTES_PATH`;
- `VECTIS_ROUTES_SIGN_PATH`;
- `VECTIS_DEFAULT_CRYPTO_PROFILE`;
- `VECTIS_CRYPTO_POLICY`.

See [Doc/ENV.md](Doc/ENV.md).

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

## Documentation

- [Doc/API.md](Doc/API.md): HTTP API and CLI mapping.
- [Doc/ENV.md](Doc/ENV.md): environment variables and expected values.
- [Doc/openapi.yaml](Doc/openapi.yaml): OpenAPI specification.
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

## License

Apache-2.0.
