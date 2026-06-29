# Vectis Environment Variables

Vectis reads configuration from process environment variables first and then from `.env`. If neither source provides a value, the built-in default is used.

Do not store secrets in `.env` for production. In particular, `VECTIS_UNSEAL_KEY` is intentionally not listed in `env.dist`.

## Resolution Order

For most configuration values:

1. Process environment variable.
2. `.env` file in the working directory.
3. Built-in default.

Example:

```bash
export VECTIS_HTTP_BIND_ADDR=127.0.0.1:3000
cargo run -- serve
```

## HTTP

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_HTTP_BIND_ADDR` | `127.0.0.1:3000` | Valid socket address, for example `127.0.0.1:3000` or `0.0.0.0:3000` | Address where the Vectis HTTP server listens. |
| `VECTIS_SERVER_SCHEME` | `http` | `http` or `https` | Transport used by the local Vectis server. If `https`, TLS cert and key paths are required. |
| `VECTIS_REMOTE_SCHEME` | `http` | `http` or `https` | Transport used by this Vectis instance when calling another Vectis instance. |
| `VECTIS_FINAL_APP_SCHEME` | `http` | `http` or `https` | Transport used when delivering protected messages to the final application. |
| `VECTIS_TLS_CERT_PATH` | Empty | Readable PEM certificate file path | Server certificate used when `VECTIS_SERVER_SCHEME=https`. |
| `VECTIS_TLS_KEY_PATH` | Empty | Readable PEM private key file path | Server private key used when `VECTIS_SERVER_SCHEME=https`. |
| `VECTIS_TLS_SKIP_VERIFY` | `false` | `true` or `false` | Disables TLS certificate verification for outbound clients. Intended only for local development with self-signed certificates. |
| `VECTIS_PUBLIC_ADDR` | `127.0.0.1:3000` | Valid host:port, for example `localhost:3000` or `vectis-a.example.com:443` | Public address advertised as `sender.host` in protected messages. Useful when Vectis runs behind a load balancer. |
| `VECTIS_PROTOCOL_VERSION` | `v1` | `v1` | Protocol version used by generated payloads and AAD. Currently only `v1` is supported. |

Notes:

- `VECTIS_HTTP_BIND_ADDR` must be a socket address.
- `VECTIS_PUBLIC_ADDR` is a host:port value and may use hostnames such as `localhost:3000`.
- `VECTIS_SERVER_SCHEME`, `VECTIS_REMOTE_SCHEME`, and `VECTIS_FINAL_APP_SCHEME` are intentionally separate. A common deployment is HTTPS between Vectis instances and HTTP for a local final app.

## CLI Client

These variables are used by CLI commands that call the HTTP API. `serve` and `init` remain local bootstrap/server commands.

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_API_URL` | `http://127.0.0.1:3000` | Valid `http` or `https` URL without query or fragment | Base URL used by CLI commands such as `health`, `test`, `keys`, `routes`, `pub`, `sign`, and `message`. |
| `VECTIS_TIMEOUT_SECONDS` | `30` | Positive integer | HTTP request timeout used by the CLI client. |
| `VECTIS_TLS_SKIP_VERIFY` | `false` | `true` or `false` | Also affects the CLI client when `VECTIS_API_URL` uses HTTPS. Use only for local self-signed certificates. |

## Final App Delivery

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_FINAL_APP_ADDR` | `localhost:3999` | Valid host:port | Default final app destination used when no manual route exists for a `kid`. |
| `VECTIS_FINAL_APP_PATH` | `/message` | HTTP path beginning with `/`, no spaces | Default final app path. |
| `VECTIS_ROUTES_PATH` | `routes.json` | Non-empty file path | Optional manual routing file. Startup falls back to default final app delivery if the file is missing or invalid. Runtime reload keeps the previous routes if the file exists but is invalid. |
| `VECTIS_ROUTES_SIGN_PATH` | `routes_sign.json` | Non-empty file path | Signature token for `VECTIS_ROUTES_PATH`, created by `vectis routes sign`. |

Manual routes file shape:

```json
{
  "routes": [
    {
      "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
      "final_app_addr": "127.0.0.1:3999",
      "final_app_path": "/message"
    }
  ]
}
```

`routes.json` is manual operational configuration. Vectis does not create it and `POST /keys` does not modify it.
If `routes.json` exists, `routes_sign.json` must exist and verify before routes are loaded.

Runtime route operations:

- `GET /routes` lists routes currently loaded in memory and requires `VECTIS_APIKEY`.
- `POST /routes/reload` reloads `VECTIS_ROUTES_PATH` and requires `VECTIS_APIKEY`.
- `vectis routes sign` signs `VECTIS_ROUTES_PATH` locally with init keys and updates `VECTIS_ROUTES_SIGN_PATH`.
- Every route `kid` must exist in the keys currently loaded in memory.
- A missing file reloads to an empty manual route list.
- An invalid existing file, or a route with an unloaded `kid`, returns an error and keeps the previous in-memory routes.

## Authentication and Unsealing

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_APIKEY` | Empty string | Hex string with the length required by `INTERNAL_KEYS_HASH` (`BLAKE2b(256)`, 64 hex characters) | API key required by protected HTTP endpoints. |
| `VECTIS_UNSEAL_KEY` | No default | 32-byte symmetric key encoded as 64 hex characters | Key used to decrypt `init.json` for `serve` and CLI validation flows. If missing, Vectis tries the unseal key file and then prompts for it as a hidden password. |
| `VECTIS_UNSEAL_KEY_FILE` | `.unseal_key` | Non-empty file path | File containing only the unseal key as a hex string. A final newline is allowed. |

Security notes:

- Unseal key resolution order is: `VECTIS_UNSEAL_KEY`, then `VECTIS_UNSEAL_KEY_FILE`, then hidden prompt.
- `VECTIS_UNSEAL_KEY_FILE` can be provided as a process environment variable or in `.env`; the file content itself must not be placed in `.env`.
- If `VECTIS_UNSEAL_KEY_FILE` is explicitly set and cannot be read, Vectis fails instead of falling back to the prompt.
- If the default `.unseal_key` file is missing, Vectis falls back to the hidden prompt.
- The unseal key file must contain one valid 64-character hex string after trimming whitespace.
- `VECTIS_UNSEAL_KEY` should be supplied as a process environment variable, unseal key file, or typed interactively.
- Do not put `VECTIS_UNSEAL_KEY` in `.env`.
- Do not commit `.unseal_key`; it is listed in `.gitignore`.
- `VECTIS_APIKEY` is less sensitive than `VECTIS_UNSEAL_KEY`, but it still gates protected endpoints and should be managed as a secret.

## Storage

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_STORAGE` | `sqlite` | `sqlite` | Storage backend. Currently only `sqlite` is supported. |
| `VECTIS_SQLITE_PATH` | Debug: `<repo>/src/db/data.db`; release: `<working-dir>/db/data.db` | Path to an existing readable and writable SQLite database file | SQLite database path. The file must exist, be a file, and allow read/write access. |

Current SQLite schema:

```sql
CREATE TABLE IF NOT EXISTS ops_keys (
    id VARCHAR(128) PRIMARY KEY,
    enc_keys VARCHAR(10240) NOT NULL,
    properties VARCHAR(10240) NOT NULL
);
```

`enc_keys` and `properties` are encrypted with the internal init symmetric key. `enc_keys` stores operational key material; `properties` stores lifecycle metadata.

## Logging

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `warning`, or `error` | Maximum tracing level. Invalid values fall back to `info`. |
| `VECTIS_LOG_DIR` | `logs` | Directory path | Directory for daily rolling JSON logs. Created automatically if missing. |
| `VECTIS_LOG_FILE` | `vectis.log` | File name | Base log file name used by daily rotation. |

Logging is JSON by default.

## Hostnames

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_SENDER_HOSTNAME` | `localhost.local` | Valid domain name | Hostname included in validation AAD for local key checks. |
| `VECTIS_RECEIVER_HOSTNAME` | `remotehost.local` | Valid domain name | Peer hostname included in validation AAD for local key checks. |

These values are validation metadata and are not the same as `VECTIS_PUBLIC_ADDR`.

## Key Generation Defaults

These variables control defaults for operational keys created by `POST /keys`. They do not change the fixed internal key material generated by `vectis init`.

| Variable | Default | Expected values | Purpose |
| --- | --- | --- | --- |
| `VECTIS_HASH` | `BLAKE2b(512)` | See supported hash algorithms below | Default hash algorithm for generated operational key material. |
| `VECTIS_SYMMETRIC` | `ChaCha20Poly1305` | `ChaCha20Poly1305`, `AES-128/GCM`, `AES-192/GCM`, `AES-256/GCM` | Default symmetric encryption algorithm for generated operational keys. |
| `VECTIS_EDDSA` | `Ed25519` | `Ed25519`, `Ed448` | Default EdDSA algorithm for generated operational keys. |
| `VECTIS_XECDH` | `X25519` | `X25519`, `X448` | Default XECDH algorithm for generated operational keys. |
| `VECTIS_ML_DSA_VARIANT` | `ML-DSA-44` | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | Default ML-DSA signature variant. |
| `VECTIS_ML_KEM_VARIANT` | `ML-KEM-512` | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | Default ML-KEM KEM variant. |
| `VECTIS_DEFAULT_CRYPTO_PROFILE` | `hybrid-performance-v1` | `hybrid-performance-v1`, `hybrid-high-assurance-v1`, `hybrid-long-term-v1` | Default crypto profile for `POST /keys` when the request does not include `profile`. |
| `VECTIS_CRYPTO_POLICY` | `profile-only` | `profile-only`, `allow-overrides` | Controls whether `POST /keys` accepts individual algorithm fields. `profile-only` rejects overrides; `allow-overrides` accepts them for dev/test. |

Crypto profiles:

- `hybrid-performance-v1`: `BLAKE2b(256)`, `ChaCha20Poly1305`, `Ed25519`, `X25519`, `ML-DSA-44`, `ML-KEM-512`
- `hybrid-high-assurance-v1`: `SHA-3(384)`, `AES-256/GCM`, `Ed25519`, `X25519`, `ML-DSA-65`, `ML-KEM-768`
- `hybrid-long-term-v1`: `SHA-3(512)`, `AES-256/GCM`, `Ed448`, `X448`, `ML-DSA-87`, `ML-KEM-1024`

Supported hash algorithms:

- `BLAKE2b(160)`, `BLAKE2b(224)`, `BLAKE2b(256)`, `BLAKE2b(384)`, `BLAKE2b(512)`
- `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA-512-256`
- `SHA-3(224)`, `SHA-3(256)`, `SHA-3(384)`, `SHA-3(512)`
- `Whirlpool`

## Validation Message

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_PLAINTEXT_MESSAGE` | `You are not special. You are not a beautiful and unique snowflake. You're the same decaying organic matter as everything else.` | Non-empty string | Plaintext used by key validation flows (`vectis test init`, `vectis test <kid>`, and HTTP self-test endpoints). |

## Internal Constants

These are not environment variables. They are compile-time constants used by Vectis for internal key material and IDs.

| Constant | Value | Purpose |
| --- | --- | --- |
| `INTERNAL_KEYS_CIPHER` | `AES-256/GCM` | Cipher used to encrypt `init.json` key material and stored operational key payloads. |
| `INTERNAL_KEYS_KEY_SIZE_BYTES` | `32` | Internal AES-256 key size. |
| `INTERNAL_KEYS_NONCE_SIZE_BYTES` | `12` | AES-GCM nonce size used for internal key encryption. |
| `INTERNAL_KEYS_HASH` | `BLAKE2b(256)` | Hash used for API key validation length and generated `kid` values. |
| `INTERNAL_KEYS_EDDSA_ALGORITHM` | `Ed25519` | Internal init EdDSA default. |
| `INTERNAL_KEYS_XECDH_ALGORITHM` | `X25519` | Internal init XECDH default. |
| `INTERNAL_KEYS_ML_DSA_VARIANT` | `ML-DSA-44` | Internal init ML-DSA default. |
| `INTERNAL_KEYS_ML_KEM_VARIANT` | `ML-KEM-512` | Internal init ML-KEM default. |

## Example `.env`

```env
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3000
VECTIS_SERVER_SCHEME=http
VECTIS_REMOTE_SCHEME=http
VECTIS_FINAL_APP_SCHEME=http
VECTIS_TLS_CERT_PATH=
VECTIS_TLS_KEY_PATH=
VECTIS_TLS_SKIP_VERIFY=false
VECTIS_API_URL=http://127.0.0.1:3000
VECTIS_TIMEOUT_SECONDS=30
VECTIS_PUBLIC_ADDR=localhost:3000
VECTIS_FINAL_APP_ADDR=localhost:3999
VECTIS_FINAL_APP_PATH=/message
VECTIS_ROUTES_PATH=routes.json
VECTIS_ROUTES_SIGN_PATH=routes_sign.json
VECTIS_LOG_LEVEL=info
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_APIKEY=20e446d000498e82b056f54e68216d4c8c9bda089a6812d0aa9d82d59f918018
# VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_PROTOCOL_VERSION=v1
VECTIS_STORAGE=sqlite
VECTIS_SQLITE_PATH=src/db/data.db
VECTIS_SENDER_HOSTNAME=instance-a.local
VECTIS_RECEIVER_HOSTNAME=instance-b.local
VECTIS_HASH=BLAKE2b(512)
VECTIS_SYMMETRIC=ChaCha20Poly1305
VECTIS_EDDSA=Ed25519
VECTIS_XECDH=X25519
VECTIS_ML_DSA_VARIANT=ML-DSA-44
VECTIS_ML_KEM_VARIANT=ML-KEM-512
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-performance-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE="You are not special. You are not a beautiful and unique snowflake. You're the same decaying organic matter as everything else."
```
