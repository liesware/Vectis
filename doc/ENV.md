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
| `VECTIS_MODE` | `dev` | `dev` or `prod` | Central transport policy. `dev` uses HTTP for server, remote Vectis, and final app delivery. `prod` uses HTTPS for all three. |
| `VECTIS_TLS_CERT_PATH` | Empty | Readable PEM certificate file path | Server certificate required when `VECTIS_MODE=prod`. |
| `VECTIS_TLS_KEY_PATH` | Empty | Readable PEM private key file path | Server private key required when `VECTIS_MODE=prod`. |
| `VECTIS_TLS_SKIP_VERIFY` | `false` | `true` or `false` | Disables TLS certificate verification for outbound HTTPS clients. It only has practical effect when `VECTIS_MODE=prod` or the CLI calls an HTTPS `VECTIS_API_URL`. |
| `VECTIS_PUBLIC_ADDR` | `127.0.0.1:3000` | Valid host:port, for example `localhost:3000` or `vectis-a.example.com:443` | Public address advertised as `sender.host` in protected messages. Useful when Vectis runs behind a load balancer. |
| `VECTIS_PROTOCOL_VERSION` | `v1` | `v1` | Protocol version used by generated payloads and AAD. Currently only `v1` is supported. |

Notes:

- `VECTIS_HTTP_BIND_ADDR` must be a socket address.
- `VECTIS_PUBLIC_ADDR` is a host:port value and may use hostnames such as `localhost:3000`.
- `VECTIS_MODE` is the only public transport selector. The legacy `VECTIS_SERVER_SCHEME`, `VECTIS_REMOTE_SCHEME`, and `VECTIS_FINAL_APP_SCHEME` variables are no longer read.

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
| `VECTIS_CONFIG_PATH` | `config.json` | Non-empty file path | Unified signed config file with `routes`, `remote_routes`, and `permissions` sections. Startup falls back to empty sections (default final app delivery, only root authorized) if missing or invalid. Runtime reload keeps the previous config if the file exists but is invalid. |
| `VECTIS_CONFIG_SIGN_PATH` | `config_sign.json` | Non-empty file path | Signature token for `VECTIS_CONFIG_PATH`, created by `vectis config sign`. |

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

The `routes`/`remote_routes`/`permissions` sections live in the unified signed `config.json`.
Vectis does not create it and `POST /keys` does not modify it.
If `config.json` exists, `config_sign.json` must exist and verify before the config is loaded.

Runtime route operations:

- `GET /routes` lists routes currently loaded in memory and requires `VECTIS_APIKEY`.
- `POST /routes/reload` reloads the unified config and requires `VECTIS_APIKEY`.
- `GET /remote-routes` lists authorized remote Vectis routes currently loaded in memory and requires `VECTIS_APIKEY`.
- `POST /remote-routes/reload` reloads the unified config and requires `VECTIS_APIKEY`.
- `vectis config sign` signs `VECTIS_CONFIG_PATH` locally with init keys and updates `VECTIS_CONFIG_SIGN_PATH`.
- Every route `kid` must exist in the keys currently loaded in memory.
- A missing file reloads to an empty manual route list.
- An invalid existing file, or a route with an unloaded `kid`, returns an error and keeps the previous in-memory routes.

Remote routes file shape:

```json
{
  "routes": [
    {
      "remote_kid": "b01cbe33187916f0f1367d07bc986d71bb0d91d7047ccd790c13fc9d85fe7259",
      "name": "site-b",
      "remote_addr": "vectis-b.example.com:443",
      "allowed_local_kids": ["*"],
      "status": "active"
    }
  ]
}
```

The `remote_routes` config section is the only source of authorized outbound Vectis destinations for `POST /message/{sender_kid}`. The request body supplies `recipient_kid`; Vectis uses the signed route to find `remote_addr`. `allowed_local_kids` limits which local sender KIDs may use the route; use `["*"]` to allow any loaded local KID.

Each entry may also include an optional `public_keys` object (the peer's full public key set, as returned by its `GET /pub/{kid}`). When present, `/message` uses those trusted keys directly instead of fetching `/pub`, and `POST /sign/verification` can verify timestamp tokens signed by that remote `kid` (cross-instance verification). Without it, Vectis fetches `/pub` on first use.

## Authentication and Unsealing

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_APIKEY` | Empty string | Hex string with the length required by `INTERNAL_KEYS_HASH` (`BLAKE2b(256)`, 64 hex characters) | Client-side API key sent as `X-API-Key` by the CLI, tests, and demo apps. |
| `VECTIS_APIKEY_HASH` | Empty string | 32-byte HMAC-SHA256 value encoded as 64 hex characters | Server-side API key verifier generated by `vectis init` or `vectis apikey create`. Protected endpoints require this value. |
| `VECTIS_INIT_KEYS_FILE` | `init.json` | Non-empty file path | Encrypted init key material file. `vectis init` refuses to overwrite this file if it already exists. |
| `VECTIS_UNSEAL_KEY` | No default | 32-byte symmetric key encoded as 64 hex characters | Key used to decrypt `VECTIS_INIT_KEYS_FILE` for `serve` and CLI validation flows. If missing, Vectis tries the unseal key file and then prompts for it as a hidden password. |
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
- `VECTIS_APIKEY` is a client secret generated by `vectis init` or `vectis apikey create` with Botan's cryptographic random number generator. Do not place it in server-only environments unless the same process also acts as a client.
- `VECTIS_APIKEY_HASH` lets the server verify `X-API-Key` without storing the API key in plaintext. It is `HMAC-SHA256(api_auth_key, VECTIS_APIKEY)`, where `api_auth_key` is derived from the init symmetric key with HKDF-SHA256.
- `vectis init` creates `VECTIS_INIT_KEYS_FILE` only when it does not already exist. To reinitialize, delete the configured file manually first.
- `vectis apikey create` can generate additional client API keys from the existing `VECTIS_INIT_KEYS_FILE`. It only prints `VECTIS_APIKEY` and `VECTIS_APIKEY_HASH`; it does not write `.env`, init key material, or storage.

## API Key Permissions

`VECTIS_APIKEY` and `VECTIS_APIKEY_HASH` are the root API key pair. Root can use every protected endpoint. Clients with `admin` can also call protected administrative endpoints, including `POST /permissions/reload`.

Additional clients are loaded from the `permissions` section of `VECTIS_CONFIG_PATH` when the config exists and its `VECTIS_CONFIG_SIGN_PATH` signature verifies.

Recommended admin permission:

```json
{
  "kid": "*",
  "actions": ["admin"]
}
```

If any permission entry contains `admin`, Vectis treats the whole client as admin and ignores `kid` plus any other actions for that client. Non-admin KID-scoped permissions must reference KIDs already loaded in memory. Global permissions such as `metrics` use `kid: "*"`.

Allowed actions:

- `admin`
- `keys`
- `lifecycle`
- `self-test`
- `sign`
- `message`
- `metrics`

Permission mapping summary:

- `admin`: administrative protected endpoints, including `POST /keys`, `POST /keys/reload`, `GET /keys/properties`, `GET /routes`, `POST /routes/reload`, `GET /remote-routes`, `POST /remote-routes/reload`, `POST /permissions/reload`, `GET /self-test/init`, and `GET /metrics`.
- `keys`: `GET /keys/properties/{kid}`.
- `lifecycle`: `POST /lifecycle/{kid}`.
- `self-test`: `GET /self-test/keys/{kid}`.
- `sign`: `POST /sign/{kid}`.
- `message`: protected message endpoints.
- `metrics`: `GET /metrics` with `kid: "*"`; this is a global permission and does not reference a loaded operational KID.

Routes operations require root or `admin`; there is no granular `routes` action.

Permissions file shape:

```json
{
  "version": "v1",
  "clients": [
    {
      "client": "client-a",
      "apikey_hash": "<VECTIS_APIKEY_HASH>",
      "status": "active",
      "permissions": [
        {
          "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
          "actions": ["sign", "message"]
        }
      ]
    }
  ]
}
```

Clients with `status` other than `active` are ignored. Invalid JSON, invalid actions, invalid hashes, signature failure, a KID-scoped non-admin permission referencing an unloaded KID, or `kid: "*"` with a non-global action rejects the whole file.

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

The init symmetric key is a root key. Vectis derives separate internal keys from it with HKDF-SHA256:

- `db_key` encrypts and decrypts `ops_keys.enc_keys`;
- `properties_key` encrypts and decrypts `ops_keys.properties`;
- `api_auth_key` verifies `X-API-Key` against `VECTIS_APIKEY_HASH`.

`enc_keys` stores operational key material; `properties` stores lifecycle metadata.

## Logging

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `warning`, or `error` | Maximum tracing level. Invalid values fall back to `info`. |
| `VECTIS_LOG_DIR` | `logs` | Directory path | Directory for daily rolling JSON logs. Created automatically if missing. |
| `VECTIS_LOG_FILE` | `vectis.log` | File name | Base log file name used by daily rotation. |
| `VECTIS_AUDIT_LOG_FILE` | `audit.log` | File name | Base file name for the dedicated audit log stream. Security audit events are written here, separate from the operational log. |

Logging is JSON by default. Audit events go to a dedicated stream (`VECTIS_AUDIT_LOG_FILE`) under `VECTIS_LOG_DIR`, separate from the operational log.

## Observability

| Variable | Default | Expected value | Purpose |
| --- | --- | --- | --- |
| `VECTIS_METRICS_ENABLED` | `true` | `true` or `false` | Enable the Prometheus `/metrics` endpoint. The endpoint requires `X-API-Key` with root, `admin`, or `metrics` permission. When `false`, authorized requests return `404`. |

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
| `INTERNAL_KEYS_CIPHER` | `AES-256/GCM` | Cipher used to encrypt `init.json` key material and stored operational key payloads. Stored operational payloads use HKDF-derived internal keys. |
| `INTERNAL_KEYS_KEY_SIZE_BYTES` | `32` | Internal AES-256 key size and HKDF-derived internal key size. |
| `INTERNAL_KEYS_NONCE_SIZE_BYTES` | `12` | AES-GCM nonce size used for internal key encryption. |
| `INTERNAL_KEYS_HASH` | `BLAKE2b(256)` | Hash used for API key validation length and generated `kid` values. |
| `INTERNAL_KEYS_EDDSA_ALGORITHM` | `Ed25519` | Internal init EdDSA default. |
| `INTERNAL_KEYS_XECDH_ALGORITHM` | `X25519` | Internal init XECDH default. |
| `INTERNAL_KEYS_ML_DSA_VARIANT` | `ML-DSA-44` | Internal init ML-DSA default. |
| `INTERNAL_KEYS_ML_KEM_VARIANT` | `ML-KEM-512` | Internal init ML-KEM default. |

## Example `.env`

```env
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3000
VECTIS_MODE=dev
VECTIS_TLS_CERT_PATH=
VECTIS_TLS_KEY_PATH=
VECTIS_TLS_SKIP_VERIFY=false
VECTIS_API_URL=http://127.0.0.1:3000
VECTIS_TIMEOUT_SECONDS=30
VECTIS_PUBLIC_ADDR=localhost:3000
VECTIS_FINAL_APP_ADDR=localhost:3999
VECTIS_FINAL_APP_PATH=/message
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
VECTIS_LOG_LEVEL=info
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.log
VECTIS_METRICS_ENABLED=true
VECTIS_APIKEY=20e446d000498e82b056f54e68216d4c8c9bda089a6812d0aa9d82d59f918018
VECTIS_APIKEY_HASH=
# VECTIS_INIT_KEYS_FILE=init.json
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
