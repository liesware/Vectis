# Vectis HTTP API

Vectis protects data throughout its lifecycle. The HTTP API exposes operations to create key material, validate keys, publish public keys, sign message hashes, exchange protected messages between Vectis instances, and encrypt/decrypt internal messages.

The `vectis` CLI is an HTTP client for the runtime API, except for `vectis init`, `vectis serve`, `vectis apikey create`, `vectis config sign`, and `vectis config list`, which are local commands.

## Conventions

- Default base URL: `http://127.0.0.1:3000`
- Requests with a body use `Content-Type: application/json`.
- Timestamps are encoded as Unix epoch seconds in a string.
- `kid` values are hex strings derived with Vectis' internal hash (`INTERNAL_KEYS_HASH`, currently `BLAKE2b(256)`), so they are normally 64 hex characters.
- Binary fields (`ctx`, `nonce`, signatures, public keys) are encoded as hex.
- Public errors use this shape:

```json
{
  "error": "invalid request"
}
```

## Protocol Versioning

Only `v1` is supported. Any other version is rejected explicitly; there is no silent downgrade.

The signed config file (`config.json`, with `routes`, `remote_routes`, and `permissions`
sections) carries a single top-level `version` that is part of the signed content.

Signed tokens and protected messages intentionally carry `version` at **two** levels:

- **Envelope** (`version`): used for dispatch — it lets a receiver decide how to interpret the
  `payload` before parsing or trusting it, which keeps room for future versions whose payload
  shape may differ.
- **Payload** (`payload.version`): used for integrity — it is inside the signed bytes, so signed
  content cannot be reinterpreted under a different version.

Verification requires `version == payload.version`; a mismatch is rejected. This binds the two
copies and defends against version-confusion / downgrade attempts. This is not accidental
duplication: the envelope copy negotiates, the payload copy authenticates.

Signatures cover the canonical JSON (sorted keys, compact, UTF-8) of the `payload`, so
`payload.version` is protected by the signature.

## Authentication

Protected endpoints require:

```http
X-API-Key: <VECTIS_APIKEY>
```

`VECTIS_APIKEY` is the client secret sent in the `X-API-Key` header. `vectis init` and `vectis apikey create` generate it from Botan's cryptographic random number generator. The server validates it against `VECTIS_APIKEY_HASH`, which is derived with the init API auth key.

`VECTIS_APIKEY` and `VECTIS_APIKEY_HASH` are the root API key pair. Root can access every protected endpoint. Additional clients can be authorized through the `permissions` section of the signed config; clients with `admin` can also access protected administrative endpoints, including `POST /permissions/reload`.

Endpoints requiring auth:

- `POST /keys`
- `GET /keys/properties`
- `GET /keys/properties/{kid}`
- `POST /keys/reload`
- `POST /lifecycle/{kid}`
- `GET /routes`
- `POST /routes/reload`
- `GET /remote-routes`
- `POST /remote-routes/reload`
- `POST /permissions/reload`
- `GET /metrics`
- `GET /self-test/init`
- `GET /self-test/keys/{kid}`
- `POST /sign/{kid}`
- `POST /message/{sender_kid}`
- `POST /message/decrypt`
- `POST /message/internal/encrypt/{kid}`
- `POST /message/internal/decrypt`

Endpoints without auth:

- `GET /healthz/startup`
- `GET /healthz/live`
- `GET /healthz/ready`
- `GET /keys`
- `GET /pub/{kid}`
- `POST /sign/verification`
- `POST /message`

## Supported Algorithms

Hash:

- `BLAKE2b(160)`, `BLAKE2b(224)`, `BLAKE2b(256)`, `BLAKE2b(384)`, `BLAKE2b(512)`
- `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA-512-256`
- `SHA-3(224)`, `SHA-3(256)`, `SHA-3(384)`, `SHA-3(512)`
- `Whirlpool`

Symmetric:

- `ChaCha20Poly1305`
- `AES-128/GCM`
- `AES-192/GCM`
- `AES-256/GCM`

EdDSA:

- `Ed25519`
- `Ed448`

XECDH:

- `X25519`
- `X448`

ML-DSA:

- `ML-DSA-44`
- `ML-DSA-65`
- `ML-DSA-87`

ML-KEM:

- `ML-KEM-512`
- `ML-KEM-768`
- `ML-KEM-1024`

## Health and Validation

### GET /healthz/startup

Startup probe. Reports when the HTTP service state was initialized.

Response:

```json
{
  "status": "started",
  "timestamp": "1782058090"
}
```

### GET /healthz/live

Liveness probe. Does not perform I/O.

Response:

```json
{
  "status": "ok"
}
```

### GET /healthz/ready

Readiness probe. Performs a lightweight storage check and reports current in-memory state counts. It does not reload keys or routes.

Response:

```json
{
  "status": "ready",
  "unsealed": true,
  "storage": "ok",
  "keys_loaded": 3,
  "routes_loaded": 1
}
```

### GET /metrics

Prometheus metrics in the text exposition format (`text/plain; version=0.0.4`). Requires auth with root, `admin`, or the `metrics` permission. Enabled by `VECTIS_METRICS_ENABLED` (default `true`); returns `404` when disabled after auth succeeds. Labels are low cardinality and carry no sensitive data (only `method`, `endpoint` route template, `status`, `outcome`).

Exposed metrics:

- `http_requests_total{method,endpoint,status}`
- `http_request_duration_seconds{method,endpoint}` (histogram)
- `auth_total{outcome}` (`allow` or `deny`)
- `vectis_keys_loaded`
- `vectis_routes_loaded`
- `vectis_remote_routes_loaded`
- `vectis_permission_clients`

### GET /self-test/init

Validates the key material generated by `vectis init`.

Requires auth.

Response:

```json
{
  "timestamp": "1782058090",
  "aad": "version=v1;hostname=localhost;type=init-keys;cipher=AES-256/GCM",
  "hash": {
    "variant": "BLAKE2b(256)",
    "value_hex": "..."
  },
  "symmetric": {
    "variant": "ChaCha20Poly1305",
    "valid": true
  },
  "eddsa": {
    "variant": "Ed25519",
    "valid": true
  },
  "xecdh": {
    "variant": "X25519",
    "valid": true
  },
  "ml-dsa": {
    "variant": "ML-DSA-44",
    "valid": true
  },
  "ml-kem": {
    "variant": "ML-KEM-512",
    "valid": true
  }
}
```

### GET /self-test/keys/{kid}

Validates a key loaded from storage into memory. It does not expose private keys.

Requires auth.

Response:

```json
{
  "timestamp": "1782058090",
  "aad": "...",
  "hash": {
    "variant": "SHA-256",
    "value_hex": "..."
  },
  "symmetric": {
    "variant": "AES-256/GCM",
    "valid": true
  },
  "eddsa": {
    "variant": "Ed25519",
    "valid": true
  },
  "xecdh": {
    "variant": "X25519",
    "valid": true
  },
  "ml-dsa": {
    "variant": "ML-DSA-44",
    "valid": true
  },
  "ml-kem": {
    "variant": "ML-KEM-512",
    "valid": true
  }
}
```

## Keys

### POST /keys

Creates an operational key set, encrypts it with the internal symmetric key created by `init`, stores it, and loads it into memory.

Requires auth.

Request:

```json
{
  "tag": "ACME Corp.",
  "profile": "hybrid-high-assurance-v1",
  "hash_algorithm": "SHA-256",
  "symmetric_algorithm": "AES-256/GCM",
  "eddsa_algorithm": "Ed25519",
  "xecdh_algorithm": "X25519",
  "ml_dsa_variant": "ML-DSA-44",
  "ml_kem_variant": "ML-KEM-512"
}
```

All fields are optional:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `tag` | string | No | Human-readable label for the key. If missing, Vectis uses a timestamp. |
| `profile` | string | No | Crypto profile used as the base algorithm policy. If missing, Vectis uses `VECTIS_DEFAULT_CRYPTO_PROFILE`. |
| `hash_algorithm` | string | No | Individual hash override. Accepted only when `VECTIS_CRYPTO_POLICY=allow-overrides`. |
| `symmetric_algorithm` | string | No | Individual symmetric algorithm override. Accepted only when `VECTIS_CRYPTO_POLICY=allow-overrides`. |
| `eddsa_algorithm` | string | No | Individual EdDSA override. Accepted only when `VECTIS_CRYPTO_POLICY=allow-overrides`. |
| `xecdh_algorithm` | string | No | Individual XECDH override. Accepted only when `VECTIS_CRYPTO_POLICY=allow-overrides`. |
| `ml_dsa_variant` | string | No | Individual ML-DSA override. Accepted only when `VECTIS_CRYPTO_POLICY=allow-overrides`. |
| `ml_kem_variant` | string | No | Individual ML-KEM override. Accepted only when `VECTIS_CRYPTO_POLICY=allow-overrides`. |

When `VECTIS_CRYPTO_POLICY=profile-only`, Vectis rejects all individual algorithm fields and accepts only `tag` and `profile`.

Supported profiles:

- `hybrid-performance-v1`: `BLAKE2b(256)`, `ChaCha20Poly1305`, `Ed25519`, `X25519`, `ML-DSA-44`, `ML-KEM-512`
- `hybrid-high-assurance-v1`: `SHA-3(384)`, `AES-256/GCM`, `Ed25519`, `X25519`, `ML-DSA-65`, `ML-KEM-768`
- `hybrid-long-term-v1`: `SHA-3(512)`, `AES-256/GCM`, `Ed448`, `X448`, `ML-DSA-87`, `ML-KEM-1024`

Response:

```json
{
  "id": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed"
}
```

### GET /keys

Lists keys currently loaded in memory. This endpoint does not require auth.

This public discovery endpoint intentionally omits decrypted lifecycle properties.

Response:

```json
{
  "keys": [
    {
      "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
      "info": "version=v1;hostname=localhost;type=ops-keys;cipher=AES-256/GCM;tag=ACME Corp.;timestamp=1782058090"
    }
  ]
}
```

### POST /keys/reload

Administrative refresh operation. Reloads the local in-memory key state from storage, decrypting the keys and properties this node can load, then returns the refreshed state with properties.

This endpoint uses `POST` because it changes server memory state.

Requires auth.

Response:

```json
{
  "keys": [
    {
      "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
      "info": "version=v1;hostname=localhost;type=ops-keys;cipher=AES-256/GCM;tag=ACME Corp.;timestamp=1782058090",
      "properties_info": "version=v1;hostname=localhost;type=ops-key-properties;cipher=AES-256/GCM;kid=f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed;tag=ACME Corp.;profile=hybrid-high-assurance-v1;timestamp=1782058090",
      "properties": {
        "version": 1,
        "profile": "hybrid-high-assurance-v1",
        "tag": "ACME Corp.",
        "created_at": "1782058090",
        "lifecycle": {
          "status": "active",
          "reason": "initial creation",
          "changed_at": "1782058090"
        },
        "access": null
      }
    }
  ]
}
```

### GET /keys/properties

Lists keys currently loaded in memory with decrypted lifecycle properties.

Requires auth.

`GET /keys` remains public and does not expose properties.

`info` is the AAD used for the encrypted operational key material. `properties_info` is the AAD used for the encrypted properties payload.

Response:

```json
{
  "keys": [
    {
      "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
      "info": "version=v1;hostname=localhost;type=ops-keys;cipher=AES-256/GCM;tag=payments-prod;profile=hybrid-high-assurance-v1;timestamp=1782058090",
      "properties_info": "version=v1;hostname=localhost;type=ops-key-properties;cipher=AES-256/GCM;kid=f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed;tag=payments-prod;profile=hybrid-high-assurance-v1;timestamp=1782058090",
      "properties": {
        "version": 1,
        "profile": "hybrid-high-assurance-v1",
        "tag": "payments-prod",
        "created_at": "1782058090",
        "lifecycle": {
          "status": "active",
          "reason": "initial creation",
          "changed_at": "1782058090"
        },
        "access": null
      }
    }
  ]
}
```

### GET /keys/properties/{kid}

Returns decrypted lifecycle properties for one key. If the key is not currently
loaded in memory, Vectis attempts to load and decrypt it from storage first.

Requires auth.

Response:

```json
{
  "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
  "info": "version=v1;hostname=localhost;type=ops-keys;cipher=AES-256/GCM;tag=payments-prod;profile=hybrid-high-assurance-v1;timestamp=1782058090",
  "properties_info": "version=v1;hostname=localhost;type=ops-key-properties;cipher=AES-256/GCM;kid=f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed;tag=payments-prod;profile=hybrid-high-assurance-v1;timestamp=1782058090",
  "properties": {
    "version": 1,
    "profile": "hybrid-high-assurance-v1",
    "tag": "payments-prod",
    "created_at": "1782058090",
    "lifecycle": {
      "status": "active",
      "reason": "initial creation",
      "changed_at": "1782058090"
    },
    "access": null
  }
}
```

### POST /lifecycle/{kid}

Updates encrypted lifecycle metadata for an operational key. Lifecycle status is
enforced by cryptographic operations.

Requires auth.

Request:

```json
{
  "status": "disabled",
  "reason": "maintenance window"
}
```

Allowed `status` values:

- `active`
- `disabled`
- `retired`
- `compromised`
- `destroyed`

Lifecycle behavior:

- `active`: normal use.
- `disabled`: blocked for all cryptographic operations.
- `retired`: allowed only for decrypt and verification; blocked for new
  encryption/signing/sending operations and `/pub`.
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

Response:

```json
{
  "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
  "lifecycle": {
    "status": "disabled",
    "reason": "maintenance window",
    "changed_at": "1782059000"
  }
}
```

## Routes

### GET /routes

Lists the final app routes currently loaded in memory. It does not read `config.json`.

Requires auth.

Response:

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

### POST /routes/reload

Administrative refresh operation. Reloads the unified signed config into memory.

Requires auth.

If the routes file does not exist, Vectis reloads to an empty route list and keeps using the default final app fallback. If the file exists but is invalid, or if any route references a `kid` not loaded in memory, the request fails and the previous in-memory routes remain active.

Response:

```json
{
  "routes": []
}
```

### GET /remote-routes

Administrative endpoint. Lists authorized remote Vectis routes currently loaded in memory.

Requires auth.

Response:

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

### POST /remote-routes/reload

Administrative refresh operation. Reloads the unified signed config into memory.

Requires auth.

If the remote routes file does not exist, Vectis reloads to an empty route list. If the file exists but is invalid or unsigned, the request fails and the previous in-memory remote routes remain active.

Response:

```json
{
  "routes": []
}
```

## API Key Permissions

Permissions are the `permissions` section of the unified signed config file:

```env
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
```

`vectis config sign` signs `VECTIS_CONFIG_PATH` locally with init keys and writes `VECTIS_CONFIG_SIGN_PATH`. The config file has `routes`, `remote_routes`, and `permissions` sections under a top-level `version`.

Recommended admin permission:

```json
{
  "kid": "*",
  "actions": ["admin"]
}
```

If any permission entry contains `admin`, Vectis treats the whole client as admin and ignores `kid` plus any other actions for that client.

Allowed actions:

- `admin`
- `keys`
- `lifecycle`
- `self-test`
- `sign`
- `message`
- `metrics`

Permission mapping:

| Permission | Endpoints |
| --- | --- |
| `admin` | `POST /keys`, `POST /keys/reload`, `GET /keys/properties`, `GET /routes`, `POST /routes/reload`, `GET /remote-routes`, `POST /remote-routes/reload`, `POST /permissions/reload`, `GET /self-test/init`, `GET /metrics` |
| `keys` | `GET /keys/properties/{kid}` |
| `lifecycle` | `POST /lifecycle/{kid}` |
| `self-test` | `GET /self-test/keys/{kid}` |
| `sign` | `POST /sign/{kid}` |
| `message` | `POST /message/{sender_kid}`, `POST /message/decrypt`, `POST /message/internal/encrypt/{kid}`, `POST /message/internal/decrypt` |
| `metrics` | `GET /metrics` with `kid: "*"` |

Root always passes permission checks. Routes operations require root or `admin`; there is no granular `routes` action.

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

There is no `GET /permissions` endpoint and no CLI list command.

### POST /permissions/reload

Administrative refresh operation. Reloads the unified signed config into memory.

Requires auth with root or an admin client.

If `config.json` is missing, Vectis reloads to an empty client list and only root remains authorized. If the config exists but is invalid, unsigned, has an invalid signature, references an unloaded KID for a KID-scoped non-admin permission, or uses `kid: "*"` with a non-global action, the request fails and the previous in-memory config remains active.

Response:

```json
{
  "status": "reloaded",
  "clients_loaded": 1
}
```

## Public Keys

### GET /pub/{kid}

Returns public keys only. This endpoint does not require auth.

Lifecycle behavior:

- `active`: public keys are returned.
- `disabled`, `retired`, `compromised`, `destroyed`: request is rejected.

Response:

```json
{
  "info": "version=v1;hostname=localhost;type=ops-keys;cipher=AES-256/GCM;tag=ACME Corp.;timestamp=1782058090",
  "keys": {
    "eddsa": {
      "alg": "Ed25519",
      "public_key_der_hex": "..."
    },
    "xecdh": {
      "alg": "X25519",
      "public_key_hex": "..."
    },
    "ml-dsa": {
      "alg": "ML-DSA-44",
      "public_key_der_hex": "..."
    },
    "ml-kem": {
      "alg": "ML-KEM-512",
      "public_key_der_hex": "..."
    }
  }
}
```

## Hybrid Timestamp Protocol

### POST /sign/{kid}

Signs a message hash with EdDSA and ML-DSA.

Requires auth.

Request:

```json
{
  "message_hash": {
    "alg": "BLAKE2b(256)",
    "hex": "..."
  }
}
```

`message_hash.hex` must have the correct length for `message_hash.alg`.

Response:

```json
{
  "version": "v1",
  "payload": {
    "version": "v1",
    "type": "vectis-sign",
    "created_at": "1782058090",
    "info": "version=v1;hostname=localhost;type=ops-keys;cipher=AES-256/GCM;tag=ACME Corp.;timestamp=1782058090",
    "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
    "serial": "...",
    "message_hash": {
      "alg": "BLAKE2b(256)",
      "hex": "..."
    }
  },
  "signatures": {
    "eddsa": {
      "alg": "Ed25519",
      "sig": "..."
    },
    "ml-dsa": {
      "alg": "ML-DSA-44",
      "sig": "..."
    }
  }
}
```

### POST /sign/verification

Verifies a token emitted by `POST /sign/{kid}`. This endpoint does not require auth.

The signer key is resolved locally first; if the token's `kid` is not a local key, Vectis resolves the signer's public keys from a trusted peer in the signed config (an active `remote_routes` entry with `public_keys` for that `kid`), enabling cross-instance verification. If the `kid` is neither local nor a known peer, verification fails.

Request: the complete JSON returned by `POST /sign/{kid}`.

Valid response:

```json
{
  "status": {
    "eddsa": "ok",
    "ml-dsa": "ok"
  },
  "valid": "ok"
}
```

Response with invalid signatures:

```json
{
  "status": {
    "eddsa": "fail",
    "ml-dsa": "ok"
  },
  "valid": "fail"
}
```

## Protected Messages Between Instances

### POST /message/{sender_kid}

Sends a protected message from this Vectis instance to another Vectis instance.

Requires auth.

Request:

```json
{
  "recipient_kid": "b01cbe33187916f0f1367d07bc986d71bb0d91d7047ccd790c13fc9d85fe7259",
  "message": "hello vectis"
}
```

Flow:

1. Validate `sender_kid`, `recipient_kid`, and `message`.
2. Resolve `recipient_kid` through the signed config `remote_routes` section.
3. If the recipient public key is not cached, call `GET /pub/{recipient_kid}` on the authorized `remote_addr`.
4. Create a hybrid secret with XECDH + ML-KEM.
5. Derive `message_key` with HKDF.
6. Encrypt the message.
7. Sign the payload with EdDSA and ML-DSA.
8. Send the envelope to `POST /message` on the recipient.

Response:

```json
{
  "message": {
    "valid": true
  },
  "symmetric": {
    "variant": "AES-256/GCM",
    "valid": true
  },
  "eddsa": {
    "variant": "Ed25519",
    "valid": true
  },
  "xecdh": {
    "variant": "X25519",
    "valid": true
  },
  "ml-dsa": {
    "variant": "ML-DSA-44",
    "valid": true
  },
  "ml-kem": {
    "variant": "ML-KEM-512",
    "valid": true
  }
}
```

Relevant public errors:

```json
{
  "error": "recipent kid not found"
}
```

```json
{
  "error": "internal server error - recipient can't be reached"
}
```

### POST /message

Receives a protected message from another Vectis instance. This endpoint does not require auth because authenticity is validated with EdDSA and ML-DSA signatures.

Request:

```json
{
  "version": "v1",
  "payload": {
    "version": "v1",
    "type": "protected-message",
    "created_at": "1782058090",
    "sender": {
      "host": "127.0.0.1:3000",
      "kid": "..."
    },
    "recipient": {
      "kid": "..."
    },
    "kem": {
      "alg": "X25519+ML-KEM-512",
      "xecdh_ephemeral_public": "...",
      "ml_kem_ciphertext": "...",
      "ml_kem_salt": "...",
      "hkdf_salt": "..."
    },
    "cipher": {
      "alg": "AES-256/GCM",
      "nonce": "...",
      "aad": "...",
      "ct": "..."
    }
  },
  "signatures": {
    "eddsa": {
      "alg": "Ed25519",
      "sig": "..."
    },
    "ml-dsa": {
      "alg": "ML-DSA-44",
      "sig": "..."
    }
  }
}
```

Response:

```json
{
  "status": "ok",
  "sender_kid": "...",
  "recipient_kid": "...",
  "local_cipher": {
    "alg": "AES-256/GCM",
    "nonce": "...",
    "aad": "...",
    "ct": "..."
  }
}
```

After receiving a message, Vectis re-encrypts the plaintext with the local symmetric key for `recipient_kid` and delivers it to the configured final app.

### POST /message/decrypt

Decrypts a local message received by the final app.

Requires auth.

Request:

```json
{
  "sender_host": "127.0.0.1:3000",
  "sender_kid": "...",
  "timestamp": "1782058090",
  "message": {
    "ctx": "...",
    "nonce": "...",
    "aad": "version=v1;type=stored-protected-message;sender_kid=...;recipient_kid=...;source_created_at=1782058090;cipher_alg=AES-256/GCM",
    "variant": "AES-256/GCM"
  }
}
```

Response:

```json
{
  "plaintext": "hello vectis"
}
```

## Internal Messages

These endpoints encrypt and decrypt internal messages with the symmetric key associated with a `kid`. They are meant for local data protection without running the network exchange flow between Vectis instances.

### POST /message/internal/encrypt/{kid}

Requires auth.

Request:

```json
{
  "plaintext": "hello vectis"
}
```

Response:

```json
{
  "timestamp": "1782058090",
  "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
  "message": {
    "ctx": "...",
    "nonce": "...",
    "aad": "version=v1;type=internal-message;kid=...;timestamp=1782058090;cipher_alg=AES-256/GCM",
    "variant": "AES-256/GCM"
  }
}
```

### POST /message/internal/decrypt

Requires auth.

Request: the JSON returned by `POST /message/internal/encrypt/{kid}`.

Response:

```json
{
  "plaintext": "hello vectis"
}
```

## Final App Delivery

When `POST /message` receives and validates a protected message, it delivers this JSON to the final app:

```json
{
  "sender_host": "127.0.0.1:3000",
  "sender_kid": "...",
  "timestamp": "1782058090",
  "message": {
    "ctx": "...",
    "nonce": "...",
    "aad": "...",
    "variant": "AES-256/GCM"
  }
}
```

The final app can call `POST /message/decrypt` to recover the plaintext.

## Configuration File (`config.json`)

Vectis loads a single signed config file (`config.json`) with three sections — `routes`, `remote_routes`, and `permissions` — plus a top-level `version`. It is loaded when `vectis serve` starts and can be reloaded at runtime with `POST /routes/reload`, `POST /remote-routes/reload`, or `POST /permissions/reload` (each reloads the whole config). Create/update its signature with `vectis config sign`; inspect it with `vectis config list`.

Default paths:

```env
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
```

Expected file shape:

```json
{
  "version": "v1",
  "routes": [
    {
      "kid": "f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed",
      "final_app_addr": "127.0.0.1:3999",
      "final_app_path": "/message"
    }
  ],
  "remote_routes": [
    {
      "remote_kid": "b01cbe33187916f0f1367d07bc986d71bb0d91d7047ccd790c13fc9d85fe7259",
      "name": "site-b",
      "remote_addr": "vectis-b.example.com:443",
      "allowed_local_kids": ["*"],
      "status": "active",
      "public_keys": {
        "eddsa":  { "alg": "Ed25519",    "public_key_der_hex": "3043..." },
        "xecdh":  { "alg": "X25519",     "public_key_hex": "a1b2..." },
        "ml-dsa": { "alg": "ML-DSA-44",  "public_key_der_hex": "3082..." },
        "ml-kem": { "alg": "ML-KEM-512", "public_key_der_hex": "3082..." }
      }
    }
  ],
  "permissions": [
    {
      "client": "clinic-app",
      "apikey_hash": "f80e3d53ecb4c086f6a4f76792df30fe70fcf383c8aaff09bce65340a9360e3e",
      "status": "active",
      "permissions": [{ "kid": "f55f086e...", "actions": ["message"] }]
    }
  ]
}
```

Top level:

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `version` | yes | `"v1"` | Config schema version; unknown versions are rejected. |
| `routes` | yes (may be `[]`) | array | Final app delivery routes per local `kid`. |
| `remote_routes` | yes (may be `[]`) | array | Authorized remote Vectis peers. |
| `permissions` | yes (may be `[]`) | array | Non-root API key clients and their allowed actions. |

`routes[]` entries:

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `kid` | yes | 64-hex kid, must be a loaded local key | Local operational key this route applies to. |
| `final_app_addr` | yes | `host:port` | Where to deliver decrypted messages for this `kid`. |
| `final_app_path` | yes | path starting with `/` | Delivery path (e.g. `/message`). |

`remote_routes[]` entries:

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `remote_kid` | yes | 64-hex kid (the remote peer's key) | Identifies the remote peer. |
| `name` | yes | text | Human label. |
| `remote_addr` | yes | `host:port` | Address of the remote Vectis instance. |
| `allowed_local_kids` | yes | non-empty array; `["*"]` or explicit loaded kids (no mixing) | Which local sender KIDs may use this route. |
| `status` | yes | `active` \| `disabled` | Disabled routes load but cannot send. |
| `public_keys` | no | object (see below) | Peer's trusted public keys for direct use and cross-instance verification. |

`public_keys` object (optional; the `keys` object from the peer's `GET /pub/{kid}`): `eddsa`/`ml-dsa`/`ml-kem` each `{ "alg", "public_key_der_hex" }`, and `xecdh` `{ "alg", "public_key_hex" }`.

`permissions[]` entries:

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `client` | yes | text, unique | Client label. |
| `apikey_hash` | yes | 64 hex (32 bytes) | Server-side verifier for this client's `X-API-Key`. |
| `status` | yes | `active` \| `disabled` \| `revoked` | Only `active` clients are authorized. |
| `permissions` | yes | array of `{ "kid", "actions" }` | Per-kid grants. `actions` ⊆ `admin`, `keys`, `lifecycle`, `self-test`, `sign`, `message`, `metrics`. `kid: "*"` is only allowed with global actions (`metrics`); an `admin` action grants all endpoints and ignores kid-scoped grants. |

Routing behavior:

1. Resolve `recipient_kid` in the in-memory routes state.
2. If a route exists, deliver to that route's `final_app_addr` and `final_app_path`.
3. If no route exists for the `kid`, deliver to the default `VECTIS_FINAL_APP_ADDR` and `VECTIS_FINAL_APP_PATH`.
4. A manual route is loaded only if its `kid` exists in the keys currently loaded in memory.
5. During startup, a missing config, invalid config, or route with an unloaded `kid` starts with empty sections and uses the default final app fallback.
6. During reload, a missing config reloads to empty sections; an invalid config, bad signature, or a section referencing an unloaded `kid` returns an error and keeps the previous in-memory config.

The config file is operational configuration. Vectis does not create it automatically and `POST /keys` does not modify it.

`POST /message/{sender_kid}` never accepts a destination host from the request body; it resolves `recipient_kid` through the signed `remote_routes` section. A route can allow specific local sender KIDs, or `allowed_local_kids: ["*"]` for any loaded local KID. The wildcard cannot be mixed with explicit KIDs. Disabled routes are loaded and listed, but cannot be used to send messages.

Each `remote_routes` entry may carry an optional `public_keys` object — the full public key set of that peer, exactly as returned by the remote's `GET /pub/{kid}`. It is trusted because the operator signs the config. When present:

- `/message` uses those keys directly for the peer (no `/pub` fetch); when absent, Vectis fetches `/pub` on demand (trust on first use).
- `POST /sign/verification` can verify timestamp tokens whose signer `kid` is not local, resolving the signer's public keys from the matching active `remote_routes` entry.

## Related Configuration

Main variables:

- `VECTIS_PUBLIC_ADDR`: public address used as `sender.host` in protected messages.
- `VECTIS_MODE`: central transport mode. `dev` uses HTTP everywhere; `prod` uses HTTPS for the local server, Vectis-to-Vectis requests, and final app delivery.
- `VECTIS_TLS_CERT_PATH`, `VECTIS_TLS_KEY_PATH`: PEM certificate and private key required when `VECTIS_MODE=prod`.
- `VECTIS_TLS_SKIP_VERIFY`: disables outbound HTTPS certificate verification.
- `VECTIS_FINAL_APP_ADDR`: final app host:port.
- `VECTIS_FINAL_APP_PATH`: final app delivery path.
- `VECTIS_CONFIG_PATH`: unified signed config file path (routes, remote routes, permissions), relative to the working directory unless absolute.
- `VECTIS_APIKEY`: client-side HTTP auth key sent as `X-API-Key`.
- `VECTIS_APIKEY_HASH`: server-side HMAC value used to verify `X-API-Key` without storing the API key in plaintext.
- `VECTIS_SQLITE_PATH`: sqlite storage path.
- `VECTIS_HASH`, `VECTIS_SYMMETRIC`, `VECTIS_EDDSA`, `VECTIS_XECDH`, `VECTIS_ML_DSA_VARIANT`, `VECTIS_ML_KEM_VARIANT`: defaults for `POST /keys`.
- `VECTIS_LOG_LEVEL`, `VECTIS_LOG_DIR`, `VECTIS_LOG_FILE`: logging configuration.

Internal defaults for `init` key material:

- `INTERNAL_KEYS_HASH`: `BLAKE2b(256)`
- `INTERNAL_KEYS_EDDSA_ALGORITHM`: `Ed25519`
- `INTERNAL_KEYS_XECDH_ALGORITHM`: `X25519`
- `INTERNAL_KEYS_ML_DSA_VARIANT`: `ML-DSA-44`
- `INTERNAL_KEYS_ML_KEM_VARIANT`: `ML-KEM-512`

## CLI Mapping

Runtime CLI commands call the HTTP API:

CLI output defaults to YAML for readability. Add `--output json` to HTTP client commands and to `vectis apikey create` to print pretty JSON instead. This does not apply to `vectis init`.

| CLI command | HTTP operation | Auth |
| --- | --- | --- |
| `vectis apikey create` | Local API key generation | No HTTP |
| `vectis health startup` | `GET /healthz/startup` | No |
| `vectis health live` | `GET /healthz/live` | No |
| `vectis health ready` | `GET /healthz/ready` | No |
| `vectis test init` | `GET /self-test/init` | Yes |
| `vectis test <kid>` | `GET /self-test/keys/{kid}` | Yes |
| `vectis keys create` | `POST /keys` | Yes |
| `vectis keys list` | `GET /keys` | No |
| `vectis keys properties` | `GET /keys/properties` | Yes |
| `vectis keys properties <kid>` | `GET /keys/properties/{kid}` | Yes |
| `vectis keys reload` | `POST /keys/reload` | Yes |
| `vectis lifecycle <kid>` | `POST /lifecycle/{kid}` | Yes |
| `vectis routes list` | `GET /routes` | Yes |
| `vectis routes reload` | `POST /routes/reload` | Yes |
| `vectis remote-routes list` | `GET /remote-routes` | Yes |
| `vectis remote-routes reload` | `POST /remote-routes/reload` | Yes |
| `vectis permissions reload` | `POST /permissions/reload` | Yes |
| `vectis config sign` | Local `config_sign.json` update | No HTTP |
| `vectis config list` | Prints local `config.json` | No HTTP |
| `vectis config reload` | `POST /routes/reload` | Yes |
| `vectis pub <kid>` | `GET /pub/{kid}` | No |
| `vectis sign <kid>` | `POST /sign/{kid}` | Yes |
| `vectis sign verify` | `POST /sign/verification` | No |
| `vectis message send <sender_kid>` | `POST /message/{sender_kid}` | Yes |
| `vectis message receive` | `POST /message` | No |
| `vectis message decrypt` | `POST /message/decrypt` | Yes |
| `vectis message internal encrypt <kid>` | `POST /message/internal/encrypt/{kid}` | Yes |
| `vectis message internal decrypt` | `POST /message/internal/decrypt` | Yes |

Local commands:

- `vectis init`: creates encrypted `VECTIS_INIT_KEYS_FILE`, default `init.json`, prints `VECTIS_UNSEAL_KEY`, `VECTIS_APIKEY`, and `VECTIS_APIKEY_HASH`. It refuses to overwrite an existing init keys file; delete it manually before reinitializing.
- `vectis apikey create`: decrypts `VECTIS_INIT_KEYS_FILE`, derives the internal API auth key, prints a new `VECTIS_APIKEY` and matching `VECTIS_APIKEY_HASH`, and does not write files.
- `vectis serve`: validates `VECTIS_INIT_KEYS_FILE`, loads storage/config into memory, and starts the HTTP service. Unseal key resolution order is `VECTIS_UNSEAL_KEY`, `VECTIS_UNSEAL_KEY_FILE` with default `.unseal_key`, then hidden prompt.
- `vectis config sign`: reads `VECTIS_CONFIG_PATH`, signs its canonical JSON with init EdDSA and init ML-DSA, and writes `VECTIS_CONFIG_SIGN_PATH`.
- `vectis config list`: prints `VECTIS_CONFIG_PATH` locally.

## Config Signature

When `config.json` exists, Vectis requires a matching config signature before loading it.

Default paths:

```env
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
```

Create or update the signature:

```bash
vectis config sign
```

`config_sign.json` uses the same signed payload structure as `POST /sign/{kid}`:

```json
{
  "version": "v1",
  "payload": {
    "version": "v1",
    "type": "vectis-config",
    "created_at": "1782058090",
    "info": "version=v1;type=vectis-config;path=config.json",
    "kid": "init-keys",
    "serial": "INTERNAL_KEYS_HASH(created_at + random_bytes)",
    "message_hash": {
      "alg": "BLAKE2b(256)",
      "hex": "hash of canonical config.json"
    }
  },
  "signatures": {
    "eddsa": {
      "alg": "Ed25519",
      "sig": "..."
    },
    "ml-dsa": {
      "alg": "ML-DSA-44",
      "sig": "..."
    }
  }
}
```

Validation rules:

- `payload.type` must be `vectis-config`.
- `payload.kid` must be `init-keys`.
- `payload.message_hash` must match canonical `config.json` using `INTERNAL_KEYS_HASH`.
- EdDSA and ML-DSA signatures must verify with init public keys.
- Startup with missing `config.json` uses empty sections (default routing, only root authorized).
- Startup with invalid config signature uses empty sections and logs the error.
- A reload endpoint rejects invalid signatures and keeps the previous in-memory config.
