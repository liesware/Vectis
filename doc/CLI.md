# CLI

## Purpose

The Vectis CLI has two jobs:

1. local bootstrap work that must happen before the HTTP service exists;
2. HTTP client work against a running Vectis service.

It is not a daemon manager, database migrator, secret manager, Kubernetes
operator, or cluster coordinator.

The CLI keeps the same rule as the rest of Vectis: do one thing, expose plain
interfaces, and stay easy to inspect.

## Command Groups

Local commands do not require the HTTP service:

- `vectis init`
- `vectis apikey create`
- `vectis config sign`
- `vectis config list`

Runtime commands call the HTTP API and normally require `VECTIS_API_URL`:

- `vectis health`
- `vectis test`
- `vectis keys`
- `vectis lifecycle`
- `vectis routes`
- `vectis remote-routes`
- `vectis permissions`
- `vectis config reload`
- `vectis pub`
- `vectis sign`
- `vectis message`

Use built-in help for exact syntax:

```sh
vectis help
vectis help keys
vectis help message
```

## Output

Most CLI commands return YAML by default.

Use JSON when another program needs stable JSON:

```sh
vectis keys list --output json
vectis health ready --output json
```

`vectis init` is the exception. It prints shell-style values because those values
are usually copied into files, environment, or secret managers.

## Environment

The CLI reads process environment variables first, then `.env`, then built-in
defaults.

Common HTTP client variables:

- `VECTIS_API_URL`: API base URL, default `http://127.0.0.1:3000`.
- `VECTIS_APIKEY`: client API key sent as `X-API-Key`.
- `VECTIS_TIMEOUT_SECONDS`: request timeout, default `30`.
- `VECTIS_TLS_SKIP_VERIFY`: disables outbound TLS verification for HTTPS
  clients.

Common local bootstrap variables:

- `VECTIS_INIT_KEYS_FILE`: encrypted init key material, default `init.json`.
- `VECTIS_UNSEAL_KEY`: unseal key from process environment.
- `VECTIS_UNSEAL_KEY_FILE`: file containing the unseal key, default
  `.unseal_key`.
- `VECTIS_CONFIG_PATH`: signed config source file, default `config.json`.
- `VECTIS_CONFIG_SIGN_PATH`: signature file, default `config_sign.json`.

`VECTIS_UNSEAL_KEY` is intentionally not read from `.env`.

Current unseal providers are:

1. `env`: `VECTIS_UNSEAL_KEY`;
2. `file`: `VECTIS_UNSEAL_KEY_FILE`;
3. `prompt`: hidden terminal prompt.

There is no configurable unseal provider selector yet.

## Local Bootstrap Commands

### `vectis init`

Creates encrypted init key material and prints:

- `VECTIS_INIT_KEYS_FILE`
- `VECTIS_UNSEAL_KEY`
- `VECTIS_APIKEY`
- `VECTIS_APIKEY_HASH`

If the configured init keys file already exists, `init` refuses to overwrite it.
There is no force flag. Delete the file manually if reinitialization is really
intended.

Example:

```sh
vectis init
```

### `vectis apikey create`

Creates another API key pair from existing init material. It prints:

- `VECTIS_APIKEY`
- `VECTIS_APIKEY_HASH`

It does not write `.env`, config files, init material, or storage.

Examples:

```sh
vectis apikey create
vectis apikey create --output json
```

### `vectis config sign`

Signs `VECTIS_CONFIG_PATH` using the init keys and writes
`VECTIS_CONFIG_SIGN_PATH`.

The config file must already exist and must be valid JSON. The CLI does not
render YAML to JSON here.

Example:

```sh
vectis config sign
```

### `vectis config list`

Reads and prints `VECTIS_CONFIG_PATH`.

Example:

```sh
vectis config list
```

## HTTP Client Commands

These commands call a running Vectis server.

### `vectis serve`

Starts the HTTP service. Before serving, it decrypts and validates
`VECTIS_INIT_KEYS_FILE`.

Example:

```sh
vectis serve
```

### `vectis health`

Calls public health endpoints.

```sh
vectis health startup
vectis health live
vectis health ready
```

### `vectis test`

Calls protected self-test endpoints.

```sh
vectis test init
vectis test <kid>
```

### `vectis keys`

Creates, lists, inspects, or reloads operational keys.

```sh
vectis keys create --tag payments --profile hybrid-high-assurance-v1
vectis keys list
vectis keys properties
vectis keys properties <kid>
vectis keys reload
```

`keys list` is public and lists keys loaded in this node's memory.

`keys reload` is explicit. It reloads local key state from storage into the node.
It is not a cluster-wide operation.

`keys create` only exposes `--tag` and `--profile`. It does not expose every
HTTP field on purpose. Profile selection is the supported CLI path.

### `vectis lifecycle`

Updates encrypted lifecycle metadata for an operational key.

```sh
vectis lifecycle <kid> --status disabled --reason maintenance
vectis lifecycle <kid> --status active --reason restored
```

Allowed statuses:

- `active`
- `disabled`
- `retired`
- `compromised`
- `destroyed`

### `vectis routes`

Lists final app routes currently loaded in memory.

```sh
vectis routes list
```

Use `vectis config reload` to reload the signed config for this node.

### `vectis remote-routes`

Lists remote Vectis routes currently loaded in memory.

```sh
vectis remote-routes list
```

Use `vectis config reload` to reload the signed config for this node.

### `vectis permissions`

Lists effective active API key permissions currently loaded in memory. It does
not print `apikey_hash`.

```sh
vectis permissions list
```

### `vectis config reload`

Calls `POST /config/reload` on the running server.

```sh
vectis config reload
```

Reload is per-node. It is not cluster-wide.

### `vectis pub`

Fetches public key material for a local operational key.

```sh
vectis pub <kid>
```

### `vectis sign`

Creates or verifies hybrid timestamp signatures.

```sh
vectis sign <kid> --file sign-request.json
vectis sign <kid> --json '{"message_hash":{"alg":"SHA-256","hex":"<64 hex chars>"}}'
vectis sign verify --file token.json
```

### `vectis message`

Sends, receives, encrypts, or decrypts messages.

```sh
vectis message send <sender_kid> --file send-message.json
vectis message receive --file envelope.json
vectis message decrypt --file encrypted-message.json
vectis message internal encrypt <kid> --file plaintext.json
vectis message internal decrypt --file internal-message.json
```

Small JSON inputs can be passed directly with `--json`, but files are easier to
read and audit.

## Authentication

Protected HTTP commands send:

```text
X-API-Key: <VECTIS_APIKEY>
```

The server verifies that value against `VECTIS_APIKEY_HASH` or against active
clients loaded from signed config permissions.

Do not put API keys in command history when avoidable. Prefer environment,
files with restricted permissions, or a secret manager.

## Input Validation

The CLI validates inputs before sending HTTP requests when it can:

- KIDs must be hex and match the internal KID length.
- `--profile` must be one of the supported crypto profiles.
- lifecycle status must be one of the supported lifecycle values.
- JSON input must be a JSON object.
- `--file` must point to a readable UTF-8 file.
- `VECTIS_API_URL` must be an HTTP or HTTPS URL.

The server validates again. CLI validation is convenience, not a trust boundary.

## Failure Model

Typical failures:

- missing or invalid `VECTIS_APIKEY`;
- server not running;
- wrong `VECTIS_API_URL`;
- TLS verification failure;
- invalid JSON input;
- denied permissions;
- key not loaded or not found;
- storage unavailable;
- invalid signed config.

HTTP errors are returned as sanitized public errors. Operational details belong
in server logs and audit logs.

## What The CLI Does Not Do

The CLI does not:

- apply database migrations;
- create PostgreSQL tables;
- manage PostgreSQL HA;
- distribute config across cluster nodes;
- manage Kubernetes resources;
- rotate secrets automatically;
- replace `curl`, `jq`, shell scripts, or deployment tooling.

It is a bootstrap tool and an HTTP client. Nothing more.
