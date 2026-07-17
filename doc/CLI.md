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
- `vectis fpe`
- `vectis token`

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
  `.unseal_key`. The file must have `0600` permissions.
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

### `vectis config init`

Creates the initial `VECTIS_CONFIG_PATH` skeleton.

It writes:

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

It refuses to overwrite an existing file. There is no force option. Delete the
file manually to start over.

Example:

```sh
vectis config init
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

### `vectis config routes`

Edits the local `routes` section in `VECTIS_CONFIG_PATH`. The lookup key is
`name`. Names must be unique.

```sh
vectis config routes list
vectis config routes add --name clinical-app-a --kid <kid> --final-app-addr 127.0.0.1:3999 --final-app-path /message
vectis config routes get clinical-app-a
vectis config routes update clinical-app-a --final-app-path /clinical/message
vectis config routes delete clinical-app-a
```

### `vectis config remote-routes`

Edits the local `remote_routes` section in `VECTIS_CONFIG_PATH`. The lookup key
is `name`. Names must be unique.

`add` fetches public keys from the peer:

```text
{scheme}://{remote_addr}/pub/{remote_kid}
```

The scheme comes from `VECTIS_MODE`: `dev` uses `http`, `prod` uses `https`.

```sh
vectis config remote-routes list
vectis config remote-routes add --name clinic-b --remote-kid <kid> --remote-addr vectis-b.example.com:443 --allowed-local-kid <local-kid> --status active
vectis config remote-routes add --name clinic-b --remote-kid <kid> --remote-addr vectis-b.example.com:443 --allowed-local-kid "*" --status active
vectis config remote-routes get clinic-b
vectis config remote-routes update clinic-b --status disabled
vectis config remote-routes delete clinic-b
```

Quote `"*"` when using wildcard `allowed_local_kids`; otherwise shells such as
`zsh` and `bash` may expand it to filenames in the current directory.

If `remote_kid` or `remote_addr` changes through `update`, the CLI re-fetches
`public_keys` from the peer. Updating `status` or `allowed_local_kids` does not
fetch keys.

### `vectis config permissions`

Edits the local `permissions` section in `VECTIS_CONFIG_PATH`. The lookup key is
`client`. Clients must be unique.

```sh
vectis config permissions list
vectis config permissions add --client clinic-app --apikey-hash <hex> --status active
vectis config permissions get clinic-app
vectis config permissions update clinic-app --status disabled
vectis config permissions grant clinic-app --kid <kid> --action message
vectis config permissions revoke clinic-app --kid <kid> --action message
vectis config permissions delete clinic-app
```

Permission editing is a two-step flow:

```sh
vectis config permissions add --client "Acme App" --apikey-hash <hex> --status active
vectis config permissions grant "Acme App" --kid "*" --action admin
```

`add` and `update` manage the client record and `apikey_hash`. `grant` and
`revoke` only manage `kid`/`action` grants. Quote `"*"` when granting wildcard
permissions so the shell does not expand it.

### `vectis config fpe`

Edits the local `fpe_profiles` section in `VECTIS_CONFIG_PATH`. The lookup key
is `name`. Names must be unique.

```sh
vectis config fpe list
vectis config fpe add --name patient-id-decimal-v1 --kid <kid> --alphabet 0123456789 --min-len 6 --max-len 32 --tweak-aad 'tenant=acme;field=patient_id;version=1'
vectis config fpe get patient-id-decimal-v1
vectis config fpe update patient-id-decimal-v1 --max-len 40
vectis config fpe delete patient-id-decimal-v1
```

`fpe_version` defaults to `fpe-ff1-2025`; that is the only accepted version in
this release. `min_len` must be at least `6`, and `max_len` must be greater than
or equal to `min_len`. `tweak_aad` must use `key=value;key=value` labels such as
`tenant=acme;field=patient_id;version=1` and is limited to 128 characters. The
CLI validates the KID shape but does not check whether
the KID is loaded in a running server. That check happens when Vectis loads the
signed config.

### `vectis config token`

Edits the local `tokenization_profiles` section in `VECTIS_CONFIG_PATH`. The
lookup key is `name`. Names must be unique.

```sh
vectis config token list
vectis config token add --name patient-id-token-v1 --kid <kid> --token-prefix tok_patient --token-len 32 --max-plaintext-len 1024
vectis config token get patient-id-token-v1
vectis config token update patient-id-token-v1 --max-plaintext-len 512
vectis config token delete patient-id-token-v1
```

`tokenization_version` defaults to `token-random-v1`; that is the only accepted
version in this release. `token_len` is the number of random bytes before
base64url encoding and must be at least `32`. `token_prefix` is a visible
prefix, is limited to 16 characters, and cannot contain whitespace, control
characters, `;`, or `=`. The CLI validates field shape but does not check
whether the KID is loaded in a running server. That check happens when Vectis
loads the signed config.

### `vectis config mac`

Edits the local `mac_profiles` section in `VECTIS_CONFIG_PATH`. The lookup key
is `name`. Names must be unique.

```sh
vectis config mac list
vectis config mac add --name pan-blind-index-v1 --kid <kid> --context 'tenant=mx;field=pan;purpose=blind-index;version=1'
vectis config mac get pan-blind-index-v1
vectis config mac update pan-blind-index-v1 --context 'tenant=mx;field=pan;purpose=blind-index;version=2'
vectis config mac delete pan-blind-index-v1
```

`context` must use `key=value;key=value` labels, is limited to 128 characters,
and comes only from signed config. The CLI validates field shape but does not
check whether the KID is loaded in a running server. That check happens when
Vectis loads the signed config.

Section `list` commands print only the local array from `config.json`. Runtime
commands such as `vectis routes list` read the server's loaded state instead.

Config edit commands write `config.json` only. They do not sign or reload. Run:

```sh
vectis config init
vectis config sign
vectis config reload
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

### `vectis fpe`

Calls local format-preserving encryption endpoints. FPE profiles are not
defined in the request; they are loaded from signed `config.json`.

```sh
vectis fpe encrypt <kid> --json '{"ref":"reg1","profile":"patient-id-decimal-v1","plaintext":"123456"}'
vectis fpe decrypt --json '{"ref":"reg1","kid":"<kid>","profile":"patient-id-decimal-v1","ciphertext":"839201"}'
```

`encrypt` requires `fpe-encrypt` permission for the KID and an `active` key.
`decrypt` requires `fpe-decrypt` permission and allows `active` or `retired`
keys. The CLI does not print or accept `fpe_version`; that value is part of the
signed profile. `ref` is a required client correlation value and is echoed in
the response.

### `vectis token`

Calls local reversible tokenization endpoints. Tokenization profiles are not
defined in the request; they are loaded from signed `config.json`.

```sh
vectis token encode <kid> --json '{"ref":"reg1","profile":"patient-id-token-v1","plaintext":"123456","metadata":{}}'
vectis token decode --json '{"ref":"reg1","kid":"<kid>","profile":"patient-id-token-v1","token":"tok_patient_..."}'
```

`encode` requires `token-encode` permission for the KID and an `active` key.
`decode` requires `token-decode` permission and allows `active` or `retired`
keys. Metadata is optional, must be a JSON object when present, and its compact
serialized JSON representation must be at most 128 characters. `ref` is a
required client correlation value and is echoed in the response.

### `vectis mac`

Calls local MAC create/verify endpoints. MAC profiles are not defined in the
request; they are loaded from signed `config.json`.

```sh
vectis mac create <kid> --json '{"profile":"pan-blind-index-v1","plaintext":"4111111111111111"}'
vectis mac verify <kid> --json '{"profile":"pan-blind-index-v1","plaintext":"4111111111111111","digest":"<hex>"}'
```

`create` requires `mac-create` permission for the KID and an `active` key.
`verify` requires `mac-verify` permission and allows `active` or `retired`
keys. The response reports the resolved MAC algorithm and digest.

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
