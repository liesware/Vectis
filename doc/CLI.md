# CLI

## Purpose

Vectis is an API-first service. Applications integrate with Vectis through its
HTTP API. The CLI exists for local bootstrap and gives administrators a
first-party way to configure, inspect, validate, and exercise a Vectis node
without requiring hand-written `curl` requests or something like that . It is not the
primary integration interface for application data workflows.

The Vectis CLI has two jobs:

1. local bootstrap work that must happen before the HTTP service exists;
2. HTTP client work against a running Vectis service.

It is not a daemon manager, database migrator, secret manager, Kubernetes
operator, or cluster coordinator.

The CLI keeps the same rule as the rest of Vectis: do one thing, expose plain
interfaces, and stay easy to inspect.

## Command Groups

### Local Bootstrap And Administration

- `vectis version`
- `vectis init`
- `vectis apikey create`
- `vectis audit verify`
- `vectis slh-dsa create|sign|verify`
- `vectis config init|validate|sign|list`
- `vectis config routes|remote-routes|permissions`
- `vectis config fpe|token|mac|masking|commitment|sharing|time`

Config edit commands modify the local signed-config source. They do not apply
changes to a running node until the config is signed and reloaded. Remote-route
editing may fetch peer public keys from the configured remote Vectis node.

### Runtime Commands

- `vectis health`
- `vectis test`
- `vectis keys`
- `vectis lifecycle`
- `vectis routes`
- `vectis remote-routes`
- `vectis permissions`
- `vectis config reload`
- `vectis pub`

These commands, together with the Data Protection and Messaging And Evidence
groups below, call the HTTP API: they require a running node and
`VECTIS_API_URL`. Some change live node state rather than only reading it —
`vectis keys create` / `keys reload`, `vectis lifecycle`, and `vectis config
reload` mutate keys, key lifecycle, or the loaded config.

### Data Protection

- `vectis symmetric`
- `vectis fpe`
- `vectis token`
- `vectis mac`
- `vectis index`
- `vectis mask`
- `vectis commit`
- `vectis shares`

### Messaging And Evidence

- `vectis sign`
- `vectis message`
- `vectis time`

The CLI exposes representative single-operation workflows. Batch data
workflows are intended for direct HTTP API integration.

Time attestation is a protected runtime command:

```sh
vectis time attest
vectis config time get
vectis config time set --max-clock-skew-ms 1000
vectis config time clear
```

`provider` is an operational provider name; v1 supports `cloudflare`. `time
attest` calls the live NTS and Roughtime sources and requires the global
`time-attest` permission. The config commands only edit signed overrides; sign
and reload them through the normal config workflow.

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

## SLH-DSA Artifact Signing

`vectis slh-dsa` is a local, offline artifact-signing command. `create` and
`sign` require encrypted init material and unseal input; `verify` uses only the
public key file and never contacts the service. It uses fixed
`SLH-DSA-SHAKE-256s` with randomized signatures and signs a SHA-3(512) hash of
the input file incrementally.

`--input` accepts any regular file: JSON, CSV, PDF, an archive, or binary
content. Vectis does not parse or interpret the artifact; it computes
SHA-3(512) over its exact bytes and signs that hash. `settlement.json` below is
only an example filename, not a required schema or file type.

```sh
vectis slh-dsa create --out signing
vectis slh-dsa sign --key signing-slh-dsa.enc --input settlement.json --out settlement.json.sig
vectis slh-dsa verify --key signing-slh-dsa.pub --input settlement.json --signature settlement.json.sig
```

The public key file is the verification trust root. Preserve or distribute it
through an independent trusted channel; replacing an artifact, signature, and
public key together defeats local provenance checking.

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
- `VECTIS_INIT_PUBLIC_KEYS_FILE`: public init verification keys, default `init_pub.json`.
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

## Audit Verification

Verify a local hash-chained audit JSONL export and its hybrid-signed checkpoints
without contacting the service:

```sh
vectis audit verify --file logs/audit.log
vectis audit verify --file logs/audit.log --output json
```

The verifier loads `init_pub.json` through `VECTIS_INIT_PUBLIC_KEYS_FILE`, then
checks JSON canonicalization, record hashes, sequence continuity, and every
hybrid-signed checkpoint. It does not load `init.json` or require an unseal key.
A result reports the latest verified checkpoint for each chain. Preserve the
public verification file and checkpoints in an independent collector to detect
complete log replacement or truncation beyond the latest checkpoint.

`valid` means that canonical records, hash-chain continuity, and every checkpoint
present verified successfully. It does not mean that every record is covered by
a checkpoint. Records after the latest checkpoint form an unsigned tail: their
structure is verified, but their authenticity is not established by the
checkpoint signatures. Review the reported checkpoint coverage when the audit
export is used as security evidence.

### `vectis init`

Creates encrypted init key material plus public init verification keys and prints:

- `VECTIS_INIT_KEYS_FILE`
- `VECTIS_INIT_PUBLIC_KEYS_FILE`
- `VECTIS_UNSEAL_KEY`
- `VECTIS_APIKEY`
- `VECTIS_APIKEY_HASH`

If either configured init key file already exists, `init` refuses to overwrite
them. There is no force flag. Delete both files manually if reinitialization is really
intended.

Example:

```sh
vectis init
```

Recover a missing public verification file without generating new keys:

```sh
vectis init pub
```

This command decrypts and validates `VECTIS_INIT_KEYS_FILE`, so it requires the
normal unseal flow. It writes only a missing `VECTIS_INIT_PUBLIC_KEYS_FILE` and
never overwrites an existing one.

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

Grant time attestation as a global action, then sign and reload the config:

```sh
vectis config permissions grant "clock-monitor" --kid "*" --action time-attest
vectis config sign
vectis config reload
vectis time attest
```

`add` and `update` manage the client record and `apikey_hash`. `grant` and
`revoke` only manage `kid`/`action` grants. Quote `"*"` when granting wildcard
permissions so the shell does not expand it.

### `vectis config fpe`

Edits the local `fpe_profiles` section in `VECTIS_CONFIG_PATH`. The lookup key
is `name`. Names must be unique.

`--authenticated true|false` enables optional authentication in the signed
profile. Omission on update preserves the policy; invalid values fail before
writing. False is omitted in canonical serialization. Adopt true through a new
profile, then sign and reload; existing ciphertexts are not migrated.

```sh
vectis config fpe add --name patient-id-auth-v1 --kid <kid> --alphabet-preset num --preserve-characters '-' --authenticated true --min-len 6 --max-len 32 --tweak-aad 'tenant=acme;field=patient_id;version=1'
```

```sh
vectis config fpe list
vectis config fpe add --name patient-id-decimal-v1 --kid <kid> --alphabet 0123456789 --min-len 6 --max-len 32 --tweak-aad 'tenant=acme;field=patient_id;version=1'
vectis config fpe get patient-id-decimal-v1
vectis config fpe update patient-id-decimal-v1 --max-len 40
vectis config fpe delete patient-id-decimal-v1
vectis config fpe add --name patient-id-formatted-v1 --kid <kid> --alphabet-preset num --preserve-characters '-' --min-len 6 --max-len 32 --tweak-aad 'tenant=acme;field=patient_id;version=1'
vectis config fpe add --name label-formatted-v1 --kid <kid> --alphabet-preset alphanum --letter-case mixed --preserve-characters '- ' --min-len 6 --max-len 32 --tweak-aad 'tenant=acme;field=label;version=1'
```

Exactly one of `--alphabet` and `--alphabet-preset` is required on add. Presets
must use `--alphabet-preset`: `--alphabet num` literally selects `n`, `u`, `m`,
not digits. That custom alphabet is valid with `--min-len 13`; `--alphabet alpha`
and `--alphabet alphanum` contain duplicate characters and fail with a preset hint.
No keyword is reserved or converted in valid custom alphabets. Presets
are `num`, `alpha`, `alphanum`; alpha/alphanum require `--letter-case`
`uppercase|lowercase|mixed`, while num/custom prohibit it. On update, an explicit
selector replaces the previous selector. Compatible alpha/alphanum updates may
inherit case; custom/num remove inherited case but reject an explicit case flag.
`--preserve-characters ''` clears the policy while retaining the explicit field.
Up to 32 distinct Unicode characters are allowed, without controls or alphabet
overlap. Total length includes separators, but only variable characters count
toward the minimum million-value domain.
For num with minimum six and preserved `-`, `001-234` is accepted, while
`001-23` meets total length but fails the domain check: only five symbols are
encrypted. This validation is per value. Inputs and formatting are not normalized
or authenticated. Use a new profile to adopt another format; requests still
select only the profile. Invalid edits leave configuration unchanged.

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
vectis config token add --name patient-id-token-v1 --kid <kid> --token-prefix tok_patient --token-len 32 --max-plaintext-len 1024 --one-time false
vectis config token get patient-id-token-v1
vectis config token update patient-id-token-v1 --max-plaintext-len 512
vectis config token delete patient-id-token-v1
```

Vectis uses the fixed internal tokenization scheme `token-random-v1`.
`max_plaintext_len` accepts 1 through 16,384 Unicode characters. Existing
profiles retain their maximum; sign and reload config after increasing it.
`token_len` is the number of random bytes before base64url encoding and must be
at least `32`. `token_prefix` is a visible prefix, is limited to 16 characters,
and cannot contain whitespace, control characters, `;`, or `=`. The CLI
requires `--one-time true|false`; when true, a successful token decode consumes
the token. This policy is evaluated from the currently loaded signed profile.
The CLI
validates field shape but does not check whether the KID is loaded in a running
server. That check happens when Vectis loads the signed config.

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

### `vectis config commitment`

Edits the local `commitment_profiles` section in `VECTIS_CONFIG_PATH`. The
lookup key is `name`. Names must be unique.

```sh
vectis config commitment list
vectis config commitment add --name pan-commitment-v1 --kid <kid> --context 'tenant=mx;field=pan;purpose=commitment;version=1' --max-plaintext-len 128 --opening-len 32
vectis config commitment get pan-commitment-v1
vectis config commitment update pan-commitment-v1 --opening-len 64
vectis config commitment delete pan-commitment-v1
```

`context` must use `key=value;key=value` labels and is limited to 128
characters. `max_plaintext_len` must be between 1 and 1024, and `opening_len`
must be between 32 and 64 bytes. The CLI validates field shape but does not
check whether the KID is loaded in a running server. That check happens when
Vectis loads the signed config.

### `vectis config sharing`

Edits stateless Shamir `sharing_profiles` in `VECTIS_CONFIG_PATH`.

```sh
vectis config sharing add --name customer-secret-3of5-v1 --kid <kid> --threshold 3 --shares 5 --max-secret-len 4096 --context 'tenant=acme;purpose=customer-secret-sharing;version=1'
vectis config sharing list
```

Names and context are signed and AAD-safe. `threshold` must be at least 2 and
no greater than `shares`; `shares` is capped at 32.

### `vectis config masking`

Edits the local `masking_profiles` section in `VECTIS_CONFIG_PATH`. The lookup
key is `name`. Names must be unique.

```sh
vectis config masking list
vectis config masking add --name pan-display-v1 --kid <kid> --visible-first 0 --visible-last 4 --mask-char '*' --min-len 12 --max-len 19
vectis config masking get pan-display-v1
vectis config masking update pan-display-v1 --visible-first 6
vectis config masking delete pan-display-v1
```

`mask_char` must be exactly one non-control character. `visible_first` plus
`visible_last` must be less than `min_len`. Masking is display-only; it does not
encrypt, tokenize, or persist data.

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

Reload is resilient per key: valid keys remain available when another stored row
cannot be decrypted or validated. The command still succeeds and prints the keys
that were loaded. Operators must use the node logs, the `key.reload.partial`
audit event, and the `vectis_keys_load_skipped` and
`vectis_key_load_failures_total` metrics to detect and investigate omissions.

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

`--reason` is required and limited to 128 characters.

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

Reload is per-node. It is not cluster-wide. If `config.json` has changes that are not covered by `config_sign.json`, the server keeps the previous signed config and returns a warning telling you to run `vectis config sign` first.

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

`vectis sign <kid>` returns `{ "kid": "...", "signature": "..." }`.
That same JSON can be passed unchanged to `vectis sign verify`; the compact
signature has four unpadded Base64URL segments.

### `vectis message`

Sends, receives, or decrypts protected messages.

```sh
vectis message send <sender_kid> --file send-message.json
vectis message receive --file envelope.json
vectis message decrypt --file encrypted-message.json
```

### `vectis symmetric`

Data Protection: encrypt or decrypt local data with the per-KID `symmetric`
permission. `message` does not grant these operations. Encrypt requires an active
key; decrypt permits active or retired keys. Both require `VECTIS_APIKEY`.

```sh
vectis symmetric encrypt <kid> --json '{"plaintext":"synthetic data"}'
vectis symmetric encrypt <kid> --file plaintext.json
vectis symmetric decrypt --file envelope.json
```

Small JSON inputs can be passed directly with `--json`, but files are easier to
read and audit.

### `vectis fpe`

Authenticated encrypt returns a separate 64-character lowercase hex `tag`.
Include it in the existing decrypt JSON or file input; there is no tag flag.
Legacy outputs omit tag and legacy decrypt forbids supplying it. `ref` is not
authenticated and may change. No request can override the signed policy.

```sh
vectis fpe decrypt --json '{"ref":"reg1","kid":"<kid>","profile":"patient-id-auth-v1","ciphertext":"<ciphertext>","tag":"<tag returned by encrypt>"}'
```

Authentication failures return `400` with `fpe authentication failed` and no
plaintext. It does not prevent replay or hide deterministic equality. Tags count
toward existing HTTP size limits; no budgets are raised.

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
vectis token delete --file token-delete.json
vectis token encode-batch <kid> --file token-encode-batch.json
vectis token decode-batch --file token-decode-batch.json
```

`encode` requires `token-encode` permission for the KID and an `active` key.
`decode` requires `token-decode` permission and allows `active` or `retired`
keys. Metadata is optional, must be a JSON object when present, and its compact
serialized JSON representation must be at most 128 characters. `ref` is a
required client correlation value and is echoed in the response.

`delete` requires its independent `token-delete` permission and is not restricted
by lifecycle. The operational key must still be loadable and the signed profile
available and authorized for that KID. It returns `{ref, deleted: true}` only
after commit. An absent, consumed or already deleted token returns `404`.
It does not decrypt the token payload, but `subject_mode=stored` requires opening
a valid subject seed to derive the token lookup key. There is no batch delete
command.

For `subject_mode=stored`, use `--subject <subject>` on `encode` or
`encode-batch` to select the subject endpoint. Include `subject` in the JSON
body for `decode`, `decode-batch` and `delete`. The flag is not accepted for
those body-based commands. No subject is inferred from the signed profile.
All JSON commands accept exactly one of `--json` or `--file` and support
`--output json|yaml` without changing request bodies.

### `vectis subject`

Calls the stored subject-key endpoints using `VECTIS_APIKEY`:

```sh
vectis subject create <kid> --json '{"profile":"patient-subject-v1","subject_name":"synthetic-user"}' --output json
vectis token encode <kid> --subject <subject> --file token-encode.json
vectis token encode-batch <kid> --subject <subject> --file token-encode-batch.json
vectis subject delete <kid> <subject>
```

`create` requires `subject-create`, an active KID and a signed `stored` profile;
it displays the API's `201` response containing `kid`, `profile` and `subject`.
Creating the same subject again returns `200` with the same identifiers, without
replacing its seed. This allows recovery after a lost create response.
`delete` requires `subject-delete` but does not load the operational key, resolve
a profile or decrypt the seed, unlike subject-bound token delete. Success is
`204`, exit code zero and empty stdout, including with `--output json|yaml`;
a second deletion returns `404` and a nonzero exit code. Subject identifiers
must be exactly 64 lowercase ASCII hexadecimal characters. Deleting a subject
prevents subsequent
recovery of its tokens and physically deletes their rows in the same transaction.
It does not require an additional `token-delete` grant. Subject-bound encode
fails with `404` if deletion wins before storage insert, or `409` if the seed
generation changed during the operation; no tokens are inserted on failure.

### `vectis mac`

Calls local MAC create/verify endpoints. MAC profiles are not defined in the
request; they are loaded from signed `config.json`.

```sh
vectis mac create <kid> --json '{"ref":"reg1","profile":"pan-blind-index-v1","plaintext":"4111111111111111"}'
vectis mac verify --json '{"ref":"reg1","kid":"<kid>","profile":"pan-blind-index-v1","plaintext":"4111111111111111","digest":"<hex>"}'
```

`create` requires `mac-create` permission for the KID and an `active` key.
`verify` requires `mac-verify` permission for the body KID and allows `active` or `retired`
keys. The response reports the resolved MAC algorithm and digest.

### `vectis index`

Calls local blind index create/verify endpoints. Blind indexes reuse signed
`mac_profiles`; manage those profiles with `vectis config mac`.

```sh
vectis index create <kid> --json '{"ref":"reg1","profile":"pan-index-v1","plaintext":"4111111111111111"}'
vectis index verify --json '{"ref":"reg1","kid":"<kid>","profile":"pan-index-v1","plaintext":"4111111111111111"}'
```

`create` requires `index-create` permission for the KID and an `active` key.
`verify` requires `index-verify` permission for the body KID and allows
`active` or `retired` keys. `/mac` computes a deterministic digest; `/index`
computes the same style of digest and persists membership for later verify.

### `vectis commit`

Calls local cryptographic commitment create/verify endpoints. Commitment
profiles are loaded from signed `config.json`.

```sh
vectis commit create <kid> --json '{"ref":"reg1","profile":"pan-commitment-v1","plaintext":"4111111111111111"}'
vectis commit verify --json '{"ref":"reg1","kid":"<kid>","profile":"pan-commitment-v1","plaintext":"4111111111111111","opening":"<base64url>","commitment":"<hex>"}'
```

`create` requires `commit-create` permission for the KID and an `active` key.
`verify` requires `commit-verify` permission for the body KID and allows
`active` or `retired` keys. Create returns a random `opening`, so the same
plaintext can produce different commitments.

### `vectis shares`

Splits or combines authenticated stateless `vectis-sss-v1` shares.

```sh
vectis shares split <kid> --json '{"profile":"customer-secret-3of5-v1","plaintext":"secret-value"}'
vectis shares combine --json '{"kid":"<kid>","profile":"customer-secret-3of5-v1","shares":["vectis-sss-v1.<share>"]}'
```

Split requires `share-split` and an active KID. Combine requires
`share-combine`, accepts active or retired KIDs, and reconstructs only after
authenticating a compatible threshold-sized share set.

### `vectis mask`

Calls the local masking endpoint. Masking profiles are loaded from signed
`config.json`.

```sh
vectis mask <kid> --json '{"ref":"row1","profile":"pan-display-v1","plaintext":"4111111111111111"}'
```

Requires `mask` permission for the KID and allows `active` or `retired` keys.

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
- lifecycle `--reason` must be non-empty, free of control characters, and at
  most 128 characters.
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
