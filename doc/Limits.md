# Vectis Limits

**Last verified:** 2026-09-24 at commit `2ef0fed21550`.

This document is the consolidated inventory of externally observable and
operational limits in Vectis. The code is the source of truth. Source links and
line numbers are navigation aids; the linked symbol or validator is the stable
reference when lines move.

The tables use these kinds:

- **Explicit:** a constant or direct validation enforces the limit.
- **Profile-controlled:** a signed capability profile selects a value inside a
  global range.
- **Effective:** the limit follows from another bound or from an encoding.
- **No dedicated limit:** only an enclosing limit applies, or Vectis does not
  impose a separate bound.

`Characters` means Rust `char` values (Unicode scalar values), not UTF-8 bytes.
`Hex characters` count the textual encoding, so two characters represent one
byte. KiB and MiB are binary multiples.

## HTTP, CLI, And Runtime

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| HTTP | Request body | `2 * 1024 * 1024 = 2,097,152` (2 MiB) | bytes | Explicit | Axum rejects larger bodies before JSON parsing and application processing | [`INTERNAL_HTTP_MAX_SIZE`](../src/core/config.rs#L33), [`DefaultBodyLimit`](../src/io/http/mod.rs#L660) |
| HTTP | Response body | No global maximum | bytes | No dedicated limit | Endpoint output and available resources are the only bounds | [`router`](../src/io/http/mod.rs#L595) |
| Runtime | Graceful shutdown | `30` | seconds | Explicit | HTTP and HTTPS use the same bounded shutdown handle | [`INTERNAL_HTTP_GRACE_SEC`](../src/core/config.rs#L34), [`http_grace_period`](../src/io/http/app.rs#L265) |
| Runtime | Remote peer and final-app request timeout | `30` | seconds | Explicit | The shared runtime `reqwest` client applies one deadline | [`INTERNAL_HTTP_TIMEOUT_SEC`](../src/core/config.rs#L35), [`runtime_http_timeout`](../src/core/http_client.rs#L68) |
| Runtime | Concurrent cryptographic operations | One less than the number of CPU cores by default (minimum 1); any integer from `1` to the tokio semaphore maximum is accepted | operations | Configurable | A global semaphore bounds crypto blocking tasks and each permit is held for the whole blocking job; requests over the limit are rejected immediately with `429`. `VECTIS_MAX_CONCURRENT_CRYPTO` overrides the default; config reload runs unbounded and is not throttled; not installed for CLI/tests (unbounded) | [`max_concurrent_crypto`](../src/core/config.rs#L95), [`spawn_blocking_crypto`](../src/core/blocking.rs#L32) |
| CLI | API request timeout | `30` by default; any integer greater than zero is accepted | seconds | Explicit | `VECTIS_TIMEOUT_SECONDS` overrides the default; there is no explicit upper bound | [`DEFAULT_TIMEOUT_SECONDS`](../src/io/cli/http.rs#L17), [`CliHttpClient::from_env`](../src/io/cli/http.rs#L911) |
| CLI | JSON input file | `2,097,152` (2 MiB) | bytes | Explicit | `--file` uses the HTTP body limit before parsing JSON | [`parse_json_source`](../src/io/cli/http.rs#L1120) |
| CLI | Config-editor public-key fetch timeout | `30` | seconds | Explicit | A separate fixed client timeout is used by the local editor | [`DEFAULT_TIMEOUT_SECONDS`](../src/io/cli/config_editor.rs#L15), [`fetch_public_keys`](../src/io/cli/config_editor.rs#L1638) |
| Time | Complete time-attestation query | `5` | seconds | Explicit | One timeout encloses the concurrent NTS and Roughtime queries | [`INTERNAL_TIME_ATTEST_TIMEOUT_SEC`](../src/core/config.rs#L36), [`attest`](../src/io/http/time.rs#L73) |
| Time | Time-attestation rate | At most `1` request per `1,000,000` microseconds | requests | Explicit | A process-local admission slot returns `429` inside the interval | [`INTERNAL_TIME_ATTEST_MIN_INTERVAL_US`](../src/core/config.rs#L37), [`admit`](../src/io/http/time.rs#L15) |
| Time | Roughtime response buffer | `4,096` (4 KiB) | bytes | Explicit | UDP receive buffer is allocated at this size | [`INTERNAL_TIME_ATTEST_MAX_ROUGHTIME_RESPONSE_BYTES`](../src/core/config.rs#L38), [`query_roughtime`](../src/core/time_attestation.rs#L334) |
| Time | Clock skew, round trip, and Roughtime radius policy | `1..=60,000`; defaults are `1,000`, `2,000`, and `2,000` respectively | milliseconds | Explicit | Signed time configuration selects each threshold inside a directly validated range | [`DEFAULT_MAX_CLOCK_SKEW_MS`, `DEFAULT_MAX_ROUND_TRIP_MS`, `DEFAULT_MAX_ROUGHTIME_RADIUS_MS`](../src/core/time_attestation.rs#L13), [`validate_effective_config`](../src/core/time_attestation.rs#L109) |

## Configuration And Files

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| Config | Signed config content | `8 * 1024 * 1024 = 8,388,608` (8 MiB) | bytes | Explicit | Bounded read occurs before config parsing and validation | [`CONFIG_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L54), [`read_config_file`](../src/core/config_file.rs#L132) |
| Config | Config signature file | `1,048,576` (1 MiB) | bytes | Explicit | Bounded read occurs before signature parsing | [`CONFIG_SIGN_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L55), [`read_config_signature_file`](../src/core/config_file.rs#L136) |
| Init | Encrypted init file | `65,536` (64 KiB) | bytes | Explicit | Generation and reads reject a larger artifact | [`INIT_KEYS_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L56), [`validate_init_encrypted_artifact_encoding`](../src/ops/init.rs#L191) |
| Init | Init public-key file | `65,536` (64 KiB) | bytes | Explicit | Generation and reads reject a larger artifact | [`INIT_PUBLIC_KEYS_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L57), [`validate_init_public_artifact_encoding`](../src/ops/init.rs#L214) |
| Init | Unseal-key file | `1,024` (1 KiB) file; key content must be exactly `64` hex characters | bytes / hex characters | Explicit | File read is bounded, then a 32-byte symmetric key is required | [`UNSEAL_KEY_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L58), [`read_file_unseal_key`](../src/core/unseal.rs#L43) |
| Process config | `.env` file | `65,536` (64 KiB) | bytes | Explicit | Bounded read occurs before line parsing | [`ENV_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L59), [`load_env_file`](../src/core/config.rs#L482) |
| SLH-DSA | Encrypted private-key file | `65,536` (64 KiB) | bytes | Explicit | File content is checked before decoding | [`SLH_DSA_PRIVATE_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L60), [`validate_private_key_file_encoding`](../src/ops/slh_dsa.rs#L264) |
| SLH-DSA | Public-key file | `65,536` (64 KiB) | bytes | Explicit | File content is checked before decoding | [`SLH_DSA_PUBLIC_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L61), [`validate_public_key_file_encoding`](../src/ops/slh_dsa.rs#L286) |
| SLH-DSA | Signature file | `131,072` (128 KiB) | bytes | Explicit | Signature text is bounded before parsing | [`SLH_DSA_SIGNATURE_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L62), [`split_compact_signature`](../src/ops/slh_dsa.rs#L503) |
| Config | Routes, remote routes, permissions, and capability profiles | No element-count maximum; the 8 MiB config-file bound is the enclosing limit | items | Effective | The complete signed config is bounded, then each element is validated | [`CONFIG_FILE_MAX_SIZE_BYTES`](../src/core/config.rs#L54), [`validate_config_content`](../src/core/config_file.rs#L102) |

## Common Fields

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| Identity | Operational KID | Exactly `64` | hex characters | Explicit | KIDs are `BLAKE2b(256)` outputs | [`INTERNAL_KEYS_HASH`](../src/core/config.rs#L12), [`KeyId::parse`](../src/ops/keys.rs#L177) |
| Authentication | API key and stored API-key hash | Exactly `64` | hex characters | Explicit | Both use the internal 256-bit hash representation | [`validate_hash_hex_field`](../src/core/validation.rs#L488), [`authorize_api_key`](../src/io/http/auth.rs#L46), [`app_config`](../src/core/config.rs#L127) |
| Correlation | `ref` | `1..=128` | characters | Explicit | Empty/control-character values are rejected before the character bound | [`INTERNAL_REF_MAX_CHARS`](../src/core/config.rs#L32), [`validate_ref`](../src/core/validation.rs#L393) |
| Config | Config, client, route, and profile names | `1..=128` | characters | Explicit | Common config-name validation is reused; AAD-bound names also reject `;` and `=` | [`CONFIG_NAME_MAX_CHARS`](../src/core/config.rs#L41), [`validate_config_name`](../src/core/validation.rs#L328), [`validate_aad_config_name`](../src/core/validation.rs#L340) |
| Lifecycle | Update reason | `1..=128` | characters | Explicit | Lifecycle input reuses the common bounded-text policy | [`INTERNAL_REF_MAX_CHARS`](../src/core/config.rs#L32), [`parse_update_lifecycle_input`](../src/ops/keys.rs#L642) |
| JSON | Canonical JSON traversal depth | `128` | nested traversal levels | Explicit | Values deeper than the bound are rejected before canonical serialization | [`MAX_JSON_DEPTH`](../src/core/validation.rs#L21), [`validate_canonical_json_value_at_depth`](../src/core/validation.rs#L27) |
| Errors | Untrusted diagnostic detail | `256` | characters | Explicit | Control characters are removed and the remaining detail is truncated | [`UNTRUSTED_ERROR_DETAIL_MAX_CHARS`](../src/error.rs#L6), [`sanitize_untrusted_error_detail`](../src/error.rs#L76) |
| HTTP errors | Public `error` value | `256` | characters | Explicit | HTTP error text is sanitized and truncated before serialization | [`MAX_ERROR_MESSAGE_CHARS`](../src/io/http/error.rs#L9), [`sanitize_error_message`](../src/io/http/error.rs#L24) |
| HTTP | `X-Request-Id` | Exactly `32` | hex characters | Explicit | An 8-byte process nonce and an 8-byte counter are hex encoded per request | [`next_request_id`](../src/io/http/middleware.rs#L79) |
| Labels | FPE tweak, MAC, commitment, and sharing context | `1..=128` | characters | Explicit | Structured `key=value` labels require unique keys | [`validate_labels`](../src/core/validation.rs#L345), [`FPE_TWEAK_AAD_MAX_CHARS`](../src/core/config.rs#L42), [`MAC_CONTEXT_MAX_CHARS`](../src/core/mac.rs#L12), [`COMMITMENT_CONTEXT_MAX_CHARS`](../src/core/commitments.rs#L14), [`SHARING_CONTEXT_MAX_CHARS`](../src/core/sharing.rs#L14) |
| AAD | Generic AAD key/value | No dedicated length maximum; the enclosing request, file, profile, or storage limit applies | characters | No dedicated limit | Values must be non-empty, contain no controls, `;`, or `=`; keys also have a restricted ASCII grammar | [`validate_aad_key`](../src/core/validation.rs#L92), [`validate_aad_value`](../src/core/validation.rs#L87) |
| Network config | TCP port | `1..=65,535` | integer | Explicit | Values parse as `u16` and zero is rejected | [`validate_host_port`](../src/core/validation.rs#L407) |

## Batches

All listed data-protection batches must contain at least one item. Batch `ref`
values must also be unique within the request.

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| FPE | Encrypt/decrypt batch | `1..=128` | items | Explicit | Common batch length and unique-ref validation | [`INTERNAL_FPE_BATCH`](../src/core/config.rs#L25), [`validate_len`](../src/ops/batch.rs#L15) |
| Tokenization | Encode/decode batch | `1..=128` | items | Explicit | Common batch length and unique-ref validation | [`INTERNAL_TOKEN_BATCH`](../src/core/config.rs#L26), [`validate_len`](../src/ops/batch.rs#L15) |
| MAC | Create/verify batch | `1..=128` | items | Explicit | Common batch length and unique-ref validation | [`INTERNAL_MAC_BATCH`](../src/core/config.rs#L27), [`validate_len`](../src/ops/batch.rs#L15) |
| Blind indexes | Create/verify batch | `1..=128` | items | Explicit | Common batch length and unique-ref validation | [`INTERNAL_INDEX_BATCH`](../src/core/config.rs#L28), [`validate_len`](../src/ops/batch.rs#L15) |
| Masking | Mask batch | `1..=128` | items | Explicit | Common batch length and unique-ref validation | [`INTERNAL_MASK_BATCH`](../src/core/config.rs#L29), [`validate_len`](../src/ops/batch.rs#L15) |
| Commitments | Create/verify batch | `1..=128` | items | Explicit | Common batch length and unique-ref validation | [`INTERNAL_COMMIT_BATCH`](../src/core/config.rs#L30), [`validate_len`](../src/ops/batch.rs#L15) |
| Secret sharing | Shares accepted by combine | `1..=32`, and at least the selected profile threshold | shares | Profile-controlled | Request count has a global cap; successful combine requires the profile threshold | [`INTERNAL_SHARE_MAX`](../src/core/config.rs#L31), [`validate_combine_input`](../src/ops/sharing.rs#L98), [`prepare_combine`](../src/ops/sharing.rs#L151) |

## Capability Limits

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| FPE | Plaintext/ciphertext length | Profile range inside `6..=1,024` | characters | Profile-controlled | Input characters must belong to the selected alphabet and fit its signed bounds | [`FPE_VALUE_MIN_LEN`, `FPE_VALUE_MAX_LEN`](../src/core/fpe.rs#L13), [`parse_fpe_value_digits`](../src/core/fpe.rs#L229) |
| FPE | Alphabet size | `2..=65,536`, with unique characters | characters | Explicit | Alphabet validation computes the radix | [`validate_fpe_alphabet`](../src/core/fpe.rs#L280) |
| FPE | Minimum domain size | At least `1,000,000` possible values at the profile minimum length | values | Effective | The alphabet radix raised to `min_len` must reach the FF1 domain floor | [`validate_fpe_lengths`](../src/core/fpe.rs#L314), [`fpe_domain_is_large_enough`](../src/core/fpe.rs#L357) |
| Tokenization | Plaintext length | Profile maximum inside `1..=1,024` | characters | Profile-controlled | Encode checks the selected profile before storage | [`TOKEN_PLAINTEXT_MAX_LEN`](../src/core/tokenization.rs#L17), [`prepare_encode`](../src/ops/tokenization.rs#L392) |
| Tokenization | Random token component | Minimum `32`; no explicit maximum | bytes | No dedicated limit | Signed profile validation enforces only the minimum | [`TOKEN_LEN_MIN_BYTES`](../src/core/tokenization.rs#L16), [`validate_token_lengths`](../src/core/tokenization.rs#L282) |
| Tokenization | Token prefix | `1..=16` | characters | Explicit | Whitespace, `;`, and `=` are also rejected | [`TOKEN_PREFIX_MAX_CHARS`](../src/core/tokenization.rs#L19), [`validate_token_prefix`](../src/core/tokenization.rs#L261) |
| Tokenization | Metadata | `128` | characters in compact serialized JSON | Explicit | Metadata is canonical-key validated, compact-serialized, then counted | [`TOKEN_METADATA_MAX_CHARS`](../src/core/tokenization.rs#L18), [`validate_metadata`](../src/ops/tokenization.rs#L639) |
| MAC | Context | `1..=128` | characters | Explicit | Signed profile uses structured labels | [`MAC_CONTEXT_MAX_CHARS`](../src/core/mac.rs#L12), [`validate_mac_profile_fields`](../src/core/mac.rs#L227) |
| MAC | Plaintext | No dedicated maximum; request-body limit applies over HTTP | UTF-8 content | No dedicated limit | Only common non-empty/control-character validation is applied | [`validate_create_input`](../src/ops/mac.rs#L233), [`INTERNAL_HTTP_MAX_SIZE`](../src/core/config.rs#L33) |
| Blind indexes | Plaintext | No dedicated maximum; request-body limit applies over HTTP | UTF-8 content | No dedicated limit | Only common non-empty/control-character validation is applied | [`validate_create_input`](../src/ops/indexes.rs#L235), [`INTERNAL_HTTP_MAX_SIZE`](../src/core/config.rs#L33) |
| Blind indexes | Stored digest | `40..=128`, depending on the operational key hash algorithm | hex characters | Effective | Hash outputs are 20 to 64 bytes; storage independently caps text at 128 characters | [`hash_output_size_bytes`](../src/core/crypto.rs#L45), [`validate_index_digest`](../src/core/storage/mod.rs#L323) |
| Masking | Plaintext length | Profile range inside `1..=1,024` | characters | Profile-controlled | The selected profile enforces minimum, maximum, and visible ranges | [`MASKING_PLAINTEXT_MAX_LEN`](../src/core/masking.rs#L6), [`validate_masking_lengths`](../src/core/masking.rs#L172), [`validate_plaintext_for_profile`](../src/core/masking.rs#L207) |
| Masking | Mask character | Exactly `1` | character | Explicit | Profile validation counts Unicode scalar values | [`validate_mask_char`](../src/core/masking.rs#L161) |
| Commitments | Plaintext length | Profile maximum inside `1..=1,024` | characters | Profile-controlled | Create and verify use the selected profile maximum | [`COMMITMENT_PLAINTEXT_MAX_CHARS`](../src/core/commitments.rs#L15), [`validate_plaintext_len`](../src/ops/commitments.rs#L526) |
| Commitments | Opening | Profile-selected `32..=64` | decoded bytes | Profile-controlled | URL-safe base64 opening must decode to the exact profile length | [`COMMITMENT_OPENING_MIN_BYTES`, `COMMITMENT_OPENING_MAX_BYTES`](../src/core/commitments.rs#L16), [`validate_opening`](../src/core/commitments.rs#L323) |
| Commitments | Context | `1..=128` | characters | Explicit | Signed profile uses structured labels | [`COMMITMENT_CONTEXT_MAX_CHARS`](../src/core/commitments.rs#L14), [`validate_commitment_profile_fields`](../src/core/commitments.rs#L244) |
| Secret sharing | Total shares and threshold | Shares `2..=32`; threshold `2..=shares` | shares | Profile-controlled | Signed profile defines both values inside global bounds | [`SHARING_MIN_THRESHOLD`](../src/core/sharing.rs#L15), [`INTERNAL_SHARE_MAX`](../src/core/config.rs#L31), [`validate_threshold`](../src/core/sharing.rs#L299) |
| Secret sharing | Secret length | Profile maximum inside `1..=4,096` | bytes | Profile-controlled | Split and reconstructed output are checked against the selected profile | [`SHARING_SECRET_MAX_BYTES`](../src/core/sharing.rs#L16), [`validate_max_secret_len`](../src/core/sharing.rs#L319), [`validate_secret`](../src/core/sharing.rs#L515) |
| Secret sharing | Encoded share envelope | `16 * 1024 = 16,384` (16 KiB) | ASCII characters | Explicit | Envelope text is bounded before base64 and JSON decoding | [`SHARE_ENVELOPE_MAX_CHARS`](../src/core/sharing.rs#L19), [`parse_share_envelope`](../src/core/sharing.rs#L496) |
| Secret sharing | Context | `1..=128` | characters | Explicit | Signed profile uses structured labels | [`SHARING_CONTEXT_MAX_CHARS`](../src/core/sharing.rs#L14), [`validate_sharing_profile_fields`](../src/core/sharing.rs#L281) |
| Protected messages | Plaintext | No dedicated maximum; the enclosing HTTP body applies | UTF-8 content | No dedicated limit | Send validation checks text shape but not length | [`validate_send_message_input`](../src/ops/message.rs#L662), [`INTERNAL_HTTP_MAX_SIZE`](../src/core/config.rs#L33) |
| Internal messages | Encrypt plaintext | Up to `2,097,136` ASCII bytes in the minimal compact `{"plaintext":"..."}` request; less when JSON escaping or multibyte UTF-8 is required | bytes | Effective | There is no message-specific cap; the 2 MiB request-body cap supplies the bound | [`InternalEncryptMessageInput`](../src/ops/message.rs#L118), [`validate_internal_encrypt_message_input`](../src/ops/message.rs#L717), [`INTERNAL_HTTP_MAX_SIZE`](../src/core/config.rs#L33) |
| Internal messages | Encrypt/decrypt round trip | Approximately `1` MiB of plaintext | bytes | Effective | Ciphertext is hex encoded, roughly doubling its contribution to the decrypt request body | [`InternalMessageCipher`](../src/ops/message.rs#L132), [`decrypt_internal_message`](../src/ops/message.rs#L596), [`INTERNAL_HTTP_MAX_SIZE`](../src/core/config.rs#L33) |
| Hybrid signatures | Compact signature | `64 * 1024 = 65,536` (64 KiB) | characters | Explicit | Compact JWS-like input is bounded before segment parsing | [`COMPACT_SIGNATURE_MAX_CHARS`](../src/ops/sign.rs#L23), [`split_compact_signature`](../src/ops/sign.rs#L353) |
| Hybrid signatures | Message hash | `40`, `56`, `64`, `96`, or `128`, according to the declared hash | hex characters | Explicit | Hash encoding must exactly match the algorithm output size | [`hash_output_size_bytes`](../src/core/crypto.rs#L45), [`validate_hash_hex_field`](../src/core/validation.rs#L488) |

### Internal Message Round Trips

`/message/internal/encrypt` can accept plaintext close to the 2 MiB HTTP
request limit. Its output contains hex-encoded ciphertext and is therefore
approximately twice as large. To ensure that the resulting artifact can be
submitted to `/message/internal/decrypt`, keep plaintext below 1 MB
(`1,000,000` bytes).

With compact JSON, a 64-character KID, and a 10-digit Unix timestamp, the
effective ceiling is approximately `1,048,393` plaintext bytes for AES-GCM and
`1,048,376` bytes for ChaCha20Poly1305. JSON formatting, longer timestamps, and
other encoding overhead can reduce it further. These are derived operational
ceilings, not dedicated plaintext limits enforced by Vectis.

## Storage

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| Storage | Encrypted key, properties, and token envelopes | `32,768` | base64-envelope characters | Explicit | Every value is validated before write and after read | [`STORAGE_ENVELOPE_MAX_CHARS`](../src/core/config.rs#L39), [`validate_storage_envelope`](../src/core/storage/mod.rs#L275) |
| Storage | KID and token hash ID | Exactly `64` | hex characters | Explicit | Storage validation requires the internal 256-bit hash encoding | [`validate_storage_kid`](../src/core/storage/mod.rs#L271), [`validate_token_hashid`](../src/core/storage/mod.rs#L295) |
| Storage | Index digest | At most `128` | hex characters | Explicit | Storage rejects non-hex or longer values | [`STORAGE_INDEX_DIGEST_MAX_CHARS`](../src/core/config.rs#L40), [`validate_index_digest`](../src/core/storage/mod.rs#L323) |
| Storage | Operational keys, tokens, and indexes | No row-count maximum | rows | No dedicated limit | Database capacity and operational resources are the bounds | [`StorageState`](../src/core/storage/mod.rs#L39) |
| Runtime | `keys reload` | No record-count or work-budget maximum; work is proportional to stored operational-key rows | rows / decryptions | No dedicated limit | Reload lists and validates/decrypts the complete key set | [`load_keys_db_state`](../src/ops/keys.rs#L665) |
| HTTP | List responses and stored collections | No pagination or global response-size maximum | items / bytes | No dedicated limit | Handlers serialize the complete selected collection | [`list_keys_from_state`](../src/ops/keys.rs#L274), [`list_endpoint`](../src/io/http/keys.rs#L134) |

SQLite declarations use `VARCHAR(128)` and `VARCHAR(10240)`, but SQLite does
not enforce those declared lengths. Vectis' storage validators above are the
portable enforcement shared with PostgreSQL. See the
[SQLite schema](../src/db/sqlite_schema.sql) and
[PostgreSQL schema](../src/db/postgres_schema.sql).

## Audit

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| Audit | JSONL record or checkpoint | `16 * 1024 = 16,384` (16 KiB) | bytes | Explicit | Serialized records and verifier input are bounded | [`AUDIT_CHAIN_RECORD_MAX_BYTES`](../src/core/config.rs#L63), [`write_event`](../src/core/audit_chain.rs#L725), [`verify_file_with_verifier`](../src/core/audit_chain.rs#L304) |
| Audit | Event, outcome, actor, fingerprints, KIDs, action, reason, and request ID | `256` each | characters | Explicit | Audit fields are sanitized and truncated before canonicalization | [`AUDIT_CHAIN_REASON_MAX_CHARS`](../src/core/config.rs#L64), [`write_event`](../src/core/audit_chain.rs#L725) |
| Audit | Writer channel | `1,024` | commands | Explicit | The channel is bounded; record submission fails closed when unavailable or full, while barriers await capacity | [`AUDIT_CHAIN_CHANNEL_CAPACITY`](../src/core/config.rs#L65), [`AuditRuntime::start`](../src/core/audit_chain.rs#L439), [`AuditRuntime::record`](../src/core/audit_chain.rs#L485) |
| Audit | Normal group-commit drain | `256` | commands per group | Explicit | The writer stops non-shutdown draining at the bound | [`AUDIT_GROUP_COMMIT_MAX_COMMANDS`](../src/core/config.rs#L66), [`writer_loop_with_policy`](../src/core/audit_chain.rs#L624) |
| Audit | Signed checkpoint interval | `10,000` | event records | Explicit | A checkpoint becomes due at the event threshold and on orderly shutdown | [`AUDIT_CHECKPOINT_EVENT_COUNT`](../src/core/config.rs#L67), [`CheckpointPolicy::default`](../src/core/audit_chain.rs#L189) |

## Cryptographic Encoding Contracts

This section lists sizes that Vectis validates as interchange or storage
contracts. It intentionally omits primitive-internal parameters that callers do
not supply.

| Area | Aspect | Current limit | Unit | Kind | Enforcement | Source |
|---|---|---:|---|---|---|---|
| Keys | Operational KID, token hash ID, and API key | Exactly `32` encoded as `64` hex characters | bytes / hex characters | Explicit | Internal hash is `BLAKE2b(256)` | [`INTERNAL_KEYS_HASH`](../src/core/config.rs#L12), [`validate_hash_hex_field`](../src/core/validation.rs#L488) |
| Init | Unseal key | Exactly `32` encoded as `64` hex characters | bytes / hex characters | Explicit | Symmetric-key validator checks exact decoded size | [`validate_symmetric_key`](../src/core/validation.rs#L136), [`read_unseal_key`](../src/core/unseal.rs#L15) |
| Internal encrypted artifacts | AES-GCM nonce | Exactly `12` encoded as `24` hex characters in init artifacts | bytes / hex characters | Explicit | Init decoding validates the nonce against the internal cipher contract | [`INTERNAL_KEYS_NONCE_SIZE_BYTES`](../src/core/config.rs#L11), [`validate_init_encrypted_artifact_encoding`](../src/ops/init.rs#L191) |
| AEAD envelopes | Authentication tag contribution | At least `16` | ciphertext bytes | Explicit | Encrypted payloads shorter than a tag are rejected | [`validate_encrypted_payload`](../src/core/validation.rs#L154), [`decode_base64_standard_envelope`](../src/core/validation.rs#L250) |
| AEAD envelopes | Nonce | `12` for AES-GCM; `24` for ChaCha20Poly1305 | bytes | Explicit | Nonce length is selected by the declared cipher and checked exactly | [`symmetric_cipher`](../src/core/crypto.rs#L183), [`validate_encrypted_payload`](../src/core/validation.rs#L154) |
| Hashes, MACs, indexes, and commitments | Digest | `20`, `28`, `32`, `48`, or `64`, encoded as `40..=128` hex characters | bytes / hex characters | Explicit | Exact size follows the selected supported hash algorithm | [`hash_output_size_bytes`](../src/core/crypto.rs#L45), [`validate_hash_hex_field`](../src/core/validation.rs#L488) |
| Hybrid signatures | Payload serial | Exactly `32` encoded as `64` hex characters | bytes / hex characters | Explicit | Signing generates 32 random bytes and verification checks the expected hex length | [`PAYLOAD_SERIAL_RANDOM_BYTES`](../src/ops/sign.rs#L20), [`validate_signed_payload_fields`](../src/ops/sign.rs#L198) |
| Hybrid signatures | Compact sections | Exactly `4` non-empty base64url sections | sections | Explicit | Header, payload, EdDSA signature, and ML-DSA signature are parsed separately | [`COMPACT_SIGNATURE_SEGMENTS`](../src/ops/sign.rs#L22), [`split_compact_signature`](../src/ops/sign.rs#L353) |
| SLH-DSA signatures | Compact sections | Exactly `3` non-empty base64url sections | sections | Explicit | Header, payload, and SLH-DSA signature are parsed separately | [`split_compact_signature`](../src/ops/slh_dsa.rs#L503) |
| Commitments | Opening | Profile-selected `32..=64`, URL-safe base64 encoded | decoded bytes | Profile-controlled | Decoded opening must match the signed profile exactly | [`validate_commitment_opening_len`](../src/core/commitments.rs#L276), [`validate_opening`](../src/core/commitments.rs#L323) |
| Secret sharing | Set ID | Exactly `16`, URL-safe base64 encoded | decoded bytes | Explicit | Every share envelope validates the decoded set ID | [`SHARING_SET_ID_BYTES`](../src/core/sharing.rs#L17), [`validate_set_id`](../src/core/sharing.rs#L527) |
| Time attestation | Roughtime public key | Exactly `32`, standard-base64 encoded | decoded bytes | Explicit | Signed time configuration is decoded and checked before use | [`validate_effective_config`](../src/core/time_attestation.rs#L103) |
| HTTP | Request ID | Exactly `16` encoded as `32` hex characters | bytes / hex characters | Explicit | Middleware generates a fresh value | [`next_request_id`](../src/io/http/middleware.rs#L79) |

## Current Unbounded Surfaces

The following are current implementation facts, not vulnerability statements or
commitments to add limits:

- `token_len` has a minimum of 32 bytes but no explicit maximum.
- HTTP responses have no global size limit.
- Protected-message, internal-message, MAC, and blind-index plaintext have no
  capability-specific maximum; their HTTP use is enclosed by the 2 MiB request
  limit.
- Operational keys, tokens, indexes, routes, permissions, and profiles have no
  dedicated maximum element count.
- `keys reload` has no row or time budget and processes the stored operational
  key set with work proportional to its size.
- Generic AAD values have syntax validation but no independent character bound;
  their enclosing contract supplies the effective limit.
