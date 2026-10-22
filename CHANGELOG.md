# Changelog

This changelog records notable public changes to Vectis. It is maintained
manually for releases; the Git history remains the detailed engineering record.

## Unreleased

Future changes will be recorded here. v1.0.0 remains the first official release.

### Changed
- Split configuration fuzzing into signed JSON, strict environment grammar and
  loader targets, with synthetic-source semantic oracles, redaction checks and
  boundary seeds. The native fuzz runner now includes 27 targets.
- Configuration now uses one invocation-scoped snapshot with consumer-specific
  validation and sanitized source/line diagnostics. Unknown or prohibited
  variables in `.env`, invalid logging settings, and invalid effective process
  values no longer silently fall back. Process values share the 4,096-byte cap;
  CLI/bootstrap no longer require unrelated server or storage settings.
- `.env` parsing is now strict and atomic: only `VECTIS_` names are accepted,
  with 128-byte names and 4,096-byte values within the existing 64 KiB file cap.
  Malformed assignments, duplicates, invalid quoting, NUL and isolated carriage
  returns fail with sanitized diagnostics. Invalid files also stop logging
  bootstrap instead of falling back to defaults. Previously ignored or accepted
  malformed files must be corrected before upgrading; process precedence and
  per-setting validation are unchanged.
- Crypto admission now waits asynchronously with a bounded queue (128 jobs,
  1000 ms by default) before returning `429`; execution concurrency is unchanged.
  Setting `VECTIS_MAX_QUEUED_CRYPTO=0` restores immediate rejection. Jobs that
  time out or are cancelled while waiting are not dispatched.
  Added restart-only queue settings and aggregate queue metrics.
- Improved the k6 performance harness with selectable targets and variants,
  native progress, readable summaries and optional `--save-results` reports.
  Added successful-only latency percentiles and queue measurements to compare
  admission settings with waiting enabled or disabled.
- Updated Tokio to 1.54.1 in the main and fuzz lockfiles, and refreshed main
  transitive dependencies, including `inout` 0.2.5 and `libsqlite3-sys` 0.37.0.

### Security
- Updated the main lockfile to `rustls-webpki` 0.103.16 and
  `webpki-root-certs`/`webpki-roots` 1.0.10 to address RUSTSEC-2026-0382,
  RUSTSEC-2026-0383 and RUSTSEC-2026-0381.

### Fixed
- Updated the `vectis version` capability inventory: `symmetric-encryption`
  replaces the retired `internal-encryption` name, and deterministic tokenization,
  shared subject keys and time attestation are now listed.

## v0.8.6 - 2026-10-19

Pre-release of Vectis with the changes below. API and configuration contracts
remain experimental; v0.9.0 will be the first official release.

### Upgrading From v0.8.5

Back up the database, matching init/unseal material, and the signed
`config.json`/`config_sign.json` pair before upgrading. Stop all Vectis nodes
using the database before applying the schema change; do not mix old and new
binaries during this upgrade.

#### Database Migration

Existing databases without `tokens.subject` and the `subjects` table require
the backend-specific migration **once**, even if subject features will not be
used. Vectis validates the schema but does not apply migrations automatically.
Run the appropriate command with schema-owner credentials:

```sh
# SQLite: path to the existing database being upgraded.
sqlite3 "$VECTIS_SQLITE_PATH" < src/db/migrations/sqlite_subject_keys.sql

# PostgreSQL: DSN for a schema owner, not the restricted runtime role.
psql "$SCHEMA_OWNER_DSN" -v ON_ERROR_STOP=1 -f src/db/migrations/postgres_subject_keys.sql
```

On PostgreSQL, also grant the runtime role subject access, including the
`UPDATE(seed)` privilege required for row locking. Replace `vectis_usr` with
your runtime role:

```sql
GRANT SELECT, INSERT, DELETE, UPDATE(seed) ON TABLE public.subjects TO vectis_usr;
```

Do not reapply these scripts to an already migrated database. New installations
use the full current schema instead. See [database operations](doc/BD.md#schemas-limits-and-operations)
and the [PostgreSQL tutorial](doc/tutorials/PostgreSQL.md) for schema and role setup.

#### Local Encryption Interfaces And Grants

Update clients from `POST /message/internal/encrypt/{kid}` and
`POST /message/internal/decrypt` to `POST /symmetric/encrypt/{kid}` and
`POST /symmetric/decrypt`. Replace `vectis message internal encrypt|decrypt`
with `vectis symmetric encrypt|decrypt`. There are no aliases or redirects.

Grant `symmetric` explicitly for the affected KIDs in signed client permissions.
`message` no longer authorizes local encryption; retain it only for protected
messaging. No grants are converted automatically. Existing local envelopes and
their AAD remain compatible with the new routes; no re-encryption is required.

#### Subject Policy And Activation

For random tokenization, deterministic tokenization and FPE, signed
`subject_mode` defaults to `none`: subject is prohibited. `stored` requires an
existing subject for encrypt/encode and decrypt/decode, in single and batch.
Use the subject encrypt/encode route and include subject in decrypt/decode JSON;
there is no fallback to general profile keys. Symmetric has no profile or
`subject_mode`; its subject route/body selects the subject context.

Keep existing unscoped profiles in `none` mode and create separate `stored`
profiles for subject-bound use; this is not an automatic ciphertext migration.
Retain the original signed tokenization creator profile and its compatible keys
to open shared seeds. Subject deletion purges associated random-token rows and
blocks future seed openings across dependent capabilities, including externally
held FPE, symmetric and deterministic outputs. Backups can restore that access.

Validate and sign the updated configuration with the new binary before starting
the upgraded nodes. Start each node with its matching signed files, confirm
`/healthz/ready`, and perform an authorized round trip before restoring traffic.
Subsequent config changes require signing and `POST /config/reload` on each
node; editing files alone does not update runtime state. See the
[API](doc/API.md#subject-keys) and [CLI](doc/CLI.md) for the exact contracts.

### Added
- Deterministic authenticated AES-256-SIV tokens without per-token storage, with
  signed contexts, profile-controlled `subject_mode: none|stored` for shared subject
  seeds, single/batch HTTP and CLI,
  independent permissions and Unicode plaintexts up to 16,384 characters.
- Subject-bound symmetric encryption reuses existing authenticated subject seeds
  with purpose-separated keys and subject-bound AEAD context. Adds an encrypt
  route and CLI `--subject`; decrypt accepts the full subject envelope. Legacy
  ciphertexts remain compatible. No ciphertext storage, fallback or migration.
- Stored FPE subject contexts reuse existing subject seeds, with independent
  request-scoped FF1 and optional MAC keys. Subject encrypt routes and CLI
  `--subject` preserve legacy behavior. Original creator configuration must
  remain available; subject deletion affects tokens and FPE without deleting
  externally stored FPE ciphertexts. No automatic migration or secret cache.
- Optional signed-profile FPE authentication (`authenticated: true`), using an
  independently derived HMAC-BLAKE2b-256 key and a separate lowercase hex tag.
  Decrypt authenticates the whole batch before FF1. Legacy ciphertexts, outputs
  and config signatures remain compatible; no replay protection or automatic
  ciphertext migration is introduced.
- Signed FPE alphabet presets (`num`, `alpha`, `alphanum`) with explicit letter
  case and optional preserved characters. Formatting bounds include separators,
  while the effective FF1 domain counts only variable characters. Existing
  custom profiles, key derivation, tweaks and ciphertexts are unchanged.
- Add optional stored subject keys for single and batch tokenization, with
  authenticated per-subject seeds, independent create/delete permissions and
  request-scoped key derivation. Existing profiles default to legacy `none` mode.
  Existing databases require the explicit subject keys SQL migration before
  upgrading; deleting a subject atomically removes its seed and associated
  token rows.
- `POST /token/delete`: explicit, single-use deletion of a stored token by its
  HMAC hashid without decrypting the envelope, gated by a new independent
  `token-delete` permission and allowed in any key lifecycle state.

### Changed
- Rust toolchain updated from 1.97.1 to 1.98.
- Deterministic token subjects now follow signed `subject_mode` like FPE:
  `none` forbids subject and `stored` requires it. Profiles without the field
  remain `none`; previously issued subject tokens require marking the same
  profile `stored`, signing and reloading. Keys and token formats are unchanged.
- Updated core and fuzz dependencies, including Botan 0.14, SQLx 0.9,
  axum-server 0.8 and reqwest 0.13, with corresponding API adaptations.
  Outbound HTTPS now uses the system certificate trust store while retaining
  the explicit ring provider. AES is updated to 0.9 alongside the compatible
  `vectis_fpe` fork tagged v0.2.0.
- Replaced the generated startup banner with static ASCII text, removing
  `artbox` and its unused transitive dependencies, including `figlet-rs` and `zip`.
- Breaking: local encryption moves to `POST /symmetric/encrypt/{kid}` and
  `POST /symmetric/decrypt`, and `vectis symmetric encrypt|decrypt`. The former
  `/message/internal/*` routes and `vectis message internal` commands are removed.
  Local operations now require the per-KID `symmetric` permission; `message`
  remains exclusive to protected messaging. Grant `symmetric`, sign and reload
  configuration explicitly; no grant conversion is performed. Envelopes, AAD,
  crypto, lifecycle, audit event names and metrics remain unchanged.
- Tokenization plaintext maximum raised to 16,384 characters, with a dedicated
  token envelope limit (131,072) independent from the operational-key envelope
  limit (32,768).
- `POST /token/decode/batch` now enforces a 5 MiB incremental read budget
  (counting duplicate occurrences) that returns `413` before any decrypt or
  one-time consumption, bounding decode-batch amplification.

### Testing
- HTTP fuzz suite: each target now derives its own RNG stream from the root seed
  (per-target seed isolation), plus a new exploration mode (`--random-seed`,
  `--mutation-only`) that complements the deterministic seed-1337 regression run,
  and per-run input-diversity metrics (unique vs. duplicate inputs) written via
  `--summary-json`.
- CI runs two HTTP fuzz campaigns — a fixed-seed regression pass and a random-seed
  exploration pass — and publishes a per-target summary (result, seeds, status
  distribution, diversity) as a job step summary and a retained artifact.
- Shared `tests/support` module lets the fuzz and integration harnesses reuse a
  single prebuilt Vectis binary instead of rebuilding per invocation.

### Security
- Updated rustls to 0.23.45 to address RUSTSEC-2026-0285.
- Config key material (`ConfigKeySource`/`ConfigKeySources`) is now zeroized on drop.
- Key material now zeroizes on drop at the owning-type level: `KeyMaterialOutput`
  and `KeyMaterialKeys` derive `Zeroize`/`ZeroizeOnDrop`, so the aggregate that
  owns secret material wipes it on drop instead of relying on each field's own
  `Drop`. Public algorithm-identifier metadata (`variant`, hash name) is excluded
  from zeroization via `#[zeroize(skip)]`.

### Performance
- Key reload no longer decrypts keys sequentially on the async runtime. Keys are now
  decrypted concurrently on the blocking pool with a bounded window, removing head-of-line
  blocking during startup and `POST /keys/reload`. Original key ordering and per-key
  skip-on-failure behavior are preserved. Partial loads now identify the affected KID and
  cause in logs, emit aggregate failure and omission metrics, and classify explicit reloads
  as `partial` in metrics and audit without changing the successful response contract.
- Cryptographic operations now run on the blocking pool under a global concurrency
  limit (`VECTIS_MAX_CONCURRENT_CRYPTO`, default: CPU cores − 1). Requests beyond the
  limit are rejected with `429 Too Many Requests`. Key-set loading at startup and on
  reload now decrypts keys concurrently instead of sequentially, and the three internal
  message endpoints no longer block the async runtime.  

### Reliability & Observability
- Operational key loading now reports a load summary. `POST /keys/reload` returns a
  `partial` result (instead of `success`) when some keys fail to load, and per-reason
  failure counts are exported via the `vectis_key_load_failures_total` and
  `vectis_keys_load_skipped` metrics — partial key sets are no longer silent.
- The reload response, key count, gauges, and audit event are now derived from a single
  consistent snapshot of the just-loaded key set (fixes a read-after-write race under
  concurrent reloads).

## v0.8.5 - 2026-08-21

Pre-release of Vectis. This tag exists to exercise the release pipeline end
to end — binary packaging, container publication, checksums, and provenance
attestations. It ships the initial public feature set described below, but
v0.9.0 will be the first official release.

### Added

- Signed configuration, operational crypto profiles, key lifecycle controls,
  permissions, HTTP APIs, and CLI workflows for sensitive-data protection.
- Local FPE, reversible tokenization with optional one-time consumption,
  display masking, deterministic MACs, blind indexes, keyed commitments, and
  authenticated Shamir secret sharing.
- Hybrid EdDSA plus ML-DSA signatures, protected messaging, compact signed
  artifacts, and offline SLH-DSA artifact signing.
- Hash-chained audit JSONL with hybrid-signed checkpoints and offline
  verification.
- Local time attestation using authenticated NTS and verified Roughtime
  evidence.

### Security

- Signed configuration validation, strict input parsing, storage-row validation
  before cryptographic use, and explicit key lifecycle enforcement.
- Hybrid crypto profiles spanning performance, standard, high-assurance, and
  long-term configurations.

### Operational

- SQLite and PostgreSQL storage support for operational keys, token data, and
  blind-index membership records.
- Local demos, HTTP and CLI test suites, native fuzz targets, OpenAPI coverage,
  and an isolated k6 performance harness.

### Compatibility

- This is the first public tag; there is no prior public release API or
  config contract to preserve.
- API and signed-config formats remain experimental and may change in a future
  pre-1.0 release. Breaking changes will be documented here.

### Known Limitations

- Vectis has not completed an external security audit.
- It does not provide mTLS, Vault/KMS/HSM auto-unseal, Merkle proofs, or
  external anchoring for audit checkpoints.
- Run Vectis as one layer of a defense-in-depth architecture, not as the only
  control protecting sensitive data.

See [README.md](README.md), [doc/API.md](doc/API.md),
[doc/ThreatModel.md](doc/ThreatModel.md), and [SECURITY.md](SECURITY.md) for
the current product, threat-model, and vulnerability-reporting guidance.
