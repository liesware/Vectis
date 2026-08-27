# Vectis Testing Guide

This document explains the current Vectis test suite, what each layer proves,
and how to run the tests consistently.

## Testing Strategy

Vectis uses several test layers because each one protects a different part of
the system:

- Rust unit and property tests validate internal invariants without running a
  server.
- CLI tests validate local command behavior, config editing, and file isolation
  without requiring a running server.
- HTTP workflow tests validate the real API, storage, crypto flows, permissions,
  routing, and final app delivery behavior.
- Schemathesis validates that `doc/openapi.yaml` stays aligned with the running
  API through OpenAPI-based contract fuzzing.
- OWASP ZAP performs active dynamic security analysis against a disposable
  HTTPS API instance.
- k6 measures latency, throughput, and stability under load for a valid positive
  runtime flow.
- `cargo-fuzz` validates parser, validation, and canonicalization robustness
  against arbitrary byte input.

The layers are complementary. A passing HTTP workflow does not prove the OpenAPI
contract is accurate, and OpenAPI fuzzing or DAST does not replace
cryptographically valid happy-path tests. k6 does not prove correctness; it
measures how a known valid flow behaves under load.

## Prerequisites

Rust checks require the normal Rust toolchain used by the project.

Python tests are executed with [uv](https://docs.astral.sh/uv). Do not run the
Python scripts directly with `python3` for the standard workflow; use `uv run`
so the pinned interpreter and dependency groups are used consistently.

Native fuzzing requires:

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

`tests_cargo-fuzz.sh` resolves the selected nightly toolchain through `rustup`
and prepends its binary directory to `PATH`. This also keeps nested Cargo
invocations on nightly when the system default comes from Homebrew or another
package manager.

GitHub Actions also runs all native fuzz targets weekly and on manual dispatch
through `.github/workflows/cargo-fuzz.yml`. The automated run uses the pinned
`nightly-2026-08-01` toolchain and `cargo-fuzz` 0.13.2.

## Rust Checks

Run these before submitting changes:

```sh
cargo fmt
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

The optional live Cloudflare NTS interoperability check is intentionally ignored
by the normal suite because it requires external network access:

```sh
cargo test cloudflare_nts_smoke_test -- --ignored
```

`tests/integration/tls/tls.sh` is the canonical local TLS happy-path test; Rust CI runs it
through `tests/ci/test-tls.sh` using the built artifact. It starts Vectis in
production HTTPS mode with a temporary self-signed certificate, drives the CLI
through health checks, creates signed config and profiles, exercises local
cryptographic operations, and verifies the audit log. The CLI disables
certificate verification only for this ephemeral self-signed test, so the
scenario validates HTTPS transport and CLI/server integration, not CA trust.

`cargo test` covers unit and property tests for validation, canonical JSON,
config loading, permissions, routes, remote routes, lifecycle policy, signing
input parsing, hash-chained audit records, hybrid-signed checkpoints, and their verification, and related
internal behavior.

## Rust Crypto Integration Tests

Run the focused Vectis/Botan integration smoke tests with:

```sh
cargo test --test crypto_integration
```

These tests do not try to duplicate Botan's own primitive test suite. They
validate Vectis' contract with Botan: supported algorithm names, DER/raw key
handling, profile key material generation, key validation, hybrid XECDH + ML-KEM
composition, HKDF-derived message keys, and symmetric encryption/decryption.

## PostgreSQL Storage Smoke Test

PostgreSQL is optional and is not required for the default test loop. When a
local PostgreSQL instance is available, apply the reference schema manually and
run Vectis with the PostgreSQL backend:

```sh
psql "postgres://vectis_usr:123456@127.0.0.1:5432/vectis" -f src/db/postgres_schema.sql
VECTIS_STORAGE=postgres \
VECTIS_POSTGRES_DSN='postgres://vectis_usr:123456@127.0.0.1:5432/vectis' \
cargo run -- serve
```

Then run the HTTP workflow. This validates the storage backend through the real
API. Vectis does not apply migrations and does not create PostgreSQL tables at
runtime.

## Python HTTP Tests

Install/sync the base Python environment:

```sh
uv sync
```

## Python CLI Tests

Run the local CLI suite with:

```sh
uv run tests/integration/cli/cli_all.py
```

`tests/integration/cli/cli_all.py` runs:

- `tests/integration/cli/cli_init.py`: init overwrite protection and custom init file handling.
- `tests/integration/cli/cli_positive.py`: local `vectis config init`, section list/edit
  commands for `routes`, `remote-routes`, `permissions`, `fpe`, `token`, and full
  `config list` happy paths.
- `tests/integration/cli/cli_negative.py`: duplicate names, invalid fields, missing records, and
  mutation safety, including missing config files and overwrite refusal.

The CLI tests isolate runtime files with temporary paths:

```text
VECTIS_CONFIG_PATH
VECTIS_CONFIG_SIGN_PATH
VECTIS_INIT_KEYS_FILE
VECTIS_UNSEAL_KEY_FILE
```

They must not read or write the repository's real `config.json`, `init.json`,
`.unseal_key`, or `.env`.

Most CLI tests are local and do not need Vectis to be running. An optional
remote-route public-key import case can run when a server is available:

```sh
uv run tests/integration/cli/cli_all.py --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Run the positive and negative HTTP suite against a running Vectis instance:

```sh
uv run tests/integration/http/http_all.py --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

`tests/integration/http/http_all.py` runs:

- `tests/integration/http/http_positive.py`: valid end-to-end workflows, including FPE and
  reversible tokenization.
- `tests/integration/http/http_negative.py`: invalid input, denied permission, lifecycle, and
  error-path checks, including FPE/tokenization validation failures.

Run targeted manual HTTP fuzzing with:

```sh
uv run tests/security/fuzz/http_fuzz.py --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

`tests/security/fuzz/http_fuzz.py` is a targeted mutation helper. It is separate from
Schemathesis and is useful for project-specific negative cases. It mutates
seeds across crypto profiles (ChaCha20 and AES-GCM variants) with domain-aware
mutations, and drives a table of targets (`--target`): `token`, `message`,
`message_send`, `internal`, `internal_encrypt`, `keys`, `sign_body`,
`lifecycle`, `decrypt`, `config`, `fpe`, `fpe_batch`, `tokenization`,
`tokenization_batch`, `mac`, `mac_batch`, `commitment`, `commitment_batch`, `index`, `index_batch`, `pubkid` (fuzzes the `{kid}` path
segment), `masking`, `masking_batch`, `sharing`, `no_body`, and `headers`
(fuzzes `X-API-Key` and the HTTP method). The `fpe`, `tokenization`, `mac`,
`commitment`, `index`, `masking`, and `sharing` targets cover the single-item
endpoints, while `fpe_batch`, `tokenization_batch`, `mac_batch`,
`commitment_batch`, `index_batch`, and `masking_batch` cover the all-or-nothing
batch endpoints. Secret sharing has no batch endpoint. The `no_body` target checks endpoints called
without a body where that shape is useful. Beyond crash/status hygiene it runs
semantic oracles that flag verification, AEAD, FPE, tokenization, and
config-integrity bypasses; `--self-check` tests
those oracles offline.

### Nadir Stateful HTTP Fuzzing

Nadir is the developing replacement for the stateful and semantic parts of
`tests/security/fuzz/http_fuzz.py`. It models request, producer/consumer, multi-step flow,
and race targets, then evaluates project-specific invariants across fresh
workflow state. It remains in parallel with `http_fuzz.py` until the existing
semantic coverage has been migrated and compared over repeated runs.

Run it against a disposable, automatically provisioned Vectis node:

```sh
bash tests/security/nadir/run.sh --iterations 100 --seed 0
```

New finding artifacts use `nadir-finding-v4` and contain a redacted per-case
recipe. `replay` only resends stored requests and does not evaluate oracles.
Use the Vectis wrapper to rebuild state and verify that the original finding
codes still appear:

```sh
bash tests/security/nadir/reproduce.sh tests/security/nadir/results/<finding.json>
```

The wrapper provisions a fresh local node, runs `nadir reproduce`, verifies the
node's audit log, and removes the laboratory. Nadir is not yet part of CI.

## Schemathesis OpenAPI Tests

Install/sync the fuzz dependency group:

```sh
uv sync --group fuzz
```

Run the default safe profile:

```sh
uv run tests/security/openapi/http_schemathesis.py --profile safe --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Run the prepared profile:

```sh
uv run tests/security/openapi/http_schemathesis.py --profile prepared --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Run the full contract only in disposable environments:

```sh
uv run tests/security/openapi/http_schemathesis.py --profile all --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Schemathesis uses `doc/openapi.yaml` by default.

- `safe`: read-oriented endpoints only; does not intentionally mutate state.
- `prepared`: creates real keys, writes and signs temporary test config, reloads
  it, and injects a real KID example into a temporary OpenAPI schema.
- `all`: runs the full OpenAPI contract against prepared state and may mutate
  runtime state.

Schemathesis helps confirm that the OpenAPI schema and backend validation stay
in sync. It does not replace `tests/integration/http/http_positive.py`, which remains the source
of cryptographically valid happy paths.

## Dynamic API Scanning With OWASP ZAP

GitHub Actions runs an OWASP ZAP API Scan every Tuesday and on manual dispatch
through `.github/workflows/zap-api-scan.yml`. This is an active DAST scan: ZAP
imports the OpenAPI contract and sends attack payloads to the described API.
Run it only against systems that you own and are explicitly authorized to test.

The workflow never targets a deployed Vectis instance. Its dedicated
`tests/security/zap/zap_scan.sh` runner creates a disposable HTTPS node with temporary
SQLite storage, init material, signed profiles, an operational KID, and a
synthetic application API key. That identity has only data-protection and
signing permissions; administrative, lifecycle, messaging, routing, and time
attestation operations remain denied. The complete laboratory is removed after
the scan.

ZAP, Schemathesis, and `tests/security/fuzz/http_fuzz.py` answer different questions:

- ZAP looks for common API and web security vulnerabilities through active and
  passive scanner rules.
- Schemathesis checks whether generated requests and observed responses conform
  to `doc/openapi.yaml`.
- `tests/security/fuzz/http_fuzz.py` applies Vectis-specific mutations and semantic oracles.

The initial ZAP policy is report-only. Scanner exit codes that indicate alerts
do not fail the workflow, but Docker failures, scanner errors, and timeouts do.
The workflow summary shows alert counts by risk and publishes HTML, Markdown,
JSON, XML, ZAP logs, and Vectis logs as a 30-day artifact. The synthetic API key
is redacted before upload.

On Linux with Docker available, run the same isolated scan locally with:

```sh
cargo build --locked --all-features
VECTIS_BIN="$PWD/target/debug/vectis" \
ZAP_RESULTS_DIR="$PWD/zap-results" \
bash tests/security/zap/zap_scan.sh
```

Review real results before adding rule suppressions. Do not point this runner at
production, shared test environments, remote peers, or final applications.

## Performance Testing With k6

`tests/performance/k6.js` is a manual local performance suite. It is not part
of `tests.sh`, and it does not replace `tests/integration/http/http_positive.py`, Schemathesis,
or fuzzing.

Prerequisites:

- `k6` must be installed locally.
- Rust, Python 3, and the Vectis build dependencies must be available.
- Port `3020` must be free. The runner creates and removes its own SQLite,
  init artifacts, signed config, audit stream, four KIDs, and API client below
  `tests/performance/local/site/`.

Run the default four-iteration smoke (one full pass through the four crypto
profiles):

```sh
bash tests/performance/run.sh
```

Run a small load test:

```sh
K6_VUS=20 K6_DURATION=2m bash tests/performance/run.sh
```

Override the target explicitly:

```sh
K6_VUS=20 K6_DURATION=2m K6_P95_MS=1000 \
  bash tests/performance/run.sh
```

The runner provisions one KID for each built-in crypto profile:

- `hybrid-performance-v1`;
- `hybrid-standard-v1`;
- `hybrid-high-assurance-v1` with a one-time token profile;
- `hybrid-long-term-v1`.

Each iteration rotates between those suites and exercises local operations:

- health probes: `/healthz/startup`, `/healthz/live`, `/healthz/ready`;
- `GET /pub/{kid}`;
- `GET /self-test/keys/{kid}`;
- FPE, tokenization, MAC, blind indexes, masking, commitments and their batch
  endpoints where available;
- secret sharing split/combine;
- internal message encrypt/decrypt;
- compact sign/verification;
- `/metrics` during teardown.

The runner stops Vectis after k6 exits and verifies the generated hash-chained
audit log offline. It intentionally excludes remote message delivery and
`/time/attest`: they depend on a second service or external time sources and
would not be a local crypto baseline. Provisioning and audit verification are
outside the measured k6 window. k6 tags every request by operation and crypto
profile; its summary reports throughput, average, p95, and p99 for each
operation/profile combination. `K6_P95_MS` optionally turns the aggregate p95
into a threshold. The scripts do not print API keys or cryptographic payloads.

## Native Fuzzing With cargo-fuzz

Run all native fuzz targets with:

```sh
./tests_cargo-fuzz.sh
```

The runner is non-interactive and can be invoked from a terminal or automation.
It uses the portable `nightly` rustup toolchain by default. Select another
installed nightly toolchain with:

```sh
TOOLCHAIN=nightly-2026-07-01 ./tests_cargo-fuzz.sh
```

Increase or reduce the number of runs per target with:

```sh
RUNS=100000 ./tests_cargo-fuzz.sh
```

Or bound each target by wall-clock time (seconds) for a longer hardening run:

```sh
MAX_TOTAL_TIME=120 ./tests_cargo-fuzz.sh
```

`MAX_TOTAL_TIME` takes precedence: when it is set, each target runs until the
time limit with no run-count cap; otherwise `RUNS` bounds each target. Both must
be positive integers.

By default the runner stops at the first target that reports a finding
(fail-fast). Set `KEEP_GOING=1` to run every target regardless and still exit
non-zero if any failed — useful for a broad sweep that collects every crash in a
single pass:

```sh
KEEP_GOING=1 ./tests_cargo-fuzz.sh
```

Instead of fuzzing, minimize the accumulated corpus to the smallest set that
preserves coverage (runs `cargo fuzz cmin` per target in place of `cargo fuzz
run`):

```sh
MINIMIZE=1 ./tests_cargo-fuzz.sh
```

Committed seed inputs live in `fuzz/seeds/<target>/` and are synchronized into
the (git-ignored) `fuzz/corpus/<target>/` before each run to bootstrap coverage
from realistic examples. Existing corpus entries discovered by libFuzzer are
preserved.

The script runs:

- `fuzz_canonical_json`
- `fuzz_sign_input`
- `fuzz_compact_signature`
- `fuzz_timestamp_token` (the compact `{kid, signature}` verification request)
- `fuzz_message_inputs`
- `fuzz_config_file`
- `fuzz_keys_inputs`
- `fuzz_validation`
- `fuzz_routes_permissions`
- `fuzz_fpe_inputs`
- `fuzz_tokenization_inputs`
- `fuzz_mac_index_inputs`
- `fuzz_masking_commitment_inputs`
- `fuzz_sharing_inputs`
- `fuzz_share_envelope`
- `fuzz_audit_chain_line`
- `fuzz_slh_dsa_signature`
- `fuzz_slh_dsa_key_files`
- `fuzz_init_artifacts`

SLH-DSA artifact signing has structural fuzz coverage for compact signatures
and key-file wrappers. Its Botan round-trip test still confirms the compiled
variant and randomized signing mode. Audit JSONL and init artifacts likewise
have structural fuzz coverage without loading private material.

These targets intentionally avoid invoking Botan, SQLite, networking, and
server startup inside the fuzz loop. They focus on parser safety, validation
boundaries, canonical JSON determinism, config parsing robustness, compact
signature encoding, audit JSONL shape, key-file wrappers, and share-envelope
encoding. The data-protection input targets stop at the `ops` parse/validate
boundary; compact signatures, audit checkpoints, init artifacts, SLH-DSA files,
and share envelopes stop before cryptographic authentication. They do not load
keys or profiles, execute cryptographic operations, or exercise HTTP. Hash
output validation and cryptographic verification remain covered by Rust unit
tests, `tests/crypto_integration.rs`, and `tests/security/fuzz/http_fuzz.py`.

### Error message hygiene

Some parse/validation targets assert that error messages contain no control
characters. Parser boundaries must construct safe errors themselves: request,
config, and CLI JSON use the shared Serde-detail sanitizer, while sensitive or
authenticated artifacts use fixed format errors. `ErrorResponse::new` in
`src/io/http/error.rs` remains a final transport defense, not the primary
guarantee. The fuzz-target assertions protect the same invariant outside HTTP.

By default the runner stops after the first finding or execution failure,
preserves the artifact under `fuzz/artifacts/<target>/`, prints a
passed/failed/skipped summary, and returns a non-zero status. The weekly
workflow runs with `KEEP_GOING=1` so every target is exercised in one pass even
if an earlier one crashes, gives every target up to 60 seconds, restores the
most recent accumulated corpus from GitHub Actions Cache, and saves the updated
corpus after the run. Cache availability is not required: the committed seeds
remain the reproducible starting point.

The corpus grows as libFuzzer discovers new inputs. To prune it, dispatch the
workflow manually with the `minimize_corpus` checkbox (or run
`MINIMIZE=1 ./tests_cargo-fuzz.sh` locally): this runs `cargo fuzz cmin` per
target and saves the reduced corpus back to the cache as the new baseline.

The workflow publishes its full log and any crash artifacts for 30 days. It is
a scheduled hardening check, not a required pull-request gate. Vectis' contract
with Botan is covered by `tests/crypto_integration.rs`.

If a fuzz target finds a crash, keep the minimized artifact, add a regression
test, fix the issue, and rerun the target against the artifact and the normal
short run.

## Aggregate Workflow

The high-level project test script is:

```sh
./tests.sh
```

It currently runs:

```sh
cargo fmt
cargo test --test crypto_integration
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
uv sync
uv run tests/integration/cli/cli_all.py
uv run tests/integration/http/http_all.py
uv run tests/security/fuzz/http_fuzz.py
uv sync --group fuzz
uv run tests/security/openapi/http_schemathesis.py --profile prepared
```

`tests.sh` runs Rust checks and local CLI tests first. It then asks the operator
to start Vectis before the HTTP, manual fuzz, and Schemathesis layers. The HTTP
tests need an API key available through the environment or `.env` flow used by
`tests/integration/support/test_config.py`.

`tests_cargo-fuzz.sh` is intentionally separate because it requires nightly,
uses sanitizer builds, and is heavier than the normal HTTP test suite.

## Test File Reference

- `tests/integration/cli/cli_all.py`: streaming CLI summary runner.
- `tests/integration/cli/cli_init.py`: CLI init behavior.
- `tests/integration/cli/cli_negative.py`: invalid local CLI config-editing workflows.
- `tests/integration/cli/cli_positive.py`: valid local CLI config-editing workflows.
- `tests/integration/support/cli_support.py`: shared Python helpers for CLI workflows.
- `tests/crypto_integration.rs`: focused Vectis/Botan crypto integration smoke
  tests.
- `tests/manual/final_app_server.py`: manual mock final-app receiver and decrypt helper; it is not part of CI or `tests.sh`.
- `tests/integration/http/http_all.py`: positive + negative summary runner.
- `tests/security/fuzz/http_fuzz.py`: targeted manual HTTP mutation tests retained during the
  Nadir migration.
- `tests/security/nadir/run.sh`: isolated Vectis harness for Nadir discovery runs.
- `tests/security/nadir/reproduce.sh`: isolated Vectis harness for v4 finding reproduction.
- `tests/integration/http/http_negative.py`: invalid, denied, and error-path workflows.
- `tests/integration/http/http_positive.py`: valid end-to-end runtime workflows.
- `tests/security/openapi/http_schemathesis.py`: OpenAPI contract fuzzing via Schemathesis.
- `tests/integration/support/http_support.py`: shared Python helpers for HTTP workflows.
- `tests/performance/run.sh`: single entry point for the isolated local k6
  harness.
- `tests/performance/k6.js`: local mixed-workload k6 scenario.
- `tests/integration/support/test_config.py`: test configuration and API key loading helpers.
- `tests_cargo-fuzz.sh`: native fuzz runner for all cargo-fuzz targets.
