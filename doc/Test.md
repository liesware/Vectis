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
- k6 measures latency, throughput, and stability under load for a valid positive
  runtime flow.
- `cargo-fuzz` validates parser, validation, and canonicalization robustness
  against arbitrary byte input.

The layers are complementary. A passing HTTP workflow does not prove the OpenAPI
contract is accurate, and OpenAPI fuzzing does not replace cryptographically
valid happy-path tests. k6 does not prove correctness; it measures how a known
valid flow behaves under load.

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

On systems where `cargo` and `rustc` come from Homebrew or another package
manager, `tests_cargo-fuzz.sh` forces the nightly toolchain path for the fuzzing
run.

## Rust Checks

Run these before submitting changes:

```sh
cargo fmt
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

`cargo test` covers unit and property tests for validation, canonical JSON,
config loading, permissions, routes, remote routes, lifecycle policy, signing
input parsing, and related internal behavior.

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
uv run tests/cli_all.py
```

`tests/cli_all.py` runs:

- `tests/cli_init.py`: init overwrite protection and custom init file handling.
- `tests/cli_positive.py`: local `vectis config init`, `routes`,
  `remote-routes`, `permissions`, and `config list` happy paths.
- `tests/cli_negative.py`: duplicate names, invalid fields, missing records, and
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
uv run tests/cli_all.py --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Run the positive and negative HTTP suite against a running Vectis instance:

```sh
uv run tests/http_all.py --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

`tests/http_all.py` runs:

- `tests/http_positive.py`: valid end-to-end workflows.
- `tests/http_negative.py`: invalid input, denied permission, lifecycle, and
  error-path checks.

Run targeted manual HTTP fuzzing with:

```sh
uv run tests/http_fuzz.py --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

`tests/http_fuzz.py` is a targeted mutation helper. It is separate from
Schemathesis and is useful for project-specific negative cases. It mutates
seeds across crypto profiles (ChaCha20 and AES-256/GCM) with domain-aware
mutations, and drives a table of targets (`--target`): `token`, `message`,
`internal`, `keys`, `sign_body`, `lifecycle`, `decrypt`, `config`, `pubkid`
(fuzzes the `{kid}` path segment) and `headers` (fuzzes `X-API-Key` and the HTTP
method). Beyond crash/status hygiene it runs semantic oracles that flag
verification, AEAD, and config-integrity bypasses; `--self-check` tests those
oracles offline.

## Schemathesis OpenAPI Tests

Install/sync the fuzz dependency group:

```sh
uv sync --group fuzz
```

Run the default safe profile:

```sh
uv run tests/http_schemathesis.py --profile safe --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Run the prepared profile:

```sh
uv run tests/http_schemathesis.py --profile prepared --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Run the full contract only in disposable environments:

```sh
uv run tests/http_schemathesis.py --profile all --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

Schemathesis uses `doc/openapi.yaml` by default.

- `safe`: read-oriented endpoints only; does not intentionally mutate state.
- `prepared`: creates real keys, writes and signs temporary test config, reloads
  it, and injects a real KID example into a temporary OpenAPI schema.
- `all`: runs the full OpenAPI contract against prepared state and may mutate
  runtime state.

Schemathesis helps confirm that the OpenAPI schema and backend validation stay
in sync. It does not replace `tests/http_positive.py`, which remains the source
of cryptographically valid happy paths.

## Performance Testing With k6

`tests/performance/k6.js` is a manual performance smoke test. It is not part of
`tests.sh`, and it does not replace `tests/http_positive.py`, Schemathesis, or
fuzzing.

Prerequisites:

- `k6` must be installed.
- Vectis must already be running.
- The final app configured for message delivery must already be running.
- `.env` must provide `VECTIS_API_URL` and `VECTIS_APIKEY`, or those values must
  be passed as real environment variables.
- `config.json` must exist, be signed, be loaded in Vectis, and contain a usable
  active `remote_routes[]` entry.

Run the default one-iteration smoke:

```sh
k6 run tests/performance/k6.js
```

Run a small load test:

```sh
k6 run --vus 20 --duration 2m tests/performance/k6.js
```

Override the target explicitly:

```sh
VECTIS_API_URL=http://127.0.0.1:3000 \
VECTIS_APIKEY=<key> \
k6 run tests/performance/k6.js
```

The script exercises:

- health probes: `/healthz/startup`, `/healthz/live`, `/healthz/ready`;
- `POST /keys`;
- `GET /pub/{kid}`;
- `GET /self-test/keys/{kid}`;
- `POST /sign/{kid}` and `POST /sign/verification`;
- internal encrypt/decrypt;
- remote message send with `POST /message/{kid}`.

k6 creates one key in `setup()` for crypto checks. Message sending uses a sender
KID selected from `config.json` local routes, because message routing policy is
config-based. The script prints only a small runtime summary with truncated KIDs
and does not print API keys, ciphertexts, signatures, or sensitive plaintext.

## Native Fuzzing With cargo-fuzz

Run all native fuzz targets with:

```sh
./tests_cargo-fuzz.sh
```

Increase or reduce the number of runs with:

```sh
RUNS=100000 ./tests_cargo-fuzz.sh
```

Or bound each target by wall-clock time (seconds) for a longer hardening run:

```sh
MAX_TOTAL_TIME=120 ./tests_cargo-fuzz.sh
```

Committed seed inputs live in `fuzz/seeds/<target>/` and are copied into the
(git-ignored) `fuzz/corpus/<target>/` before each run to bootstrap coverage from
realistic examples.

The script runs:

- `fuzz_canonical_json`
- `fuzz_sign_input`
- `fuzz_timestamp_token`
- `fuzz_message_inputs`
- `fuzz_config_file`

Additional registered targets can be run manually with `cargo fuzz run`:

- `fuzz_keys_inputs`
- `fuzz_validation`
- `fuzz_routes_permissions`

These targets intentionally avoid Botan, SQLite, networking, and server startup
inside the fuzz loop. They focus on parser safety, validation boundaries,
canonical JSON determinism, and config parsing robustness.

### Error message hygiene

Some parse/validation targets assert that error messages contain no control
characters. The **guarantee** is that the HTTP boundary sanitizes every public
error message (`ErrorResponse::new` in `src/io/http/error.rs`, unit-tested
there): responses always conform to the OpenAPI `TextField` contract regardless
of what deeper code interpolates. The fuzz-target assertions are **defense in
depth** — the `ops`/`core` layers should not gratuitously inject control
characters into error text — not the primary guarantee.

`cargo-fuzz` is currently a local/manual hardening tool rather than a CI gate.
Botan itself stays outside these fuzz loops; Vectis' contract with Botan is
covered by `tests/crypto_integration.rs`.

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
uv run tests/cli_all.py
uv run tests/http_all.py
uv run tests/http_fuzz.py
uv sync --group fuzz
uv run tests/http_schemathesis.py --profile prepared
```

`tests.sh` runs Rust checks and local CLI tests first. It then asks the operator
to start Vectis before the HTTP, manual fuzz, and Schemathesis layers. The HTTP
tests need an API key available through the environment or `.env` flow used by
`tests/test_config.py`.

`tests_cargo-fuzz.sh` is intentionally separate because it requires nightly,
uses sanitizer builds, and is heavier than the normal HTTP test suite.

## Test File Reference

- `tests/cli_all.py`: streaming CLI summary runner.
- `tests/cli_init.py`: CLI init behavior.
- `tests/cli_negative.py`: invalid local CLI config-editing workflows.
- `tests/cli_positive.py`: valid local CLI config-editing workflows.
- `tests/cli_support.py`: shared Python helpers for CLI workflows.
- `tests/crypto_integration.rs`: focused Vectis/Botan crypto integration smoke
  tests.
- `tests/final_app_server.py`: mock final app receiver and decrypt helper.
- `tests/http_all.py`: positive + negative summary runner.
- `tests/http_fuzz.py`: targeted manual HTTP mutation tests.
- `tests/http_negative.py`: invalid, denied, and error-path workflows.
- `tests/http_positive.py`: valid end-to-end runtime workflows.
- `tests/http_schemathesis.py`: OpenAPI contract fuzzing via Schemathesis.
- `tests/http_support.py`: shared Python helpers for HTTP workflows.
- `tests/performance/k6.js`: manual k6 performance/load smoke test.
- `tests/test_config.py`: test configuration and API key loading helpers.
- `tests_cargo-fuzz.sh`: native fuzz runner for all cargo-fuzz targets.
