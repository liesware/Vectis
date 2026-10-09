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

Token deletion coverage includes independent permissions, lifecycle, repeated
deletion, and races with one-time consumption in the positive HTTP suite.
The `token_delete` HTTP fuzz target mutates delete input. SQLite tests also
cover corrupt envelopes and rollback on DELETE or COMMIT failure.
The optional PostgreSQL deletion test requires a dedicated test database with
the Vectis schema:

```sh
VECTIS_TEST_POSTGRES_DSN='<test-dsn>' cargo test explicit_delete_is_atomic_and_single_use -- --ignored
```

Rust checks require the normal Rust toolchain used by the project.

The `token_batch_budget` HTTP fuzz target checks rejection of repeated reusable
tokens whose envelopes exceed 5 MiB, then verifies a smaller batch returns its
complete plaintexts. The positive HTTP suite additionally checks one-time tokens
remain available after budget rejection and that accepted responses may exceed
2 MiB. Storage tests cover exact limits, duplicate accounting and overflow;
PostgreSQL budget tests require `VECTIS_TEST_POSTGRES_DSN` and `--ignored`.

Subject-key HTTP cases cover independent grants, concurrent creation, subject
isolation, one-time batch races and deletion/recreation without legacy fallback.
Storage contracts run on SQLite and optionally on disposable PostgreSQL:

```sh
VECTIS_TEST_POSTGRES_DSN='<migrated-test-dsn>' cargo test postgres_subject_contract -- --ignored
```

The tokenization input and config fuzz targets accept `subject` and
`subject_mode`; the separate `fuzz_tokenization_roundtrip` crypto target also
checks authenticated seed opening, subject-key round trips and seed replacement.

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

FPE coverage includes signed ASCII presets and Unicode custom alphabets,
preserved separator positions, effective-domain rejection and all-or-nothing
batch errors. CLI tests cover selector replacement, case inheritance/removal and
invalid edits without writes. Native `fuzz_fpe_roundtrip` exercises legacy,
preset and Unicode profiles, including insufficient effective domains; curated
input/config seeds cover incompatible selectors, nulls and overlap. Legacy
serialization and a deterministic ciphertext vector are regression-tested.

The positive suite races eight subject creations and expects one `201` and
seven `200` responses with the same ID and unchanged seed. Storage tests cover
transactional token purging, stale-generation writes and encode/delete races.
Run its isolated server with
`VECTIS_MAX_CONCURRENT_CRYPTO=8` (or greater) so crypto admission does not turn
this storage-uniqueness check into an overload test. The CI integration runner
sets eight slots explicitly; the production default remains unchanged.

Install/sync the base Python environment:

```sh
uv sync
```

The HTTP suite is structured so that adding a case is adding one function:

- `tests/integration/http/cases/` holds the endpoint contracts, one module per
  capability (`positive_*.py` / `negative_*.py`). A case is a function decorated
  with `@cases("capability.contract")`, and each module exposes the resulting
  `CASES` tuple. `cases/registry.py` is the only place that composes the ordered
  execution across modules.
- `tests/integration/http/lib/` is private to this suite: transport clients,
  assertions, the `HttpTestContext` (`ctx`), configuration transactions,
  fixtures, and the case runner. Each suite owns these helpers and must not
  import another suite's private `lib/`. Only executable resolution is shared
  through `tests/support/vectis.py`.
- A case receives `ctx`: `ctx.http` for status-preserving requests, `ctx.client`
  for successful authenticated ones, `ctx.expect`/`ctx.require` for assertions,
  `ctx.set_*`/`ctx.write_config()` for signed-config changes (both config files
  are restored and reloaded during cleanup), and `ctx.fixtures` for ordered
  shared state produced by earlier cases.
- Counting: a negative case counts its `weight` (default 1); a positive case
  returns `CaseResult(passed=N)`. `http_positive.py` runs the positive suite
  with `require_result=True`, so a positive case that forgets its `CaseResult`
  fails loudly instead of silently undercounting the total.
- `tests/integration/http/lib/test_lib.py` holds structural guards, run with the
  standard-library runner (no server needed):

  ```sh
  PYTHONPATH=tests/integration:tests/integration/http \
    python3 -m unittest discover -s tests/integration/http/lib -p 'test_*.py'
  ```

  They keep the split from regressing: every declared `CASES` module must be
  composed by the registry and use the `@cases`/`ctx` model. Shared fixtures and
  assertions remain forbidden; `support.vectis` is the sole allowed shared helper.

### Adding an HTTP case

1. Put the endpoint-specific contract in the appropriate `cases/positive_*.py`
   or `cases/negative_*.py` module. Split a capability into its own module when
   it would make the existing one hard to scan.
2. Add a function decorated with the module's `@cases(...)` decorator. Adding a
   case is adding one function — no manual tuple entry and no registry edit for
   the case itself:

   ```python
   from lib.casekit import CaseSet

   cases = CaseSet()  # once, near the top

   @cases("tokenization.decode-rejects-unknown-profile")
   def _(ctx):
       status, _ = ctx.http.post("/token/decode", {"profile": "nope", ...})
       ctx.expect(status, 400)

   CASES = cases.tuple()  # once, at the bottom
   ```

   Only a *new module* needs an explicit entry in `cases/registry.py`; the
   `lib/test_lib.py` guards fail if you declare a `CASES` module the registry
   never composes.
3. The case receives `HttpTestContext` as `ctx`. Use `ctx.http` for
   status-preserving requests (keeps 4xx/5xx), `ctx.client` for successful
   authenticated requests, `ctx.expect`/`ctx.require` for assertions, and
   `ctx.fixtures` for ordered, suite-local shared data (positive cases currently
   also use the `ctx.artifacts` dict for the same purpose).
4. Change signed configuration through `ctx.set_*`, `ctx.write_config()`, or
   `ctx.write_unsigned_config()`. The context transaction restores both config
   files and reloads the restored runtime state during cleanup.
5. Counting: a negative case counts its `weight` (default 1); a positive case
   returns `CaseResult(passed=N)` with the number of sub-checks it makes. Use
   `@cases(..., weight=0)` for a setup/bootstrap case that counts nothing.
6. Keep endpoint-specific assertions next to the case. Move an abstraction into
   `lib/` only when more than one HTTP capability needs it.

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
mutations, and drives a table of targets (`--target`). Alongside the generic
surface targets, it includes deterministic contracts for compact hybrid
signatures (`compact_signature_integrity`), lifecycle (`lifecycle_contract`),
reusable and one-time token behavior, batch ordering and atomicity
(`*_batch_contract` and `index_batch_transaction`), and the single-item
cryptographic capabilities. `compact_signature_integrity` creates fresh tokens
and verifies the ML-DSA-before-EdDSA failure order for every compact segment.
`subject_contract` verifies `201/200` idempotent creation, preservation of the
seed on retry, and token unavailability after deletion and recreation. It uses
fresh names per iteration and redacts names, plaintexts and tokens in artifacts.
`time_attest_offline` temporarily configures loopback-only unavailable sources
and verifies the fail-closed `502` contract without using the Internet or
affecting readiness. `http_protocol` checks the 2 MiB request boundary,
content type, empty-body, method, and per-response latency contracts.
`lifecycle_contract` verifies that
new use requires an active KID, retired keys retain only historical
decrypt/verify capability, and disabled, compromised, and destroyed keys are
blocked consistently. Secret sharing has no batch endpoint. The `no_body`
target checks endpoints called without a body where that shape is useful.
Beyond crash/status hygiene it runs semantic oracles that flag verification,
AEAD, FPE, tokenization, batch-atomicity, lifecycle, and config-integrity
bypasses, plus a secret-leak oracle that fails any response containing the API
key or the on-disk unseal key; the entry point reads `.unseal_key` only to feed
that oracle, never to unseal. `--self-check` tests those oracles and campaign
measurements offline. Output ends with `SUMMARY fuzz passed=<N> failed=<M>`
(non-zero exit if any case failed or the server is unhealthy afterward). Run it
only against a disposable instance you own.

The harness combines random mutation with regression scenarios. Local runs
default to root seed `1337`; `--seed <integer>` selects a reproducible sequence
of mutation decisions when fixtures are identical. Each target has an independent
RNG derived using SHA-256 (`http-fuzz-target-seed-v1`), so selection or execution
order does not change another target's RNG. This does not reproduce server-generated
KIDs, signatures, ciphertexts, state or race scheduling. Findings include both
the root seed and derived target seed; rerun using the root seed and `--target`.

Use fresh exploration seeds with:

```sh
uv run tests/security/fuzz/http_fuzz.py --random-seed --mutation-only \
  --iterations 100 --summary-json .ci/http-fuzz/exploration.json
```

`--random-seed` generates and prints a 64-bit root seed before requests and is
mutually exclusive with `--seed`. `--mutation-only` selects body, path, headers
and config mutation targets, excluding deterministic scenarios and no-body probes.
An incompatible `--target` is rejected before bootstrap.

`--summary-json <path>` records run configuration, target seeds, completed cases,
passed/failed counts and primary status distributions. Status counts exclude
setup, downstream requests and health probes: they measure the response supplied
to the case oracle, not all HTTP traffic. Mutation targets also report generated,
unique and duplicate inputs. Fingerprints use complete input before description
truncation, never valid auth headers or responses, and remain only in memory.
Reports contain aggregate counts, not payloads, credentials or fingerprints.
Uniqueness is scoped to one target in one run; fresh fixtures make cross-run
comparisons unsuitable as accumulated coverage. The harness has neither
instrumented coverage nor an evolving corpus; saved findings are not seed input.
A run without findings does not establish saturation or absence of vulnerabilities.

CI keeps the complete regression pass (`--seed 1337 --iterations 300`) and adds
an exploratory pass (`--random-seed --mutation-only --iterations 100`). The latter
still runs after regression findings if Vectis remains ready. Either failure fails
the step. Both JSON summaries are published for 30 days as
`http-fuzz-summaries-<run_id>`, with a Job Summary showing seeds, results and input
diversity. Missing reports are identified explicitly. Findings retain their
existing failure artifact publication.

The fuzz client uses direct HTTP/HTTPS connections with certificate validation,
without automatic redirects or environment proxies. Each request has a 15-second
deadline shared by upload and response reading. If the server rejects an upload
early, the client attempts to read the HTTP response on the same connection after
a broken pipe or reset; it never resends the request. Only a complete HTTP response
is accepted. A disconnect without a response remains status `0` and a finding,
even when a subsequent health probe succeeds.

The `token_delete` oracle checks the exact success shape and detects fixture-issued
tokens in response JSON strings (including nested values and keys) or non-JSON
text. Mutated tokens are checked as complete JSON values, not arbitrary
substrings: a mutation to `"t"` must not flag an ordinary error mentioning
`token`. Only the exact top-level `ref` echo in a successful response is exempt;
reflection elsewhere remains a finding. This does not attempt to attribute
arbitrary short fragments to a token leak.

Findings use `http-fuzz-finding-v3`. The JSON records seeds, case index, transport
phase, exception type/errno, request byte counts and timing, without arbitrary
exception messages or authentication headers. Body previews are at most 2,000
characters and explicitly marked when truncated. Each `responses` entry records
`response_body_preview` from the client's decoded response text and
`response_preview_truncated`, including for GET and empty responses. When that
exchange has a request body, its evidence is separate: `request_payload`,
`request_body_preview` and `request_preview_truncated`. Complete request bodies and
mutated config files are saved only for findings, as sibling `.payload.gz` files;
multi-request cases may include additional `.request-N.payload.gz` files. Payload
references include original and stored uncompressed sizes and SHA-256 hashes.
The declared API key and unseal key are redacted before previews and payloads are
written. A payload marked `redacted` is not a byte-for-byte reproduction of the
original. Summaries remain aggregate-only.

Historical v2 artifacts are not rewritten. Their `responses[].body_preview`
contains the submitted request body, not the actual HTTP response; those artifacts
cannot reconstruct the original response text. The top-level request payload
references retain their meaning in v3. Response previews are bounded decoded
text, not complete original wire bytes; response files and headers are not saved.

Payloads are published before their JSON metadata using atomic file replacement.
Storage failures propagate; existing artifacts, including historical truncated
ones, are not overwritten. To inspect a downloaded payload:

```sh
gzip -dc crash_<target>_<seed>_<index>.payload.gz > request-body.bin
sha256sum request-body.bin
```

Compare the uncompressed bytes with `stored_bytes` and `stored_sha256` in the
JSON, not the hash of the compressed file. Saved payloads may contain synthetic
sensitive test data; run and retain findings only for disposable laboratories.
There is no automatic replay command for this format.

`--self-check` includes offline transport and artifact regressions. To also run
disposable HTTP/HTTPS early-rejection tests (requires OpenSSL and local sockets):

```sh
uv run python -m unittest discover -s tests/security/fuzz -p test_fuzz_io.py -v
```

`http_fuzz.py` is only the entry point; the substance lives in sibling modules:
`targets.py` (the `TARGETS` table, one dict per target, and the runners),
`seeds.py` / `mutations.py` (domain-aware seed corpora and mutators),
`oracle.py` / `semantics.py` (the leak oracle and per-capability semantic
oracles), `campaign.py` (seed isolation and aggregate measurements), and
`self_check.py` (offline self-tests). Each of `client.py`, `config.py`,
`reporting.py` and `credentials.py` is private to this suite.

To add a target:

1. Add a seed factory (and any mutator) in `seeds.py` / `mutations.py`.
2. Append one dict to the `TARGETS` list in `targets.py`:

   ```python
   {"name": "my_capability", "runner": run_body, "seed_factory": my_seeds,
    "auth": True, "semantic": my_semantic_oracle},
   ```

   `run_body` covers most body endpoints; use a dedicated runner (e.g.
   `run_http_protocol`, `run_batch_contract`) for richer contracts. `--target`
   picks the new name up automatically because `TARGET_NAMES` is derived from
   `TARGETS`.
3. If the target asserts a semantic contract, add its oracle in `semantics.py`
   and cover it in `self_check.py` so `--self-check` protects it offline.

Cloudflare validation is deliberately manual and opt-in:

```sh
VECTIS_TIME_ATTESTATION_LIVE=1 \
uv run tests/manual/time_attestation_cloudflare.py \
  --base-url http://127.0.0.1:3000 --apikey <VECTIS_APIKEY>
```

It validates a complete authenticated NTS and verified Roughtime response, but
does not require `server_clock.acceptable: true`. It is not part of `tests.sh`,
CI, release workflows, or normal HTTP fuzzing.

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
- symmetric encrypt/decrypt;
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

These targets intentionally avoid invoking Botan, SQLite, PostgreSQL,
networking, and server startup inside the fuzz loop. They focus on parser
safety, complete semantic validation at the `ops` contract boundary, canonical
JSON determinism, config parsing robustness, compact signature encoding, audit
JSONL shape, key-file wrappers, and share-envelope encoding. Message inputs are
checked for KID, host, timestamp, algorithm, nonce, hex, AAD, and envelope
consistency. Key creation inputs are resolved under both `profile-only` and
`allow-overrides` policy.

The targets do not resolve loaded-key state, enforce runtime lifecycle, load
profiles from signed config, execute cryptographic operations, access storage,
or exercise HTTP. Compact signatures, audit checkpoints, init artifacts,
SLH-DSA files, and share envelopes stop before cryptographic authentication.
Hash algorithm output sizes are validated without invoking Botan in the fuzz
loop and separately checked against Botan by Rust unit and integration tests.

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
cargo fmt -- --check
cargo audit
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked
export VECTIS_BIN="$PWD/target/debug/vectis"
uv sync --locked --group fuzz
export UV_NO_SYNC=1 UV_LOCKED=1
uv run --no-sync tests/integration/cli/cli_all.py
uv run --no-sync tests/integration/http/http_all.py
uv run --no-sync tests/security/fuzz/http_fuzz.py \
  --random-seed --mutation-only --iterations 100
uv run --no-sync tests/security/openapi/http_schemathesis.py --profile prepared
bash tests/integration/tls/tls.sh
```

`tests.sh` always runs from the repository root, including when invoked from
another directory. It runs Rust checks and builds the debug binary once, then
checks readiness before the CLI, HTTP, fuzz and Schemathesis suites. The operator
must start the main service separately against a disposable database; TLS creates
its own isolated server. HTTP tests need an API key available through the
environment or `.env` flow used by their local credential helper.

The runner exports an absolute `VECTIS_BIN` so every CLI invocation, including
HTTP fixture setup, config signing, fuzz setup and Schemathesis provisioning,
executes that binary directly. An explicitly configured binary must be an
executable file; an invalid path fails rather than falling back to Cargo.
Relative `VECTIS_BIN` paths used outside this runner resolve from the repository
root. Without the variable, standalone suites retain their Cargo fallbacks;
the standalone fuzzer builds once per process. Only binary resolution is shared
in `tests/support/vectis.py`; fixtures and assertions remain suite-private.

Python dependencies are synchronized once with the `fuzz` group. `UV_NO_SYNC`
and `UV_LOCKED` also apply to nested Schemathesis invocations. Rust tests still
compile their own test artifacts; `cargo test` already includes
`crypto_integration`, so no separate invocation is needed. Suites remain sequential.

The local fuzz pass uses a fresh seed and 100 iterations per mutation target.
It excludes deterministic scenarios and non-mutation probes; CI retains the
complete regression pass with seed `1337` and 300 iterations, plus its exploration
pass. Run the complete suite explicitly when changing those scenarios or before
a release. Use the printed seed with `--seed` to repeat mutation decisions with
identical fixtures; this does not restore remote state or scheduling.

Each stage records elapsed wall-clock seconds and its exit code. A final table
and total duration are printed on success or failure; the runner stops at the
first failed stage and preserves its exit code. Timing output contains stage
names, never command arguments or credentials. Compare warm-cache runs under
equivalent conditions before attributing improvements to these changes.

Run the resolver and runner regression checks offline with:

```sh
python3 -m unittest discover -s tests/support -v
```

`tests_cargo-fuzz.sh` is intentionally separate because it requires nightly,
uses sanitizer builds, and is heavier than the normal HTTP test suite.

## Test File Reference

- `tests/integration/cli/cli_all.py`: streaming CLI summary runner.
- `tests/integration/cli/cli_init.py`: CLI init behavior.
- `tests/integration/cli/cli_negative.py`: invalid local CLI config-editing workflows.
- `tests/integration/cli/cli_positive.py`: valid local CLI config-editing workflows.
- `tests/integration/cli/lib/`: private Python helpers for CLI workflows.
- `tests/crypto_integration.rs`: focused Vectis/Botan crypto integration smoke
  tests.
- `tests/manual/final_app_server.py`: manual mock final-app receiver and decrypt helper; it is not part of CI or `tests.sh`.
- `tests/integration/http/http_all.py`: positive + negative summary runner.
- `tests/security/fuzz/http_fuzz.py`: targeted manual HTTP mutation and semantic contract tests.
- `tests/integration/http/http_negative.py`: invalid, denied, and error-path workflows.
- `tests/integration/http/http_positive.py`: valid end-to-end runtime workflows.
- `tests/security/openapi/http_schemathesis.py`: OpenAPI contract fuzzing via Schemathesis.
- `tests/integration/http/cases/`: HTTP endpoint contracts as `@cases` functions
  (one module per capability) plus `registry.py`, which composes their order.
- `tests/integration/http/lib/`: private client, fixtures, configuration and assertion helpers for HTTP cases.
- `tests/integration/http/lib/test_lib.py`: harness unit tests and structural guards that keep the case split from regressing.
- `tests/performance/run.sh`: single entry point for the isolated local k6
  harness.
- `tests/performance/k6.js`: local mixed-workload k6 scenario.
- Each HTTP, fuzzing, OpenAPI and manual suite owns its API-key loading helper.
- `tests_cargo-fuzz.sh`: native fuzz runner for all cargo-fuzz targets.
