# Engineering Rules

This document distills the engineering rules behind Vectis into a reusable
template. It is written for **new projects in any language**. Every rule is
generic, with a Rust note describing the tooling used here and an "In Vectis"
pointer showing the rule in a real codebase.

The aim is plain: keep the system understandable and hard to misuse.

Each rule carries an **Applies** tag so you can select the subset that fits your
project. Read every rule tagged `always`; add `networked services` rules when you
expose an API or load operational config, and `systems handling secrets or
cryptography` rules when you hold key material, credentials, or sign/encrypt
data. A few rules are conditional even within their tag — those carry a
**Don't apply when** line. An AI agent scaffolding a project should filter by
these tags first, then follow the bootstrap order at the end.

Rule format:

- **Rule** — one imperative sentence.
- **Applies** — which projects the rule is for (`always`, `networked services`,
  or `systems handling secrets or cryptography`).
- **Why** — the failure the rule prevents.
- **How** — concrete implementation guidance.
- **Don't apply when** — explicit exceptions (only where the rule is conditional).
- **Rust note** — tooling/crates used in this repository.
- **In Vectis** — where to see it working.

## 1. Architecture

### Rule 1 — Structure the code in three layers with one-way dependencies

**Applies**: always.

**Why**: without an enforced direction, business logic leaks into transport
handlers and primitives grow upward dependencies, until nothing can be tested
or replaced in isolation.

**How**:

- `core`: reusable primitives — validation, crypto helpers, config, storage,
  logging. Knows nothing about business flows.
- `ops`: business operations and protocol flows. Depends on `core` only.
- `io`: input/output adapters (HTTP, CLI). Depends on `ops` and `core`.
- The direction is law. If a lower layer needs a type owned by an upper layer,
  mirror the type downward and convert at the boundary — never import upward.
- IO handlers stay thin: authenticate, parse, delegate to `ops`, map the
  response. No business decisions inside handlers.

**Rust note**: enforce with module visibility (`pub(crate)`) and review; in a
workspace, make the layers separate crates so the compiler enforces direction.

**In Vectis**: `src/core`, `src/ops`, `src/io`; `PeerPublicKeys` lives in
`core/remote_routes.rs` and `ops` converts it, instead of `core` importing
`ops::contracts`.

### Rule 1A — Isolate and discipline shared mutable state

**Applies**: always.

**Why**: shared mutable state reached from several tasks or threads is the root
of data races, deadlocks, and heisenbugs that unit tests rarely reproduce.

**How**:

- prefer message passing or immutable snapshots over shared mutation;
- when shared state is unavoidable, put it behind one lock type with a
  documented lock order, keep critical sections small (copy out what you need,
  then release), and never hold a lock across an `await` or a blocking call;
- never run CPU-bound or blocking-IO work on an async runtime thread — offload
  it so the event loop keeps serving.

**Rust note**: `Arc<RwLock<...>>`/`Mutex` for shared state; `spawn_blocking` for
CPU-bound work; hold guards for the shortest scope possible.

**In Vectis**: HTTP state wraps the config and key databases in
`tokio::sync::RwLock`; blocking cryptography runs through `spawn_blocking_crypto`
(`core/blocking.rs`) so it never stalls the async runtime.

### Rule 2 — The CLI is a client of the API, not a second implementation

**Applies**: networked services.

**Why**: two implementations of the same operation drift apart; bugs get fixed
in one path and survive in the other.

**How**: every CLI command calls the same HTTP API the service exposes. Only
bootstrap operations that must work offline (init, local key generation) run
locally.

**Don't apply when**: the project is a library or a pure CLI tool with no
service behind it — then the CLI *is* the implementation and this rule is moot.

**In Vectis**: `io/cli/http.rs` is an HTTP client; only `init` and
`apikey create` are local.

## 2. Single Source of Truth

### Rule 3 — One configuration file, one signature, one loader

**Applies**: networked services.

**Why**: N config files mean N loaders, N canonicalizations, N signatures, and
N reload paths — triplicated code and inconsistent failure modes.

**How**: unify operational configuration (routing, peers, permissions) into a
single versioned document, protected by a single integrity mechanism, loaded by
a single code path that validates every section.

**In Vectis**: `config.json` (`version`, `routes`, `remote_routes`,
`permissions`, plus optional `fpe_profiles`, `tokenization_profiles`, and
`mac_profiles`) signed as one unit; `core/config_file.rs` is the only loader.
The unification collapsed 6 sign/verify functions into 2 and 3 loaders into 1.

### Rule 4 — No fallback sources of truth

**Applies**: always.

**Why**: when data can come from two places, the weaker path becomes the attack
surface and the strong path becomes optional. A fallback that "helps" in dev
silently degrades trust in production.

**How**: if trust-relevant data (keys, policy, identity) can be obtained from a
secondary source, delete the secondary source and fail closed. Absence of
registered data is a rejection, not a trigger to go fetch it.

**Don't apply when**: the second source is a pure performance cache of the
authoritative one (same trust, reconstructible, invalidatable). Caching data is
fine; deriving *trust* from a second source is not.

**In Vectis**: peer public keys come only from the operator-signed config;
the runtime fetch from remote `/pub` (trust-on-first-use) was removed. Sending
to or receiving from an unregistered peer returns `403`.

### Rule 5 — Fixed, documented settings precedence

**Applies**: always.

**Why**: ambiguous precedence between environment, files, and defaults produces
"works on my machine" configuration bugs.

**How**: one prefix for all project variables; one precedence order (process
environment → env file → built-in defaults); documented in a dedicated file
with expected values, and a `dist` example file kept current.

**In Vectis**: `VECTIS_` prefix, env → `.env` → defaults in `core/config.rs`,
documented in `doc/ENV.md` with `env.dist`.

## 3. Validate Everything External

Core lesson: every externally supplied value must have an owner, a validator, a
bound, tests, and one consistent policy across config, CLI, and HTTP.

### Rule 6 — Parse, don't validate

**Applies**: always.

**Why**: scattering re-validation through the codebase means some paths forget
it; passing raw strings around means invalid states are representable.

**How**: define raw input types (`*Input`) that only exist at the boundary.
Convert them once into validated domain types; the rest of the code accepts
only the validated types and never re-checks. Make invalid states
unrepresentable. In dynamically typed languages, enforce the same idea with a
single constructor/factory (or schema) that all inputs pass through, so validity
is established exactly once.

**Rust note**: `serde` deserializes into `*Input` structs; validation functions
return owned domain types; newtypes (e.g. a parsed id) carry the proof.

**In Vectis**: `RemoteRouteInput` → `RemoteRoute` via `validate_remote_routes`;
`KeyId::parse` as proof-carrying newtype; `validate_permission_clients` builds
`PermissionsState`.

### Rule 7 — Constrain every field

**Applies**: always.

**Why**: free-form strings become injection vectors, typo bugs, and undefined
behavior in downstream consumers.

**How**: enumerable fields validate against explicit allowed-value lists;
binary fields validate encoding and exact length; addresses, paths, and names
each get a dedicated validator. Reject, never coerce.

Every external value needs a documented shape and limit. "Non-empty string" is
not enough. Decide whether the value is a reference, a config name, a profile
name, a label set, a token, a hostname, a path, or payload text, then route it
through the validator for that concept. Bounds are part of the type: maximum
length, exact length, alphabet, delimiter policy, and whether Unicode is allowed
must be explicit.

**In Vectis**: `core/validation.rs` (`validate_allowed_value`,
`validate_hex_field`, `validate_host_port`, `validate_symmetric_key`,
`validate_ref`, `validate_config_name`); statuses like
`active`/`disabled`/`revoked` are closed lists.

### Rule 7A — One concept, one validation policy across all entry points *(refines Rule 7)*

**Applies**: always.

**Why**: when config accepts one shape, HTTP accepts another, and the CLI
pre-validates a third, the weakest surface becomes the real contract.

**How**: name concepts first, then share validators. A `profile` should have the
same length and delimiter rules whether it appears in `config.json`, an HTTP
body, a CLI command, an AAD string, or an internal lookup. CLI validation is a
convenience; server-side validation remains the trust boundary.

**In Vectis**: FPE and tokenization profile names use the same config-name
policy in signed config and HTTP requests; batch `ref` values are bounded by a
single `validate_ref` rule instead of being arbitrary strings.

### Rule 7B — Build structured strings through validated constructors *(refines Rule 7)*

**Applies**: always.

**Why**: strings such as `key=value;key=value` look simple until a caller passes
`tenant=acme;field=evil` as a value. Delimiter injection in structured strings
breaks SQL, shell commands, log lines, authentication context, and key
derivation alike.

**How**: never hand-concatenate structured strings (AAD, labels, context,
queries, HKDF info) when dynamic fields are involved. Use a single builder that
validates keys and values, preserves field order, and returns the exact
canonical string. Keep a plain builder only for constants, fixtures, and
already-validated test cases.

**In Vectis**: `build_validated_aad` validates AAD keys and values before
constructing strings used by FPE, tokenization, keys, messages, init, key
validation, and config signing. `validate_labels` remains the validator for
complete user-authored label strings.

### Rule 7C — Harden validation without changing valid encodings *(refines Rule 7)*

**Applies**: always.

**Why**: hardening often happens after data already exists. If valid inputs
(records, tokens, signed payloads, derived keys) change byte-for-byte, the fix
becomes a migration instead of a guardrail.

**How**: when replacing a weaker validator with a stronger one, prove that valid
inputs produce the same encoded bytes as before. The change should reject more
bad input without changing stored data, signatures, or decryptability for
records that were already valid.

**In Vectis**: AAD migrations compare the new validated builder against the
legacy `build_aad` output for valid fields, while adding delimiter and
over-limit rejection tests for invalid fields.

### Rule 8 — Lenient startup, strict reload

**Applies**: networked services.

**Why**: a service that refuses to boot over a bad config file cannot be
diagnosed remotely; a service that silently accepts a bad config at runtime
destroys known-good state.

**How**: at startup, invalid or missing operational config produces an empty,
safe state plus a loud warning — the service comes up and reports itself. At
runtime reload, any invalid input is rejected and the previous in-memory state
is kept untouched.

**Don't apply when**: the system is safety- or security-critical and must
**fail closed** — a bad config at boot should refuse to start, not come up in a
degraded state. Choose per project which failure is worse.

**In Vectis**: `load_config_state` (lenient) vs `reload_config_state` (strict)
in `core/config_file.rs`, both covered by unit tests.

### Rule 9 — Bound config and file parsing before expensive work

**Applies**: networked services.

**Why**: unbounded reads let a malformed or oversized file consume memory, CPU,
or cryptographic verification time before the application knows whether it is
safe to process.

**How**: before reading, parsing, canonicalizing, signing, or verifying an
operator-controlled file, validate that the path exists when required, points to
a regular file, and stays under a documented size limit. Startup can fall back
to a safe empty state; runtime reload must reject the new file and keep the
previous state.

**Rust note**: use `fs::metadata` before `read_to_string`, keep `NotFound`
distinguishable when missing files are allowed, and centralize the helper so all
load/sign/list paths share the same limits.

**In Vectis**: `config.json` and `config_sign.json` have explicit maximum
sizes enforced through `core/config_file.rs` and constants in `core/config.rs`
before config load, reload, list, sign, and verification paths.

### Rule 9A — Pin, minimize, and audit dependencies

**Applies**: always.

**Why**: every dependency is code you ship and trust; an unpinned or unaudited
dependency turns a transitive update into an uncontrolled change to your
security surface.

**How**:

- commit a lockfile and build from it; pin versions deliberately and update on
  purpose, not implicitly;
- minimize the dependency count — prefer the standard library and a few vetted
  libraries over many shallow ones;
- run a vulnerability/audit tool in CI and review new transitive dependencies
  before adopting them;
- vendor or otherwise verify anything security-critical.

**Rust note**: commit `Cargo.lock`; `cargo audit`/`cargo deny` in CI; pin the
crypto backend and prefer well-maintained crates.

**In Vectis**: the Botan cryptographic backend is vendored and version-pinned
(`botan = { version = "0.13.0", features = ["vendored"] }`); the build is
reproducible from a committed `Cargo.lock`.

## 4. Centralized, Typed Errors

### Rule 10 — One semantic error type per application

**Applies**: always.

**Why**: ad-hoc errors (strings, borrowed OS error kinds) carry no contract;
every consumer invents its own interpretation.

**How**: define a single error enum whose variants are **response categories**
(invalid input, not found, forbidden, invalid signature, unreachable, storage,
internal), not error origins. Provide one-line constructor helpers so creating
a typed error is cheaper than creating an untyped one. Per-layer enums are
justified only in multi-crate workspaces. In languages without enums, use a
closed set of error classes or codes with the same category discipline.

**Rust note**: `thiserror` for the enum; helpers returning `Box<dyn Error>`
allow migrating call sites without touching signatures.

**In Vectis**: `VectisError` in `src/error.rs`; 148 sites migrated from
fabricated `io::Error` kinds with zero signature changes.

### Rule 11 — Map errors to public responses with an exhaustive match

**Applies**: networked services.

**Why**: deciding responses by substring-matching error text means rewording a
message silently changes the API. It fossilizes typos into public contracts.

**How**: the transport boundary downcasts to the semantic error type and maps
variants with an exhaustive match — adding a variant forces a status decision
at compile time. Never `contains()` on error prose.

**In Vectis**: `status_for_error` in `io/http/error.rs`; the previous
string-matching block preserved a typo ("recipent") in the public API until the
migration removed it.

### Rule 12 — Never leak internals in public errors

**Applies**: networked services.

**Why**: 5xx detail (hosts, paths, library errors) maps your internals for
attackers and couples clients to incidental strings.

**How**: 4xx return the variant's message (caller-actionable, derived from
caller input); 5xx return fixed generic messages per category; full detail goes
to logs only. Documented error examples must match code strings **literally** —
treat them as contract.

**In Vectis**: `public_error_message_for_error`; `RemoteUnreachable` maps to a
fixed public message; `doc/API.md` error examples mirror `src` strings.

### Rule 12A — Evolve public interfaces without breaking clients

**Applies**: networked services.

**Why**: once a request/response shape, field, status code, or error contract
ships, clients depend on it; a silent change is a broken integration discovered
in production.

**How**:

- add fields, don't repurpose or remove them; treat removals and type changes as
  versioned, announced breaks;
- handle unknown fields deliberately — reject on trusted config and on strict
  request bodies, ignore only where forward-compatibility demands it;
- when a break is unavoidable, version the interface and support the old shape
  through a deprecation window;
- documented request/response examples are part of the contract (Rule 12).

**In Vectis**: request `*Input` structs use `deny_unknown_fields`; the wire
protocol carries an explicit version and payloads bind it (Rule 13). During
pre-release, breaking changes are allowed but stay deliberate and documented.

### Rule 12B — Make state-changing operations idempotent and retry-safe

**Applies**: networked services.

**Why**: networks retry. A client that times out and retries must not
double-apply an effect (double charge, duplicate record, replayed message).

**How**:

- make writes idempotent by construction (deterministic ids, upserts, or dedup
  keys) or guard them with an idempotency token;
- define retry semantics explicitly (at-least-once vs exactly-once) and make
  handlers safe under at-least-once;
- distinguish "already done" from "failed" so a safe retry returns success, not
  a spurious error.

**In Vectis**: message identity and lifecycle guards make replays observable
rather than silently reprocessed; object replay is an explicit, documented
assumption (Rule 17).

## 5. Security Defaults

### Rule 13 — Canonicalize everything you sign

**Applies**: systems handling secrets or cryptography.

**Why**: signing non-canonical encodings makes signatures depend on key order
and whitespace; two semantically equal documents verify differently.

**How**: apply the RFC 8785 JSON Canonicalization Scheme (or an equivalent
deterministic encoding: sorted keys, no insignificant whitespace) before
hashing or signing. Put the protocol version **inside** the signed payload and
require it to match the envelope version — this closes version-downgrade
splits.

**Rust note**: `serde_json::to_value` + `to_vec` yields sorted-key compact JSON
without extra dependencies.

**In Vectis**: `core/canonical.rs` (`canonical_json_v1`), `core/protocol.rs`;
envelope/payload version match enforced in `ops/sign.rs`.

### Rule 14 — Verify before decrypt, bind the context

**Applies**: systems handling secrets or cryptography.

**Why**: decrypting unauthenticated data processes attacker input with your
keys; unbound ciphertexts can be replayed across contexts (wrong recipient,
wrong protocol, wrong algorithm).

**How**: signature verification always precedes decryption. Authenticated
associated data (AAD) binds version, message type, sender, recipient,
algorithms, and timestamp, so a ciphertext is only valid in its exact context.
Derive a fresh key per message (ephemeral key establishment) so nonce reuse is
structurally impossible.

**In Vectis**: `receive_message` verifies signatures before
`open_message_cipher`; the AAD binds 8 context fields; ephemeral XECDH +
fresh ML-KEM encapsulation per message.

### Rule 14A — Requests choose policy; they do not define trust *(refines Rule 14)*

**Applies**: networked services.

**Why**: letting requests supply destinations, peers, routes, algorithms, or
policy turns caller input into part of the trust model. The system becomes a
cryptographic relay for whoever can shape a request.

**How**: requests may select from operator-approved names, such as a profile or
registered peer. They must not define remote hosts, peer public keys,
permissions, routing rules, or cryptographic algorithms inline. Trust-relevant
data comes from signed config, validated storage state, or a loaded domain
object.

**In Vectis**: outbound message destinations come from signed `remote_routes`;
peer keys are operator-approved; crypto algorithms come from profiles; callers
select registered FPE/tokenization profiles rather than redefining cryptography
in the request.

### Rule 15 — Treat secrets as radioactive

**Applies**: systems handling secrets or cryptography (the logging and
comparison points apply to any app with credentials).

**Why**: secrets leak through memory dumps, timing side channels, logs, and
telemetry labels — every channel you did not explicitly close.

**How**:

- zeroize secret material in memory when dropped;
- avoid credential timing leaks; use constant-time comparison for secret
  material, and keep authorization indexes separate from authentication
  matching;
- never log secrets; keep telemetry labels low-cardinality and content-free;
- encrypt stored key material and bind it to its identity so a swapped record
  fails closed.

**Rust note**: `zeroize`/`Zeroizing`; a constant-time `eq` helper for secret
comparison; structured logging with an explicit field allowlist mindset.

**In Vectis**: 180+ `Zeroizing` uses; `PermissionsState` keeps an index for
permission lookup while `authenticate_hash` still compares credential hashes
with `constant_time_eq`; kid-binding via `validate_key_id_matches_keys`;
dedicated audit stream with request ids and no payload contents.

### Rule 16 — Model resource lifecycle explicitly

**Applies**: always (any resource with more than two states).

**Why**: resources rarely stay simply "valid" or "invalid". Without an explicit
lifecycle, disabled, retired, compromised, and destroyed states become ad-hoc
flags that every operation interprets differently.

**How**: define closed lifecycle states, allowed transitions, and centralized
guards for each operation class. New use, read-only use, verification, public
discovery, and administrative changes may each require different permissions
from the lifecycle model, but the decision must live in one place.

**In Vectis**: operational keys use `active`, `disabled`, `retired`,
`compromised`, and `destroyed`; helpers such as
`require_lifecycle_for_new_use`, `require_lifecycle_for_decrypt_or_verify`, and
`require_lifecycle_for_public_keys` enforce the model, including blocking
`/pub` for retired keys.

### Rule 17 — Write the threat model, including what you refuse to defend

**Applies**: always.

**Why**: undocumented gaps are indistinguishable from oversights. An explicit
assumption is a defensible design decision; an implicit one is a finding in
someone else's audit.

**How**: maintain a threat model document with: assets, trust model, threats
addressed (threat → mitigation → mechanism), **explicit assumptions** (what you
deliberately do not defend and why), out-of-scope items, and residual risks
with operational mitigations. Update it when the trust model changes.

**In Vectis**: `doc/ThreatModel.md` — e.g. object replay and config rollback
are documented assumptions with operational mitigations, not silent gaps.

## 6. Testing and Tooling Discipline

### Rule 18 — Unit-test every validation function; e2e-test the contract both ways

**Applies**: always.

**Why**: validation functions are the security boundary — untested rules decay.
A positive-only e2e suite proves the happy path while the rejection contract
(status codes) silently changes. Tests are not a final polishing step; they are
part of designing the rule.

**How**:

- validation functions take injected dependencies (closures/interfaces), so
  unit tests run without services;
- every new validator or guardrail gets cases for valid input, exact limit,
  over-limit, delimiter/control-character rejection, and legacy byte-equivalence
  when the valid encoding must remain stable;
- maintain a **positive** e2e suite (workflows succeed) and a **negative** one
  (each invalid input yields the documented status code) — the negative suite
  *is* the API contract;
- tests isolate the section under test and restore state afterwards;
- fuzzing and contract fuzzing extend the same idea: when they find a class of
  bug, add a reusable guardrail and a normal regression test.

**In Vectis**: `#[cfg(test)]` modules across `core`/`ops` cover validation,
AAD canonicalization, lifecycle, storage, FPE, tokenization, messages, and
signing; `tests/http_positive.py` and `tests/http_negative.py` assert runtime
contracts; `http_fuzz.py`, cargo-fuzz targets, and Schemathesis cover mutation
and OpenAPI contract behavior.

### Rule 18A — Inject time, randomness, and other ambient inputs

**Applies**: always.

**Why**: code that reads the clock or RNG directly is untestable and
non-deterministic; that same call is where subtle security bugs hide
(predictable nonces, expiry off-by-one).

**How**:

- pass clocks, random sources, and environment as parameters or injected
  dependencies, not as global calls buried in logic;
- unit tests supply fixed time and seeded/typed randomness; production supplies
  the real source;
- centralize secure randomness behind one helper so no path reaches for an
  insecure RNG.

**Rust note**: thread a `CryptoRng`/timestamp provider through functions;
validation functions already take injected closures (Rule 18).

**In Vectis**: cryptographic randomness goes through a single `core/crypto.rs`
helper; validation functions accept injected dependencies so unit tests run
without real services.

### Rule 19 — Zero warnings, always

**Applies**: always.

**Why**: a build with tolerated warnings hides the new warning that matters.
Lint debt compounds silently.

**How**: run the linter over all targets (including tests) and the formatter on
every change; the acceptable count is zero. During mechanical refactors,
compile between every module to keep errors local.

**Rust note**: `cargo clippy --all-targets`, `cargo fmt`, `cargo fix` for
mechanical cleanups.

**In Vectis**: every change in the repository lands with clippy and fmt clean.

### Rule 20 — Keep an executable demo, and verify against the fresh build

**Applies**: always.

**Why**: documentation lies over time; a runnable end-to-end scenario cannot.
And test results against a stale binary validate nothing (a classic false
green).

**How**: maintain a scripted multi-instance demo exercising the full flow; it
doubles as living documentation. Before trusting any verification run, confirm
the running binary is the one you just built.

**In Vectis**: `demo/message/` runs two clinics exchanging a record end-to-end.
A session lesson stands as the cautionary example: suites once passed against a
server started *before* the rebuild — the results were discarded and re-run.

## 7. Observability Contract

### Rule 21 — Separate operational logs, audit logs, and metrics

**Applies**: networked services.

**Why**: debugging output, security evidence, and operational counters have
different audiences and retention needs. Mixing them makes logs noisy, audits
incomplete, and metrics unsafe.

**How**: keep three channels. Operational logs explain what the service is doing
and why it failed. Audit logs record stable security events with actor,
resource, action, outcome, and reason, but no secrets or payloads. Metrics expose
runtime health and behavior using counters/gauges/histograms with
low-cardinality labels only.

**In Vectis**: JSON operational logs, a dedicated audit stream through
`core/audit.rs`, and Prometheus metrics through `core/metrics.rs` and
`/metrics`; labels avoid KIDs, actors, remote addresses, payloads, and free-form
errors.

## 8. Documentation Contract

### Rule 22 — Fixed documentation set, swept on every behavior change

**Applies**: always.

**Why**: docs rot section by section; a stale paragraph about removed behavior
(e.g. an old fallback) misleads users into building on it.

**How**: maintain a minimal fixed set — README (what/why/quick start), API
reference with field tables (required, allowed values), environment reference,
threat model, architecture reference. After every behavior change, grep the
**entire** doc tree for the affected claims and update all occurrences; verify
relative links and that documented examples match code literally.

**In Vectis**: `README.md`, `doc/API.md`, `doc/ENV.md`, `doc/ThreatModel.md`,
`doc/Reference.md`; removing runtime peer-key fetch required sweeping four
documents that described the old fallback.

### Rule 23 — Code explains itself; documents explain the system

**Applies**: always.

**Why**: explanatory comments duplicate the code and drift from it; the
information either belongs in a name/type or in a document with an owner.

**How**: avoid redundant comments that restate the code. Express normal intent
through names, types, and small functions. Use short comments only for
non-obvious security, protocol, fallback, or invariant behavior. Design
rationale and system flows live in the documentation set (Rule 22), which is
reviewed and kept consistent.

**In Vectis**: comments are reserved for small pieces of non-obvious protocol or
fallback behavior; broader rationale lives in `doc/Reference.md` and this
document.

## How to Apply This to a New Project

First, **filter by the Applies tags**: take every `always` rule, add
`networked services` rules if you expose an API or load operational config, and
add `systems handling secrets or cryptography` rules if you hold key material or
sign/encrypt data. Then follow the bootstrap order — each step makes the next
one cheaper:

1. **Layout**: create the three layers (`core`, `ops`, `io`) empty, with the
   dependency rule and a shared-state/concurrency policy written down
   (Rules 1, 1A).
2. **Errors first**: define the semantic error enum and constructor helpers
   before writing the first fallible function (Rules 10-12).
3. **Validation module**: `core/validation` with generic validators for names,
   refs, labels, encoded material, host/path fields, and structured strings;
   every new input type gets its `*Input` → domain conversion, and every
   external value gets an owner, a bound, injected time/randomness where needed,
   and tests (Rules 6-7C, 18A).
4. **Config loader**: one settings precedence (env → file → defaults) and, if
   the project has operational config, one unified file with one bounded loader
   and lenient-startup/strict-reload semantics (Rules 3, 5, 8-9).
5. **Supply chain + CI from day one**: commit a lockfile, pin and audit
   dependencies, and wire format + lint (zero warnings) + unit tests + negative
   e2e as the pipeline; every endpoint adds validators, limits, unit tests,
   idempotency, compatible-evolution discipline, and negative contract coverage
   at the same time (Rules 9A, 12A-12B, 18-19).
6. **Lifecycle model**: if the project manages sensitive resources, define
   states, transitions, and centralized operation guards before exposing the
   first mutation endpoint (Rule 16).
7. **Observability from day one**: create operational logs, audit events, and
   metrics as separate channels with a no-secrets rule (Rule 21).
8. **Threat model from day one**: even three lines of explicit assumptions
   beat a perfect document written after the audit (Rule 17).
9. **Docs as contract**: README + API + ENV skeletons created with the first
   endpoint; sweep them on every behavior change, especially validation,
   permission, lifecycle, config, and error-contract changes (Rules 22-23).
10. When a second source of truth appears — a cache, a fallback, a convenience
   fetch — delete it unless it is a pure performance cache of the authoritative
   source (Rule 4).

## Revision

Distilled from the Vectis codebase as of 2026-07-17. Update when a rule is
learned, invalidated, or superseded by a better one.
