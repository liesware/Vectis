# Engineering Rules

This document distills the engineering rules behind Vectis into a reusable
template. It is written for **new projects in any language**. Every rule is
generic, with a Rust note describing the tooling used here and an "In Vectis"
pointer showing the rule in a real codebase.

The aim is plain: keep the system understandable and hard to misuse.

Rule format:

- **Rule** — one imperative sentence.
- **Why** — the failure the rule prevents.
- **How** — concrete implementation guidance.
- **Rust note** — tooling/crates used in this repository.
- **In Vectis** — where to see it working.

## 1. Architecture

### Rule 1 — Structure the code in three layers with one-way dependencies

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

### Rule 2 — The CLI is a client of the API, not a second implementation

**Why**: two implementations of the same operation drift apart; bugs get fixed
in one path and survive in the other.

**How**: every CLI command calls the same HTTP API the service exposes. Only
bootstrap operations that must work offline (init, local key generation) run
locally.

**In Vectis**: `io/cli/http.rs` is an HTTP client; only `init` and
`apikey create` are local.

## 2. Single Source of Truth

### Rule 3 — One configuration file, one signature, one loader

**Why**: N config files mean N loaders, N canonicalizations, N signatures, and
N reload paths — triplicated code and inconsistent failure modes.

**How**: unify operational configuration (routing, peers, permissions) into a
single versioned document, protected by a single integrity mechanism, loaded by
a single code path that validates every section.

**In Vectis**: `config.json` (`version`, `routes`, `remote_routes`,
`permissions`) signed as one unit; `core/config_file.rs` is the only loader.
The unification collapsed 6 sign/verify functions into 2 and 3 loaders into 1.

### Rule 4 — No fallback sources of truth

**Why**: when data can come from two places, the weaker path becomes the attack
surface and the strong path becomes optional. A fallback that "helps" in dev
silently degrades trust in production.

**How**: if trust-relevant data (keys, policy, identity) can be obtained from a
secondary source, delete the secondary source and fail closed. Absence of
registered data is a rejection, not a trigger to go fetch it.

**In Vectis**: peer public keys come only from the operator-signed config;
the runtime fetch from remote `/pub` (trust-on-first-use) was removed. Sending
to or receiving from an unregistered peer returns `403`.

### Rule 5 — Fixed, documented settings precedence

**Why**: ambiguous precedence between environment, files, and defaults produces
"works on my machine" configuration bugs.

**How**: one prefix for all project variables; one precedence order (process
environment → env file → built-in defaults); documented in a dedicated file
with expected values, and a `dist` example file kept current.

**In Vectis**: `VECTIS_` prefix, env → `.env` → defaults in `core/config.rs`,
documented in `doc/ENV.md` with `env.dist`.

## 3. Validate Everything External

### Rule 6 — Parse, don't validate

**Why**: scattering re-validation through the codebase means some paths forget
it; passing raw strings around means invalid states are representable.

**How**: define raw input types (`*Input`) that only exist at the boundary.
Convert them once into validated domain types; the rest of the code accepts
only the validated types and never re-checks. Make invalid states
unrepresentable.

**Rust note**: `serde` deserializes into `*Input` structs; validation functions
return owned domain types; newtypes (e.g. a parsed id) carry the proof.

**In Vectis**: `RemoteRouteInput` → `RemoteRoute` via `validate_remote_routes`;
`KeyId::parse` as proof-carrying newtype; `validate_permission_clients` builds
`PermissionsState`.

### Rule 7 — Constrain every field

**Why**: free-form strings become injection vectors, typo bugs, and undefined
behavior in downstream consumers.

**How**: enumerable fields validate against explicit allowed-value lists;
binary fields validate encoding and exact length; addresses, paths, and names
each get a dedicated validator. Reject, never coerce.

**In Vectis**: `core/validation.rs` (`validate_allowed_value`,
`validate_hex_field`, `validate_host_port`, `validate_symmetric_key`); statuses
like `active`/`disabled`/`revoked` are closed lists.

### Rule 8 — Lenient startup, strict reload

**Why**: a service that refuses to boot over a bad config file cannot be
diagnosed remotely; a service that silently accepts a bad config at runtime
destroys known-good state.

**How**: at startup, invalid or missing operational config produces an empty,
safe state plus a loud warning — the service comes up and reports itself. At
runtime reload, any invalid input is rejected and the previous in-memory state
is kept untouched.

**In Vectis**: `load_config_state` (lenient) vs `reload_config_state` (strict)
in `core/config_file.rs`, both covered by unit tests.

### Rule 9 — Bound config and file parsing before expensive work

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

## 4. Centralized, Typed Errors

### Rule 10 — One semantic error type per application

**Why**: ad-hoc errors (strings, borrowed OS error kinds) carry no contract;
every consumer invents its own interpretation.

**How**: define a single error enum whose variants are **response categories**
(invalid input, not found, forbidden, invalid signature, unreachable, storage,
internal), not error origins. Provide one-line constructor helpers so creating
a typed error is cheaper than creating an untyped one. Per-layer enums are
justified only in multi-crate workspaces.

**Rust note**: `thiserror` for the enum; helpers returning `Box<dyn Error>`
allow migrating call sites without touching signatures.

**In Vectis**: `VectisError` in `src/error.rs`; 148 sites migrated from
fabricated `io::Error` kinds with zero signature changes.

### Rule 11 — Map errors to public responses with an exhaustive match

**Why**: deciding responses by substring-matching error text means rewording a
message silently changes the API. It fossilizes typos into public contracts.

**How**: the transport boundary downcasts to the semantic error type and maps
variants with an exhaustive match — adding a variant forces a status decision
at compile time. Never `contains()` on error prose.

**In Vectis**: `status_for_error` in `io/http/error.rs`; the previous
string-matching block preserved a typo ("recipent") in the public API until the
migration removed it.

### Rule 12 — Never leak internals in public errors

**Why**: 5xx detail (hosts, paths, library errors) maps your internals for
attackers and couples clients to incidental strings.

**How**: 4xx return the variant's message (caller-actionable, derived from
caller input); 5xx return fixed generic messages per category; full detail goes
to logs only. Documented error examples must match code strings **literally** —
treat them as contract.

**In Vectis**: `public_error_message_for_error`; `RemoteUnreachable` maps to a
fixed public message; `doc/API.md` error examples mirror `src` strings.

## 5. Security Defaults

### Rule 13 — Canonicalize everything you sign

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

### Rule 15 — Treat secrets as radioactive

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

**Why**: validation functions are the security boundary — untested rules decay.
A positive-only e2e suite proves the happy path while the rejection contract
(status codes) silently changes.

**How**:

- validation functions take injected dependencies (closures/interfaces), so
  unit tests run without services;
- maintain a **positive** e2e suite (workflows succeed) and a **negative** one
  (each invalid input yields the documented status code) — the negative suite
  *is* the API contract;
- tests isolate the section under test and restore state afterwards.

**In Vectis**: `#[cfg(test)]` modules across `core`/`ops` (56 tests);
`tests/http_positive.py` and `tests/http_negative.py` asserting status codes.

### Rule 19 — Zero warnings, always

**Why**: a build with tolerated warnings hides the new warning that matters.
Lint debt compounds silently.

**How**: run the linter over all targets (including tests) and the formatter on
every change; the acceptable count is zero. During mechanical refactors,
compile between every module to keep errors local.

**Rust note**: `cargo clippy --all-targets`, `cargo fmt`, `cargo fix` for
mechanical cleanups.

**In Vectis**: every change in the repository lands with clippy and fmt clean.

### Rule 20 — Keep an executable demo, and verify against the fresh build

**Why**: documentation lies over time; a runnable end-to-end scenario cannot.
And test results against a stale binary validate nothing (a classic false
green).

**How**: maintain a scripted multi-instance demo exercising the full flow; it
doubles as living documentation. Before trusting any verification run, confirm
the running binary is the one you just built.

**In Vectis**: `demo/` (two clinics exchanging a record end-to-end); a session
lesson: suites once passed against a server started before the rebuild — the
results were discarded and re-run.

## 7. Observability Contract

### Rule 21 — Separate operational logs, audit logs, and metrics

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

Bootstrap order — each step makes the next one cheaper:

1. **Layout**: create the three layers (`core`, `ops`, `io`) empty, with the
   dependency rule written down (Rule 1).
2. **Errors first**: define the semantic error enum and constructor helpers
   before writing the first fallible function (Rules 10-12).
3. **Validation module**: `core/validation` with the generic field validators;
   every new input type gets its `*Input` → domain conversion (Rules 6-7).
4. **Config loader**: one settings precedence (env → file → defaults) and, if
   the project has operational config, one unified file with one bounded loader
   and lenient-startup/strict-reload semantics (Rules 3, 5, 8-9).
5. **CI from day one**: format + lint (zero warnings) + unit tests + negative
   e2e as the pipeline; the negative suite grows with every endpoint
   (Rules 18-19).
6. **Lifecycle model**: if the project manages sensitive resources, define
   states, transitions, and centralized operation guards before exposing the
   first mutation endpoint (Rule 16).
7. **Observability from day one**: create operational logs, audit events, and
   metrics as separate channels with a no-secrets rule (Rule 21).
8. **Threat model from day one**: even three lines of explicit assumptions
   beat a perfect document written after the audit (Rule 17).
9. **Docs as contract**: README + API + ENV skeletons created with the first
   endpoint; sweep them on every behavior change (Rules 22-23).
10. When a second source of truth appears — a cache, a fallback, a convenience
   fetch — delete it (Rule 4).

## Revision

Distilled from the Vectis codebase as of 2026-07-02. Update when a rule is
learned, invalidated, or superseded by a better one.
