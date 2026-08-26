# Nadir

Nadir is a **stateful, semantic HTTP fuzzer**. It builds valid multi-step
workflows against a service, breaks one step the way an attacker would, and
checks that a project-defined **invariant** still holds — across the HTTP
response, durable state, and downstream steps.

That is the line that separates Nadir from other tools, and the reason to reach
for it:

- **Schemathesis** fuzzes an OpenAPI surface and checks *schema conformance + no
  500s*. It cannot express "a mutated token must never decode to the original
  plaintext" or "a tampered coupon must not survive to checkout".
- **OWASP ZAP** scans for known web-vuln signatures (injection, headers,
  disclosure). It has no concept of a business flow.
- **Nadir** runs a 4-step happy path, follows the API for the first steps, then
  **breaks a chosen step**, and asserts a semantic property. Neither of the
  others does this.

Use Schemathesis and ZAP for the generic surface. Use Nadir for the properties
that need valid state, workflow context, and project knowledge.

Nadir accepts only **loopback** targets. It never starts, configures, or
administers the target service, although a declared workflow may execute
state-changing application operations inside an isolated test environment. It
is not a production scanner.

## How Nadir works

**Targets are data.** You describe endpoints and flows in a YAML file
(`targets.yaml`); the engine executes them. There are three target shapes:

| Shape | Use it for |
|-------|-----------|
| `request` | a single endpoint (auth fuzzing, a path variable) |
| `producer` / `consumer` | a 2-step flow (produce an artifact, tamper it, consume it) |
| `flow` | an N-step flow — build state, break one step, observe downstream |

**Every run mixes four case classes.** For each target Nadir runs one valid
`control` case, then fills the remaining iterations with:

- `semantic` — your hand-authored mutations (the curated, meaningful ones);
- `structured` — generic schema corruption (delete a field, swap a type, inject
  a bad value);
- `raw` — byte-level corruption of the serialized body (truncate, bit-flip,
  null-byte, invalid UTF-8, …).
- `deser` — bounded deserialization stress: nesting, wide structures, duplicate
  keys, unknown-field floods and numeric edges.

`structured` and `raw` are generated automatically for any step that has a body.
The run summary reports how many of each class ran and where the responses
landed (2xx / 4xx / 5xx / transport failure), so you can see whether the fuzzer
is reaching real logic or just bouncing off the parser.

`deser` payloads are always capped at Nadir's `64 KiB` transport limit. A
completed generative request over the local `2,000 ms` budget is a finding. A
timeout is reported as possible resource exhaustion only when an immediate
readiness probe is also slow or fails.

**Oracles decide what a bug is.** Two kinds:

- **Built-in, generic** (declared in YAML): allowed status, JSON-error shape,
  no-server-error, and *no declared secret ever appears in a response or
  artifact* (always on).
- **Semantic invariants** (named Python functions): the cryptographic /
  business properties that are the whole point. A single-request target that
  only uses generic oracles is doing Schemathesis's job — prefer a flow with a
  real invariant.

**Flows build state, then break a step.** In a `flow`, the steps before the
`fuzz` step run valid and thread captured values forward. The `fuzz` step is
mutated. If the mutation is wrongly **accepted**, the flow *continues* so a
downstream step's oracle can catch the propagated corruption.

**The engine is generic.** It holds no knowledge of the target domain. A project
integration supplies three things: a fixture (how to reach a test instance), a
set of named invariants, and the `targets.yaml`.

## Quick start

Run from the `nadir/` directory. Fill `projects/vectis/env.dist` (or export the
values) with an already-running local instance:

```sh
uv run nadir list  --project projects/vectis/project.py
uv run nadir check --project projects/vectis/project.py --target vectis.public-keys
uv run nadir run   --project projects/vectis/project.py --target vectis.keys
```

### Vectis harness

From the repository root, the all-in-one local harness provisions a temporary
SQLite-backed Vectis instance, creates the required key and least-privilege
client, then exports the `NADIR_*` values for a run:

```sh
bash tests/nadir/run.sh
bash tests/nadir/run.sh --target vectis.sign-verification --iterations 4
bash tests/nadir/run.sh --target vectis.fpe-round-trip --iterations 8
bash tests/nadir/run.sh --target vectis.one-time-token --iterations 8
```

It stops Vectis, verifies its audit log, and removes its workspace on exit. Set
`NADIR_KEEP_WORKSPACE=true` only when retaining the isolated workspace is useful
for debugging a failure. Finding artifacts are retained under
`tests/nadir/results/` in the repository (or `NADIR_RESULTS_DIR` when set); an
all-clear run leaves no empty result directory behind.

A run prints a per-target summary:

```
vectis.keys: controls=1 expected_rejections=8 findings=0
  classes: semantic=8 structured=0 raw=0
  responses: 2xx=1 4xx=8 5xx=0 transport_failures=0
```

Exit codes are a contract: `0` no findings, `1` findings, `2` bad
configuration, `3` infrastructure/setup/cleanup failure, `4` bad replay
artifact.

## Adding an endpoint

Adding or changing a target is editing `projects/vectis/targets.yaml`. You only
touch Python when a target needs a new semantic invariant. Nothing needs
registering — target names are derived from the file.

### 1 — A single request (YAML only)

Fuzz the API key on a permission-protected endpoint. Valid credentials return
key properties; a bad key must be rejected and must never leak a secret:

```yaml
- name: vectis.keys
  request: {method: GET, path: "/keys/properties/{kid}", auth: true}
  mutate:
    - variable: api_key
      values: ["", "0000...", "not-a-real-key", "wrong-but-plausible"]
  expect:
    control: {status: [200]}
    mutated: {status: [401, 403]}
```

This is the shallow case. It needs no Python — but because it has no semantic
invariant, ask whether ZAP/Schemathesis should own it instead.

### 2 — A flow (the real value)

Build valid state, break one step, and catch corruption downstream:

```yaml
- name: shop.coupon-fraud
  flow:
    - step: login
      request: {method: POST, path: /login, body: {user: "{user}"}}
      capture: {token: $.token}
    - step: apply-promo
      request: {method: POST, path: /promo, body: {token: "{token}", code: "SAVE10"}}
      fuzz: true                       # the step the attacker breaks
      mutate: [{json_field: $.code}]
      expect: {status: [200]}          # the happy path
      fuzz_expect: {status: [403]}     # a tampered coupon must be rejected
    - step: checkout
      request: {method: POST, path: /checkout, body: {token: "{token}"}}
      expect: {status: [200], invariant: charge_is_sane}   # catches propagation
```

If the vulnerable server *accepts* the tampered coupon, Nadir flags it at
`apply-promo` **and** the flow continues to `checkout`, where `charge_is_sane`
catches the impossible discount. Exactly one step per flow may be marked `fuzz`.

### 3 — A semantic invariant (Python)

When a target references `invariant: charge_is_sane`, that name resolves to a
pure function in `projects/vectis/invariants.py`:

```python
def charge_is_sane(result, context):
    charged = json.loads(result.body).get("charged")
    if charged is not None and charged < 50:
        return (Finding("coupon-fraud", f"checkout charged only {charged}"),)
    return ()
```

An invariant takes the HTTP result and an evaluation context and returns zero or
more `Finding`s. It is pure: it never writes files, mutates state, or sends
requests. Register it in the project's invariants map (in `project.py`). This is
the one piece that stays Python — a cryptographic or business property is code,
not config.

## Target reference

**Oracle** (`control`, `mutated`, `expect`, `fuzz_expect`):

```yaml
{status: [200] | "4xx", json_error: true, invariant: some_name}
```

`status` is a list of codes or a class string (`"2xx"`/`"4xx"`/`"5xx"`).
`No declared secret in the response` is always enforced.

**Mutators** (`mutate:` list — each entry):

```yaml
- {variable: kid, values: ["bad", "../x"]}          # replace a template variable
- {json_field: $.signature}                         # flip a character in a field
- {json_field: $.sig, delimiter: ".", segments: [0,1,2,3], name: seg}
- some-registered-group                             # a named group from the project
```

Generic `structured` and `raw` mutations are added automatically; you do not
list them.

## Environment variables

Every `NADIR_*` value becomes a lowercased template variable, so specs reference
values from the environment instead of hardcoding them:

| Variable | Template | Notes |
|----------|----------|-------|
| `NADIR_BASE_URL` | `{base_url}` | required, loopback only |
| `NADIR_KID` | `{kid}` | required |
| `NADIR_API_KEY` | `{api_key}` | redacted from artifacts; used when `auth: true` |
| `NADIR_SCOPED_API_KEY` | `{scoped_api_key}` | optional valid least-privilege client for scope targets; redacted |
| `NADIR_DIGEST` | `{digest}` | example of a free-form value |
| `NADIR_ANYTHING` | `{anything}` | any other `NADIR_*` flows through |

`env.dist` holds committed defaults (keep them blank or synthetic). An exported
`NADIR_*` overrides the file, so local credentials never touch Git.

## Findings and replay

Findings are written under `nadir-results/` — the redacted step sequence, the
mutation record, the run seed, and exact request/response bytes (Base64 when a
value does not round-trip as UTF-8). Declared secrets are scrubbed everywhere,
including the mutation record; if redaction ever fails, the artifact is refused.

Replay re-sends the exact recorded replayable request without generating a new
mutation. A public artifact needs no credentials. For an authenticated artifact,
Nadir keeps only `requires_api_key: true`; it takes a fresh `NADIR_API_KEY` from
the environment and injects it as `X-API-Key` at replay time. The original key
is never persisted.

```sh
NADIR_API_KEY='...' uv run nadir replay --artifact nadir-results/<finding>.json
```

## Project files

A project integration is small. For Vectis:

```
projects/vectis/
├── targets.yaml     # the endpoints and flows (config)
├── invariants.py    # named semantic oracle functions (Python)
├── fixture.py       # how to reach a test instance; env pass-through
├── env.dist          # declared NADIR_* defaults and control values
└── project.py       # wiring: fixture + invariants registry + healthcheck + redaction
```

You add YAML for a new endpoint; you add Python only for a new invariant or new
stateful fixture setup.

## Development

```sh
uv run python -m unittest discover -s tests -v
```

The architecture test enforces that no module under `src/nadir/` imports project
code — the engine stays generic.

## Architecture

Two layers with a strict, one-way dependency: the **generic core**
(`src/nadir/`) knows nothing about any target domain; a **project integration**
(`projects/<name>/`) supplies the domain knowledge and depends on the core's
public API — never the reverse.

```
CLI ──▶ engine ──▶ transport (http)
 │        ├──▶ mutations
 │        ├──▶ artifacts
 │        └──▶ workflows  (shared vocabulary)
 │
 └──▶ project ──▶ spec (YAML) ──▶ workflows
        ▲
        └── projects/vectis  (fixture + invariants + targets.yaml)
```

```
nadir/
├── pyproject.toml            # isolated package, `nadir` console script, deps
├── README.md
├── src/nadir/                # the generic engine — no project knowledge
│   ├── __init__.py           # package version and the small public API
│   ├── __main__.py           # `python -m nadir` → cli.main()
│   ├── cli.py                # arg parsing, project loading, env→variables, exit codes
│   ├── engine.py             # execution: rendering, case scheduling, flows, counters
│   ├── http.py               # bounded HTTP transport, failure typing, loopback guard
│   ├── workflows.py          # declarative types: targets, steps, oracles, findings
│   ├── mutations.py          # generic mutators + JSON navigation + bad-value vocabulary
│   ├── spec.py               # YAML → target dataclasses (the config layer)
│   ├── artifacts.py          # versioned, redacted finding evidence + replay
│   └── project.py            # the Project protocol, project loader, env.dist parsing
├── projects/vectis/          # the Vectis integration — the only domain-aware code
│   ├── targets.yaml          # endpoints and flows (config)
│   ├── invariants.py         # named semantic oracle functions (Python)
│   ├── fixture.py            # reach a test instance; validate; pass env vars through
│   ├── project.py            # wiring: fixture + invariants registry + healthcheck + redaction
│   └── env.dist              # committed environment template (blank/synthetic)
└── tests/                    # unit tests per module + integration
    ├── test_architecture.py  # enforces src/nadir never imports project code
    ├── test_mutations.py     # deterministic + generative mutators
    ├── test_spec.py          # YAML loader: shapes, required vars, validation
    ├── test_artifacts.py     # byte round-trip, mandatory redaction, replay
    ├── test_engine.py        # producer→consumer execution and replay
    ├── test_flow.py          # N-step flow: preamble, broken step, downstream catch
    ├── test_cli.py           # command wiring and exit codes
    ├── test_invariants.py    # Vectis oracle self-checks
    └── test_vectis_project.py# the loaded Vectis project end-to-end
```

### Core files (`src/nadir/`)

| File | Purpose |
|------|---------|
| `cli.py` | The command-line boundary. Parses `list`/`check`/`run`/`replay`, loads the project module, turns every `NADIR_*` value into a template variable, and maps results to exit codes. Contains no fuzzing logic. |
| `engine.py` | The heart. Renders request templates once, guarantees every semantic and applicable structured/raw/deserialization class before weighted draws, executes `request`, `producer→consumer`, and `flow` targets, threads captures through a flow, and reports classes omitted by a small iteration budget. |
| `http.py` | The only place that talks HTTP. Sends bounded requests, captures exact bytes, classifies transport failures (dns/tls/refused/reset/timeout/…), and refuses non-loopback hosts by default. |
| `workflows.py` | The shared vocabulary the engine and projects both speak: target types, `HttpStep`, `Capture`, the composable oracles (`ExpectStatus`, `ExpectAuthorizationMatrix`, `ExpectNoServerError`, `NoDeclaredSecrets`, `ProjectPredicate`, `AllOf`), `Finding`, and `MutationRecord`. No behavior beyond oracle evaluation. |
| `mutations.py` | Generic mutators: deterministic ones (template value, JSON field) and generative ones (`StructuredMutation`, `RawBodyMutation`), plus JSON path navigation and the bad-value vocabulary. Knows no domain concepts. |
| `spec.py` | Translates `targets.yaml` into the dataclasses in `workflows.py`. Resolves generic oracles inline and named invariants against a project-supplied registry. The single YAML↔engine translation layer. |
| `artifacts.py` | Owns durable evidence: version, redaction (including the mutation record), lossless byte encoding, atomic write, and exact replay. Refuses to publish if a declared secret survives redaction. |
| `project.py` | Defines the `Project` protocol, loads a project from an explicit path, and parses `env.dist` with process-environment overrides. |

### Project integration (`projects/vectis/`)

| File | Purpose |
|------|---------|
| `targets.yaml` | The endpoints and flows as data. Adding a target is editing this file. |
| `invariants.py` | The pure semantic oracles referenced by name from the YAML — the irreducible Python that makes Nadir more than a conformance checker. |
| `fixture.py` | Resolves and validates the test instance (loopback, KID shape), enforces required credentials, and passes `NADIR_*` values through as template variables. The home of future stateful setup (key creation, profile signing). |
| `env.dist` | Declares every `NADIR_*` variable consumed by this project, including synthetic control values for profile-driven workflows. |
| `project.py` | The wiring: exposes the fixture, the invariants registry, the health check, and which variables are secrets to redact. Small by design. |
