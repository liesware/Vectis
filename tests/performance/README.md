# Selective k6 Performance Harness

Manual local measurements against **Vectis + SQLite**, not a CI gate or a
replacement for correctness/security suites. The runner builds once with
`cargo build --release --locked`; Rust, Python 3 and k6 must be installed.
No Node packages or Python dependencies are needed to run it.

```sh
bash tests/performance/run.sh
bash tests/performance/run.sh --target fpe --subject --authenticated --vusr 10 --duration 1m
bash tests/performance/run.sh --target fpe --vusr 10 --duration 1m --save-results
bash tests/performance/run.sh --target token-deterministic-batch --subject --batch-size 3 \
  --crypto-profile hybrid-standard-v1 --vusr 2 --duration 30s
```

## Targets and Options

| Target | One measured iteration |
| --- | --- |
| `all` | Every flow and compatible subject/FPE-authentication variant, in fixed order |
| `fpe`, `fpe-batch` | Encrypt then decrypt |
| `token`, `token-batch` | Reusable random encode then decode |
| `token-deterministic`, `token-deterministic-batch` | AES-256-SIV encode then decode |
| `symmetric` | Encrypt then decrypt |
| `sign` | Sign then hybrid verification |
| `mac`, `mac-batch` | Create then verify |
| `index`, `index-batch` | Create then verify positive membership |
| `commitment`, `commitment-batch` | Create then verify |
| `masking`, `masking-batch` | Apply and validate the exact masking policy |
| `sharing` | Split 3-of-5 then combine three nonconsecutive shares |

| Option | Default and restrictions |
| --- | --- |
| `--target` | `all` |
| `--subject` | Off; only FPE, either token family or symmetric |
| `--authenticated` | Off; only FPE single/batch; selects a signed profile, not a request override |
| `--batch-size` | `3`; `1..128`, concrete batch targets only |
| `--vusr` | `1`; positive concurrent k6 virtual users (not `--vus`); at most `--iterations` unless `--duration` is used |
| `--iterations` | `4` total complete iterations **per selected crypto profile** |
| `--duration` | Positive k6 duration, e.g. `30s`, `1m30s`; mutually exclusive with iterations |
| `--crypto-profile` | `all`, or one of the four names below |
| `--save-results` | Off; explicitly persist sanitized reports and resource samples |

The only hybrid profiles are `hybrid-performance-v1`, `hybrid-standard-v1`,
`hybrid-high-assurance-v1` and `hybrid-long-term-v1`. `all` profiles means four
**sequential subruns**, each with a fresh SQLite laboratory. It does not rotate
profiles randomly within a VU iteration. Each laboratory contains only the KID
of the hybrid profile it measures, its capability variants and one stored
subject, so every profile is measured under the same conditions without paying
for the others' key generation. Capability profiles are fixtures, not new hybrid
crypto algorithms or profiles.

The `req/flow/s` and `values/s` columns are counts divided by the whole k6 run
duration. With a single target they are its throughput; with `all` they are
campaign rates over the mixed workload, not per-operation throughput.

The `all` target runs 28 cases each iteration, including four FPE combinations
(subject on/off x tag on/off) for single and batch, and both subject modes for
random tokens, deterministic tokens and symmetric. It uses batch size 3 and
rejects `--subject`, `--authenticated` and `--batch-size`. Select a concrete
target to isolate a variant. Every VU runs the full case list; coverage never
depends on random scheduling. Single/batch are different targets even at size 1.

`K6_VUS`, `K6_DURATION`, `K6_ITERATIONS` and `K6_P95_MS` remain supported. The
corresponding explicit CLI load flag wins: e.g. `--duration` overrides an
inherited `K6_ITERATIONS`. Conflicting load modes at the same precedence fail.
The runner also accepts `K6_TARGET`, `K6_CRYPTO_PROFILE`, `K6_BATCH_SIZE`,
`K6_SUBJECT` and `K6_AUTHENTICATED`; boolean values are `true/false` or `1/0`.
All arguments are validated before building or creating a lab, including
duplicates and unknown flags. Abbreviations are not accepted.

## Measurement Boundaries

Each profile is bootstrapped using a free loopback port. Preparation, health,
public-key/self-test checks and subject creation run before k6. One full selected
iteration warms the service in a separate k6 process, excluded from the reported
metrics. The actual load then starts with its requested VUs and iteration count
or duration. Metrics checking and offline audit verification happen afterwards.
The measured k6 process inherits the terminal directly: its native banner,
scenario and progress remain visible. Non-terminal output uses k6's normal
behavior without a forced pseudo-TTY. Warmup output stays in the private lab.
Each subrun announces its profile and position, then prints one aligned
operation/flow summary and a resource summary, without per-request logs.

Every family uses the same 16-character synthetic numeric data and equivalent
bounds across profiles/variants. Tokens are reusable, not one-time. Random
token/index writes are part of their measured flows; no hidden cleanup requests
are added to the measured loop. Database growth is reported, not normalized away.
This is a warm local benchmark with real storage/audit costs, not a cold-key or
raw-primitive benchmark. No secret cache or crypto optimization is introduced.

HTTP rows report latency through the full HTTP response (`http` kind). Flow rows
also include client-side request construction and checks across the complete
round trip (`flow` kind). A flow is one unit of work, not one HTTP request.
Throughput uses the whole measured k6 window; in `all` it is each operation's
observed frequency in mixed traffic, not that operation's maximum capacity.
Values/s counts actual successfully validated items, including every batch item.
The `fpe_authenticated` column describes only the optional FPE tag; other
families retain their normal authentication even when that column is false.

The load model is closed concurrent VUs, not fixed arrivals per second. Slow
responses can reduce offered traffic. `429`, transport errors, HTTP errors and
contract errors remain visible; a fast rejection must not count as useful
throughput. Thresholds require checks >99%, HTTP failures <1% and zero failed
flows. Any incomplete/failed flow makes the campaign fail even if the aggregate
check ratio exceeds 99%; this prevents a late error in `all` being hidden by
earlier successful checks. `K6_P95_MS` optionally adds an aggregate HTTP latency
threshold. Always inspect counters as well as the exit status.

Vectis admits only a bounded number of concurrent crypto operations (by default,
available CPU cores minus one, minimum one). Exceeding that capacity can return
HTTP `429`, even with valid FPE inputs. The harness reports the actual status and
keeps these rejections as failed flows; it does not retry or hide them. Lower
`--vusr` to measure within the admitted load. Increasing concurrency is a load
experiment, not a guarantee that every request will succeed.

Few iterations are **smoke**, not evidence for p99 or capacity claims. Duration
mode is a sustained measurement, but users must still inspect sample counts,
repeat experiments, and control machine load. k6 runs on the same host and can
compete with Vectis for CPU. Do not extrapolate SQLite results to PostgreSQL.

## Files and Resources

By default no report directory or files are created under `local/results/`,
including on failure. Parameters, status and incremental CPU/RSS aggregates stay
in memory and are displayed in the terminal; resource samples are not retained.

With `--save-results`, the same interactive output is shown and the campaign
writes `local/results/<UTC-time>-<random-id>/` (ignored by Git):

- `manifest.json`: sanitized options, release-build identification, commit/dirty
  state, versions, hardware and subrun status.
- `<profile>/manifest.json`: phase/status, warmup boundary, SQLite + WAL/SHM byte
  sizes before/after measurement, CPU/RSS aggregates, k6/audit exit codes and
  resource-sampler errors.
- `<profile>/summary.json`: native k6 metrics/state, without setup data or env.
- `<profile>/summary.tsv`: operation/flow, sample count, average, p95/p99,
  requests-or-flows/s, useful values/s and error counts.
- `<profile>/resources.csv`: Vectis PID RSS bytes, cumulative CPU seconds and
  delta CPU percent, using one core = 100% (can exceed 100% with several cores).

The resource sampler uses `ps` on macOS/Linux, takes baseline/final samples and
samples each second during the measured k6 invocation, including generator
startup/shutdown. These samples are not per-request heap measurements. For
`all`, CPU/RSS describe the whole mixed subrun, not individual operations.

Secrets, SQLite, signed config and logs live separately under
`local/site/<run-id>/<profile>/` (also ignored). Successful campaigns remove
their laboratory after audit verification, whether or not reports were saved.
Saved manifests may therefore reference a lab that no longer exists.
Failures and interruptions retain the private lab and print its location;
partial reports are retained only with `--save-results`. Older laboratories and
reports are never removed. No script prints API keys or request/response bodies. Treat
retained labs as private: they contain init/unseal and client credentials.
Server and sampler are stopped on normal exit, failures and interruption;
audit verification runs after stopping Vectis. Concurrent campaigns use distinct
directories and ports. Neither campaign touches a user's ordinary database.

## Offline Tests

```sh
python3 -m unittest discover -s tests/performance/local -p test_performance.py -v
bash -n tests/performance/run.sh tests/performance/local/*.sh
```

Node is optional for JavaScript registry and stubbed transport/flow regressions;
those tests skip if Node is unavailable. No Node dependencies are installed.
The runner and fixture modules are private to this performance suite.

## Maintenance Boundaries

The harness separates metadata, fixture preparation, lifecycle and measured API
contracts. No module imports infrastructure from other test suites.

| Component | Owns |
| --- | --- |
| `catalog.json` | Ordered hybrid profiles and targets, operations and supported variants |
| `local/options.py` | CLI/env precedence and validation, using the catalog |
| `local/provision.py` | Signed capability profiles, grants and their exact fixture names |
| `local/laboratory.py` | Bootstrap scripts, readiness, subjects, SQLite sizes, server shutdown and audit |
| `local/runner.py` | Build once, sequential campaign, warmup/load, resource sampling and retention |
| `lib/flows/` | Explicit requests and response assertions for each capability |
| `lib/transport.js` | HTTP transport, measurements and failure classification |
| `lib/reporting.js` | Terminal table and optional JSON/TSV exports |

Python and k6 load the same catalog. It contains no URLs, payload templates,
secrets or executable expressions. The registry checks that every declared
family has exactly one implementation. Existing variant IDs and metric names
are pinned in `lib/regression.json`; this file is a regression baseline, not a
second runtime catalog.

### Private Fixture Contract

`local/provision.py` builds the signed configuration and `fixtures.json`
together, so the names passed to k6 are the actual configured names. The version
1 fixture has `url`, `apikey` and a `profiles` mapping keyed by hybrid profile.
Each entry has `kid`, `subject` and `profiles`, the capability profile names.
FPE names are keyed by `none-legacy|none-auth|stored-legacy|stored-auth`; each
token family uses `none|stored`; other profiled capabilities have a single name.
The index fixture explicitly identifies its shared MAC profile.

The laboratory fills subject IDs before warmup. k6 receives
`K6_FIXTURE_PATH` and `K6_CRYPTO_PROFILE`, plus non-secret selection/load
parameters; it never reconstructs profile names from a slug. Fixtures stay in
the private lab with mode `0600` and are never exported with reports.

### Add a Capability

1. Declare its target(s), family, operation names and supported flags in
   `catalog.json`. Batch targets retain their own explicit catalog entry.
2. Add an explicit function under `lib/flows/` and register it in
   `lib/flows.js`. Use the provided fixture, `measured.post` and small input/batch
   helpers; keep endpoint-specific expectations in the capability module.
3. If it needs profiles or grants, extend `local/provision.py` to create both
   configuration and fixture entries together. Use `none|stored` maps for
   scoped profiles; extend fixture validation for a genuinely new fixture shape.
4. Add positive/negative contract tests, including arbitrary profile names,
   batch order and zero useful values on failure. Review intentional baseline
   changes; do not regenerate the baseline just to silence a regression.
5. Run offline tests and a real isolated smoke for the new target and `all`.

Adding a capability does not require edits to the campaign runner, transport,
resource sampler or summary renderer. Lab shutdown is idempotent and safe after
partial setup. Cleanup/audit errors are reported separately without replacing
the initial preparation or measurement failure.
