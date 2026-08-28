#!/usr/bin/env bash
set -uo pipefail

RUNS="${RUNS:-20000}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-}"
PER_INPUT_TIMEOUT="${PER_INPUT_TIMEOUT:-5}"
TOOLCHAIN="${TOOLCHAIN-nightly}"
KEEP_GOING="${KEEP_GOING:-0}"
MINIMIZE="${MINIMIZE:-0}"
SEEDS_ONLY="${SEEDS_ONLY:-0}"
INCLUDE_SLOW="${INCLUDE_SLOW:-1}"
EXPECTED_TARGETS="${EXPECTED_TARGETS:-25}"

# Structural targets: fast, parse/validate/canonicalize without panics.
FAST_TARGETS=(
  fuzz_canonical_json
  fuzz_sign_input
  fuzz_compact_signature
  fuzz_timestamp_token
  fuzz_message_inputs
  fuzz_config_file
  fuzz_keys_inputs
  fuzz_validation
  fuzz_routes_permissions
  fuzz_fpe_inputs
  fuzz_tokenization_inputs
  fuzz_mac_index_inputs
  fuzz_masking_commitment_inputs
  fuzz_sharing_inputs
  fuzz_share_envelope
  fuzz_audit_chain_line
  fuzz_slh_dsa_signature
  fuzz_slh_dsa_key_files
  fuzz_init_artifacts
  fuzz_protected_message_artifact
  fuzz_time_attestation_evaluate
)

# Bounded crypto property targets: real round-trip / verify properties over live
# primitives. Lower throughput (crypto backend), so they run as a separate group
# that a fast weekly pass can skip with INCLUDE_SLOW=0.
SLOW_TARGETS=(
  fuzz_fpe_roundtrip
  fuzz_tokenization_roundtrip
  fuzz_commitment_verify
  fuzz_internal_encryption_roundtrip
)

TARGETS=("${FAST_TARGETS[@]}")
if [[ "$INCLUDE_SLOW" == "1" ]]; then
  TARGETS+=("${SLOW_TARGETS[@]}")
fi

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got '$value'"
  fi
}

require_positive_integer "RUNS" "$RUNS"
if [[ -n "$MAX_TOTAL_TIME" ]]; then
  require_positive_integer "MAX_TOTAL_TIME" "$MAX_TOTAL_TIME"
fi
require_positive_integer "PER_INPUT_TIMEOUT" "$PER_INPUT_TIMEOUT"

case "$KEEP_GOING" in
  0 | 1) ;;
  *) fail "KEEP_GOING must be 0 or 1, got '$KEEP_GOING'" ;;
esac

case "$MINIMIZE" in
  0 | 1) ;;
  *) fail "MINIMIZE must be 0 or 1, got '$MINIMIZE'" ;;
esac

case "$SEEDS_ONLY" in
  0 | 1) ;;
  *) fail "SEEDS_ONLY must be 0 or 1, got '$SEEDS_ONLY'" ;;
esac

if [[ "$MINIMIZE" == "1" && "$SEEDS_ONLY" == "1" ]]; then
  fail "MINIMIZE and SEEDS_ONLY are mutually exclusive"
fi

case "$INCLUDE_SLOW" in
  0 | 1) ;;
  *) fail "INCLUDE_SLOW must be 0 or 1, got '$INCLUDE_SLOW'" ;;
esac

require_positive_integer "EXPECTED_TARGETS" "$EXPECTED_TARGETS"
known_targets=$((${#FAST_TARGETS[@]} + ${#SLOW_TARGETS[@]}))
if (( known_targets != EXPECTED_TARGETS )); then
  fail "expected $EXPECTED_TARGETS fuzz targets but found $known_targets; update EXPECTED_TARGETS if this change is intentional"
fi

[[ -n "$TOOLCHAIN" ]] || fail "TOOLCHAIN must not be empty"
command -v rustup >/dev/null 2>&1 || fail "rustup is required"

TOOLCHAIN_CARGO="$(rustup which --toolchain "$TOOLCHAIN" cargo 2>/dev/null)" ||
  fail "Rust toolchain '$TOOLCHAIN' is not installed; run: rustup toolchain install $TOOLCHAIN"
TOOLCHAIN_BIN="$(dirname "$TOOLCHAIN_CARGO")"
export PATH="$TOOLCHAIN_BIN:$HOME/.cargo/bin:$PATH"

if ! cargo fuzz --help >/dev/null 2>&1; then
  fail "cargo-fuzz is not installed; run: cargo install cargo-fuzz"
fi

# Prebuilt cargo-fuzz binaries are musl-static and default the fuzz target to
# their own musl triple, which ASan cannot link (static libc). Pin the build to
# the host triple; callers may override via FUZZ_TRIPLE.
FUZZ_TRIPLE="${FUZZ_TRIPLE:-$(rustc -vV 2>/dev/null | awk '/^host:/ { print $2 }')}"
[[ -n "$FUZZ_TRIPLE" ]] || fail "could not determine target triple; set FUZZ_TRIPLE explicitly"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR" || fail "could not enter repository directory: $REPO_DIR"

printf '%s\n' "Vectis cargo-fuzz testing"
printf '%s\n\n' "##########################"
echo "Toolchain:"
rustc --version
cargo --version
cargo fuzz --version
echo

echo "Configuration:"
echo "  TOOLCHAIN=$TOOLCHAIN"
echo "  Target: $FUZZ_TRIPLE"
echo "  KEEP_GOING=$KEEP_GOING"
echo "  INCLUDE_SLOW=$INCLUDE_SLOW"
if [[ "$MINIMIZE" == "1" ]]; then
  echo "  Mode: minimize (cargo fuzz cmin)"
elif [[ "$SEEDS_ONLY" == "1" ]]; then
  echo "  Mode: seeds replay (regression gate; -runs=0 over committed seeds)"
else
  echo "  Mode: fuzz"
  if [[ -n "$MAX_TOTAL_TIME" ]]; then
    echo "  Stop condition: max_total_time=${MAX_TOTAL_TIME}s (run count unbounded)"
  else
    echo "  Stop condition: runs=$RUNS (time unbounded)"
  fi
fi
echo

echo "Targets (${#TARGETS[@]}):"
printf '  %s\n' "${TARGETS[@]}"
echo

if [[ -n "$MAX_TOTAL_TIME" ]]; then
  libfuzzer_args=(-max_total_time="$MAX_TOTAL_TIME")
else
  libfuzzer_args=(-runs="$RUNS")
fi

# Flag any single input that takes longer than PER_INPUT_TIMEOUT seconds, so an
# algorithmic-complexity DoS (a crafted input that makes a parser/validator hang)
# surfaces as a finding instead of silently eating the time budget.
libfuzzer_args+=(-timeout="$PER_INPUT_TIMEOUT")

# Seed the mutator with the domain's field names, enum values, and algorithm
# identifiers so it synthesizes structurally valid JSON far more often than from
# random bytes, reaching past the initial parse into the real logic.
DICT_FILE="$REPO_DIR/fuzz/vectis.dict"
if [[ -f "$DICT_FILE" ]]; then
  libfuzzer_args+=(-dict="$DICT_FILE")
fi

passed=0
failed=0

for target in "${TARGETS[@]}"; do
  seed_dir="$REPO_DIR/fuzz/seeds/$target"
  if [[ -d "$seed_dir" ]]; then
    corpus_dir="$REPO_DIR/fuzz/corpus/$target"
    if ! mkdir -p "$corpus_dir"; then
      echo "ERROR: could not create corpus directory for $target" >&2
      failed=$((failed + 1))
      if [[ "$KEEP_GOING" == "1" ]]; then continue; else break; fi
    fi

    shopt -s nullglob
    seed_files=("$seed_dir"/*)
    shopt -u nullglob
    if (( ${#seed_files[@]} > 0 )) && ! cp -f "${seed_files[@]}" "$corpus_dir/"; then
      echo "ERROR: could not synchronize seeds for $target" >&2
      failed=$((failed + 1))
      if [[ "$KEEP_GOING" == "1" ]]; then continue; else break; fi
    fi
  fi

  if [[ "$MINIMIZE" == "1" ]]; then
    action=(cargo fuzz cmin --target "$FUZZ_TRIPLE" "$target")
  elif [[ "$SEEDS_ONLY" == "1" ]]; then
    # Regression gate: execute every committed seed exactly once (-runs=0) and
    # exit. Fast enough for a per-PR check; any seed that now crashes is a
    # reintroduced bug. Targets without seeds have nothing to replay.
    if [[ ! -d "$seed_dir" ]]; then
      echo "[$target] no committed seeds; skipping replay"
      continue
    fi
    action=(cargo fuzz run --target "$FUZZ_TRIPLE" "$target" "$seed_dir" -- -runs=0 -timeout="$PER_INPUT_TIMEOUT")
  else
    action=(cargo fuzz run --target "$FUZZ_TRIPLE" "$target" -- "${libfuzzer_args[@]}")
  fi

  echo "== ${action[*]} =="
  if "${action[@]}"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "ERROR: $target reported a finding or execution failure" >&2
    [[ "$KEEP_GOING" == "1" ]] || break
  fi
  echo
done

skipped=$((${#TARGETS[@]} - passed - failed))
echo
echo "cargo-fuzz summary: passed=$passed failed=$failed skipped=$skipped total=${#TARGETS[@]}"

(( failed == 0 ))
