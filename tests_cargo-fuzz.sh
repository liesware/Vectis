#!/usr/bin/env bash
set -uo pipefail

RUNS="${RUNS:-20000}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-}"
TOOLCHAIN="${TOOLCHAIN-nightly}"

TARGETS=(
  fuzz_canonical_json
  fuzz_sign_input
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
)

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

[[ -n "$TOOLCHAIN" ]] || fail "TOOLCHAIN must not be empty"
command -v rustup >/dev/null 2>&1 || fail "rustup is required"

TOOLCHAIN_CARGO="$(rustup which --toolchain "$TOOLCHAIN" cargo 2>/dev/null)" ||
  fail "Rust toolchain '$TOOLCHAIN' is not installed; run: rustup toolchain install $TOOLCHAIN"
TOOLCHAIN_BIN="$(dirname "$TOOLCHAIN_CARGO")"
export PATH="$TOOLCHAIN_BIN:$HOME/.cargo/bin:$PATH"

if ! cargo fuzz --help >/dev/null 2>&1; then
  fail "cargo-fuzz is not installed; run: cargo install cargo-fuzz"
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR" || fail "could not enter repository directory: $REPO_DIR"

figlet Vectis
cowsay Cargo-Fuzz Testing
echo "\n###########################"
echo
echo "Toolchain:"
rustc --version
cargo --version
cargo fuzz --version
echo

echo "Configuration:"
echo "  TOOLCHAIN=$TOOLCHAIN"
echo "  RUNS=$RUNS"
if [[ -n "$MAX_TOTAL_TIME" ]]; then
  echo "  MAX_TOTAL_TIME=$MAX_TOTAL_TIME"
else
  echo "  MAX_TOTAL_TIME=unbounded"
fi
echo

echo "Targets (${#TARGETS[@]}):"
printf '  %s\n' "${TARGETS[@]}"
echo

libfuzzer_args=(-runs="$RUNS")
if [[ -n "$MAX_TOTAL_TIME" ]]; then
  libfuzzer_args+=(-max_total_time="$MAX_TOTAL_TIME")
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
      break
    fi

    shopt -s nullglob
    seed_files=("$seed_dir"/*)
    shopt -u nullglob
    if (( ${#seed_files[@]} > 0 )) && ! cp -f "${seed_files[@]}" "$corpus_dir/"; then
      echo "ERROR: could not synchronize seeds for $target" >&2
      failed=$((failed + 1))
      break
    fi
  fi

  echo "== cargo fuzz run $target -- ${libfuzzer_args[*]} =="
  if cargo fuzz run "$target" -- "${libfuzzer_args[@]}"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "ERROR: $target reported a finding or execution failure" >&2
    break
  fi
  echo
done

skipped=$((${#TARGETS[@]} - passed - failed))
echo
echo "cargo-fuzz summary: passed=$passed failed=$failed skipped=$skipped total=${#TARGETS[@]}"

(( failed == 0 ))
