#!/usr/bin/env bash
set -uo pipefail

RUNS="${RUNS:-20000}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-}"
TOOLCHAIN="${TOOLCHAIN-nightly}"
KEEP_GOING="${KEEP_GOING:-0}"
MINIMIZE="${MINIMIZE:-0}"
EXPECTED_TARGETS="${EXPECTED_TARGETS:-19}"

TARGETS=(
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

case "$KEEP_GOING" in
  0 | 1) ;;
  *) fail "KEEP_GOING must be 0 or 1, got '$KEEP_GOING'" ;;
esac

case "$MINIMIZE" in
  0 | 1) ;;
  *) fail "MINIMIZE must be 0 or 1, got '$MINIMIZE'" ;;
esac

require_positive_integer "EXPECTED_TARGETS" "$EXPECTED_TARGETS"
if (( ${#TARGETS[@]} != EXPECTED_TARGETS )); then
  fail "expected $EXPECTED_TARGETS fuzz targets but found ${#TARGETS[@]}; update EXPECTED_TARGETS if this change is intentional"
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
if [[ "$MINIMIZE" == "1" ]]; then
  echo "  Mode: minimize (cargo fuzz cmin)"
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
