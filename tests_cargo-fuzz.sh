#!/usr/bin/env bash
set -euo pipefail

RUNS="${RUNS:-20000}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-}"
TOOLCHAIN="${TOOLCHAIN:-nightly-aarch64-apple-darwin}"
NIGHTLY_BIN="$HOME/.rustup/toolchains/$TOOLCHAIN/bin"

TARGETS=(
  fuzz_canonical_json
  fuzz_sign_input
  fuzz_timestamp_token
  fuzz_message_inputs
  fuzz_config_file
  fuzz_keys_inputs
  fuzz_validation
  fuzz_routes_permissions
)

if [[ ! -x "$NIGHTLY_BIN/cargo" ]]; then
  echo "ERROR: Rust toolchain not found: $TOOLCHAIN" >&2
  echo "Install it with: rustup toolchain install nightly" >&2
  exit 1
fi

export PATH="$NIGHTLY_BIN:$HOME/.cargo/bin:$PATH"

if ! cargo fuzz --help >/dev/null 2>&1; then
  echo "ERROR: cargo-fuzz is not installed" >&2
  echo "Install it with: cargo install cargo-fuzz" >&2
  exit 1
fi

figlet Vectis
cowsay Cargo-Fuzz Testing

read -p "Press any key to start: " keyboard
echo "\n###########################"

echo "Rust:"
rustc --version
cargo --version
echo

echo "cargo-fuzz targets:"
cargo fuzz list
echo

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

libfuzzer_args=(-runs="$RUNS")
if [[ -n "$MAX_TOTAL_TIME" ]]; then
  libfuzzer_args+=(-max_total_time="$MAX_TOTAL_TIME")
fi

for target in "${TARGETS[@]}"; do
  seed_dir="$REPO_DIR/fuzz/seeds/$target"
  if [[ -d "$seed_dir" ]]; then
    mkdir -p "$REPO_DIR/fuzz/corpus/$target"
    cp -n "$seed_dir"/* "$REPO_DIR/fuzz/corpus/$target/" 2>/dev/null || true
  fi

  echo "== cargo fuzz run $target -- ${libfuzzer_args[*]} =="
  cargo fuzz run "$target" -- "${libfuzzer_args[@]}"
  echo
done

echo "cargo-fuzz summary: ${#TARGETS[@]} passed, 0 failed"
