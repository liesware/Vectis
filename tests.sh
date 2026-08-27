#!/bin/bash

set -euo pipefail

figlet Vectis || true
cowsay Standard Procedure Testing || true
echo "\n###########################"

echo "\n### Cargo fmt"
cargo fmt

echo "\n### Cargo audit"
cargo audit

echo "\n### Integration Test - Botan"
cargo test --test crypto_integration

echo "\n### Cargo check"
cargo check

echo "\n### Cargo test"
cargo test

echo "\n### Cargo clippy"
cargo clippy --all-targets --all-features -- -D warnings
# cargo clippy --all-targets --all-features -- -W clippy::pedantic

echo "\n### Cargo build"
cargo build

echo "\n\n"

vectis_api_url="${VECTIS_API_URL:-http://127.0.0.1:3000}"
health_url="${vectis_api_url%/}/healthz/ready"

echo "\n### Vectis readiness"
if ! curl --fail --silent --show-error --connect-timeout 5 "${health_url}"; then
  echo "\nVectis is not ready at ${health_url}; start the service and try again." >&2
  exit 1
fi
echo

echo "\n### CLI Positive/Negative"
uv sync
uv run tests/integration/cli/cli_all.py

echo "\n### HTTP Positive/Negative"
uv sync
uv run tests/integration/http/http_all.py

echo "\n### Manual HTTP Fuzzing"
uv run tests/security/fuzz/http_fuzz.py

echo "\n### HTTP Schemathesis"
uv sync --group fuzz
uv run tests/security/openapi/http_schemathesis.py --profile prepared

echo "\n### TLS happy path"
bash tests/integration/tls/tls.sh
