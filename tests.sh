#!/bin/bash

figlet Vectis
cowsay Standard Procedure Testing

read -p "Press any key to start: " keyboard
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

echo "\n\n"
read -p "Start Vectis now, then press Enter to run HTTP tests: "

echo "\n### CLI Positive/Negative"
uv sync
uv run tests/cli_all.py

echo "\n### HTTP Positive/Negative"
uv sync
uv run tests/http_all.py

echo "\n### Manual HTTP Fuzzing"
uv run tests/http_fuzz.py 

echo "\n### HTTP Schemathesis"
uv sync --group fuzz
uv run tests/http_schemathesis.py --profile prepared 
