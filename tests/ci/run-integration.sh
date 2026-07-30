#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

ci_dir="$root_dir/.ci"
mkdir -p "$ci_dir"

export VECTIS_SQLITE_PATH="$ci_dir/vectis-integration.db"
export VECTIS_INIT_KEYS_FILE="$ci_dir/init.json"
export VECTIS_INIT_PUBLIC_KEYS_FILE="$ci_dir/init_pub.json"
export VECTIS_UNSEAL_KEY_FILE="$ci_dir/.unseal_key"
export VECTIS_API_URL="http://127.0.0.1:3000"

sqlite3 "$VECTIS_SQLITE_PATH" < src/db/sqlite_schema.sql

init_output="$(cargo run --quiet -- init)"
export VECTIS_UNSEAL_KEY="$(printf '%s\n' "$init_output" | sed -n 's/^VECTIS_UNSEAL_KEY=//p')"
export VECTIS_APIKEY="$(printf '%s\n' "$init_output" | sed -n 's/^VECTIS_APIKEY=//p')"
export VECTIS_APIKEY_HASH="$(printf '%s\n' "$init_output" | sed -n 's/^VECTIS_APIKEY_HASH=//p')"

test -n "$VECTIS_UNSEAL_KEY"
test -n "$VECTIS_APIKEY"
test -n "$VECTIS_APIKEY_HASH"

server_log="$ci_dir/vectis.log"
# The HTTP fixtures deliberately exercise documented development/test overrides.
VECTIS_CRYPTO_POLICY=allow-overrides \
    cargo run --quiet -- serve >"$server_log" 2>&1 &
server_pid="$!"

cleanup() {
    status="$?"

    if [ "$status" -ne 0 ]; then
        tail -n 200 "$server_log" || true
    fi

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT

for _ in $(seq 1 60); do
    if curl --fail --silent --show-error "$VECTIS_API_URL/healthz/ready" >/dev/null; then
        break
    fi
    sleep 1
done

curl --fail --silent --show-error "$VECTIS_API_URL/healthz/ready" >/dev/null

uv sync --locked

env -u VECTIS_UNSEAL_KEY -u VECTIS_APIKEY -u VECTIS_APIKEY_HASH \
    uv run tests/cli_all.py \
    --base-url "$VECTIS_API_URL" \
    --apikey "$VECTIS_APIKEY"

uv run tests/http_all.py \
    --base-url "$VECTIS_API_URL" \
    --apikey "$VECTIS_APIKEY"

uv run tests/http_fuzz.py \
    --base-url "$VECTIS_API_URL" \
    --apikey "$VECTIS_APIKEY"

uv sync --locked --group fuzz

uv run tests/http_schemathesis.py \
    --profile prepared \
    --base-url "$VECTIS_API_URL" \
    --apikey "$VECTIS_APIKEY"
