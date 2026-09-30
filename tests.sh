#!/bin/bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root_dir"

started="$SECONDS"
stage_names=()
stage_seconds=()
stage_statuses=()
stage_count=0

print_summary() {
    status="$?"
    trap - EXIT
    printf '\n%-28s %10s %8s\n' "Stage" "Seconds" "Exit"
    for ((index = 0; index < stage_count; index++)); do
        printf '%-28s %10s %8s\n' "${stage_names[$index]}" "${stage_seconds[$index]}" "${stage_statuses[$index]}"
    done
    printf 'Total: %s seconds; exit=%s\n' "$((SECONDS - started))" "$status"
    exit "$status"
}
trap print_summary EXIT

run_stage() {
    local name="$1"
    shift
    local start="$SECONDS"
    local status
    printf '\n### %s\n' "$name"
    if "$@"; then
        status=0
    else
        status="$?"
    fi
    stage_names[$stage_count]="$name"
    stage_seconds[$stage_count]="$((SECONDS - start))"
    stage_statuses[$stage_count]="$status"
    stage_count=$((stage_count + 1))
    return "$status"
}

figlet Vectis || true
cowsay Standard Procedure Testing || true
printf '\n###########################\n'

run_stage "Cargo fmt" cargo fmt -- --check
run_stage "Cargo audit" cargo audit
run_stage "Cargo test" cargo test --locked
run_stage "Cargo clippy" cargo clippy --locked --all-targets --all-features -- -D warnings
run_stage "Cargo build" cargo build --locked

export VECTIS_BIN="$root_dir/target/debug/vectis"
run_stage "Binary validation" test -x "$VECTIS_BIN"

vectis_api_url="${VECTIS_API_URL:-http://127.0.0.1:3000}"
health_url="${vectis_api_url%/}/healthz/ready"

if run_stage "Vectis readiness" curl --fail --silent --show-error --connect-timeout 5 "${health_url}"; then
    printf '\n'
else
    status="$?"
    printf '\nVectis is not ready at %s; start the service and try again.\n' "$health_url" >&2
    exit "$status"
fi

run_stage "Python environment" uv sync --locked --group fuzz
export UV_NO_SYNC=1 UV_LOCKED=1

run_stage "CLI Positive/Negative" uv run --no-sync tests/integration/cli/cli_all.py
run_stage "HTTP Positive/Negative" uv run --no-sync tests/integration/http/http_all.py
run_stage "Manual HTTP Fuzzing" uv run --no-sync tests/security/fuzz/http_fuzz.py \
    --random-seed --mutation-only --iterations 100
run_stage "HTTP Schemathesis" uv run --no-sync tests/security/openapi/http_schemathesis.py --profile prepared
run_stage "TLS happy path" bash tests/integration/tls/tls.sh
