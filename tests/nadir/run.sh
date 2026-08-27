#!/usr/bin/env bash

# Provision an isolated local Vectis instance, then run Nadir against it.
# Pass ordinary Nadir run options after this script, for example:
#   bash tests/nadir/run.sh --target vectis.sign-verification --iterations 4

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NADIR_PROJECT="${ROOT_DIR}/nadir"
NADIR_VECTIS_PROJECT="${NADIR_PROJECT}/projects/vectis/project.py"
WORKSPACE="$(mktemp -d "${TMPDIR:-/tmp}/vectis-nadir.XXXXXX")"
RESULTS_ROOT="${NADIR_RESULTS_DIR:-${ROOT_DIR}/tests/nadir/results}"
mkdir -p "${RESULTS_ROOT}"
RESULTS_DIR="$(mktemp -d "${RESULTS_ROOT}/vectis.XXXXXX")"
SERVER_PID=""
NADIR_COMMAND="${NADIR_COMMAND:-run}"

if [[ "${NADIR_COMMAND}" != "run" && "${NADIR_COMMAND}" != "reproduce" ]]; then
  echo "unsupported Nadir harness command: ${NADIR_COMMAND}" >&2
  exit 2
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "tests/nadir/run.sh requires $1" >&2
    exit 2
  fi
}

require_command sqlite3
require_command uv
require_command python3

if [[ -n "${VECTIS_BIN:-}" ]]; then
  VECTIS_BIN="${VECTIS_BIN}"
  if [[ "${VECTIS_BIN}" != /* ]]; then
    VECTIS_BIN="${ROOT_DIR}/${VECTIS_BIN}"
  fi
elif [[ -x "${ROOT_DIR}/target/debug/vectis" ]]; then
  VECTIS_BIN="${ROOT_DIR}/target/debug/vectis"
else
  echo "Building Vectis debug binary..."
  (cd "${ROOT_DIR}" && cargo build --locked)
  VECTIS_BIN="${ROOT_DIR}/target/debug/vectis"
fi

if [[ ! -x "${VECTIS_BIN}" ]]; then
  echo "Vectis binary is not executable: ${VECTIS_BIN}" >&2
  exit 2
fi

PORT="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
BASE_URL="http://127.0.0.1:${PORT}"

extract_init_value() {
  local key="$1"
  awk -F= -v key="${key}" '
    $1 == key {
      print substr($0, length(key) + 2)
      found = 1
      exit
    }
    END { exit !found }
  '
}

json_field() {
  local field="$1"
  python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "${field}"
}

json_array_item() {
  local field="$1"
  local index="$2"
  python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]][int(sys.argv[2])])' "${field}" "${index}"
}

stop_vectis() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill -INT "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  SERVER_PID=""
}

cleanup() {
  local status="$?"
  trap - EXIT

  stop_vectis

  if [[ "${status}" -eq 0 || "${NADIR_VERIFY_AUDIT_ALWAYS:-false}" == "true" ]]; then
    if ! (cd "${WORKSPACE}" && ./vectis audit verify --file logs/audit.jsonl >/dev/null); then
      echo "Nadir harness: audit verification failed" >&2
      status=3
    fi
  fi
  if [[ "${status}" -ne 0 ]]; then
    echo "Nadir harness failed; Vectis log follows:" >&2
    tail -n 200 "${WORKSPACE}/logs/vectis.log" >&2 || true
  fi

  if [[ "${NADIR_KEEP_WORKSPACE:-false}" == "true" ]]; then
    echo "Nadir workspace retained at ${WORKSPACE}" >&2
  else
    rm -rf "${WORKSPACE}"
  fi
  if [[ -n "$(find "${RESULTS_DIR}" -mindepth 1 -maxdepth 1 -type f -print -quit)" ]]; then
    echo "Nadir finding artifacts retained at ${RESULTS_DIR}" >&2
  else
    rmdir "${RESULTS_DIR}" 2>/dev/null || true
  fi
  exit "${status}"
}
trap cleanup EXIT

mkdir -p "${WORKSPACE}/db" "${WORKSPACE}/logs"
cp "${VECTIS_BIN}" "${WORKSPACE}/vectis"
chmod 755 "${WORKSPACE}/vectis"
sqlite3 "${WORKSPACE}/db/data.db" < "${ROOT_DIR}/src/db/sqlite_schema.sql"

cat > "${WORKSPACE}/.env" <<ENV
VECTIS_MODE=dev
VECTIS_HTTP_BIND_ADDR=127.0.0.1:${PORT}
VECTIS_API_URL=${BASE_URL}
VECTIS_INIT_KEYS_FILE=init.json
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
VECTIS_STORAGE=sqlite
VECTIS_SQLITE_PATH=db/data.db
VECTIS_LOG_TARGET=file
VECTIS_LOG_LEVEL=warn
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.jsonl
VECTIS_PROTOCOL_VERSION=v1
VECTIS_SENDER_HOSTNAME=nadir-local
VECTIS_RECEIVER_HOSTNAME=nadir-local
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
ENV
chmod 600 "${WORKSPACE}/.env"

cd "${WORKSPACE}"
init_output="$(./vectis init)"
unseal_key="$(printf '%s\n' "${init_output}" | extract_init_value VECTIS_UNSEAL_KEY)"
root_apikey="$(printf '%s\n' "${init_output}" | extract_init_value VECTIS_APIKEY)"
root_apikey_hash="$(printf '%s\n' "${init_output}" | extract_init_value VECTIS_APIKEY_HASH)"

if [[ -z "${unseal_key}" || -z "${root_apikey}" || -z "${root_apikey_hash}" ]]; then
  echo "vectis init did not return the required bootstrap values" >&2
  exit 1
fi
printf '%s\n' "${unseal_key}" > .unseal_key
chmod 600 .unseal_key
cat >> .env <<ENV
VECTIS_APIKEY=${root_apikey}
VECTIS_APIKEY_HASH=${root_apikey_hash}
ENV

./vectis serve > logs/vectis.log 2>&1 &
SERVER_PID="$!"
for _ in $(seq 1 120); do
  if ./vectis health ready --output json >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
./vectis health ready --output json >/dev/null

kid="$(./vectis keys create --tag nadir-target --profile hybrid-standard-v1 --output json | json_field kid)"
retired_kid="$(./vectis keys create --tag nadir-retired-target --profile hybrid-standard-v1 --output json | json_field kid)"
client_output="$(./vectis apikey create --output json)"
client_apikey="$(printf '%s\n' "${client_output}" | json_field VECTIS_APIKEY)"
client_apikey_hash="$(printf '%s\n' "${client_output}" | json_field VECTIS_APIKEY_HASH)"
scoped_client_output="$(./vectis apikey create --output json)"
scoped_client_apikey="$(printf '%s\n' "${scoped_client_output}" | json_field VECTIS_APIKEY)"
scoped_client_apikey_hash="$(printf '%s\n' "${scoped_client_output}" | json_field VECTIS_APIKEY_HASH)"
denied_client_output="$(./vectis apikey create --output json)"
denied_client_apikey="$(printf '%s\n' "${denied_client_output}" | json_field VECTIS_APIKEY)"
denied_client_apikey_hash="$(printf '%s\n' "${denied_client_output}" | json_field VECTIS_APIKEY_HASH)"

./vectis config init >/dev/null
./vectis config permissions add --client nadir-local --apikey-hash "${client_apikey_hash}" --status active >/dev/null
./vectis config permissions add --client nadir-denied --apikey-hash "${denied_client_apikey_hash}" --status active >/dev/null
./vectis config permissions add --client nadir-scoped --apikey-hash "${scoped_client_apikey_hash}" --status active >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action keys >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action sign >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action message >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action fpe-encrypt >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action fpe-decrypt >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action mac-create >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action mac-verify >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action index-create >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action index-verify >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action commit-create >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action commit-verify >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action share-split >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action share-combine >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action mask >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action token-encode >/dev/null
./vectis config permissions grant nadir-local --kid "${kid}" --action token-decode >/dev/null
./vectis config permissions grant nadir-local --kid "${retired_kid}" --action fpe-encrypt >/dev/null
./vectis config permissions grant nadir-local --kid "${retired_kid}" --action fpe-decrypt >/dev/null
./vectis config permissions grant nadir-local --kid "${retired_kid}" --action share-split >/dev/null
./vectis config permissions grant nadir-local --kid "${retired_kid}" --action share-combine >/dev/null
./vectis config permissions grant nadir-scoped --kid "${kid}" --action fpe-encrypt >/dev/null
./vectis config fpe add --name nadir-fpe-v1 --kid "${kid}" --alphabet 0123456789 --min-len 6 --max-len 32 --tweak-aad 'tenant=nadir;field=account;version=1' >/dev/null
./vectis config fpe add --name nadir-retired-fpe-v1 --kid "${retired_kid}" --alphabet 0123456789 --min-len 6 --max-len 32 --tweak-aad 'tenant=nadir;field=historical-account;version=1' >/dev/null
./vectis config mac add --name nadir-mac-v1 --kid "${kid}" --context 'tenant=nadir;field=pan;purpose=mac;version=1' >/dev/null
./vectis config commitment add --name nadir-commitment-v1 --kid "${kid}" --context 'tenant=nadir;field=commitment;purpose=commitment;version=1' --max-plaintext-len 128 --opening-len 32 >/dev/null
./vectis config sharing add --name nadir-sharing-3of5-v1 --kid "${kid}" --threshold 3 --shares 5 --max-secret-len 128 --context 'tenant=nadir;purpose=sharing;version=1' >/dev/null
./vectis config sharing add --name nadir-retired-sharing-3of5-v1 --kid "${retired_kid}" --threshold 3 --shares 5 --max-secret-len 128 --context 'tenant=nadir;purpose=sharing;version=1' >/dev/null
./vectis config masking add --name nadir-mask-v1 --kid "${kid}" --visible-first 0 --visible-last 4 --mask-char '*' --min-len 12 --max-len 19 >/dev/null
./vectis config token add --name nadir-token-v1 --kid "${kid}" --token-prefix nadir_tok --token-len 32 --max-plaintext-len 128 --one-time false >/dev/null
./vectis config token add --name nadir-once-v1 --kid "${kid}" --token-prefix nadir_once --token-len 32 --max-plaintext-len 128 --one-time true >/dev/null
./vectis config validate --output json >/dev/null
./vectis config sign --output json >/dev/null
./vectis config reload --output json >/dev/null

# State transition fixture: produce one historical ciphertext while active, then
# retire the KID. The target suite can now assert both sides of the lifecycle.
retired_ciphertext="$(./vectis fpe encrypt "${retired_kid}" --json '{"ref":"nadir-retired-fpe-control","profile":"nadir-retired-fpe-v1","plaintext":"1234567890"}' --output json | json_field ciphertext)"
retired_shares_output="$(./vectis shares split "${retired_kid}" --json '{"profile":"nadir-retired-sharing-3of5-v1","plaintext":"nadir-sharing-retired-secret"}' --output json)"
retired_share_set_id="$(printf '%s\n' "${retired_shares_output}" | json_field set_id)"
retired_share_zero="$(printf '%s\n' "${retired_shares_output}" | json_array_item shares 0)"
retired_share_one="$(printf '%s\n' "${retired_shares_output}" | json_array_item shares 1)"
retired_share_two="$(printf '%s\n' "${retired_shares_output}" | json_array_item shares 2)"
./vectis lifecycle "${retired_kid}" --status retired --reason 'nadir lifecycle fixture' --output json >/dev/null

echo "Running Nadir ${NADIR_COMMAND} against isolated Vectis at ${BASE_URL}"
common_environment=(
  "NADIR_BASE_URL=${BASE_URL}"
  "NADIR_KID=${kid}"
  "NADIR_API_KEY=${client_apikey}"
  "NADIR_DENIED_API_KEY=${denied_client_apikey}"
  "NADIR_SCOPED_API_KEY=${scoped_client_apikey}"
  "NADIR_RETIRED_KID=${retired_kid}"
  "NADIR_RETIRED_FPE_CIPHERTEXT=${retired_ciphertext}"
  "NADIR_RETIRED_SHARE_SET_ID=${retired_share_set_id}"
  "NADIR_RETIRED_SHARE_ZERO=${retired_share_zero}"
  "NADIR_RETIRED_SHARE_ONE=${retired_share_one}"
  "NADIR_RETIRED_SHARE_TWO=${retired_share_two}"
  "UV_CACHE_DIR=${ROOT_DIR}/.uv-cache"
)

if [[ "${NADIR_COMMAND}" == "reproduce" ]]; then
  env "${common_environment[@]}" \
    uv run --project "${NADIR_PROJECT}" nadir reproduce \
      --project "${NADIR_VECTIS_PROJECT}" \
      "$@"
else
  env "${common_environment[@]}" \
    uv run --project "${NADIR_PROJECT}" nadir run \
      --project "${NADIR_VECTIS_PROJECT}" \
      --output-dir "${RESULTS_DIR}" \
      "$@"
fi
