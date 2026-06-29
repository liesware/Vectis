#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"

mkdir -p "${BIN_DIR}" "${SCRIPT_DIR}/site-a/db" "${SCRIPT_DIR}/site-a/logs" "${SCRIPT_DIR}/site-b/db" "${SCRIPT_DIR}/site-b/logs"

echo "Building vectis..."
(cd "${ROOT_DIR}" && cargo build)
cp "${ROOT_DIR}/target/debug/vectis" "${BIN_DIR}/vectis"

init_db() {
  local db_path="$1"
  python3 - "${db_path}" "${ROOT_DIR}/src/db/data_schema.sql" <<'PY'
import pathlib
import sqlite3
import sys

db_path = sys.argv[1]
schema_path = pathlib.Path(sys.argv[2])
connection = sqlite3.connect(db_path)
connection.executescript(schema_path.read_text(encoding="utf-8"))
connection.commit()
connection.close()
PY
}

write_env() {
  local site="$1"
  local bind_addr="$2"
  local public_addr="$3"
  local final_app_addr="$4"
  local sender_hostname="$5"
  local receiver_hostname="$6"

  cat > "${SCRIPT_DIR}/${site}/.env" <<ENV
VECTIS_HTTP_BIND_ADDR=${bind_addr}
VECTIS_SERVER_SCHEME=http
VECTIS_REMOTE_SCHEME=http
VECTIS_FINAL_APP_SCHEME=http
VECTIS_TLS_SKIP_VERIFY=false
VECTIS_API_URL=http://${bind_addr}
VECTIS_TIMEOUT_SECONDS=30
VECTIS_PUBLIC_ADDR=${public_addr}
VECTIS_FINAL_APP_ADDR=${final_app_addr}
VECTIS_FINAL_APP_PATH=/message
VECTIS_ROUTES_PATH=routes.json
VECTIS_ROUTES_SIGN_PATH=routes_sign.json
VECTIS_LOG_LEVEL=info
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_PROTOCOL_VERSION=v1
VECTIS_STORAGE=sqlite
VECTIS_SQLITE_PATH=db/data.db
VECTIS_SENDER_HOSTNAME=${sender_hostname}
VECTIS_RECEIVER_HOSTNAME=${receiver_hostname}
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-performance-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE="hello vectis demo"
ENV
}

init_db "${SCRIPT_DIR}/site-a/db/data.db"
init_db "${SCRIPT_DIR}/site-b/db/data.db"

write_env "site-a" "127.0.0.1:3001" "127.0.0.1:3001" "127.0.0.1:4001" "site-a.local" "site-b.local"
write_env "site-b" "127.0.0.1:3002" "127.0.0.1:3002" "127.0.0.1:4002" "site-b.local" "site-a.local"

echo "Demo workspace ready."
echo "Next: bash demo/create-keys.sh"
