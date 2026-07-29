#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SITE_DIR="${SCRIPT_DIR}/site"
BIN_DIR="${SITE_DIR}/bin"

rm -rf "${SITE_DIR}"
mkdir -p "${BIN_DIR}" "${SITE_DIR}/db" "${SITE_DIR}/logs"

echo "Building vectis performance binary..."
(cd "${ROOT_DIR}" && cargo build)
cp "${ROOT_DIR}/target/debug/vectis" "${BIN_DIR}/vectis"

python3 - "${SITE_DIR}/db/data.db" "${ROOT_DIR}/src/db/sqlite_schema.sql" <<'PY'
import pathlib
import sqlite3
import sys

db_path = pathlib.Path(sys.argv[1])
schema_path = pathlib.Path(sys.argv[2])
connection = sqlite3.connect(db_path)
connection.executescript(schema_path.read_text(encoding="utf-8"))
connection.commit()
connection.close()
PY

cat > "${SITE_DIR}/.env" <<'ENV'
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3020
VECTIS_MODE=dev
VECTIS_TLS_SKIP_VERIFY=false
VECTIS_API_URL=http://127.0.0.1:3020
VECTIS_TIMEOUT_SECONDS=30
VECTIS_PUBLIC_ADDR=127.0.0.1:3020
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
VECTIS_LOG_TARGET=file
VECTIS_LOG_LEVEL=info
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.jsonl
VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_PROTOCOL_VERSION=v1
VECTIS_STORAGE=sqlite
VECTIS_SQLITE_PATH=db/data.db
VECTIS_SENDER_HOSTNAME=k6-performance
VECTIS_RECEIVER_HOSTNAME=k6-performance
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-performance-v1
VECTIS_CRYPTO_POLICY=profile-only
ENV

echo "Performance workspace ready: ${SITE_DIR}"
