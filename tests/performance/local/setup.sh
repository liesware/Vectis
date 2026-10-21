#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SITE_DIR="${K6_SITE_DIR:-${SCRIPT_DIR}/site}"
BIN_DIR="${SITE_DIR}/bin"
PORT="${K6_PORT:-3020}"

# The runner owns the release build; this script only installs its binary.
if [[ -z "${K6_BINARY:-}" || ! -x "${K6_BINARY}" ]]; then
  echo "K6_BINARY must point to the vectis binary built by runner.py" >&2
  exit 1
fi

if [[ -e "${SITE_DIR}" ]]; then
  echo "Refusing to overwrite an existing performance workspace: ${SITE_DIR}" >&2
  exit 1
fi
umask 077
mkdir -p "${BIN_DIR}" "${SITE_DIR}/db" "${SITE_DIR}/logs"

cp "${K6_BINARY}" "${BIN_DIR}/vectis"

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

cat > "${SITE_DIR}/.env" <<ENV
VECTIS_HTTP_BIND_ADDR=127.0.0.1:${PORT}
VECTIS_MODE=dev
VECTIS_TLS_SKIP_VERIFY=false
VECTIS_API_URL=http://127.0.0.1:${PORT}
VECTIS_TIMEOUT_SECONDS=30
VECTIS_PUBLIC_ADDR=127.0.0.1:${PORT}
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
