#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SITE_DIR="${SCRIPT_DIR}/site"
VECTIS="${SCRIPT_DIR}/bin/vectis"

if [[ ! -x "${VECTIS}" ]]; then
  echo "Missing ${VECTIS}. Run: bash demo/local/setup.sh" >&2
  exit 1
fi

python3 - "${SITE_DIR}/db/data.db" "${ROOT_DIR}/src/db/sqlite_schema.sql" <<'PY'
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

set_env_value() {
  local env_file="$1"
  local key="$2"
  local value="$3"
  local tmp_file
  tmp_file="$(mktemp)"
  grep -v "^${key}=" "${env_file}" > "${tmp_file}" || true
  printf '%s=%s\n' "${key}" "${value}" >> "${tmp_file}"
  mv "${tmp_file}" "${env_file}"
}

extract_init_value() {
  local key="$1"
  awk -F= -v key="${key}" '
    $1 == key {
      print substr($0, length(key) + 2)
      found = 1
      exit
    }
    END {
      if (!found) {
        exit 1
      }
    }
  '
}

json_field() {
  local field="$1"
  python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "${field}"
}

wait_ready() {
  local url="$1"
  python3 - "${url}" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

url = sys.argv[1]
for _ in range(60):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            payload = json.loads(response.read().decode("utf-8"))
            if payload.get("status") == "ready":
                raise SystemExit(0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        pass
    time.sleep(0.5)
raise SystemExit(f"timed out waiting for {url}")
PY
}

start_vectis() {
  (cd "${SITE_DIR}" && exec ../bin/vectis serve) > "${SITE_DIR}/logs/local.log" 2>&1 &
  echo "$!"
}

stop_vectis() {
  local pid="$1"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

rm -f \
  "${SITE_DIR}/init.json" \
  "${SITE_DIR}/config.json" \
  "${SITE_DIR}/config_sign.json" \
  "${SITE_DIR}/.unseal_key"

init_output="$(cd "${SITE_DIR}" && ../bin/vectis init)"
unseal_key="$(printf '%s\n' "${init_output}" | extract_init_value "VECTIS_UNSEAL_KEY")"
root_apikey="$(printf '%s\n' "${init_output}" | extract_init_value "VECTIS_APIKEY")"
root_apikey_hash="$(printf '%s\n' "${init_output}" | extract_init_value "VECTIS_APIKEY_HASH")"

printf '%s\n' "${unseal_key}" > "${SITE_DIR}/.unseal_key"
chmod 600 "${SITE_DIR}/.unseal_key"
set_env_value "${SITE_DIR}/.env" "VECTIS_APIKEY" "${root_apikey}"
set_env_value "${SITE_DIR}/.env" "VECTIS_APIKEY_HASH" "${root_apikey_hash}"

pid="$(start_vectis)"
trap 'stop_vectis "${pid}"' EXIT
wait_ready "http://127.0.0.1:3010/healthz/ready"

local_kid="$(
  (cd "${SITE_DIR}" && ../bin/vectis keys create --tag local-data-protection --profile hybrid-standard-v1 --output json) \
    | json_field "kid"
)"
app_api_output="$(cd "${SITE_DIR}" && ../bin/vectis apikey create --output json)"
app_apikey="$(printf '%s\n' "${app_api_output}" | json_field "VECTIS_APIKEY")"
app_apikey_hash="$(printf '%s\n' "${app_api_output}" | json_field "VECTIS_APIKEY_HASH")"

cat > "${SITE_DIR}/app.env" <<ENV
APP_NAME=local-demo
VECTIS_URL=http://127.0.0.1:3010
LOCAL_KID=${local_kid}
VECTIS_APIKEY=${app_apikey}
APP_CLIENT=local-demo-app
APP_APIKEY_HASH=${app_apikey_hash}
ENV

echo "Created local demo key:"
echo "  local kid: ${local_kid}"
echo "Next: bash demo/local/configure-config.sh"
