#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VECTIS="${SCRIPT_DIR}/bin/vectis"

if [[ ! -x "${VECTIS}" ]]; then
  echo "Missing ${VECTIS}. Run: bash demo/setup.sh" >&2
  exit 1
fi

init_db() {
  local site_dir="$1"
  rm -f "${site_dir}/db/data.db"
  python3 - "${site_dir}/db/data.db" "${ROOT_DIR}/src/db/data_schema.sql" <<'PY'
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

create_client_api_key_pair() {
  local site="$1"
  local site_dir="${SCRIPT_DIR}/${site}"
  (cd "${site_dir}" && ../bin/vectis apikey create --output json)
}

write_permissions() {
  local site="$1"
  local client="$2"
  local apikey_hash="$3"
  local kid="$4"
  local site_dir="${SCRIPT_DIR}/${site}"

  cat > "${site_dir}/permissions.json" <<JSON
{
  "version": "v1",
  "clients": [
    {
      "client": "${client}",
      "apikey_hash": "${apikey_hash}",
      "status": "active",
      "permissions": [
        {
          "kid": "${kid}",
          "actions": ["message"]
        }
      ]
    }
  ]
}
JSON

  (cd "${site_dir}" && ../bin/vectis permissions sign --output json >/dev/null)
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

prepare_site() {
  local site="$1"
  local site_dir="${SCRIPT_DIR}/${site}"

  init_db "${site_dir}"
  rm -f \
    "${site_dir}/init.json" \
    "${site_dir}/routes.json" \
    "${site_dir}/routes_sign.json" \
    "${site_dir}/remote_routes.json" \
    "${site_dir}/remote_routes_sign.json" \
    "${site_dir}/permissions.json" \
    "${site_dir}/permissions_sign.json" \
    "${site_dir}/.unseal_key"

  local init_output
  init_output="$(cd "${site_dir}" && ../bin/vectis init)"
  local unseal_key
  local apikey
  local apikey_hash
  unseal_key="$(printf '%s\n' "${init_output}" | extract_init_value "VECTIS_UNSEAL_KEY")"
  apikey="$(printf '%s\n' "${init_output}" | extract_init_value "VECTIS_APIKEY")"
  apikey_hash="$(printf '%s\n' "${init_output}" | extract_init_value "VECTIS_APIKEY_HASH")"

  printf '%s\n' "${unseal_key}" > "${site_dir}/.unseal_key"
  chmod 600 "${site_dir}/.unseal_key"
  set_env_value "${site_dir}/.env" "VECTIS_APIKEY" "${apikey}"
  set_env_value "${site_dir}/.env" "VECTIS_APIKEY_HASH" "${apikey_hash}"
}

start_vectis() {
  local site="$1"
  local site_dir="${SCRIPT_DIR}/${site}"
  (cd "${site_dir}" && exec ../bin/vectis serve) > "${site_dir}/logs/${site}.log" 2>&1 &
  echo "$!"
}

stop_vectis() {
  local pid="$1"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

create_key() {
  local site="$1"
  local tag="$2"
  local site_dir="${SCRIPT_DIR}/${site}"
  (cd "${site_dir}" && ../bin/vectis keys create --tag "${tag}" --profile hybrid-performance-v1 --output json) | json_field "id"
}

create_site_key() {
  local site="$1"
  local tag="$2"
  local ready_url="$3"
  local pid
  local kid

  pid="$(start_vectis "${site}")"
  if ! wait_ready "${ready_url}"; then
    stop_vectis "${pid}"
    return 1
  fi

  if ! kid="$(create_key "${site}" "${tag}")"; then
    stop_vectis "${pid}"
    return 1
  fi

  stop_vectis "${pid}"
  printf '%s\n' "${kid}"
}

prepare_site "site-a"
prepare_site "site-b"

kid_a="$(create_site_key "site-a" "clinic-a-records" "http://127.0.0.1:3001/healthz/ready")"
kid_b="$(create_site_key "site-b" "clinic-b-records" "http://127.0.0.1:3002/healthz/ready")"
app_api_output_a="$(create_client_api_key_pair "site-a")"
app_api_output_b="$(create_client_api_key_pair "site-b")"
app_apikey_a="$(printf '%s\n' "${app_api_output_a}" | json_field "VECTIS_APIKEY")"
app_apikey_hash_a="$(printf '%s\n' "${app_api_output_a}" | json_field "VECTIS_APIKEY_HASH")"
app_apikey_b="$(printf '%s\n' "${app_api_output_b}" | json_field "VECTIS_APIKEY")"
app_apikey_hash_b="$(printf '%s\n' "${app_api_output_b}" | json_field "VECTIS_APIKEY_HASH")"

write_permissions "site-a" "clinic-a-app" "${app_apikey_hash_a}" "${kid_a}"
write_permissions "site-b" "clinic-b-app" "${app_apikey_hash_b}" "${kid_b}"

cat > "${SCRIPT_DIR}/site-a/app.env" <<ENV
APP_NAME=clinic-a
APP_BIND_ADDR=127.0.0.1:4001
VECTIS_URL=http://127.0.0.1:3001
LOCAL_KID=${kid_a}
REMOTE_APP_NAME=clinic-b
REMOTE_VECTIS_HOST=127.0.0.1:3002
REMOTE_KID=${kid_b}
VECTIS_APIKEY=${app_apikey_a}
ENV

cat > "${SCRIPT_DIR}/site-b/app.env" <<ENV
APP_NAME=clinic-b
APP_BIND_ADDR=127.0.0.1:4002
VECTIS_URL=http://127.0.0.1:3002
LOCAL_KID=${kid_b}
REMOTE_APP_NAME=clinic-a
REMOTE_VECTIS_HOST=127.0.0.1:3001
REMOTE_KID=${kid_a}
VECTIS_APIKEY=${app_apikey_b}
ENV

echo "Created demo keys:"
echo "  site-a kid: ${kid_a}"
echo "  site-b kid: ${kid_b}"
echo "Created and signed permissions:"
echo "  site-a client: clinic-a-app -> message on ${kid_a}"
echo "  site-b client: clinic-b-app -> message on ${kid_b}"
echo "Next: bash demo/configure-routes.sh"
