#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_DIR="${K6_SITE_DIR:-${SCRIPT_DIR}/site}"
VECTIS="${SITE_DIR}/bin/vectis"

if [[ ! -x "${VECTIS}" ]]; then
  echo "Missing ${VECTIS}. Run: bash tests/performance/local/setup.sh" >&2
  exit 1
fi

if [[ -z "${K6_PROFILE:-}" ]]; then
  echo "K6_PROFILE must name the crypto profile this laboratory measures" >&2
  exit 1
fi

# A plain command substitution (unlike a process substitution) stops the script
# under set -e, before any init or key material is created.
kid_env="$(python3 - "${SCRIPT_DIR}" "${K6_PROFILE}" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from catalog import PROFILE_SPECS
matches = [spec["kid_env"] for spec in PROFILE_SPECS if spec["name"] == sys.argv[2]]
if not matches:
    sys.exit("unknown performance crypto profile")
print(matches[0])
PY
)"

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local temporary
  temporary="$(mktemp)"
  grep -v "^${key}=" "${file}" > "${temporary}" || true
  printf '%s=%s\n' "${key}" "${value}" >> "${temporary}"
  mv "${temporary}" "${file}"
}

extract_value() {
  local key="$1"
  awk -F= -v key="${key}" '$1 == key { print substr($0, length(key) + 2); exit }'
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

for _ in range(60):
    try:
        with urllib.request.urlopen(sys.argv[1], timeout=1) as response:
            if json.loads(response.read().decode("utf-8")).get("status") == "ready":
                raise SystemExit(0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        pass
    time.sleep(0.5)
raise SystemExit(f"timed out waiting for {sys.argv[1]}")
PY
}

stop_vectis() {
  if kill -0 "$1" 2>/dev/null; then
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
  fi
}

cd "${SITE_DIR}"
umask 077
init_output="$(./bin/vectis init)"
unseal_key="$(printf '%s\n' "${init_output}" | extract_value VECTIS_UNSEAL_KEY)"
root_apikey="$(printf '%s\n' "${init_output}" | extract_value VECTIS_APIKEY)"
root_apikey_hash="$(printf '%s\n' "${init_output}" | extract_value VECTIS_APIKEY_HASH)"

if [[ -z "${unseal_key}" || -z "${root_apikey}" || -z "${root_apikey_hash}" ]]; then
  echo "vectis init did not return required bootstrap values" >&2
  exit 1
fi

printf '%s\n' "${unseal_key}" > .unseal_key
chmod 600 .unseal_key
set_env_value .env VECTIS_APIKEY "${root_apikey}"
set_env_value .env VECTIS_APIKEY_HASH "${root_apikey_hash}"

./bin/vectis serve > logs/bootstrap.log 2>&1 &
server_pid="$!"
trap 'stop_vectis "${server_pid}"' EXIT
wait_ready "http://127.0.0.1:${K6_PORT:-3020}/healthz/ready"

create_kid() {
  local profile="$1"
  ./bin/vectis keys create --tag "k6-${profile}" --profile "${profile}" --output json | json_field kid
}

kid="$(create_kid "${K6_PROFILE}")"
printf '%s=%s\n' "${kid_env}" "${kid}" >> app.env
app_key_output="$(./bin/vectis apikey create --output json)"
app_apikey="$(printf '%s\n' "${app_key_output}" | json_field VECTIS_APIKEY)"
app_apikey_hash="$(printf '%s\n' "${app_key_output}" | json_field VECTIS_APIKEY_HASH)"

cat >> app.env <<ENV
K6_BASE_URL=http://127.0.0.1:${K6_PORT:-3020}
K6_APIKEY=${app_apikey}
K6_APIKEY_HASH=${app_apikey_hash}
K6_CLIENT=k6-performance
ENV

echo "Created performance KID for ${K6_PROFILE}."
