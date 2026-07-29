#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_DIR="${SCRIPT_DIR}/site"
K6_SCRIPT="${SCRIPT_DIR}/../k6.js"
server_pid=""

wait_ready() {
  python3 - "http://127.0.0.1:3020/healthz/ready" <<'PY'
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
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  server_pid=""
}

cleanup() {
  stop_vectis
}
trap cleanup EXIT

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 must be installed to run the performance harness" >&2
  exit 1
fi

bash "${SCRIPT_DIR}/setup.sh"
bash "${SCRIPT_DIR}/create-keys.sh"
bash "${SCRIPT_DIR}/configure-config.sh"

set -a
# shellcheck disable=SC1091
source "${SITE_DIR}/app.env"
set +a

bash "${SCRIPT_DIR}/start-vectis.sh" > "${SITE_DIR}/logs/vectis.log" 2>&1 &
server_pid="$!"
wait_ready

set +e
VECTIS_API_URL="${K6_BASE_URL}" \
VECTIS_APIKEY="${K6_APIKEY}" \
K6_KID_PERFORMANCE="${K6_KID_PERFORMANCE}" \
K6_KID_STANDARD="${K6_KID_STANDARD}" \
K6_KID_HIGH_ASSURANCE="${K6_KID_HIGH_ASSURANCE}" \
K6_KID_LONG_TERM="${K6_KID_LONG_TERM}" \
k6 run "${K6_SCRIPT}"
k6_status="$?"
set -e

stop_vectis

set +e
(cd "${SITE_DIR}" && ./bin/vectis audit verify --file logs/audit.jsonl)
audit_status="$?"
set -e

if [[ "${k6_status}" -ne 0 ]]; then
  exit "${k6_status}"
fi
exit "${audit_status}"
