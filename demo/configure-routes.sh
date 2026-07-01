#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

load_app_env() {
  local file="$1"
  local prefix="$2"
  while IFS='=' read -r key value; do
    [[ -z "${key}" || "${key}" == \#* ]] && continue
    printf -v "${prefix}_${key}" '%s' "${value}"
  done < "${file}"
}

if [[ ! -f "${SCRIPT_DIR}/site-a/app.env" || ! -f "${SCRIPT_DIR}/site-b/app.env" ]]; then
  echo "Missing app.env files. Run: bash demo/create-keys.sh" >&2
  exit 1
fi

load_app_env "${SCRIPT_DIR}/site-a/app.env" "A"
load_app_env "${SCRIPT_DIR}/site-b/app.env" "B"

cat > "${SCRIPT_DIR}/site-a/routes.json" <<JSON
{
  "version": "v1",
  "routes": [
    {
      "kid": "${A_LOCAL_KID}",
      "final_app_addr": "${A_APP_BIND_ADDR}",
      "final_app_path": "/message"
    }
  ]
}
JSON

cat > "${SCRIPT_DIR}/site-b/routes.json" <<JSON
{
  "version": "v1",
  "routes": [
    {
      "kid": "${B_LOCAL_KID}",
      "final_app_addr": "${B_APP_BIND_ADDR}",
      "final_app_path": "/message"
    }
  ]
}
JSON

cat > "${SCRIPT_DIR}/site-a/remote_routes.json" <<JSON
{
  "version": "v1",
  "routes": [
    {
      "remote_kid": "${B_LOCAL_KID}",
      "name": "site-b",
      "remote_addr": "${A_REMOTE_VECTIS_HOST}",
      "allowed_local_kids": ["${A_LOCAL_KID}"],
      "status": "active"
    }
  ]
}
JSON

cat > "${SCRIPT_DIR}/site-b/remote_routes.json" <<JSON
{
  "version": "v1",
  "routes": [
    {
      "remote_kid": "${A_LOCAL_KID}",
      "name": "site-a",
      "remote_addr": "${B_REMOTE_VECTIS_HOST}",
      "allowed_local_kids": ["${B_LOCAL_KID}"],
      "status": "active"
    }
  ]
}
JSON

(cd "${SCRIPT_DIR}/site-a" && ../bin/vectis routes sign --output json >/dev/null)
(cd "${SCRIPT_DIR}/site-b" && ../bin/vectis routes sign --output json >/dev/null)
(cd "${SCRIPT_DIR}/site-a" && ../bin/vectis remote-routes sign --output json >/dev/null)
(cd "${SCRIPT_DIR}/site-b" && ../bin/vectis remote-routes sign --output json >/dev/null)

echo "Routes created and signed:"
echo "  site-a -> ${A_APP_BIND_ADDR}/message (${A_LOCAL_KID})"
echo "  site-b -> ${B_APP_BIND_ADDR}/message (${B_LOCAL_KID})"
echo "Remote routes created and signed:"
echo "  site-a -> ${A_REMOTE_VECTIS_HOST} (${B_LOCAL_KID})"
echo "  site-b -> ${B_REMOTE_VECTIS_HOST} (${A_LOCAL_KID})"
