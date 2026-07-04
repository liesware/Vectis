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

cat > "${SCRIPT_DIR}/site-a/config.json" <<JSON
{
  "version": "v1",
  "routes": [
    {
      "kid": "${A_LOCAL_KID}",
      "name": "site-a-clinical-app",
      "final_app_addr": "${A_APP_BIND_ADDR}",
      "final_app_path": "/message"
    }
  ],
  "remote_routes": [
    {
      "remote_kid": "${B_LOCAL_KID}",
      "name": "site-b",
      "remote_addr": "${A_REMOTE_VECTIS_HOST}",
      "allowed_local_kids": ["${A_LOCAL_KID}"],
      "status": "active"
    }
  ],
  "permissions": [
    {
      "client": "${A_APP_CLIENT}",
      "apikey_hash": "${A_APP_APIKEY_HASH}",
      "status": "active",
      "permissions": [
        {
          "kid": "${A_LOCAL_KID}",
          "actions": ["message"]
        }
      ]
    }
  ]
}
JSON

cat > "${SCRIPT_DIR}/site-b/config.json" <<JSON
{
  "version": "v1",
  "routes": [
    {
      "kid": "${B_LOCAL_KID}",
      "name": "site-b-clinical-app",
      "final_app_addr": "${B_APP_BIND_ADDR}",
      "final_app_path": "/message"
    }
  ],
  "remote_routes": [
    {
      "remote_kid": "${A_LOCAL_KID}",
      "name": "site-a",
      "remote_addr": "${B_REMOTE_VECTIS_HOST}",
      "allowed_local_kids": ["${B_LOCAL_KID}"],
      "status": "active"
    }
  ],
  "permissions": [
    {
      "client": "${B_APP_CLIENT}",
      "apikey_hash": "${B_APP_APIKEY_HASH}",
      "status": "active",
      "permissions": [
        {
          "kid": "${B_LOCAL_KID}",
          "actions": ["message"]
        }
      ]
    }
  ]
}
JSON

# Embed each peer's public keys (captured from /pub during create-keys) into the
# other site's remote_routes entry, so cross-instance verification and /message
# use the signed config directly instead of fetching /pub.
if [[ -f "${SCRIPT_DIR}/site-a/pub.json" && -f "${SCRIPT_DIR}/site-b/pub.json" ]]; then
  python3 - "${SCRIPT_DIR}" "${A_LOCAL_KID}" "${B_LOCAL_KID}" <<'PY'
import json, sys
root, kid_a, kid_b = sys.argv[1], sys.argv[2], sys.argv[3]
pub_a = json.load(open(f"{root}/site-a/pub.json"))["keys"]
pub_b = json.load(open(f"{root}/site-b/pub.json"))["keys"]

def embed(site, remote_kid, peer_keys):
    path = f"{root}/{site}/config.json"
    cfg = json.load(open(path))
    for r in cfg["remote_routes"]:
        if r["remote_kid"] == remote_kid:
            r["public_keys"] = peer_keys
    json.dump(cfg, open(path, "w"), indent=2)

embed("site-a", kid_b, pub_b)  # site-a trusts site-b's keys
embed("site-b", kid_a, pub_a)  # site-b trusts site-a's keys
PY
fi

(cd "${SCRIPT_DIR}/site-a" && ../bin/vectis config sign --output json >/dev/null)
(cd "${SCRIPT_DIR}/site-b" && ../bin/vectis config sign --output json >/dev/null)

echo "Signed unified config for both sites:"
echo "  site-a -> ${A_APP_BIND_ADDR}/message (${A_LOCAL_KID}), remote site-b (${B_LOCAL_KID})"
echo "  site-b -> ${B_APP_BIND_ADDR}/message (${B_LOCAL_KID}), remote site-a (${A_LOCAL_KID})"
