#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY="${VECTIS_BIN:-$ROOT/target/debug/vectis}"
if [[ "$BINARY" != /* ]]; then
  BINARY="$ROOT/$BINARY"
fi

RESULTS="${ZAP_RESULTS_DIR:-$ROOT/zap-results}"
ZAP_IMAGE="${ZAP_DOCKER_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef}"
KID_PLACEHOLDER="f55f086e75b58ac4dfaffd3e75c90d25719281df90e87880145fb9f2e32f2eed"

for command in curl docker jq openssl python3 sqlite3 timeout uv; do
  command -v "$command" >/dev/null || {
    echo "[zap] required command not found: $command" >&2
    exit 1
  }
done
test -x "$BINARY"
if [[ ! "$ZAP_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
  echo "[zap] ZAP_DOCKER_IMAGE must be pinned by sha256 digest" >&2
  exit 1
fi

mkdir -p "$RESULTS"
RESULTS="$(cd "$RESULTS" && pwd)"
rm -f \
  "$RESULTS/openapi-zap.json" \
  "$RESULTS/report.html" \
  "$RESULTS/report.md" \
  "$RESULTS/report.json" \
  "$RESULTS/report.xml" \
  "$RESULTS/vectis.log" \
  "$RESULTS/zap-exit-code.txt" \
  "$RESULTS/zap.log"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/vectis-zap.XXXXXX")"
SERVER_PID=
APP_APIKEY=

redact_results() {
  if [[ -z "$APP_APIKEY" || ! -d "$RESULTS" ]]; then
    return
  fi

  REDACT_SECRET="$APP_APIKEY" REDACT_DIRECTORY="$RESULTS" python3 - <<'PY'
import os
from pathlib import Path

secret = os.environ["REDACT_SECRET"].encode()
directory = Path(os.environ["REDACT_DIRECTORY"])
replacement = b"<redacted>"

for path in directory.iterdir():
    if not path.is_file():
        continue
    data = path.read_bytes()
    temporary = path.with_name(f".{path.name}.redacted")
    temporary.write_bytes(data.replace(secret, replacement))
    temporary.chmod(0o600)
    os.replace(temporary, path)
PY
}

cleanup() {
  status="$?"
  trap - EXIT

  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  if [[ -f "$LAB/server.out" ]]; then
    cp "$LAB/server.out" "$RESULTS/vectis.log" || true
  fi
  redact_results || true
  chmod 700 "$RESULTS" 2>/dev/null || true

  if [[ "$status" -ne 0 ]]; then
    echo "[zap] scan failed; Vectis log follows:" >&2
    tail -n 200 "$LAB/server.out" 2>/dev/null >&2 || true
    echo "[zap] ZAP log follows:" >&2
    tail -n 200 "$RESULTS/zap.log" 2>/dev/null >&2 || true
  fi

  rm -rf "$LAB"
  exit "$status"
}
trap cleanup EXIT

if [[ -n "${VECTIS_ZAP_TEST_PORT:-}" ]]; then
  TLS_PORT="$VECTIS_ZAP_TEST_PORT"
else
  TLS_PORT="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
fi
BASE_URL="https://127.0.0.1:${TLS_PORT}"

echo "[zap] prepare disposable HTTPS node"
cp "$BINARY" "$LAB/vectis"
chmod 755 "$LAB/vectis"
cd "$LAB"
mkdir -p db logs tls
sqlite3 db/data.db < "$ROOT/src/db/sqlite_schema.sql"
export VECTIS_SQLITE_PATH="$LAB/db/data.db"

cat > tls/openssl.cnf <<'EOF'
[req]
prompt = no
distinguished_name = subject
x509_extensions = server
[subject]
CN = localhost
[server]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
openssl ecparam -name prime256v1 -genkey -noout -out tls/server-key.pem
openssl req -new -x509 -sha256 -days 1 \
  -key tls/server-key.pem -out tls/server-cert.pem \
  -config tls/openssl.cnf -extensions server >/dev/null 2>&1
chmod 600 tls/server-key.pem

INIT_OUTPUT="$(./vectis init)"
value() {
  printf '%s\n' "$INIT_OUTPUT" |
    awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }'
}
UNSEAL_KEY="$(value VECTIS_UNSEAL_KEY)"
ROOT_APIKEY="$(value VECTIS_APIKEY)"
ROOT_APIKEY_HASH="$(value VECTIS_APIKEY_HASH)"
printf '%s\n' "$UNSEAL_KEY" > .unseal_key
chmod 600 .unseal_key

cat > .env <<EOF
VECTIS_MODE=prod
VECTIS_HTTP_BIND_ADDR=127.0.0.1:${TLS_PORT}
VECTIS_PUBLIC_ADDR=localhost:${TLS_PORT}
VECTIS_TLS_CERT_PATH=tls/server-cert.pem
VECTIS_TLS_KEY_PATH=tls/server-key.pem
VECTIS_TLS_SKIP_VERIFY=true
VECTIS_API_URL=https://localhost:${TLS_PORT}
VECTIS_INIT_KEYS_FILE=init.json
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_APIKEY=${ROOT_APIKEY}
VECTIS_APIKEY_HASH=${ROOT_APIKEY_HASH}
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
VECTIS_STORAGE=sqlite
VECTIS_SQLITE_PATH=db/data.db
VECTIS_LOG_LEVEL=warn
VECTIS_LOG_TARGET=file
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.log
VECTIS_PROTOCOL_VERSION=v1
VECTIS_SENDER_HOSTNAME=vectis-zap.local
VECTIS_RECEIVER_HOSTNAME=vectis-zap.local
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE=vectis-zap-self-test
EOF
chmod 600 .env

./vectis serve >server.out 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 180); do
  ./vectis health ready --output json >/dev/null 2>&1 && break
  sleep 0.25
done
if ! ./vectis health ready --output json >/dev/null 2>&1; then
  echo "[zap] Vectis did not become ready" >&2
  exit 1
fi

echo "[zap] configure limited application identity"
KID="$(./vectis keys create --tag zap-scan --profile hybrid-standard-v1 --output json | jq -r .kid)"
APP_KEY_OUTPUT="$(./vectis apikey create --output json)"
APP_APIKEY="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r .VECTIS_APIKEY)"
APP_APIKEY_HASH="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r .VECTIS_APIKEY_HASH)"

./vectis config init >/dev/null
./vectis config permissions add \
  --client zap-app --apikey-hash "$APP_APIKEY_HASH" --status active >/dev/null
for action in \
  fpe-encrypt fpe-decrypt \
  token-encode token-decode \
  mac-create mac-verify \
  index-create index-verify \
  mask \
  commit-create commit-verify \
  share-split share-combine \
  sign
do
  ./vectis config permissions grant zap-app --kid "$KID" --action "$action" >/dev/null
done

./vectis config fpe add --name patient-id-decimal-v1 --kid "$KID" \
  --alphabet 0123456789 --min-len 6 --max-len 32 \
  --tweak-aad 'tenant=zap;field=patient_id;version=1' >/dev/null
./vectis config token add --name patient-id-token-v1 --kid "$KID" \
  --token-prefix tok_patient --token-len 32 --max-plaintext-len 128 \
  --one-time false >/dev/null
./vectis config mac add --name pan-blind-index-v1 --kid "$KID" \
  --context 'tenant=zap;field=pan;purpose=mac;version=1' >/dev/null
./vectis config mac add --name pan-index-v1 --kid "$KID" \
  --context 'tenant=zap;field=pan;purpose=index;version=1' >/dev/null
./vectis config commitment add --name pan-commitment-v1 --kid "$KID" \
  --context 'tenant=zap;field=pan;purpose=commitment;version=1' \
  --max-plaintext-len 128 --opening-len 32 >/dev/null
./vectis config sharing add --name customer-secret-3of5-v1 --kid "$KID" \
  --threshold 3 --shares 5 --max-secret-len 4096 \
  --context 'tenant=zap;purpose=secret-sharing;version=1' >/dev/null
./vectis config masking add --name pan-display-v1 --kid "$KID" \
  --visible-first 0 --visible-last 4 --mask-char '*' \
  --min-len 16 --max-len 16 >/dev/null
./vectis config validate --output json >/dev/null
./vectis config sign --output json >/dev/null
./vectis config reload --output json >/dev/null

VECTIS_APIKEY="$APP_APIKEY" ./vectis fpe encrypt "$KID" \
  --json '{"ref":"zap-preflight","profile":"patient-id-decimal-v1","plaintext":"123456"}' \
  --output json | jq -e '.ciphertext | length == 6' >/dev/null
DENIED_STATUS="$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --header "X-API-Key: $APP_APIKEY" "$BASE_URL/keys/properties")"
if [[ "$DENIED_STATUS" != "403" ]]; then
  echo "[zap] limited API key unexpectedly received HTTP $DENIED_STATUS from /keys/properties" >&2
  exit 1
fi

echo "[zap] prepare OpenAPI document"
export ZAP_OPENAPI_INPUT="$ROOT/doc/openapi.yaml"
export ZAP_OPENAPI_OUTPUT="$RESULTS/openapi-zap.json"
export ZAP_OPENAPI_BASE_URL="$BASE_URL"
export ZAP_OPENAPI_KID="$KID"
export ZAP_OPENAPI_KID_PLACEHOLDER="$KID_PLACEHOLDER"
uv run --project "$ROOT" --group dast --frozen python - <<'PY'
import json
import os
from pathlib import Path

import yaml

source = Path(os.environ["ZAP_OPENAPI_INPUT"])
destination = Path(os.environ["ZAP_OPENAPI_OUTPUT"])
base_url = os.environ["ZAP_OPENAPI_BASE_URL"]
kid = os.environ["ZAP_OPENAPI_KID"]
placeholder = os.environ["ZAP_OPENAPI_KID_PLACEHOLDER"]
replacements = 0


def replace_kid(value):
    global replacements
    if isinstance(value, dict):
        return {key: replace_kid(item) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_kid(item) for item in value]
    if value == placeholder:
        replacements += 1
        return kid
    return value


document = yaml.safe_load(source.read_text(encoding="utf-8"))
if not isinstance(document, dict):
    raise SystemExit("OpenAPI document must be an object")
for required in ("openapi", "paths", "components"):
    if required not in document:
        raise SystemExit(f"OpenAPI document is missing {required}")

document["servers"] = [{"url": base_url, "description": "Disposable ZAP target"}]
document = replace_kid(document)
if replacements == 0:
    raise SystemExit("OpenAPI KID placeholder was not found")

destination.write_text(
    json.dumps(document, indent=2, ensure_ascii=True) + "\n",
    encoding="utf-8",
)
print(f"Prepared OpenAPI with {replacements} KID example replacements")
PY

echo "[zap] run active API scan"
export ZAP_AUTH_HEADER="X-API-Key"
export ZAP_AUTH_HEADER_VALUE="$APP_APIKEY"
export ZAP_AUTH_HEADER_SITE="127.0.0.1"
# The official image runs as the unprivileged zap user. Make only this
# disposable report directory writable across the bind mount.
chmod 777 "$RESULTS"
set +e
timeout --signal=TERM --kill-after=30s 45m \
  docker run --rm --network host --user zap \
    --env ZAP_AUTH_HEADER \
    --env ZAP_AUTH_HEADER_VALUE \
    --env ZAP_AUTH_HEADER_SITE \
    --volume "$RESULTS:/zap/wrk:rw" \
    "$ZAP_IMAGE" \
    zap-api-scan.py \
      -t /zap/wrk/openapi-zap.json \
      -f openapi \
      -r report.html \
      -w report.md \
      -J report.json \
      -x report.xml \
      -T 10 >"$RESULTS/zap.log" 2>&1
ZAP_STATUS="$?"
set -e
printf '%s\n' "$ZAP_STATUS" > "$RESULTS/zap-exit-code.txt"
redact_results
if LC_ALL=C grep -R -F -l -- "$APP_APIKEY" "$RESULTS" >/dev/null 2>&1; then
  echo "[zap] generated evidence still contains the synthetic API key" >&2
  exit 1
fi
cat "$RESULTS/zap.log"

case "$ZAP_STATUS" in
  0)
    echo "[zap] scan completed without configured alerts"
    ;;
  1)
    echo "[zap] scan completed with FAIL alerts (report-only)"
    ;;
  2)
    echo "[zap] scan completed with WARN alerts (report-only)"
    ;;
  *)
    echo "[zap] scanner infrastructure failure, exit code $ZAP_STATUS" >&2
    exit "$ZAP_STATUS"
    ;;
esac

echo "[zap] ok"
