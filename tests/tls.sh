#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${VECTIS_BIN:-$ROOT/target/debug/vectis}"
if [[ "$BINARY" != /* ]]; then
  BINARY="$ROOT/$BINARY"
fi
test -x "$BINARY"

LAB="$(mktemp -d "${TMPDIR:-/tmp}/vectis-tls.XXXXXX")"
SERVER_PID=

if [[ -n "${VECTIS_TLS_TEST_PORT:-}" ]]; then
  TLS_PORT="$VECTIS_TLS_TEST_PORT"
else
  TLS_PORT="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
fi

cleanup() {
  status="$?"
  trap - EXIT

  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -INT "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  if [[ "$status" -ne 0 && -f "$LAB/server.out" ]]; then
    echo "[smoke] TLS test failed; Vectis log follows:" >&2
    tail -n 200 "$LAB/server.out" >&2 || true
  fi

  rm -rf "$LAB"
  exit "$status"
}
trap cleanup EXIT

echo "[smoke] workspace"
cp "$BINARY" "$LAB/vectis"
chmod 755 "$LAB/vectis"
cd "$LAB"
mkdir -p db logs tls
sqlite3 db/data.db < "$ROOT/src/db/sqlite_schema.sql"

cat > tls/openssl.cnf <<'EOF'
[req]
prompt = no
distinguished_name = subject
x509_extensions = server
[subject]
CN = localhost
[server]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1 \
  -keyout tls/server-key.pem -out tls/server-cert.pem \
  -config tls/openssl.cnf -extensions server >/dev/null 2>&1

echo "[smoke] init"
INIT_OUTPUT="$(./vectis init)"
value() { printf '%s\n' "$INIT_OUTPUT" | awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }'; }
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
VECTIS_SENDER_HOSTNAME=vectis-lab.local
VECTIS_RECEIVER_HOSTNAME=vectis-lab.local
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE=vectis-lab-self-test
EOF
chmod 600 .env

echo "[smoke] serve"
./vectis serve >server.out 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 180); do
  ./vectis health ready --output json >/dev/null 2>&1 && break
  sleep 0.25
done
if ! ./vectis health ready --output json >/dev/null 2>&1; then
  cat server.out >&2
  exit 1
fi

echo "[smoke] key and config"
KID="$(./vectis keys create --tag getting-started --profile hybrid-standard-v1 --output json | jq -r .kid)"
APP_KEY_OUTPUT="$(./vectis apikey create --output json)"
APP_APIKEY="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r .VECTIS_APIKEY)"
APP_APIKEY_HASH="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r .VECTIS_APIKEY_HASH)"
./vectis config init >/dev/null
./vectis config permissions add --client lab-app --apikey-hash "$APP_APIKEY_HASH" --status active >/dev/null
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
  ./vectis config permissions grant lab-app --kid "$KID" --action "$action" >/dev/null
done
./vectis config fpe add --name pan-decimal-v1 --kid "$KID" --alphabet 0123456789 \
  --min-len 16 --max-len 16 --tweak-aad 'tenant=lab;field=pan;version=1' >/dev/null
./vectis config masking add --name pan-display-v1 --kid "$KID" --visible-first 0 \
  --visible-last 4 --mask-char '*' --min-len 16 --max-len 16 >/dev/null
./vectis config token add --name pan-token-v1 --kid "$KID" --token-prefix tok_pan \
  --token-len 32 --max-plaintext-len 128 --one-time false >/dev/null
./vectis config mac add --name pan-equality-v1 --kid "$KID" \
  --context 'tenant=lab;field=pan;purpose=equality;version=1' >/dev/null
./vectis config commitment add --name pan-commitment-v1 --kid "$KID" \
  --context 'tenant=lab;field=pan;purpose=commitment;version=1' \
  --max-plaintext-len 128 --opening-len 32 >/dev/null
./vectis config sharing add --name secret-3of5-v1 --kid "$KID" \
  --threshold 3 --shares 5 --max-secret-len 4096 \
  --context 'tenant=lab;purpose=secret-sharing;version=1' >/dev/null
./vectis config validate --output json >/dev/null
./vectis config sign --output json >/dev/null
./vectis config reload --output json >/dev/null

echo "[smoke] operations"
VECTIS_APIKEY="$APP_APIKEY" ./vectis fpe encrypt "$KID" \
  --json '{"ref":"pan-1","profile":"pan-decimal-v1","plaintext":"4111111111111111"}' \
  --output json | jq -e '.ciphertext | length == 16' >/dev/null
VECTIS_APIKEY="$APP_APIKEY" ./vectis mask "$KID" \
  --json '{"ref":"pan-5","profile":"pan-display-v1","plaintext":"4111111111111111"}' \
  --output json | jq -e '.masked == "************1111"' >/dev/null

TOKEN="$(VECTIS_APIKEY="$APP_APIKEY" ./vectis token encode "$KID" \
  --json '{"ref":"pan-2","profile":"pan-token-v1","plaintext":"4111111111111111","metadata":{"source":"getting-started"}}' \
  --output json | jq -r .token)"
TOKEN_INPUT="$(jq -nc --arg kid "$KID" --arg token "$TOKEN" \
  '{ref:"pan-2",kid:$kid,profile:"pan-token-v1",token:$token}')"
VECTIS_APIKEY="$APP_APIKEY" ./vectis token decode --json "$TOKEN_INPUT" \
  --output json | jq -e '.plaintext == "4111111111111111" and .metadata.source == "getting-started"' >/dev/null

DIGEST="$(VECTIS_APIKEY="$APP_APIKEY" ./vectis mac create "$KID" \
  --json '{"ref":"pan-3","profile":"pan-equality-v1","plaintext":"4111111111111111"}' \
  --output json | jq -r .digest)"
MAC_INPUT="$(jq -nc --arg kid "$KID" --arg digest "$DIGEST" \
  '{ref:"pan-3",kid:$kid,profile:"pan-equality-v1",plaintext:"4111111111111111",digest:$digest}')"
VECTIS_APIKEY="$APP_APIKEY" ./vectis mac verify --json "$MAC_INPUT" \
  --output json | jq -e '.valid == true' >/dev/null

VECTIS_APIKEY="$APP_APIKEY" ./vectis index create "$KID" \
  --json '{"ref":"pan-4","profile":"pan-equality-v1","plaintext":"4111111111111111"}' \
  --output json | jq -e '.index | length > 0' >/dev/null
INDEX_INPUT="$(jq -nc --arg kid "$KID" \
  '{ref:"pan-4",kid:$kid,profile:"pan-equality-v1",plaintext:"4111111111111111"}')"
VECTIS_APIKEY="$APP_APIKEY" ./vectis index verify --json "$INDEX_INPUT" \
  --output json | jq -e '.matched == true' >/dev/null

COMMIT_OUTPUT="$(VECTIS_APIKEY="$APP_APIKEY" ./vectis commit create "$KID" \
  --json '{"ref":"pan-6","profile":"pan-commitment-v1","plaintext":"4111111111111111"}' \
  --output json)"
OPENING="$(printf '%s\n' "$COMMIT_OUTPUT" | jq -r .opening)"
COMMITMENT="$(printf '%s\n' "$COMMIT_OUTPUT" | jq -r .commitment)"
COMMIT_INPUT="$(jq -nc --arg kid "$KID" --arg opening "$OPENING" \
  --arg commitment "$COMMITMENT" \
  '{ref:"pan-6",kid:$kid,profile:"pan-commitment-v1",plaintext:"4111111111111111",opening:$opening,commitment:$commitment}')"
VECTIS_APIKEY="$APP_APIKEY" ./vectis commit verify --json "$COMMIT_INPUT" \
  --output json | jq -e '.valid == true' >/dev/null

SHARE_OUTPUT="$(VECTIS_APIKEY="$APP_APIKEY" ./vectis shares split "$KID" \
  --json '{"profile":"secret-3of5-v1","plaintext":"customer-secret-demo"}' \
  --output json)"
FIRST_THREE="$(printf '%s\n' "$SHARE_OUTPUT" | jq -c '.shares[:3]')"
COMBINE_INPUT="$(jq -nc --arg kid "$KID" --argjson shares "$FIRST_THREE" \
  '{kid:$kid,profile:"secret-3of5-v1",shares:$shares}')"
VECTIS_APIKEY="$APP_APIKEY" ./vectis shares combine --json "$COMBINE_INPUT" \
  --output json | jq -e '.plaintext == "customer-secret-demo"' >/dev/null

VECTIS_APIKEY="$APP_APIKEY" ./vectis sign "$KID" \
  --json '{"message_hash":{"alg":"SHA-256","hex":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}' \
  --output json > signature.json
./vectis sign verify --file signature.json --output json | jq -e '.valid == "ok"' >/dev/null

echo "[smoke] lifecycle and audit"
./vectis lifecycle "$KID" --status disabled --reason maintenance >/dev/null
./vectis lifecycle "$KID" --status active --reason maintenance-complete >/dev/null
kill -INT "$SERVER_PID"
# A nonzero graceful-shutdown status must not abort the smoke test before the
# audit verification below; cleanup() guards its wait the same way.
wait "$SERVER_PID" || true
SERVER_PID=
./vectis audit verify --file logs/audit.log --output json >/dev/null
echo "[smoke] ok"
