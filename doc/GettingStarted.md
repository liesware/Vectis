# Getting Started With Vectis

## Purpose

This tutorial starts from a signed Vectis release and builds one local HTTPS
node backed by SQLite. It creates an operational key, an application identity,
signed capability profiles, and then exercises the main local data-protection
workflows.

All values in this tutorial are synthetic. The TLS certificate and local secret
handling are appropriate for a lab, not a production deployment. Protected
node-to-node messaging is intentionally outside this tutorial; see
[UseCases.md](UseCases.md) and the [message demo](../demo/message/README.md).

## Download And Verify

Open the [Vectis releases page](https://github.com/liesware/Vectis/releases)
in a browser and choose the release you want to install. Download these files
to the same directory:

- `vectis-linux-amd64-vX.Y.Z.tar.gz` for x86-64 Linux, or
  `vectis-linux-arm64-vX.Y.Z.tar.gz` for ARM64 Linux;
- `SHA256SUMS`;
- `SHA256SUMS.sigstore.json`.

Install `tar`, `sha256sum`, and
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) before
continuing. The commands below use the Linux AMD64 archive. For ARM64, replace
`amd64` with `arm64` in `ARCHIVE` and `ARCH_PREFIX`.

Create the lab workspace and move the three downloaded files into it using your
file manager. Then open a terminal in that directory and replace `X.Y.Z` below
with the selected release version:

```sh
mkdir -p "$HOME/vectis-lab"
cd "$HOME/vectis-lab"

ARCH_PREFIX="vectis-linux-amd64-"
ARCHIVE="${ARCH_PREFIX}vX.Y.Z.tar.gz"
RELEASE_TAG="${ARCHIVE#${ARCH_PREFIX}}"
RELEASE_TAG="${RELEASE_TAG%.tar.gz}"
```

Verify the signed checksum manifest. The certificate identity binds the
signature to this repository, release workflow, and exact Git tag:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity \
    "https://github.com/liesware/Vectis/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

Select the expected digest for the downloaded archive:

```sh
EXPECTED="$(awk -v file="$ARCHIVE" '$2 == file { print $1 }' SHA256SUMS)"
test -n "$EXPECTED"
```

```sh
printf '%s  %s\n' "$EXPECTED" "$ARCHIVE" | sha256sum -c -
```

The verification chain is:

```text
Cosign identity -> SHA256SUMS -> release archive -> vectis binary
```

Extract the archive and install the binary into the lab workspace:

```sh
tar -xzf "$ARCHIVE"
install -m 755 "${ARCHIVE%.tar.gz}/vectis" ./vectis
./vectis version
```

The reported version must match `RELEASE_TAG` without its leading `v`. The
build status is currently `Experimental Build`.

## Prepare The Workspace

The remaining commands run from `$HOME/vectis-lab`. Install these local tools:

- `sqlite3`;
- `openssl`;
- `jq`.

Create dedicated data, log, and TLS directories:

```sh
cd "$HOME/vectis-lab"
mkdir -p db logs tls
chmod 700 db logs tls
```

## Initialize SQLite

Create the SQLite database directly from the current Vectis schema:

```sh
sqlite3 db/data.db <<'SQL'
CREATE TABLE IF NOT EXISTS opskeys (
    kid VARCHAR(128) PRIMARY KEY,
    keys VARCHAR(10240) NOT NULL,
    properties VARCHAR(10240) NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    kid VARCHAR(128) NOT NULL,
    hashid VARCHAR(128) NOT NULL,
    data VARCHAR(10240) NOT NULL,
    PRIMARY KEY (kid, hashid)
);

CREATE TABLE IF NOT EXISTS indexes (
    kid VARCHAR(128) NOT NULL,
    digest VARCHAR(128) NOT NULL,
    PRIMARY KEY (kid, digest)
);
SQL

chmod 600 db/data.db
```

SQLite is the single-node backend for this tutorial. Use PostgreSQL for shared
multi-node storage; see [Clustering.md](Clustering.md) and [HA_DR.md](HA_DR.md).

## Create Local TLS

Create an OpenSSL configuration with SAN entries for both names used by the
local client:

```sh
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

openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -days 30 \
  -keyout tls/server-key.pem \
  -out tls/server-cert.pem \
  -config tls/openssl.cnf \
  -extensions server

chmod 600 tls/server-key.pem
```

This is a self-signed, short-lived lab certificate. Production deployments
must use an appropriately managed certificate and must not disable certificate
verification.

## Initialize Vectis

Generate encrypted init material and the root API key pair:

```sh
INIT_OUTPUT="$(./vectis init)"
printf '%s\n' "$INIT_OUTPUT"

UNSEAL_KEY="$(printf '%s\n' "$INIT_OUTPUT" | awk -F= '$1 == "VECTIS_UNSEAL_KEY" { print substr($0, index($0, "=") + 1); exit }')"
ROOT_APIKEY="$(printf '%s\n' "$INIT_OUTPUT" | awk -F= '$1 == "VECTIS_APIKEY" { print substr($0, index($0, "=") + 1); exit }')"
ROOT_APIKEY_HASH="$(printf '%s\n' "$INIT_OUTPUT" | awk -F= '$1 == "VECTIS_APIKEY_HASH" { print substr($0, index($0, "=") + 1); exit }')"

test -n "$UNSEAL_KEY"
test -n "$ROOT_APIKEY"
test -n "$ROOT_APIKEY_HASH"
```

Store the unseal key in its dedicated file. Vectis intentionally does not load
`VECTIS_UNSEAL_KEY` from `.env`:

```sh
printf '%s\n' "$UNSEAL_KEY" > .unseal_key
chmod 600 .unseal_key
```

Create the lab process configuration:

```sh
cat > .env <<EOF
VECTIS_MODE=prod
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3000
VECTIS_PUBLIC_ADDR=localhost:3000
VECTIS_TLS_CERT_PATH=tls/server-cert.pem
VECTIS_TLS_KEY_PATH=tls/server-key.pem
VECTIS_TLS_SKIP_VERIFY=true

VECTIS_API_URL=https://localhost:3000
VECTIS_TIMEOUT_SECONDS=30

VECTIS_INIT_KEYS_FILE=init.json
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_UNSEAL_KEY_FILE=.unseal_key

VECTIS_APIKEY=${ROOT_APIKEY}
VECTIS_APIKEY_HASH=${ROOT_APIKEY_HASH}

VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json

VECTIS_STORAGE=sqlite
VECTIS_SQLITE_PATH=db/data.db

VECTIS_LOG_LEVEL=info
VECTIS_LOG_TARGET=file
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.log
VECTIS_METRICS_ENABLED=true

VECTIS_PROTOCOL_VERSION=v1
VECTIS_SENDER_HOSTNAME=vectis-lab.local
VECTIS_RECEIVER_HOSTNAME=vectis-lab.local
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE=vectis-lab-self-test
EOF

chmod 600 .env
unset INIT_OUTPUT UNSEAL_KEY ROOT_APIKEY ROOT_APIKEY_HASH
```

`VECTIS_TLS_SKIP_VERIFY=true` is used only because this tutorial created a
self-signed certificate. Vectis logs a warning while this setting is active.

## Start And Bootstrap The Node

In terminal 1, from `$HOME/vectis-lab`, start Vectis:

```sh
./vectis serve
```

Leave that process running. In terminal 2, use the same working directory:

```sh
cd "$HOME/vectis-lab"
./vectis health startup
./vectis health live
./vectis health ready
./vectis test init
```

Create one operational key and retain its KID in the terminal session:

```sh
KEY_OUTPUT="$(./vectis keys create \
  --tag getting-started \
  --profile hybrid-standard-v1 \
  --output json)"
printf '%s\n' "$KEY_OUTPUT"

KID="$(printf '%s\n' "$KEY_OUTPUT" | jq -r '.kid')"
test -n "$KID"
export KID

./vectis keys list
./vectis keys properties "$KID"
./vectis pub "$KID"
./vectis test "$KID"
unset KEY_OUTPUT
```

## Create Application Policy

Create a separate API key for the tutorial application:

```sh
APP_KEY_OUTPUT="$(./vectis apikey create --output json)"
APP_APIKEY="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r '.VECTIS_APIKEY')"
APP_APIKEY_HASH="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r '.VECTIS_APIKEY_HASH')"

test -n "$APP_APIKEY"
test -n "$APP_APIKEY_HASH"
unset APP_KEY_OUTPUT
```

Keep `APP_APIKEY` in the shell variable. Only its keyed verifier is written to
signed policy. Initialize `config.json` and register the client:

```sh
./vectis config init
./vectis config permissions add \
  --client lab-app \
  --apikey-hash "$APP_APIKEY_HASH" \
  --status active
```

Grant only the actions used by this tour:

```sh
for ACTION in \
  fpe-encrypt fpe-decrypt \
  token-encode token-decode \
  mac-create mac-verify \
  index-create index-verify \
  mask \
  commit-create commit-verify \
  share-split share-combine \
  sign
do
  ./vectis config permissions grant lab-app \
    --kid "$KID" \
    --action "$ACTION"
done
```

Add one signed profile for each capability:

```sh
./vectis config fpe add \
  --name pan-decimal-v1 \
  --kid "$KID" \
  --alphabet 0123456789 \
  --min-len 16 \
  --max-len 16 \
  --tweak-aad 'tenant=lab;field=pan;version=1'

./vectis config token add \
  --name pan-token-v1 \
  --kid "$KID" \
  --token-prefix tok_pan \
  --token-len 32 \
  --max-plaintext-len 128 \
  --one-time false

./vectis config mac add \
  --name pan-equality-v1 \
  --kid "$KID" \
  --context 'tenant=lab;field=pan;purpose=equality;version=1'

./vectis config commitment add \
  --name pan-commitment-v1 \
  --kid "$KID" \
  --context 'tenant=lab;field=pan;purpose=commitment;version=1' \
  --max-plaintext-len 128 \
  --opening-len 32

./vectis config sharing add \
  --name secret-3of5-v1 \
  --kid "$KID" \
  --threshold 3 \
  --shares 5 \
  --max-secret-len 4096 \
  --context 'tenant=lab;purpose=secret-sharing;version=1'

./vectis config masking add \
  --name pan-display-v1 \
  --kid "$KID" \
  --visible-first 0 \
  --visible-last 4 \
  --mask-char '*' \
  --min-len 16 \
  --max-len 16
```

Inspect, validate, sign, and reload the complete policy:

```sh
./vectis config list
./vectis config validate
./vectis config sign
./vectis config reload
./vectis permissions list
```

Config edit commands only update local `config.json`. The running node sees the
changes only after successful validation, signing, and reload.

## Capability Tour

Define a helper that applies the application API key without writing it into
command arguments:

```sh
run_as_app() {
  VECTIS_APIKEY="$APP_APIKEY" ./vectis "$@"
}
```

First confirm that an invalid API key is rejected:

```sh
if VECTIS_APIKEY=invalid ./vectis mask "$KID" \
  --json '{"ref":"unauthorized","profile":"pan-display-v1","plaintext":"4111111111111111"}'
then
  echo "unexpected authorization success" >&2
  exit 1
else
  echo "authorization rejection: expected"
fi
```

### Format-Preserving Encryption

```sh
FPE_OUTPUT="$(run_as_app fpe encrypt "$KID" \
  --json '{"ref":"pan-1","profile":"pan-decimal-v1","plaintext":"4111111111111111"}' \
  --output json)"
CIPHERTEXT="$(printf '%s\n' "$FPE_OUTPUT" | jq -r '.ciphertext')"
printf '%s\n' "$FPE_OUTPUT"

FPE_DECRYPT_INPUT="$(jq -nc \
  --arg kid "$KID" \
  --arg ciphertext "$CIPHERTEXT" \
  '{ref:"pan-1",kid:$kid,profile:"pan-decimal-v1",ciphertext:$ciphertext}')"
run_as_app fpe decrypt --json "$FPE_DECRYPT_INPUT"
```

The ciphertext remains 16 decimal digits and decrypts to the original value.

### Reversible Tokenization

```sh
TOKEN_OUTPUT="$(run_as_app token encode "$KID" \
  --json '{"ref":"pan-2","profile":"pan-token-v1","plaintext":"4111111111111111","metadata":{"source":"getting-started"}}' \
  --output json)"
TOKEN="$(printf '%s\n' "$TOKEN_OUTPUT" | jq -r '.token')"
printf '%s\n' "$TOKEN_OUTPUT"

TOKEN_DECODE_INPUT="$(jq -nc \
  --arg kid "$KID" \
  --arg token "$TOKEN" \
  '{ref:"pan-2",kid:$kid,profile:"pan-token-v1",token:$token}')"
run_as_app token decode --json "$TOKEN_DECODE_INPUT"
```

The token is random and visible; Vectis stores the plaintext encrypted in
SQLite and returns the metadata during decode.

### MAC

```sh
MAC_OUTPUT="$(run_as_app mac create "$KID" \
  --json '{"ref":"pan-3","profile":"pan-equality-v1","plaintext":"4111111111111111"}' \
  --output json)"
DIGEST="$(printf '%s\n' "$MAC_OUTPUT" | jq -r '.digest')"
printf '%s\n' "$MAC_OUTPUT"

MAC_VERIFY_INPUT="$(jq -nc \
  --arg kid "$KID" \
  --arg digest "$DIGEST" \
  '{ref:"pan-3",kid:$kid,profile:"pan-equality-v1",plaintext:"4111111111111111",digest:$digest}')"
run_as_app mac verify --json "$MAC_VERIFY_INPUT"
```

### Persistent Blind Index

Blind indexes reuse the signed MAC profile and persist equality membership:

```sh
INDEX_OUTPUT="$(run_as_app index create "$KID" \
  --json '{"ref":"pan-4","profile":"pan-equality-v1","plaintext":"4111111111111111"}' \
  --output json)"
printf '%s\n' "$INDEX_OUTPUT"

INDEX_VERIFY_INPUT="$(jq -nc \
  --arg kid "$KID" \
  '{ref:"pan-4",kid:$kid,profile:"pan-equality-v1",plaintext:"4111111111111111"}')"
run_as_app index verify --json "$INDEX_VERIFY_INPUT"
```

### Masking

```sh
run_as_app mask "$KID" \
  --json '{"ref":"pan-5","profile":"pan-display-v1","plaintext":"4111111111111111"}'
```

The expected masked value is `************1111`. Masking is display-only and
does not encrypt or persist the input.

### Cryptographic Commitment

```sh
COMMIT_OUTPUT="$(run_as_app commit create "$KID" \
  --json '{"ref":"pan-6","profile":"pan-commitment-v1","plaintext":"4111111111111111"}' \
  --output json)"
OPENING="$(printf '%s\n' "$COMMIT_OUTPUT" | jq -r '.opening')"
COMMITMENT="$(printf '%s\n' "$COMMIT_OUTPUT" | jq -r '.commitment')"
printf '%s\n' "$COMMIT_OUTPUT"

COMMIT_VERIFY_INPUT="$(jq -nc \
  --arg kid "$KID" \
  --arg opening "$OPENING" \
  --arg commitment "$COMMITMENT" \
  '{ref:"pan-6",kid:$kid,profile:"pan-commitment-v1",plaintext:"4111111111111111",opening:$opening,commitment:$commitment}')"
run_as_app commit verify --json "$COMMIT_VERIFY_INPUT"
```

### Secret Sharing

Split one synthetic secret into five authenticated shares and reconstruct it
with the first three:

```sh
SHARE_OUTPUT="$(run_as_app shares split "$KID" \
  --json '{"profile":"secret-3of5-v1","plaintext":"customer-secret-demo"}' \
  --output json)"
FIRST_THREE="$(printf '%s\n' "$SHARE_OUTPUT" | jq -c '.shares[:3]')"
printf '%s\n' "$SHARE_OUTPUT"

COMBINE_INPUT="$(jq -nc \
  --arg kid "$KID" \
  --argjson shares "$FIRST_THREE" \
  '{kid:$kid,profile:"secret-3of5-v1",shares:$shares}')"
run_as_app shares combine --json "$COMBINE_INPUT"
```

### Hybrid Signature

Sign the known SHA-256 digest of the string `hello`, then verify the complete
compact hybrid signature returned by Vectis:

```sh
run_as_app sign "$KID" \
  --json '{"message_hash":{"alg":"SHA-256","hex":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}' \
  --output json > signature.json

run_as_app sign verify --file signature.json
```

## Lifecycle

Use the root API key from `.env` for lifecycle administration. Demonstrate the
reversible maintenance transition:

```sh
./vectis lifecycle "$KID" --status disabled --reason maintenance

if run_as_app mask "$KID" \
  --json '{"ref":"disabled","profile":"pan-display-v1","plaintext":"4111111111111111"}'
then
  echo "unexpected operation with disabled key" >&2
  exit 1
else
  echo "disabled-key rejection: expected"
fi

./vectis lifecycle "$KID" --status active --reason maintenance-complete
./vectis keys properties "$KID"
run_as_app mask "$KID" \
  --json '{"ref":"active-again","profile":"pan-display-v1","plaintext":"4111111111111111"}'
```

Do not use `retired`, `compromised`, or `destroyed` for this lab key. Those
states are terminal by design.

## Verify The Audit Chain

In terminal 1, press `Ctrl-C` and wait for Vectis to finish its orderly
shutdown. This writes the final hybrid-signed audit checkpoint.

In terminal 2, verify the local chain using only `init_pub.json`:

```sh
./vectis audit verify --file logs/audit.log
```

Preserve `init_pub.json` independently when audit evidence must survive loss or
replacement of the node.

Remove secrets from the current shell when the tour is complete:

```sh
unset APP_APIKEY APP_APIKEY_HASH KID
```

## Optional Next Steps

- Inspect Prometheus metrics before shutdown using the protected `/metrics`
  endpoint; see [API.md](API.md#get-metrics).
- Configure authenticated NTS and Roughtime evidence; see the time-attestation
  commands in [CLI.md](CLI.md#command-groups).
- Create and sign offline artifacts with SLH-DSA; see
  [CLI.md](CLI.md#slh-dsa-artifact-signing).
- Replace SQLite with PostgreSQL and review the shared-storage model in
  [Clustering.md](Clustering.md).
- Deploy with the [Helm chart](../charts/vectis/README.md).
- Explore protected node-to-node messaging with the
  [message demo](../demo/message/README.md).

For exact command contracts and all validation limits, use [CLI.md](CLI.md),
[API.md](API.md), and the [OpenAPI specification](openapi.yaml).
