# Getting Started With Vectis

## Purpose

This tutorial builds one local Vectis node from a signed release, backed by
SQLite, and walks through every core data-protection capability. It is not a
list of commands to copy: each step explains what you are doing and why, so
that by the end you understand how Vectis thinks — keys, profiles, signed
policy, and the audit chain — not just how to type at it.

All values in this tutorial are synthetic. The TLS certificate and local
secret handling are appropriate for a lab, not a production deployment.
Protected node-to-node messaging is intentionally outside this tutorial; see
[UseCases.md](UseCases.md) and the [message demo](../demo/message/README.md).

## How Vectis Works

Before touching a terminal, here is the whole mental model. Vectis is a small
service that runs next to your application. The application sends it a
sensitive value over HTTPS; Vectis returns a safe representation of that
value — encrypted, tokenized, masked, or digested. Sensitive input in, safe
representation out.

```text
your app --HTTPS--> vectis node --> SQLite (keys, tokens, indexes)
                        |
                        +--> audit.log (hash-chained, signed)
```

Five ideas carry everything else in this tutorial:

- **Operational key** — a named cryptographic key that Vectis creates, stores
  encrypted, and never hands out. Every protection operation names the key it
  uses by its identifier, the `kid`.
- **Profile** — a small named recipe that fixes how one operation behaves:
  which alphabet, what lengths, what context. Applications choose a profile
  by name; they can never improvise the parameters. That is how Vectis keeps
  crypto decisions with the operator instead of scattered across app code.
- **Signed configuration** — profiles and permissions live in a config file,
  but the node obeys the file only after it is validated and *signed*.
  Editing the file is proposing; signing is deciding.
- **API keys** — the root key (created at init) administers the node; each
  application gets its own key with only the permissions it needs.
- **Audit chain** — every operation is appended to a log where each record is
  linked to the previous one by a hash. You can verify the whole chain
  offline, and nobody can silently edit or remove a record.

Keep this picture in mind; every section below is one of these ideas made
concrete.

## Download And Verify

A data-protection tool must itself be verifiable — otherwise you are trusting
your most sensitive workflows to an unverified download. That is why this
tutorial starts with provenance, not installation.

Open the [Vectis releases page](https://github.com/liesware/Vectis/releases)
in a browser and choose the release you want to install. Download these files
to the same directory:

- `vectis-linux-amd64-vX.Y.Z.tar.gz` for x86-64 Linux, or
  `vectis-linux-arm64-vX.Y.Z.tar.gz` for ARM64 Linux — the program itself;
- `SHA256SUMS` — the list of official fingerprints for this release;
- `SHA256SUMS.sigstore.json` — the signature that proves who made that list.

Install `tar`, `sha256sum`, and
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) before
continuing. The commands below use the Linux AMD64 archive; for ARM64, replace
`amd64` with `arm64` in the file names. Wherever a command says `vX.Y.Z`, type
the version you downloaded — the one in the archive's file name.

Create the lab workspace and move the three downloaded files into it using your
file manager. Then open a terminal in that directory:

```sh
mkdir -p "$HOME/vectis-lab"
cd "$HOME/vectis-lab"
```

Verify that the fingerprint list is authentic. This proves `SHA256SUMS` was
produced by the Vectis release workflow on GitHub, for that exact version —
not by someone else:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity \
    "https://github.com/liesware/Vectis/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

You should see `Verified OK`.

Verify that the archive you downloaded matches that authenticated list:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

You should see `vectis-linux-amd64-vX.Y.Z.tar.gz: OK`.

Each step vouches for the next — that is the verification chain:

```text
Cosign identity -> SHA256SUMS -> release archive -> vectis binary
```

Extract the archive and install the binary into the lab workspace:

```sh
tar -xzf vectis-linux-amd64-vX.Y.Z.tar.gz
install -m 755 vectis-linux-amd64-vX.Y.Z/vectis ./vectis
./vectis version
```

The reported version must match the release you downloaded. The build status
is currently `Experimental Build`. The binary in your hands is now provably
the one the release workflow built.

## Prepare The Workspace

The remaining commands run from `$HOME/vectis-lab`. Install these local tools:

- `sqlite3`;
- `openssl`.

Vectis keeps its state in three kinds of places — a database, log files, and
TLS material — and each gets its own directory with permissions restricted to
you. Tight permissions from the first minute is a habit this tutorial keeps
throughout, because in production these directories hold real key material:

```sh
cd "$HOME/vectis-lab"
mkdir -p db logs tls
chmod 700 db logs tls
```

## Initialize SQLite

Vectis does not own your database — you create it, Vectis uses it. This is
deliberate: the operator stays in control of the schema, backups, and
migrations. The schema is also worth reading, because it is a map of
everything Vectis ever persists — three tables, nothing more:

- `opskeys` — the operational keys, stored encrypted, one row per `kid`;
- `tokens` — the encrypted plaintext behind each token you create;
- `indexes` — the digests that record blind-index membership.

Notice what is *not* there: no plaintext sensitive data, ever.

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

Vectis only speaks HTTPS — there is no plaintext HTTP mode to accidentally
leave on. Even in a local lab, that means the node needs a certificate. Here
we create a self-signed one that is valid for `localhost` and `127.0.0.1`,
the two names the local client will use:

```sh
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

openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -pkeyopt ec_param_enc:named_curve \
  -out tls/server-key.pem

chmod 600 tls/server-key.pem

openssl req -new -x509 -sha256 \
  -days 30 \
  -key tls/server-key.pem \
  -out tls/server-cert.pem \
  -config tls/openssl.cnf \
  -extensions server
```

This is a self-signed, short-lived lab certificate. Production deployments
must use an appropriately managed certificate and must not disable certificate
verification.

## Initialize Vectis

Now the node gets its own identity. `init` generates the node's signing keys —
a hybrid pair combining a classical algorithm (Ed25519) with a post-quantum
one (ML-DSA), so that policy signatures hold even if one algorithm is ever
broken. Those keys are written to disk **encrypted**, and the thing that
decrypts them at startup is the *unseal key*. Whoever holds the unseal key can
awaken the node's identity; that is why it gets special handling.

```sh
./vectis init
```

This writes two files and prints three secrets:

- `init.json` — the node's private keys, encrypted with the unseal key;
- `init_pub.json` — the matching public keys; safe to share, and later the
  only thing needed to verify the audit chain;
- three lines in `NAME=value` form: `VECTIS_UNSEAL_KEY`, `VECTIS_APIKEY`
  (the root API key — the node's administrator credential), and
  `VECTIS_APIKEY_HASH` (its verifier).

Keep this terminal open — the next two steps copy those values by hand. Every
value in this lab is synthetic, so copying them through an editor is
acceptable here; it would not be in production.

Store the unseal key in its dedicated file. Vectis intentionally does not load
`VECTIS_UNSEAL_KEY` from `.env` — separating "configuration" from "the secret
that unlocks the keys" means a leaked config file does not leak the kingdom.
Open a new file named `.unseal_key` in your text editor, paste in only the
value after the `=` sign of the `VECTIS_UNSEAL_KEY` line, save it, and
restrict its permissions:

```sh
chmod 600 .unseal_key
```

Create the lab process configuration. Skim the blocks as you paste: network
and TLS, client settings, key-material files, policy files, storage, logging,
and crypto defaults — this one file is the node's whole runtime shape:

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
```

Now open `.env` in your editor and add the `VECTIS_APIKEY=...` and
`VECTIS_APIKEY_HASH=...` lines exactly as `./vectis init` printed them — they
are already in `.env` format.

`VECTIS_TLS_SKIP_VERIFY=true` is used only because this tutorial created a
self-signed certificate. Vectis logs a warning while this setting is active.

## Start And Bootstrap The Node

In terminal 1, from `$HOME/vectis-lab`, start Vectis. At startup the node
reads `.env`, uses the unseal key to decrypt its identity from `init.json`,
connects to SQLite, and begins listening on HTTPS:

```sh
./vectis serve
```

Leave that process running. In terminal 2, use the same working directory and
ask the node how it feels — `startup` (did initialization complete?), `live`
(is the process responsive?), and `ready` (can it serve requests, storage
included?) are the three standard health probes, and `test init` runs a
self-test of the init key material:

```sh
cd "$HOME/vectis-lab"
./vectis health startup
./vectis health live
./vectis health ready
./vectis test init
```

Now create the first *operational key* — the workhorse of everything that
follows. `hybrid-standard-v1` is a crypto profile: a named bundle of
algorithms, again pairing classical and post-quantum, so you pick a vetted
combination instead of assembling algorithms by hand:

```sh
./vectis keys create --tag getting-started --profile hybrid-standard-v1
```

The output includes the new key's identifier, its `kid`. Operations never
touch the key itself — they name it by kid, and the key never leaves the
node. The rest of the tutorial uses the kid constantly, so store it once in
this terminal session — replace the placeholder with your own:

```sh
KID=paste-your-kid-here
```

Then inspect the key you just created — its properties, its public half, and
a self-test:

```sh
./vectis keys list
./vectis keys properties "$KID"
./vectis pub "$KID"
./vectis test "$KID"
```

## Create Application Policy

So far you have acted as the node's administrator, using the root API key
from `.env`. Real applications must not hold that power. In this section you
create a second identity — a least-privilege application called `lab-app` —
and write the policy that says exactly what it may do. This is the "signed
configuration" idea from the mental model, made concrete.

Create a separate API key for the tutorial application:

```sh
./vectis apikey create
```

The output contains a `VECTIS_APIKEY` value (the secret the application will
present) and a `VECTIS_APIKEY_HASH` value (its keyed verifier — the only part
that is written into signed policy, so the policy file never contains the
secret itself). Store both in this terminal session, replacing the
placeholders with your own values:

```sh
APP_APIKEY=paste-the-apikey-value-here
APP_APIKEY_HASH=paste-the-apikey-hash-here
```

Initialize `config.json` and register the client:

```sh
./vectis config init
./vectis config permissions add \
  --client lab-app \
  --apikey-hash "$APP_APIKEY_HASH" \
  --status active
```

Grant only the actions used by this tour. Permissions in Vectis are
allowlists per client, per key, per action — anything not granted is denied:

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

Next, add one profile for each capability. Remember what a profile is: the
operator's recipe. The application will only ever say "use `pan-decimal-v1`";
the alphabet, the lengths, and the context strings below are decisions that
stay here, in signed policy, out of application code. The `context` and
`tweak-aad` strings bind each profile to a purpose — the same value protected
under a different context yields unrelated results, which stops results from
being reused across tenants, fields, or purposes:

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

Everything so far only edited the local `config.json` — the running node has
not changed behavior at all. That is by design: editing is proposing. The
policy takes effect through a four-step pipeline — inspect it, validate it,
*sign* it with the node's init keys, and reload it into the running node:

```sh
./vectis config list
./vectis config validate
./vectis config sign
./vectis config reload
./vectis permissions list
```

If someone tampers with `config.json` behind your back, the signature no
longer matches and the node refuses it. Policy is what was signed — nothing
else.

## Capability Tour

Time to use what you built. Each primitive in this tour answers a different
question about the same underlying problem — "how do I work with a sensitive
value without exposing it?" — and the tour uses one synthetic card number,
`4111111111111111`, so you can compare what each primitive does to it.

Define a helper that acts as the application, applying its API key without
writing it into command arguments:

```sh
run_as_app() {
  VECTIS_APIKEY="$APP_APIKEY" ./vectis "$@"
}
```

Some commands below need values from a previous response, including your kid
inside a JSON body (`echo "$KID"` prints it). Wherever you see a
`paste-...` placeholder, replace it with your own value.

First confirm that an invalid API key is rejected — a protection service that
fails open is worse than none. This command must fail with an authorization
error; if it succeeds, stop and review your policy:

```sh
VECTIS_APIKEY=invalid ./vectis mask "$KID" \
  --json '{"ref":"unauthorized","profile":"pan-display-v1","plaintext":"4111111111111111"}'
```

### Format-Preserving Encryption

**What it is:** encryption whose output keeps the shape of the input — 16
digits in, 16 digits out. **Why it matters:** databases, forms, and legacy
systems that validate "must be 16 digits" accept the ciphertext without any
schema change. You get encryption without touching the systems around it.

Encrypt the synthetic card number:

```sh
run_as_app fpe encrypt "$KID" \
  --json '{"ref":"pan-1","profile":"pan-decimal-v1","plaintext":"4111111111111111"}'
```

The response's `ciphertext` is again 16 decimal digits — same shape as the
input, different number. Decrypt it to recover the original value:

```sh
run_as_app fpe decrypt \
  --json '{"ref":"pan-1","kid":"paste-your-kid","profile":"pan-decimal-v1","ciphertext":"paste-your-ciphertext"}'
```

### Reversible Tokenization

**What it is:** the value is replaced by a random claim ticket — the token —
and the real value is stored encrypted inside Vectis. **Why it matters:**
unlike FPE, the token has *no mathematical relationship* to the value; a
system holding only tokens holds nothing to break. Recovery is only possible
by asking Vectis, which checks permissions and writes an audit record.

Encode the same synthetic value as a token:

```sh
run_as_app token encode "$KID" \
  --json '{"ref":"pan-2","profile":"pan-token-v1","plaintext":"4111111111111111","metadata":{"source":"getting-started"}}'
```

The response's `token` starts with `tok_pan` and is random — it reveals
nothing about the input. Decode it to get the plaintext and metadata back:

```sh
run_as_app token decode \
  --json '{"ref":"pan-2","kid":"paste-your-kid","profile":"pan-token-v1","token":"paste-your-token"}'
```

The token is random and visible; Vectis stores the plaintext encrypted in
SQLite (remember the `tokens` table you created) and returns the metadata
during decode.

### MAC

**What it is:** a keyed digest — the same input under the same key and
context always yields the same digest, but the digest reveals nothing about
the input, and only someone with the key can produce it. **Why it matters:**
it answers "are these two values equal?" without ever comparing plaintext —
deduplication and equality checks over sensitive data.

Create a keyed digest for the synthetic value:

```sh
run_as_app mac create "$KID" \
  --json '{"ref":"pan-3","profile":"pan-equality-v1","plaintext":"4111111111111111"}'
```

Copy the `digest` from the response and verify that the same plaintext
produces the same digest:

```sh
run_as_app mac verify \
  --json '{"ref":"pan-3","kid":"paste-your-kid","profile":"pan-equality-v1","plaintext":"4111111111111111","digest":"paste-your-digest"}'
```

### Persistent Blind Index

**What it is:** a MAC that Vectis also remembers — the digest is stored in
the `indexes` table. **Why it matters:** it answers "have we seen this value
before?" without ever storing the value — think duplicate account detection,
or a deny-list of known card numbers, queryable without holding a single
plaintext entry.

```sh
run_as_app index create "$KID" \
  --json '{"ref":"pan-4","profile":"pan-equality-v1","plaintext":"4111111111111111"}'
```

Verify membership by presenting the same plaintext again:

```sh
run_as_app index verify \
  --json '{"ref":"pan-4","kid":"paste-your-kid","profile":"pan-equality-v1","plaintext":"4111111111111111"}'
```

### Masking

**What it is:** a display transformation — show the last 4 digits, hide the
rest. **Why it matters:** support screens, receipts, and logs usually need to
*identify* a value, not possess it. Masking is one-way and stores nothing;
it is presentation, not protection of the stored value.

```sh
run_as_app mask "$KID" \
  --json '{"ref":"pan-5","profile":"pan-display-v1","plaintext":"4111111111111111"}'
```

The expected masked value is `************1111`.

### Cryptographic Commitment

**What it is:** a sealed envelope. The `commitment` proves you had a specific
value at a specific moment; the `opening` is the flap that later lets anyone
check the envelope really contained that value. **Why it matters:** you can
publish the commitment now (in a report, a contract, a ledger) and reveal the
value only when required — and nobody, including you, can swap the value in
between.

Commit to the synthetic value without revealing it:

```sh
run_as_app commit create "$KID" \
  --json '{"ref":"pan-6","profile":"pan-commitment-v1","plaintext":"4111111111111111"}'
```

The response contains the `commitment` (publishable) and the `opening` (kept
private until reveal time). Copy both and verify that the plaintext matches
the commitment:

```sh
run_as_app commit verify \
  --json '{"ref":"pan-6","kid":"paste-your-kid","profile":"pan-commitment-v1","plaintext":"4111111111111111","opening":"paste-your-opening","commitment":"paste-your-commitment"}'
```

### Secret Sharing

**What it is:** one secret split into several pieces so that no single piece
— and no pair of pieces — reveals anything; only a quorum reconstructs it.
This profile is 3-of-5: five shares, any three suffice. **Why it matters:**
it removes single custodians. A recovery secret held by five officers where
any three can act survives lost shares *and* prevents any lone actor from
using it.

Split one synthetic secret into five authenticated shares:

```sh
run_as_app shares split "$KID" \
  --json '{"profile":"secret-3of5-v1","plaintext":"customer-secret-demo"}'
```

The response's `shares` array holds five entries, and any three of them can
reconstruct the secret. Copy three entries exactly as they appear in the
array, comma-separated, into the combine command:

```sh
run_as_app shares combine \
  --json '{"kid":"paste-your-kid","profile":"secret-3of5-v1","shares":[paste-share-1,paste-share-2,paste-share-3]}'
```

### Hybrid Signature

**What it is:** one signing operation that produces two signatures over the
same data — one classical (EdDSA), one post-quantum (ML-DSA) — bundled into a
single compact artifact. **Why it matters:** verification requires both, so
the signature stays trustworthy even if one of the two algorithms is broken
in the future. This is the same hybrid principle the node uses for its own
policy signatures.

Sign the known SHA-256 digest of the string `hello`, then verify the complete
compact hybrid signature returned by Vectis:

```sh
run_as_app sign "$KID" \
  --json '{"message_hash":{"alg":"SHA-256","hex":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}' \
  --output json > signature.json

run_as_app sign verify --file signature.json
```

## Lifecycle

Keys age, get rotated, and are sometimes compromised — so every operational
key carries a lifecycle status, and the node enforces it on every call.
`active` and `disabled` are reversible, like suspending and restoring a badge.
`retired`, `compromised`, and `destroyed` are terminal *by design*: a key
that was ever declared compromised must never quietly return to service.

Use the root API key from `.env` for lifecycle administration — note that
`lab-app` was never granted lifecycle powers. Disable the key:

```sh
./vectis lifecycle "$KID" --status disabled --reason maintenance
```

While the key is disabled, operations against it must fail. Run this and
expect an error:

```sh
run_as_app mask "$KID" \
  --json '{"ref":"disabled","profile":"pan-display-v1","plaintext":"4111111111111111"}'
```

Re-enable the key and confirm the same operation succeeds again:

```sh
./vectis lifecycle "$KID" --status active --reason maintenance-complete
./vectis keys properties "$KID"
run_as_app mask "$KID" \
  --json '{"ref":"active-again","profile":"pan-display-v1","plaintext":"4111111111111111"}'
```

Do not use `retired`, `compromised`, or `destroyed` for this lab key. Those
states are terminal by design.

## Verify The Audit Chain

Everything you did in this tutorial — every key creation, every encrypt,
every rejected call — was appended to `logs/audit.log`. Each record includes
a hash of the previous record, which chains them: removing or editing any
record breaks every link after it. On shutdown, the node signs a final
checkpoint over the chain with its hybrid init keys.

In terminal 1, press `Ctrl-C` and wait for Vectis to finish its orderly
shutdown — that writes the final signed checkpoint.

In terminal 2, verify the local chain. Note what this needs: only
`init_pub.json`, the public keys. No secrets, no running node — anyone
holding the log and the public keys can check the evidence:

```sh
./vectis audit verify --file logs/audit.log
```

Preserve `init_pub.json` independently when audit evidence must survive loss
or replacement of the node.

Remove secrets from the current shell when the tour is complete:

```sh
unset APP_APIKEY APP_APIKEY_HASH KID
```

## What You Learned

You now hold the complete Vectis mental model, exercised end to end:

- a **verified binary**, with a provenance chain you checked yourself;
- a node with its own **hybrid identity keys**, unlocked by an unseal key;
- an **operational key** referenced by kid, never exported;
- **signed policy**: least-privilege permissions and operator-owned profiles,
  effective only after validate → sign → reload;
- the **primitives** and the question each answers — FPE (keep the shape),
  tokenization (replace with a ticket), MAC (compare without revealing),
  blind index (remember without storing), masking (display safely),
  commitment (prove later), secret sharing (split trust), hybrid signature
  (sign for the long term);
- key **lifecycle** enforcement, with terminal states that stay terminal;
- a **hash-chained audit log** verifiable offline with public keys alone.

## Optional Next Steps

- Inspect Prometheus metrics before shutdown using the protected `/metrics`
  endpoint; see [API.md](API.md#get-metrics).
- Configure authenticated NTS and Roughtime evidence; see the time-attestation
  commands in [CLI.md](CLI.md#command-groups).
- Create and sign offline artifacts with SLH-DSA; see
  [CLI.md](CLI.md#slh-dsa-artifact-signing).
- Replace SQLite with PostgreSQL using the
  [PostgreSQL tutorial](tutorials/PostgreSQL.md), then review the shared-storage
  model in [Clustering.md](Clustering.md).
- Deploy with the [Helm chart](../charts/vectis/README.md).
- Explore protected node-to-node messaging with the
  [message demo](../demo/message/README.md).

For exact command contracts and all validation limits, use [CLI.md](CLI.md),
[API.md](API.md), and the [OpenAPI specification](openapi.yaml).
