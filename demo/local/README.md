# Vectis Local Data Protection Demo

This demo runs one local Vectis instance and exercises local data protection
operations over HTTP:

- format-preserving encryption;
- display masking;
- reversible tokenization;
- MAC create/verify;
- blind index create/verify;
- internal message encrypt/decrypt;
- sign and verification.

It complements the `message` demo. The `message` demo shows a two-site protected
message flow; this demo focuses on one local node and field-level data
protection profiles.

## What The Demo Shows

The demo creates profiles for several synthetic sensitive data categories:

- credit card numbers;
- Social Security numbers;
- bank accounts.

FPE profiles preserve alphabet and length. Masking profiles reveal configured
leading/trailing characters for display only; they do not encrypt, tokenize, or
persist data. Tokenization profiles return visible random tokens and store
encrypted plaintext in SQLite. MAC profiles produce deterministic keyed digests
scoped by signed profile context. Blind indexes reuse those MAC profiles and
persist deterministic indexes in SQLite. The internal message and sign examples
read `personaldata.json` and use a compact JSON representation of that file as
the message body.

This demo prints synthetic values in full so the transformation and round-trip
are easy to inspect. Do not use real sensitive data.

## Prepare The Demo

Run these commands from the repository root:

```sh
bash demo/local/setup.sh
bash demo/local/create-keys.sh
bash demo/local/configure-config.sh
```

The scripts create local state under `demo/local/site`, including SQLite
storage, `init.json`, `.unseal_key`, an app API key, and signed FPE, masking,
tokenization, and MAC config profiles. Blind indexes reuse the MAC profiles and
are enabled by the same local config. The operational key is created with the
`hybrid-standard-v1` crypto profile.

## Run The Demo

Start Vectis in one terminal:

```sh
bash demo/local/start-vectis.sh
```

Run the demo in another terminal:

```sh
uv run demo/local/run-demo.py
```

The runner prints each operation as it happens, including full synthetic request
and response payloads. It also prints request headers, including `X-API-Key`, so
run it only in a local demo terminal. Before sending requests, it pauses before
printing each file, shows `init.json`, `config.json`, and `config_sign.json` as
YAML, then waits at:

```text
Press any key to start:
```

After each HTTP request/response pair, the runner waits at:

```text
Press any key to continue:
```

The internal message and sign sections also print `personaldata.json` as YAML
before their requests.

Example shape:

```text
[credit-card-pan-v1]

encode
url: http://127.0.0.1:3010/fpe/encrypt/<kid>
request:
{
  "body": {
    "ref": "credit-card-pan-v1-sample",
    "plaintext": "4111111111111111",
    "profile": "credit-card-pan-v1"
  },
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "..."
  },
  "method": "POST"
}
response:
{
  "ciphertext": "5555555555554444",
  "kid": "<kid>",
  "profile": "credit-card-pan-v1",
  "ref": "credit-card-pan-v1-sample"
}

decode
url: http://127.0.0.1:3010/fpe/decrypt
request:
{
  "body": {
    "ciphertext": "5555555555554444",
    "kid": "<kid>",
    "profile": "credit-card-pan-v1",
    "ref": "credit-card-pan-v1-sample"
  },
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "..."
  },
  "method": "POST"
}
response:
{
  "plaintext": "4111111111111111",
  "ref": "credit-card-pan-v1-sample"
}

input: 4111111111111111
output: 5555555555554444
decode: 4111111111111111
status: OK
```

Masking profiles show display-only masked values:

```text
[credit-card-pan-display-v1]

mask
url: http://127.0.0.1:3010/mask/<kid>
request:
{
  "body": {
    "plaintext": "4111111111111111",
    "profile": "credit-card-pan-display-v1",
    "ref": "credit-card-pan-display-v1-sample"
  },
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "..."
  },
  "method": "POST"
}
response:
{
  "kid": "<kid>",
  "masked": "************1111",
  "profile": "credit-card-pan-display-v1",
  "ref": "credit-card-pan-display-v1-sample"
}

input: 4111111111111111
masked: ************1111
status: OK
```

MAC and blind index profiles use the same detailed request/response pattern:

```text
[credit-card-pan-mac-v1]

create
url: http://127.0.0.1:3010/mac/<kid>
request:
{
  "body": {
    "plaintext": "4111111111111111",
    "profile": "credit-card-pan-mac-v1",
    "ref": "credit-card-pan-mac-v1-sample"
  },
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "..."
  },
  "method": "POST"
}
response:
{
  "algorithm": "HMAC(BLAKE2b(256))",
  "digest": "hex...",
  "kid": "<kid>",
  "profile": "credit-card-pan-mac-v1",
  "ref": "credit-card-pan-mac-v1-sample"
}

verify
url: http://127.0.0.1:3010/mac/verify
request:
{
  "body": {
    "digest": "hex...",
    "kid": "<kid>",
    "plaintext": "4111111111111111",
    "profile": "credit-card-pan-mac-v1",
    "ref": "credit-card-pan-mac-v1-sample"
  },
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "..."
  },
  "method": "POST"
}
response:
{
  "ref": "credit-card-pan-mac-v1-sample",
  "valid": true
}

input: 4111111111111111
algorithm: HMAC(BLAKE2b(256))
digest: hex...
verify: true
status: OK
```

Blind indexes create and verify storage membership:

```text
[credit-card-pan-mac-v1]

create
url: http://127.0.0.1:3010/index/<kid>
request:
{
  "body": {
    "plaintext": "4111111111111111",
    "profile": "credit-card-pan-mac-v1",
    "ref": "credit-card-pan-mac-v1-index-sample"
  },
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "..."
  },
  "method": "POST"
}
response:
{
  "index": "hex...",
  "kid": "<kid>",
  "profile": "credit-card-pan-mac-v1",
  "ref": "credit-card-pan-mac-v1-index-sample"
}

verify
url: http://127.0.0.1:3010/index/verify
request:
{
  "body": {
    "kid": "<kid>",
    "plaintext": "4111111111111111",
    "profile": "credit-card-pan-mac-v1",
    "ref": "credit-card-pan-mac-v1-index-sample"
  },
  "headers": {
    "Content-Type": "application/json",
    "X-API-Key": "..."
  },
  "method": "POST"
}
response:
{
  "index": "hex...",
  "kid": "<kid>",
  "matched": true,
  "profile": "credit-card-pan-mac-v1",
  "ref": "credit-card-pan-mac-v1-index-sample"
}

input: 4111111111111111
index: hex...
matched: true
status: OK
```

Use Ctrl-C to stop Vectis when finished.
