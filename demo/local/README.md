# Vectis Local Data Protection Demo

This demo runs one local Vectis instance and exercises local data protection
operations over HTTP:

- format-preserving encryption;
- reversible tokenization;
- internal message encrypt/decrypt;
- sign and verification.

It complements the `message` demo. The `message` demo shows a two-site protected
message flow; this demo focuses on one local node and field-level data
protection profiles.

## What The Demo Shows

The demo creates profiles for several synthetic sensitive data categories:

- credit card numbers;
- Social Security numbers;
- identity documents;
- driver licenses;
- bank accounts;
- payroll numbers;
- insurance policies.

FPE profiles preserve alphabet and length. Tokenization profiles return visible
random tokens and store encrypted plaintext in SQLite. The internal message and
sign examples read `personaldata.json` and use a compact JSON representation of
that file as the message body.

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
storage, `init.json`, `.unseal_key`, an app API key, and signed config profiles.

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
  "profile": "credit-card-pan-v1"
}

decode
url: http://127.0.0.1:3010/fpe/decrypt
request:
{
  "body": {
    "ciphertext": "5555555555554444",
    "kid": "<kid>",
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
  "plaintext": "4111111111111111"
}

input: 4111111111111111
output: 5555555555554444
decode: 4111111111111111
status: OK
```

Use Ctrl-C to stop Vectis when finished.
