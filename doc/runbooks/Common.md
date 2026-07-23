# Common Vectis Runbooks

This document is for operators handling common Vectis failures.

Rule before touching cryptographic material:

> Check readiness, config state, key state, routes, and final app reachability before touching cryptographic material.

Vectis does not fix file permissions automatically. Vectis does not create
PostgreSQL tables. Vectis does not auto-reload signed config after file changes.

## Service Will Not Start

### Problem

`vectis serve` exits before the HTTP server starts.

### Likely Causes

- `init.json` is missing, unreadable, invalid, or has unsafe permissions.
- `.unseal_key` is missing, invalid, or has unsafe permissions.
- `config.json` exists but is invalid or has an invalid signature.
- Storage is unavailable or has an incompatible schema.
- TLS files are missing when `VECTIS_MODE=prod`.

### Checks

```sh
ls -l init.json .unseal_key config.json config_sign.json
chmod 600 init.json
chmod 600 .unseal_key
cargo run -- serve
```

If using the installed binary:

```sh
vectis serve
```

### Recovery

- Fix file permissions first.
- Confirm the unseal key is the right 64-character hex string.
- If `config.json` exists, validate and sign it again:
  ```sh
  vectis config sign
  ```
- If using PostgreSQL, confirm the database is reachable and the schema exists.

### Do Not

- Do not delete or regenerate init material as a first step.
- Do not copy init material from another environment without understanding the
  recovery boundary.
- Do not bypass config signature validation.

## Init File Permissions Are Too Open

### Problem

Startup or a local command fails with:

```text
init keys file permissions are too open; allowed modes must not grant group write, execute, or any access to others
```

### Likely Causes

- `init.json` was created by an old version.
- The file was copied or restored with loose permissions.
- The current `VECTIS_INIT_KEYS_FILE` points to a file managed outside Vectis.

### Checks

```sh
ls -l init.json
stat -f "%OLp %N" init.json
```

### Recovery

For local files, prefer owner-only permissions:

```sh
chmod 600 init.json
```

If a custom path is used:

```sh
chmod 600 "$VECTIS_INIT_KEYS_FILE"
```

### Do Not

- Do not run `vectis init` again unless you are intentionally creating a new
  deployment and have manually deleted the old init file.
- Do not grant group write, execute bits, or any access to others.

## Unseal Key File Permissions Are Too Open

### Problem

Startup or a local command fails with:

```text
unseal key file permissions are too open; allowed modes must not grant group write, execute, or any access to others
```

### Likely Causes

- `.unseal_key` was created manually with default shell permissions.
- The file was copied or restored with loose permissions.
- `VECTIS_UNSEAL_KEY_FILE` points to a file with unsafe permissions.

### Checks

```sh
ls -l .unseal_key
stat -f "%OLp %N" .unseal_key
```

### Recovery

For local files, prefer owner-only permissions:

```sh
chmod 600 .unseal_key
```

If a custom path is used:

```sh
chmod 600 "$VECTIS_UNSEAL_KEY_FILE"
```

### Do Not

- Do not put `VECTIS_UNSEAL_KEY` in `.env`.
- Do not commit `.unseal_key`.
- Do not share the unseal key in logs, tickets, or chat.

## Unseal Key Missing Or Invalid

### Problem

Vectis cannot decrypt or validate `init.json`.

### Likely Causes

- The unseal key does not match the init material.
- `.unseal_key` contains whitespace plus invalid content.
- `VECTIS_UNSEAL_KEY_FILE` points to the wrong file.
- The operator is using init material from one environment and an unseal key from
  another.

### Checks

```sh
wc -c .unseal_key
cat .unseal_key
```

The trimmed value must be one 64-character hex string.

### Recovery

- Point `VECTIS_UNSEAL_KEY_FILE` to the correct file.
- Restore the matching unseal key from the deployment secret store.
- Retry startup after confirming file permissions are `0600`.

### Do Not

- Do not regenerate init material to fix a lost unseal key unless this is a full
  deployment reset.
- Do not log the unseal key.

## Config Signature Or Config Reload Fails

### Problem

`vectis config reload` fails, or startup fails when `config.json` exists.

### Likely Causes

- `config.json` was edited but not signed.
- `config_sign.json` does not match `config.json`.
- `config.json` and `config_sign.json` were not moved together.
- A route references a KID that is not loaded in memory.
- A remote route has invalid public keys, invalid `allowed_local_kids`, or an
  invalid `remote_addr`.
- A permissions client has an invalid API key hash or references an unloaded
  KID.
- An FPE, tokenization, or MAC profile references an unloaded KID or has invalid
  profile fields.

### Checks

```sh
vectis config list --output json
vectis config sign
vectis config reload
vectis routes list
vectis remote-routes list
vectis permissions list
```

### Recovery

- Fix `config.json`.
- Re-sign it:
  ```sh
  vectis config sign
  ```
- Reload it:
  ```sh
  vectis config reload
  ```
- If a route references an unloaded KID, load keys first:
  ```sh
  vectis keys reload
  vectis config reload
  ```

### Do Not

- Do not hand-edit `config_sign.json`.
- Do not expect Vectis to reload config automatically after editing files.
- Do not remove route or permission validation to force a reload.

## Readiness Reports Storage Not Ready

### Problem

`/healthz/ready` is not ready or reports storage failure.

### Likely Causes

- SQLite path is unavailable or not writable.
- PostgreSQL is down or unreachable.
- PostgreSQL credentials are wrong.
- PostgreSQL schema is missing or incompatible.

### Checks

```sh
vectis health ready
curl -sS http://127.0.0.1:3000/healthz/ready
```

For PostgreSQL:

```sh
psql "$VECTIS_POSTGRES_DSN" -c '\d opskeys'
psql "$VECTIS_POSTGRES_DSN" -c '\d tokens'
psql "$VECTIS_POSTGRES_DSN" -c '\d indexes'
```

### Recovery

- Restore storage connectivity.
- Confirm the configured storage backend:
  ```sh
  echo "$VECTIS_STORAGE"
  echo "$VECTIS_SQLITE_PATH"
  echo "$VECTIS_POSTGRES_DSN"
  ```
- For PostgreSQL, apply the reference schema manually if this is a new database:
  ```sh
  psql "$VECTIS_POSTGRES_DSN" -f src/db/postgres_schema.sql
  ```

### Do Not

- Do not expect Vectis to create PostgreSQL tables.
- Do not treat a ready HTTP port as proof that storage is healthy.

## PostgreSQL Schema Or Connectivity Failure

### Problem

Vectis reports PostgreSQL connection or schema errors.

### Likely Causes

- Database is unreachable.
- User lacks privileges.
- `opskeys`, `tokens`, or `indexes` table does not exist.
- Column types or nullability do not match the expected schema.
- The DSN points to the wrong database.

### Checks

```sh
psql "$VECTIS_POSTGRES_DSN" -c 'select 1'
psql "$VECTIS_POSTGRES_DSN" -c '\d opskeys'
psql "$VECTIS_POSTGRES_DSN" -c '\d tokens'
psql "$VECTIS_POSTGRES_DSN" -c '\d indexes'
```

Expected table:

```sql
CREATE TABLE opskeys (
    kid VARCHAR(128) PRIMARY KEY,
    keys TEXT NOT NULL,
    properties TEXT NOT NULL
);

CREATE TABLE tokens (
    kid VARCHAR(128) NOT NULL,
    hashid VARCHAR(128) NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (kid, hashid)
);

CREATE TABLE indexes (
    kid VARCHAR(128) NOT NULL,
    digest VARCHAR(128) NOT NULL,
    PRIMARY KEY (kid, digest)
);
```

### Recovery

- Fix the DSN, network path, credentials, or grants.
- Ask the DBA to apply the schema if the table is missing.
- Restart Vectis after the database is corrected.

### Do Not

- Do not change Vectis to create or migrate production databases.
- Do not relax schema validation to start the service.

## Key Not Found

### Problem

An endpoint returns:

```text
ops key not found
```

### Likely Causes

- The KID was never created on this deployment.
- The key exists in storage but is not loaded into this node's memory.
- The request uses the remote KID where a local KID is required.
- The node is using a different storage backend or database.

### Checks

```sh
vectis keys list
vectis keys reload
vectis keys list
```

For public key lookup:

```sh
curl -sS http://127.0.0.1:3000/pub/<kid>
```

### Recovery

- Run `vectis keys reload` if the key exists in storage.
- Confirm the KID belongs to the current deployment.
- Confirm the node points to the expected storage backend.

### Do Not

- Do not create a replacement key with the same operational meaning without
  updating config and dependent systems.
- Do not assume `/keys` lists every key in shared storage; it lists loaded state.

## Lifecycle Blocks Key Use

### Problem

A key exists, but Vectis refuses to use it.

### Likely Causes

- The key is `disabled`.
- The key is `retired`.
- The key is `compromised`.
- The key is `destroyed`.

### Checks

```sh
vectis keys properties <kid>
```

### Recovery

- If the key is `disabled`, decide whether it should return to `active`.
- If the key is `retired`, use it only for allowed legacy decrypt or verify
  paths.
- If the key is `compromised` or `destroyed`, create and route to new key
  material through the normal config process.

### Do Not

- Do not force terminal lifecycle states back to active.
- Do not expose `/pub/{kid}` for retired, compromised, or destroyed keys.

## Remote Route Not Found Or Sender Not Allowed

### Problem

`POST /message/{sender_kid}` fails with route or sender authorization errors.

### Likely Causes

- `remote_routes[]` does not contain the requested `recipient_kid`.
- The route is `disabled`.
- `allowed_local_kids` does not include the sender KID.
- `config.json` was edited but not signed and reloaded.
- The sender KID is not loaded locally.

### Checks

```sh
vectis remote-routes list
vectis keys list
vectis config reload
```

Inspect the relevant route in `config.json`:

```json
{
  "remote_kid": "...",
  "name": "...",
  "remote_addr": "...",
  "allowed_local_kids": ["..."],
  "status": "active"
}
```

### Recovery

- Add or update the remote route with the CLI config editor.
- Re-sign and reload config:
  ```sh
  vectis config sign
  vectis config reload
  ```
- Ensure the sender KID is loaded:
  ```sh
  vectis keys reload
  ```

### Do Not

- Do not add request-supplied remote hosts back into the message API.
- Do not use `allowed_local_kids: ["*"]` unless that is the intended policy.

## Final App Cannot Be Reached

### Problem

Message send fails with:

```text
internal server error final app can't be reached
```

### Likely Causes

- Vectis received and verified the remote message, but delivery to the final app
  failed.
- The final app process is not running.
- `final_app_addr` or `final_app_path` is wrong.
- `VECTIS_MODE=prod` requires HTTPS but the final app is HTTP-only.

### Checks

```sh
vectis routes list
curl -sS http://127.0.0.1:<final-app-port>/message
```

Check the configured local route:

```json
{
  "kid": "...",
  "name": "...",
  "final_app_addr": "127.0.0.1:3999",
  "final_app_path": "/message"
}
```

### Recovery

- Start the final app.
- Fix the final app address or path.
- Re-sign and reload config if the route changed:
  ```sh
  vectis config sign
  vectis config reload
  ```

### Do Not

- Do not debug remote public keys first when the error says final app reachability.
- Do not send plaintext directly to the final app as a workaround.

## Message Verification Or Decrypt Failure

### Problem

Message receive, decrypt, or verification fails.

### Likely Causes

- The sender public keys in signed config do not match the sender.
- The payload was modified.
- The recipient KID is wrong.
- The key lifecycle blocks decrypt or verify.
- The message was generated under a different profile or algorithm set.

### Checks

```sh
vectis remote-routes list
vectis keys properties <recipient-kid>
vectis keys reload
```

Review operational logs for the specific validation failure. Use the request ID
from the response header:

```sh
grep '<request-id>' logs/vectis.log
grep '<request-id>' logs/audit.log
```

If `VECTIS_LOG_TARGET=stdout`, search the container logs or log collector for
the same request ID. Audit events are JSON records with `target: "vectis::audit"`.

### Recovery

- Confirm the sender route public keys were imported from the right remote KID.
- Rebuild, sign, and reload config if peer keys changed.
- Confirm the recipient KID is local and loaded.

### Do Not

- Do not skip verify-before-decrypt.
- Do not paste plaintext, ciphertext, API keys, or private key material into
  tickets.

## Metrics Endpoint Check

### Problem

Metrics are unavailable or do not show expected runtime state.

### Likely Causes

- Missing or invalid API key.
- API key lacks `admin` or `metrics` permission.
- Metrics are disabled.
- Runtime state has not been reloaded after config or key changes.

### Checks

```sh
curl -sS -H "X-API-Key: $VECTIS_APIKEY" http://127.0.0.1:3000/metrics
```

Look for:

```text
vectis_keys_loaded
vectis_routes_loaded
vectis_remote_routes_loaded
vectis_permission_clients
vectis_fpe_profiles_loaded
vectis_tokenization_profiles_loaded
vectis_mac_profiles_loaded
vectis_commitment_profiles_loaded
vectis_masking_profiles_loaded
vectis_config_reload_total
vectis_message_total
```

### Recovery

- Use a root or admin API key.
- Check permissions for a non-root client.
- Reload keys or config if the runtime state is stale:
  ```sh
  vectis keys reload
  vectis config reload
  ```

### Do Not

- Do not add high-cardinality labels such as KID, API key, actor, or remote
  address.
- Do not expose metrics without an authorization boundary.

## Audit Log Review

### Problem

An operator needs to understand who did what and why a sensitive operation was
allowed or denied.

### Likely Causes

- Permission denied.
- Lifecycle denied.
- Config reload failed.
- Message send or receive failed.
- Internal encrypt/decrypt was used.

### Checks

Use `X-Request-Id` from the HTTP response:

```sh
grep '<request-id>' logs/audit.log
grep '<request-id>' logs/vectis.log
```

If `VECTIS_LOG_TARGET=stdout`, query container logs or the central collector
instead. Filter audit records with `target: "vectis::audit"`.

Look for:

```text
auth.success
auth.denied
permission.allowed
permission.denied
config.reload.success
config.reload.stale
config.reload.failed
message.send.success
message.send.failed
message.internal.encrypt.success
message.internal.decrypt.success
```

### Recovery

- Use audit logs to identify actor, action, KID, result, and reason.
- Use operational logs for stack-level debugging.
- Correlate both with `X-Request-Id`.

### Do Not

- Do not log or paste API keys, unseal keys, private keys, plaintext, full
  ciphertext, or full signatures.
- Do not treat operational logs as a complete security audit trail.

## Restore Sanity Checklist After Restart Or Reload

### Problem

Vectis restarted, storage changed, keys were reloaded, or config was reloaded.

### Likely Causes

- Normal deployment.
- Config update.
- Storage maintenance.
- Recovery after failure.

### Checks

```sh
vectis health startup
vectis health live
vectis health ready
vectis keys list
vectis routes list
vectis remote-routes list
vectis permissions list
curl -sS -H "X-API-Key: $VECTIS_APIKEY" http://127.0.0.1:3000/metrics
```

### Recovery

- If keys are missing:
  ```sh
  vectis keys reload
  ```
- If config is stale:
  ```sh
  vectis config reload
  ```
- If final app delivery fails, verify final app process and route config.
- If storage is not ready, fix storage before debugging higher layers.

### Do Not

- Do not assume shared storage means shared runtime state.
- Do not assume editing `config.json` changes live behavior before signing and
  reloading.
- Do not rotate keys or regenerate init material just because a node restarted.
