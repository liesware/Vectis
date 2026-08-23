# Clustering And HA Foundations

This tutorial extends the [PostgreSQL tutorial](PostgreSQL.md) from one Vectis
process to two replicas of the same logical deployment. Both nodes use the same
PostgreSQL database, cryptographic identity, and signed policy, while retaining
their own process configuration, TLS key, memory, logs, and audit chain.

The model is deliberately conventional:

> Shared database, replicated identity and policy, local runtime state, external
> traffic management.

The lab demonstrates clustering, Nginx load balancing, and manual continuity
after one Vectis process stops. It does not add active readiness polling or make
the single PostgreSQL container highly available.

## How This Cluster Works

Picture one brain in two bodies. The *brain* — the cluster identity, the signed
policy, and the PostgreSQL database — is shared. The *bodies* — two Vectis
processes, each with its own address, TLS key, memory, and logs — are
interchangeable. Three ideas carry the lab:

- **One identity, initialized once.** `vectis init` creates the cluster's
  identity; every node reuses it. A node that runs `init` again becomes a
  stranger that cannot read the others' data — the next section shows why.
- **Shared state lives in PostgreSQL; runtime state stays local.** Keys, tokens,
  and blind indexes are shared through the database; each process keeps its own
  memory, logs, and audit chain.
- **You prove it two ways.** Work created on node A is usable on node B (shared
  state), and when one node stops, the other keeps serving through Nginx (manual
  continuity).

The two tables in the next section are these ideas spelled out field by field.

## Prerequisites

Complete the PostgreSQL tutorial through
[Restart And Verify Persistence](PostgreSQL.md#restart-and-verify-persistence).

Before continuing:

- keep the `vectis-postgres-lab` PostgreSQL container running;
- stop the Vectis process from that tutorial with SIGTERM;
- do not run its cleanup section;
- retain `$HOME/vectis-postgres-lab` as node A;
- use the same Linux system, Bash, OpenSSL, and `jq`;
- have Nginx installed and available as `nginx`.

Confirm that PostgreSQL is still ready:

```sh
docker exec vectis-postgres-lab pg_isready -U vectis_owner -d vectis
```

## Understand The Cluster Identity

`vectis init` bootstraps a logical Vectis deployment, not an individual
replica. Run it once, then distribute the resulting encrypted identity to every
node in that cluster.

Node B must **not** run `vectis init`. A separately initialized node derives
different internal encryption and authentication keys. Even if it points to the
same PostgreSQL database, it cannot decrypt operational keys created by A or
verify config signed with A's init identity.

The lab shares these values:

| Shared cluster state | Purpose |
|---|---|
| `init.json` | Encrypted cluster identity and internal root material |
| `init_pub.json` | Public verification material |
| `.unseal_key` | Unlocks the shared encrypted identity |
| Signed config and signature | Common policy selected for this lab |
| `VECTIS_APIKEY_HASH` | Root administrator verifier |
| `VECTIS_POSTGRES_DSN` | Shared durable storage |
| PostgreSQL rows | Keys, encrypted tokens, and blind indexes |

Each replica retains its own:

| Node-local state | Purpose |
|---|---|
| `.env` | Process address, paths, and runtime settings |
| TLS certificate and private key | Transport identity for that process |
| Logs and audit file | Independent operational and evidence streams |
| Loaded keys and config | Local in-memory snapshots |

Sharing config is an operational choice, not a Vectis requirement. This lab
uses identical policy so either node can serve the same application workflow.

## Prepare The Cluster Variables

Define both workspaces and read the shared values from node A without sourcing
its `.env` as a shell program:

```sh
NODE_A="$HOME/vectis-postgres-lab"
NODE_B="$HOME/vectis-cluster-node-b"

ROOT_APIKEY="$(sed -n 's/^VECTIS_APIKEY=//p' "$NODE_A/.env" | head -n 1)"
ROOT_APIKEY_HASH="$(sed -n 's/^VECTIS_APIKEY_HASH=//p' "$NODE_A/.env" | head -n 1)"
POSTGRES_DSN="$(sed -n 's/^VECTIS_POSTGRES_DSN=//p' "$NODE_A/.env" | head -n 1)"
KID="$(jq -r '.tokenization_profiles[]
  | select(.name == "postgres-token-v1")
  | .kid' "$NODE_A/config-postgres.json")"

test -n "$ROOT_APIKEY"
test -n "$ROOT_APIKEY_HASH"
test -n "$POSTGRES_DSN"
test -n "$KID"
test "$KID" != null
```

Those `test` lines are guards: they stop the tutorial right here if any value
came back empty or `null`, instead of letting it fail confusingly several steps
later.

The root API key remains an administrator secret. It is held in this shell so
the tutorial can address either node; it is not copied into node B's `.env`.

## Create Node B

Create a separate workspace and copy only the shared cluster artifacts:

```sh
mkdir -p "$NODE_B"/{logs,tls}
chmod 700 "$NODE_B" "$NODE_B/logs" "$NODE_B/tls"

install -m 0755 "$NODE_A/vectis" "$NODE_B/vectis"
install -m 0600 "$NODE_A/init.json" "$NODE_B/init.json"
install -m 0644 "$NODE_A/init_pub.json" "$NODE_B/init_pub.json"
install -m 0600 "$NODE_A/.unseal_key" "$NODE_B/.unseal_key"
install -m 0600   "$NODE_A/config-postgres.json"   "$NODE_B/config-postgres.json"
install -m 0600   "$NODE_A/config-postgres-sign.json"   "$NODE_B/config-postgres-sign.json"
```

The config signature is portable across paths. It authenticates the canonical
config content, not the source filesystem path. The config and signature still
form one versioned pair: distribute both before requesting a reload.

Generate a TLS key and certificate specifically for B:

```sh
cat > "$NODE_B/tls/openssl.cnf" <<'EOF'
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
  -out "$NODE_B/tls/server-key.pem"

chmod 600 "$NODE_B/tls/server-key.pem"

openssl req -new -x509 -sha256 \
  -days 30 \
  -key "$NODE_B/tls/server-key.pem" \
  -out "$NODE_B/tls/server-cert.pem" \
  -config "$NODE_B/tls/openssl.cnf" \
  -extensions server
```

Create node B's process-local configuration. It uses port `3444`, its own
hostname and logs, and the shared PostgreSQL and root verifier:

```sh
cat > "$NODE_B/.env" <<EOF
VECTIS_MODE=prod
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3444
VECTIS_PUBLIC_ADDR=localhost:3444
VECTIS_TLS_CERT_PATH=tls/server-cert.pem
VECTIS_TLS_KEY_PATH=tls/server-key.pem
VECTIS_TLS_SKIP_VERIFY=true

VECTIS_API_URL=https://localhost:3444
VECTIS_TIMEOUT_SECONDS=30

VECTIS_INIT_KEYS_FILE=init.json
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_UNSEAL_KEY_FILE=.unseal_key

VECTIS_CONFIG_PATH=config-postgres.json
VECTIS_CONFIG_SIGN_PATH=config-postgres-sign.json

VECTIS_STORAGE=postgres
VECTIS_POSTGRES_DSN=$POSTGRES_DSN

VECTIS_LOG_LEVEL=info
VECTIS_LOG_TARGET=file
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.log
VECTIS_METRICS_ENABLED=true

VECTIS_PROTOCOL_VERSION=v1
VECTIS_SENDER_HOSTNAME=vectis-cluster-node-b.local
VECTIS_RECEIVER_HOSTNAME=vectis-cluster-node-b.local
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE=vectis-cluster-node-b-self-test

VECTIS_APIKEY_HASH=$ROOT_APIKEY_HASH
EOF

chmod 600 "$NODE_B/.env"
```

Node A retains port `3443`, its existing TLS identity, and its own logs. TLS
private keys and audit files are intentionally not shared.

## Start Both Nodes

Start A and B in the background. The subshells use `exec` so each saved PID is
the Vectis process itself:

```sh
(
  cd "$NODE_A"
  exec ./vectis serve >>logs/cluster-node-a.log 2>&1
) &
NODE_A_PID=$!

(
  cd "$NODE_B"
  exec ./vectis serve >>logs/cluster-node-b.log 2>&1
) &
NODE_B_PID=$!
```

Create administrative helpers. Each command runs from the target node's
workspace, while the API URL and root API key remain explicit:

```sh
node_a() {
  (
    cd "$NODE_A"
    VECTIS_API_URL=https://localhost:3443 \
      VECTIS_APIKEY="$ROOT_APIKEY" \
      ./vectis "$@"
  )
}

node_b() {
  (
    cd "$NODE_B"
    VECTIS_API_URL=https://localhost:3444 \
      VECTIS_APIKEY="$ROOT_APIKEY" \
      ./vectis "$@"
  )
}
```

Wait for both readiness checks:

```sh
for attempt in $(seq 1 60); do
  node_a health ready >/dev/null 2>&1 && break
  sleep 1
done

for attempt in $(seq 1 60); do
  node_b health ready >/dev/null 2>&1 && break
  sleep 1
done

node_a health startup
node_a health live
node_a health ready

node_b health startup
node_b health live
node_b health ready
```

Both nodes should report ready storage. Compare their loaded key sets:

```sh
node_a keys list --output json | jq .
node_b keys list --output json | jq .

node_a keys list --output json |
  jq -e --arg kid "$KID" '.keys | any(.kid == $kid)'

node_b keys list --output json |
  jq -e --arg kid "$KID" '.keys | any(.kid == $kid)'
```

Both final checks must return `true`. The key came from shared PostgreSQL and
was decrypted with matching init material.

## Distribute A Signed Policy Change

Use A as the administrative source of truth for this lab. Generate a fresh
application credential locally from the shared init identity:

```sh
CLUSTER_APIKEY_OUTPUT="$(
  cd "$NODE_A"
  ./vectis apikey create --output json
)"

CLUSTER_APIKEY="$(printf '%s\n' "$CLUSTER_APIKEY_OUTPUT" |
  jq -r '.VECTIS_APIKEY')"
CLUSTER_APIKEY_HASH="$(printf '%s\n' "$CLUSTER_APIKEY_OUTPUT" |
  jq -r '.VECTIS_APIKEY_HASH')"

test -n "$CLUSTER_APIKEY"
test -n "$CLUSTER_APIKEY_HASH"
test "$CLUSTER_APIKEY" != null
test "$CLUSTER_APIKEY_HASH" != null
```

Edit A's local config and grant only the operations used here:

```sh
(
  cd "$NODE_A"

  ./vectis config permissions add \
    --client cluster-app \
    --apikey-hash "$CLUSTER_APIKEY_HASH" \
    --status active

  for ACTION in token-encode token-decode index-create index-verify; do
    ./vectis config permissions grant cluster-app \
      --kid "$KID" \
      --action "$ACTION"
  done

  ./vectis config validate
  ./vectis config sign
)
```

At this point neither running node has loaded `cluster-app`. A config edit and
signature update are filesystem changes, not runtime mutation.

Copy the complete signed pair to B:

```sh
install -m 0600   "$NODE_A/config-postgres.json"   "$NODE_B/config-postgres.json"
install -m 0600   "$NODE_A/config-postgres-sign.json"   "$NODE_B/config-postgres-sign.json"
```

Define application helpers:

```sh
app_a() {
  (
    cd "$NODE_A"
    VECTIS_API_URL=https://localhost:3443 \
      VECTIS_APIKEY="$CLUSTER_APIKEY" \
      ./vectis "$@"
  )
}

app_b() {
  (
    cd "$NODE_B"
    VECTIS_API_URL=https://localhost:3444 \
      VECTIS_APIKEY="$CLUSTER_APIKEY" \
      ./vectis "$@"
  )
}
```

Before reload, this request must fail authorization even though B already has
the new files:

```sh
if app_b index verify \
  --json "{\"ref\":\"before-config-reload\",\"kid\":\"$KID\",\"profile\":\"postgres-index-v1\",\"plaintext\":\"account-000099\"}"; then
  echo 'unexpected: node B loaded the new policy before reload' >&2
  false
else
  echo 'expected: node B still uses its previous in-memory policy'
fi
```

Reload each node explicitly with its own local config files:

```sh
node_a config reload
node_b config reload

node_a permissions list
node_b permissions list
```

Vectis does not distribute config and does not broadcast reloads. A deployment
system must deliver a matching config/signature pair and trigger or replace
each replica deliberately.

## Run Cross-Node Workflows

Here is the whole point of a cluster: work done on one node is usable on the
other, because both share one identity and one database. A token is a random
ticket standing in for a stored value — create it through A and redeem it
through B:

```sh
TOKEN_RESPONSE="$(app_a token encode "$KID" \
  --json '{"ref":"cluster-token-create","profile":"postgres-token-v1","plaintext":"account-000314","metadata":{"source":"cluster-node-a"}}')"

printf '%s\n' "$TOKEN_RESPONSE" | jq .
CLUSTER_TOKEN="$(printf '%s\n' "$TOKEN_RESPONSE" | jq -r '.token')"

test -n "$CLUSTER_TOKEN"
test "$CLUSTER_TOKEN" != null

app_b token decode \
  --json "{\"ref\":\"cluster-token-decode\",\"kid\":\"$KID\",\"profile\":\"postgres-token-v1\",\"token\":\"$CLUSTER_TOKEN\"}"
```

The decode response from B must return `account-000314`. The plaintext was
encrypted by A, persisted in PostgreSQL, fetched by B, and decrypted using the
same cluster identity.

Create a blind index through B and verify membership through A:

```sh
app_b index create "$KID" \
  --json '{"ref":"cluster-index-create","profile":"postgres-index-v1","plaintext":"account-000271"}'

app_a index verify \
  --json "{\"ref\":\"cluster-index-verify\",\"kid\":\"$KID\",\"profile\":\"postgres-index-v1\",\"plaintext\":\"account-000271\"}"
```

The verification response must report `matched: true`.

## Observe Local Key State

Create another operational key through A and retain its KID:

```sh
NEW_KEY_RESPONSE="$(node_a keys create \
  --tag cluster-reload-demo \
  --profile hybrid-standard-v1 \
  --output json)"

printf '%s\n' "$NEW_KEY_RESPONSE" | jq .
NEW_KID="$(printf '%s\n' "$NEW_KEY_RESPONSE" | jq -r '.kid')"

test -n "$NEW_KID"
test "$NEW_KID" != null
```

A writes the encrypted key to PostgreSQL and inserts it into A's memory. B does
not receive a cache-invalidation event. Confirm the difference:

```sh
node_a keys list --output json |
  jq -e --arg kid "$NEW_KID" '.keys | any(.kid == $kid)'

node_b keys list --output json |
  jq --arg kid "$NEW_KID" '.keys | any(.kid == $kid)'
```

A must report `true`; B should report `false`. Reload only B's key state:

```sh
node_b keys reload

node_b keys list --output json |
  jq -e --arg kid "$NEW_KID" '.keys | any(.kid == $kid)'
```

B must now report `true`.

> Storage is shared. Runtime state is local. Reload is explicit.

Missing-key operations may also lazy-load a key, but explicit reload makes the
state transition visible for this lab.

## Add An Nginx Load Balancer

Any conventional HTTP load balancer can sit in front of Vectis. Vectis does
not require an Nginx-specific protocol, session affinity, or a writer leader.
Treat each ready node like a replica of a conventional application:

```text
Application
    |
    v
Nginx :3543
    |
    +-- Vectis A :3443
    |
    +-- Vectis B :3444
            |
            v
      Shared PostgreSQL
```

Both Vectis nodes may perform reads and writes. PostgreSQL owns durable
concurrency, constraints, and transaction semantics; Vectis owns cryptographic
processing and its local in-memory state. The nodes must still share the same
init identity and must have loaded policy compatible with the requested
operation.

This section assumes the `nginx` executable is already installed. Create a
standalone, unprivileged Nginx workspace instead of changing `/etc/nginx`:

```sh
NGINX_DIR="$HOME/vectis-nginx-lab"
mkdir -p "$NGINX_DIR"/{logs,tls}
chmod 700 "$NGINX_DIR" "$NGINX_DIR/logs" "$NGINX_DIR/tls"

cat > "$NGINX_DIR/tls/openssl.cnf" <<'EOF'
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
  -out "$NGINX_DIR/tls/server-key.pem"

chmod 600 "$NGINX_DIR/tls/server-key.pem"

openssl req -new -x509 -sha256 \
  -days 30 \
  -key "$NGINX_DIR/tls/server-key.pem" \
  -out "$NGINX_DIR/tls/server-cert.pem" \
  -config "$NGINX_DIR/tls/openssl.cnf" \
  -extensions server
```

Create an Nginx configuration with both Vectis nodes in one *upstream* — Nginx's
name for a pool of backend servers it spreads traffic across:

```sh
cat > "$NGINX_DIR/nginx.conf" <<'EOF'
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log info;

events {
    worker_connections 128;
}

http {
    log_format upstream '$remote_addr [$time_local] "$request" $status '
                        'upstream=$upstream_addr upstream_status=$upstream_status';
    access_log logs/access.log upstream;

    upstream vectis_nodes {
        server 127.0.0.1:3443 max_fails=1 fail_timeout=5s;
        server 127.0.0.1:3444 max_fails=1 fail_timeout=5s;
        keepalive 16;
    }

    server {
        listen 127.0.0.1:3543 ssl;
        server_name localhost;

        ssl_certificate tls/server-cert.pem;
        ssl_certificate_key tls/server-key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        client_max_body_size 2m;

        location / {
            proxy_pass https://vectis_nodes;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;

            proxy_ssl_server_name on;
            proxy_ssl_name localhost;
            proxy_ssl_verify off;

            proxy_connect_timeout 2s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
            proxy_next_upstream error timeout;
            proxy_next_upstream_tries 2;
        }
    }
}
EOF

nginx -t -p "$NGINX_DIR/" -c nginx.conf
nginx -p "$NGINX_DIR/" -c nginx.conf
```

`proxy_ssl_verify off` is acceptable only for these self-signed lab
certificates. A real deployment should issue node certificates from a trusted
internal CA and verify the upstream certificate chain.

Define administrator and application helpers for the balanced endpoint:

```sh
cluster() {
  (
    cd "$NODE_A"
    VECTIS_API_URL=https://localhost:3543 \
      VECTIS_APIKEY="$ROOT_APIKEY" \
      ./vectis "$@"
  )
}

cluster_app() {
  (
    cd "$NODE_A"
    VECTIS_API_URL=https://localhost:3543 \
      VECTIS_APIKEY="$CLUSTER_APIKEY" \
      ./vectis "$@"
  )
}

cluster health startup
cluster health live
cluster health ready
```

Run several requests and inspect which upstream served them:

```sh
for attempt in $(seq 1 6); do
  cluster health ready >/dev/null
done

tail -n 6 "$NGINX_DIR/logs/access.log"

cluster_app index verify \
  --json "{\"ref\":\"balanced-index-verify\",\"kid\":\"$KID\",\"profile\":\"postgres-index-v1\",\"plaintext\":\"account-000271\"}"
```

The index verification must report `matched: true` regardless of which node
receives it. Ordinary data workflows do not require sticky sessions because
their durable state is in PostgreSQL.

Do not add `non_idempotent` to `proxy_next_upstream`. Some Vectis `POST`
operations intentionally generate fresh objects or may complete before a
response is lost. Nginx may fail over when it cannot connect to a node, but it
must not promise transparent replay of every state-changing request.

Nginx Open Source provides passive failure handling in this configuration; it
does not actively poll `/healthz/ready`. Production traffic removal based on
readiness requires a load balancer with active HTTP health checks, an
orchestrator, or an external health-check mechanism.

## Exercise Manual Failover

Stop A gracefully:

```sh
kill -TERM "$NODE_A_PID"
wait "$NODE_A_PID"
```

Confirm that A no longer responds while B and the balanced endpoint remain
ready:

```sh
if node_a health live >/dev/null 2>&1; then
  echo 'unexpected: node A is still responding' >&2
  false
else
  echo 'node A is stopped'
fi

node_b health ready
cluster health ready
```

Use the same load-balanced endpoint while A is unavailable:

```sh
cluster_app index verify \
  --json "{\"ref\":\"manual-failover\",\"kid\":\"$KID\",\"profile\":\"postgres-index-v1\",\"plaintext\":\"account-000271\"}"
```

Restart A and wait for readiness:

```sh
(
  cd "$NODE_A"
  exec ./vectis serve >>logs/cluster-node-a-restart.log 2>&1
) &
NODE_A_PID=$!

for attempt in $(seq 1 60); do
  node_a health ready >/dev/null 2>&1 && break
  sleep 1
done

node_a health ready
cluster health ready
node_a keys list --output json |
  jq -e --arg kid "$NEW_KID" '.keys | any(.kid == $kid)'
```

A reloads durable keys and signed config during startup, so the final check must
return `true`.

This is manual continuity, not automatic HA. A production deployment still
needs:

- active readiness-based traffic removal and failover;
- a supervisor or scheduler that replaces failed processes;
- PostgreSQL with its own HA design;
- secure, versioned distribution of init material and signed config.

Vectis does not implement those systems. It exposes readiness and predictable
replica behavior so they can operate it like a conventional application.

## Audit And Shutdown

A and B use the same signing identity but maintain independent audit sequences.
Each audit file has its own genesis, records, checkpoints, and shutdown
boundary. Do not concatenate them and present the result as one hash chain.

Stop Nginx and both nodes gracefully:

```sh
nginx -p "$NGINX_DIR/" -c nginx.conf -s quit
kill -TERM "$NODE_A_PID"
kill -TERM "$NODE_B_PID"
wait "$NODE_A_PID"
wait "$NODE_B_PID"
```

Verify each chain from its own workspace:

```sh
(
  cd "$NODE_A"
  ./vectis audit verify --file logs/audit.log
)

(
  cd "$NODE_B"
  ./vectis audit verify --file logs/audit.log
)
```

Both verifiers use the same `init_pub.json`, but each result describes only
that node's local evidence stream.

Remove application secrets from the shell:

```sh
unset CLUSTER_APIKEY CLUSTER_APIKEY_HASH CLUSTER_APIKEY_OUTPUT
unset CLUSTER_TOKEN TOKEN_RESPONSE
unset ROOT_APIKEY ROOT_APIKEY_HASH
```

Leave the PostgreSQL container and both workspaces in place if you will continue
with deployment tutorials. When the lab is no longer needed, review and remove
node B's workspace manually. Its local TLS key, logs, audit chain, copied init
material, and config are independent of the shared PostgreSQL state.

## What This Lab Proved

- One Vectis init identity can support multiple replicas.
- Signed config can be distributed as an immutable content/signature pair.
- PostgreSQL state is shared while keys and config loaded in memory are local.
- Token and blind-index workflows can cross node boundaries.
- Explicit reload makes state changes predictable.
- A conventional load balancer can expose the replicas through one endpoint.
- Losing one Vectis process does not make the balanced service unavailable.
- Full HA remains a deployment property, not an internal clustering protocol.

For the formal runtime model and failure boundaries, continue with
[Clustering](../Clustering.md) and
[High Availability And Disaster Recovery](../HA_DR.md). To move the same model
into a scheduler, continue with the [Kubernetes tutorial](Kubernetes.md).
