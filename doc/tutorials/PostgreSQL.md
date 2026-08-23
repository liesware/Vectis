# PostgreSQL Tutorial

This tutorial replaces the SQLite backend from
[Getting Started](../GettingStarted.md) with PostgreSQL. It creates a local,
single-node Vectis lab, applies the schema explicitly, gives the Vectis runtime
only the permissions it needs, and verifies that operational keys, reversible
tokens, and blind indexes survive a Vectis restart.

All values used here are synthetic. The Docker credentials and unencrypted
loopback PostgreSQL connection are suitable only for this local lab.

## Why PostgreSQL

SQLite carried Getting Started because one node backed by one local file is the
simplest thing that works. It stops being enough the moment you want more than
one Vectis process to share the same keys and tokens: SQLite is a single file on
one machine, so a second node cannot safely read and write it at the same time.

PostgreSQL is a shared database *server* that many nodes connect to at once, with
real concurrency and transactions. That is why every multi-node and production
Vectis deployment uses it. Nothing about *what* Vectis stores changes — the same
three kinds of state, still encrypted the same way — only *where* it lives and
who can reach it. This tutorial makes that single change on one node first, so
the moving part is isolated before you add a second node in the next tutorial.

## How This Lab Works

You will make one change and then prove it holds. Four ideas carry the whole
tutorial:

- **The node identity does not change.** You reuse the same init keys from Getting
  Started; only the *storage backend* moves from a local SQLite file to a
  PostgreSQL server.
- **Two database roles, not one.** A powerful *owner* role creates the tables
  once; Vectis then runs as a weaker *runtime* role that can only read and write
  rows. If the runtime credential ever leaks, it cannot reshape the database.
- **Vectis stores only protected data.** Keys, token plaintext, and index digests
  reach PostgreSQL already encrypted or hashed — the database never holds anything
  it could read on its own.
- **The proof is a restart.** You create a key, a token, and a blind index, then
  stop the node and start it again. If they come back, the state truly lives in
  PostgreSQL, not in the process's memory.

Every section below is one of these four ideas made concrete.

## Purpose And Boundaries

PostgreSQL stores three kinds of durable Vectis state:

- `opskeys`: encrypted operational keys and encrypted lifecycle properties;
- `tokens`: encrypted plaintext and metadata behind reversible tokens;
- `indexes`: deterministic keyed digests used for blind-index membership.

Vectis connects to the database, validates the expected schema, encrypts
sensitive fields before persistence, and reports storage readiness. It does
not create databases, apply migrations, manage roles, or operate PostgreSQL.
The operator remains responsible for schema deployment, credentials, backups,
HA, monitoring, tuning, and maintenance.

This tutorial does not migrate existing SQLite rows. It also does not cover
clustering or PostgreSQL HA. Those subjects are documented in
[Clustering](../Clustering.md) and
[High Availability And Disaster Recovery](../HA_DR.md).

## Prerequisites

Use a Linux system with:

- the [Getting Started](../GettingStarted.md) lab initialized in
  `$HOME/vectis-lab`;
- its verified `vectis` binary, TLS files, `init.json`, `init_pub.json`,
  `.unseal_key`, and root API-key values;
- Bash;
- Docker;
- `psql` and `jq`.

The Getting Started node must be stopped before this tutorial begins. This lab
reuses its node identity, but deliberately does not reuse its SQLite database
or signed config. Profiles in the old config refer to operational KIDs that do
not exist in the new PostgreSQL database.

## Create An Isolated Workspace

Copy only the reusable bootstrap material into a new directory:

```sh
SOURCE_LAB="$HOME/vectis-lab"
PG_LAB="$HOME/vectis-postgres-lab"

mkdir -p "$PG_LAB"/{logs,tls}
chmod 700 "$PG_LAB" "$PG_LAB/logs" "$PG_LAB/tls"

install -m 0755 "$SOURCE_LAB/vectis" "$PG_LAB/vectis"
install -m 0600 "$SOURCE_LAB/init.json" "$PG_LAB/init.json"
install -m 0644 "$SOURCE_LAB/init_pub.json" "$PG_LAB/init_pub.json"
install -m 0600 "$SOURCE_LAB/.unseal_key" "$PG_LAB/.unseal_key"
install -m 0600 "$SOURCE_LAB/tls/server-key.pem" "$PG_LAB/tls/server-key.pem"
install -m 0644 "$SOURCE_LAB/tls/server-cert.pem" "$PG_LAB/tls/server-cert.pem"

cd "$PG_LAB"
```

Read the existing root API-key values without sourcing the old `.env` as a
shell script:

```sh
ROOT_APIKEY="$(sed -n 's/^VECTIS_APIKEY=//p' "$SOURCE_LAB/.env" | head -n 1)"
ROOT_APIKEY_HASH="$(sed -n 's/^VECTIS_APIKEY_HASH=//p' "$SOURCE_LAB/.env" | head -n 1)"

test -n "$ROOT_APIKEY"
test -n "$ROOT_APIKEY_HASH"
```

These variables remain secrets even in a lab. Do not print them or commit the
workspace.

## Start PostgreSQL With Docker

Run a pinned PostgreSQL image and bind it only to loopback:

```sh
docker run --name vectis-postgres-lab \
  --restart no \
  -e POSTGRES_DB=vectis \
  -e POSTGRES_USER=vectis_owner \
  -e POSTGRES_PASSWORD=vectis-owner-lab-only \
  -p 127.0.0.1:5432:5432 \
  -d postgres:17-alpine
```

Wait for PostgreSQL to accept connections:

```sh
for attempt in $(seq 1 60); do
  if docker exec vectis-postgres-lab \
    pg_isready -U vectis_owner -d vectis >/dev/null 2>&1
  then
    break
  fi
  sleep 1
done

docker exec vectis-postgres-lab pg_isready -U vectis_owner -d vectis
```

## Create The Schema And Runtime Role

The container bootstrap account owns the database and schema. Vectis connects
with a separate role named `vectis_usr` that cannot create or drop schema
objects.

Why two roles? The account that creates tables is powerful — it can drop or
reshape the entire schema. Vectis never needs that power at runtime; it only
reads and writes rows. So it runs as a second, weaker role. This is defense in
depth: if the runtime credential ever leaks, it cannot alter or destroy the
schema, only touch the rows it was explicitly granted.

The three `CREATE TABLE` statements below are exactly the reference schema in
`src/db/postgres_schema.sql`:

```sh
docker exec -i vectis-postgres-lab \
  psql -v ON_ERROR_STOP=1 -U vectis_owner -d vectis <<'SQL'
CREATE ROLE vectis_usr LOGIN PASSWORD 'vectis-runtime-lab-only';

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

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE vectis TO vectis_usr;
GRANT USAGE ON SCHEMA public TO vectis_usr;
GRANT SELECT, INSERT, UPDATE ON TABLE public.opskeys TO vectis_usr;
GRANT SELECT, INSERT, DELETE ON TABLE public.tokens TO vectis_usr;
GRANT SELECT, INSERT ON TABLE public.indexes TO vectis_usr;
SQL
```

`UPDATE` is required for lifecycle properties. `DELETE` on `tokens` is
required because decoding a profile with `one_time=true` consumes its row
transactionally. Blind indexes are insert-only from the Vectis runtime's point
of view.

Confirm the role can connect and has no schema creation privilege:

```sh
PGPASSWORD=vectis-runtime-lab-only \
  psql -h 127.0.0.1 -U vectis_usr -d vectis \
  -c "SELECT has_schema_privilege('vectis_usr', 'public', 'CREATE');"

PGPASSWORD=vectis-runtime-lab-only \
  psql -h 127.0.0.1 -U vectis_usr -d vectis -c '\dt public.*'
```

The first command should report `f`. The second should show the three tables.

## Using An Existing PostgreSQL Server

For an operator-managed PostgreSQL service, perform the same provisioning
explicitly. The account used in this section must be allowed to create roles
and databases. Start by entering the server connection details and passwords:

```sh
export PGHOST=postgres.example.internal
export PGPORT=5432
export PGADMIN_USER=postgres
export PGADMIN_DATABASE=postgres

# Use these when the administrative PostgreSQL endpoint supports TLS.
export PGSSLMODE=verify-full
export PGSSLROOTCERT=/path/to/postgresql-ca.pem

read -rsp 'PostgreSQL administrator password: ' PGADMIN_PASSWORD
printf '\n'
read -rsp 'Vectis schema-owner password: ' VECTIS_OWNER_PASSWORD
printf '\n'
read -rsp 'Vectis runtime password: ' VECTIS_RUNTIME_PASSWORD
printf '\n'
```

Do not place these passwords in shell history. `psql` variables quote the role
passwords as SQL literals instead of interpolating them into SQL text.

Create the schema-owner role, runtime role, and database:

```sh
PGPASSWORD="$PGADMIN_PASSWORD" \
  psql -v ON_ERROR_STOP=1 \
  -h "$PGHOST" -p "$PGPORT" \
  -U "$PGADMIN_USER" -d "$PGADMIN_DATABASE" \
  --set=owner_password="$VECTIS_OWNER_PASSWORD" \
  --set=runtime_password="$VECTIS_RUNTIME_PASSWORD" <<'SQL'
CREATE ROLE vectis_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE vectis_usr LOGIN PASSWORD :'runtime_password';
CREATE DATABASE vectis OWNER vectis_owner;
SQL
```

Connect as the schema owner, create the exact Vectis schema, and grant the
runtime permissions:

```sh
PGPASSWORD="$VECTIS_OWNER_PASSWORD" \
  psql -v ON_ERROR_STOP=1 \
  -h "$PGHOST" -p "$PGPORT" \
  -U vectis_owner -d vectis <<'SQL'
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

REVOKE CONNECT ON DATABASE vectis FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE vectis TO vectis_usr;
GRANT USAGE ON SCHEMA public TO vectis_usr;
GRANT SELECT, INSERT, UPDATE ON TABLE public.opskeys TO vectis_usr;
GRANT SELECT, INSERT, DELETE ON TABLE public.tokens TO vectis_usr;
GRANT SELECT, INSERT ON TABLE public.indexes TO vectis_usr;
SQL
```

Verify the runtime login and every required privilege before configuring
Vectis:

```sh
PGPASSWORD="$VECTIS_RUNTIME_PASSWORD" \
  psql -v ON_ERROR_STOP=1 \
  -h "$PGHOST" -p "$PGPORT" \
  -U vectis_usr -d vectis <<'SQL'
SELECT current_user;
SELECT has_schema_privilege(current_user, 'public', 'CREATE')
       AS can_create_schema_objects;
SELECT has_table_privilege(current_user, 'public.opskeys', 'SELECT')
       AND has_table_privilege(current_user, 'public.opskeys', 'INSERT')
       AND has_table_privilege(current_user, 'public.opskeys', 'UPDATE')
       AS opskeys_access;
SELECT has_table_privilege(current_user, 'public.tokens', 'SELECT')
       AND has_table_privilege(current_user, 'public.tokens', 'INSERT')
       AND has_table_privilege(current_user, 'public.tokens', 'DELETE')
       AS tokens_access;
SELECT has_table_privilege(current_user, 'public.indexes', 'SELECT')
       AND has_table_privilege(current_user, 'public.indexes', 'INSERT')
       AS indexes_access;
SQL
```

The result must identify `vectis_usr`, report `f` for schema creation, and
report `t` for all three table checks.

The current Vectis PostgreSQL client is built without direct PostgreSQL TLS
support. The runtime endpoint must therefore be reachable through a protected
private network or a local authenticated TLS connector/proxy supplied by the
deployment. Do not expose a plaintext PostgreSQL endpoint to an untrusted
network.

Build the runtime DSN from the endpoint Vectis will actually reach. A DSN (Data
Source Name) is the single connection string that tells Vectis where the database
is and how to log in — host, port, database, user, and password in one URL. If a
local connector is required, set `VECTIS_DB_HOST` and `VECTIS_DB_PORT` to that
connector's loopback listener:

```sh
export VECTIS_DB_HOST="${VECTIS_DB_HOST:-$PGHOST}"
export VECTIS_DB_PORT="${VECTIS_DB_PORT:-$PGPORT}"

ENCODED_RUNTIME_PASSWORD="$(printf '%s' "$VECTIS_RUNTIME_PASSWORD" | jq -sRr @uri)"
export VECTIS_POSTGRES_DSN="postgresql://vectis_usr:${ENCODED_RUNTIME_PASSWORD}@${VECTIS_DB_HOST}:${VECTIS_DB_PORT}/vectis"

PGSSLMODE=disable PGPASSWORD="$VECTIS_RUNTIME_PASSWORD" \
  psql -h "$VECTIS_DB_HOST" -p "$VECTIS_DB_PORT" \
  -U vectis_usr -d vectis -c 'SELECT 1;'
```

Keep the administrator and schema-owner credentials out of Vectis. Only the
runtime DSN belongs in its process configuration. Backups, replication,
failover, and PostgreSQL monitoring remain deployment responsibilities.

## Configure Vectis

Create an independent process configuration. Port `3443` avoids colliding with
the original Getting Started lab. For Docker, the first command selects the
local lab DSN. For an existing server, it preserves the
`VECTIS_POSTGRES_DSN` exported above:

```sh
POSTGRES_DSN="${VECTIS_POSTGRES_DSN:-postgres://vectis_usr:vectis-runtime-lab-only@127.0.0.1:5432/vectis}"

cat > .env <<EOF
VECTIS_MODE=prod
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3443
VECTIS_PUBLIC_ADDR=localhost:3443
VECTIS_TLS_CERT_PATH=tls/server-cert.pem
VECTIS_TLS_KEY_PATH=tls/server-key.pem
VECTIS_TLS_SKIP_VERIFY=true

VECTIS_API_URL=https://localhost:3443
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
VECTIS_SENDER_HOSTNAME=vectis-postgres-lab.local
VECTIS_RECEIVER_HOSTNAME=vectis-postgres-lab.local
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE=vectis-postgres-self-test

VECTIS_APIKEY=$ROOT_APIKEY
VECTIS_APIKEY_HASH=$ROOT_APIKEY_HASH
EOF

chmod 600 .env
```

The DSN contains a lab-only password. In a real deployment, inject the DSN
through the platform's secret-delivery mechanism and follow the PostgreSQL
provider's TLS requirements. `VECTIS_TLS_SKIP_VERIFY=true` affects Vectis HTTP
clients and is present only because this lab reuses a self-signed HTTPS
certificate.

## Start And Validate The Node

Start Vectis in the background and wait for readiness:

```sh
./vectis serve >logs/server-postgres.log 2>&1 &
VECTIS_PID=$!

for attempt in $(seq 1 60); do
  if ./vectis health ready >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

./vectis health startup
./vectis health live
./vectis health ready
```

At startup, Vectis checks all three tables, their columns, nullability, lengths,
and primary keys. If the DSN is unreachable or the schema is absent or
incompatible, startup fails instead of operating against an unknown layout.
Inspect `logs/server-postgres.log` if readiness does not become healthy.

## Create Durable State

Create an operational key and save its `kid` from the response:

```sh
./vectis keys create --tag postgres-tutorial --profile hybrid-standard-v1
KID=paste-your-kid-here
```

Create a least-privilege application credential and save the two returned
values:

```sh
./vectis apikey create
APP_APIKEY=paste-the-apikey-value-here
APP_APIKEY_HASH=paste-the-apikey-hash-here
```

Now write the policy for this node. Two ideas from Getting Started carry the
whole section:

- a **permission** is one allowlist entry — this client, on this key, may do this
  one action; anything not granted is denied;
- a **profile** is the operator's named recipe for one operation (here, a token
  and a blind index), so the application asks for a profile by name and never
  improvises the crypto parameters.

Everything below only edits the local `config-postgres.json` file — the running
node does not change yet, because editing is proposing. The last four commands
are the decision: inspect it, validate it, *sign* it with the node's init keys,
and reload it. Only after `config reload` does the new policy take effect.

```sh
./vectis config init
./vectis config permissions add \
  --client postgres-app \
  --apikey-hash "$APP_APIKEY_HASH" \
  --status active

for ACTION in token-encode token-decode index-create index-verify; do
  ./vectis config permissions grant postgres-app \
    --kid "$KID" \
    --action "$ACTION"
done

./vectis config token add \
  --name postgres-token-v1 \
  --kid "$KID" \
  --token-prefix tok_pg \
  --token-len 32 \
  --max-plaintext-len 128 \
  --one-time false

./vectis config mac add \
  --name postgres-index-v1 \
  --kid "$KID" \
  --context 'tenant=lab;field=account;purpose=blind-index;version=1'

./vectis config list
./vectis config validate
./vectis config sign
./vectis config reload
```

The persistent token profile deliberately uses `one_time=false`. A one-time
token would be deleted after its first successful decode and would therefore
be the wrong artifact for this restart test.

Define a small helper that presents the application API key without replacing
the root credential in `.env`:

```sh
run_as_app() {
  VECTIS_APIKEY="$APP_APIKEY" ./vectis "$@"
}
```

Remember what a token is: a random ticket that stands in for the value, with no
mathematical link to it — the real plaintext lives encrypted in the `tokens`
table. Create one and keep the ticket:

```sh
TOKEN_RESPONSE="$(run_as_app token encode "$KID" \
  --json '{"ref":"pg-token-create","profile":"postgres-token-v1","plaintext":"account-000042","metadata":{"source":"postgres-tutorial"}}')"

printf '%s\n' "$TOKEN_RESPONSE" | jq .
TOKEN="$(printf '%s\n' "$TOKEN_RESPONSE" | jq -r '.token')"
test -n "$TOKEN"
test "$TOKEN" != null
```

A blind index answers one question — *have we seen this value before?* — without
ever storing the value; it keeps only a keyed digest in the `indexes` table.
Create one for another synthetic value:

```sh
run_as_app index create "$KID" \
  --json '{"ref":"pg-index-create","profile":"postgres-index-v1","plaintext":"account-000099"}'
```

## Restart And Verify Persistence

Stop Vectis gracefully, wait for it to exit, and start the same node again:

```sh
kill -TERM "$VECTIS_PID"
wait "$VECTIS_PID"

./vectis serve >logs/server-postgres-restart.log 2>&1 &
VECTIS_PID=$!

for attempt in $(seq 1 60); do
  if ./vectis health ready >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

./vectis health ready
./vectis keys list
```

This is the real test. Restarting discarded everything the node held in memory
and rebuilt it from PostgreSQL. If the token still decodes to its original value
and the index still reports a match, the state genuinely survived in the
database — not in process memory. Decode the persistent token and verify
blind-index membership:

```sh
run_as_app token decode \
  --json "{\"ref\":\"pg-token-after-restart\",\"kid\":\"$KID\",\"profile\":\"postgres-token-v1\",\"token\":\"$TOKEN\"}"

run_as_app index verify \
  --json "{\"ref\":\"pg-index-after-restart\",\"kid\":\"$KID\",\"profile\":\"postgres-index-v1\",\"plaintext\":\"account-000099\"}"
```

The token response should contain `account-000042`; the index response should
report `matched: true`. Together with `keys list`, these checks exercise all
three PostgreSQL tables after process memory has been discarded and rebuilt.

## Inspect Stored State

Inspect row identifiers and encoded lengths without printing complete stored
payloads:

```sh
PGPASSWORD=vectis-runtime-lab-only \
  psql -h 127.0.0.1 -U vectis_usr -d vectis <<'SQL'
SELECT kid, length(keys) AS keys_chars,
       length(properties) AS properties_chars
FROM opskeys;

SELECT kid, length(hashid) AS hashid_chars,
       length(data) AS data_chars
FROM tokens;

SELECT kid, length(digest) AS digest_chars
FROM indexes;
SQL
```

`opskeys.keys`, `opskeys.properties`, and `tokens.data` are encrypted by
Vectis before they reach PostgreSQL. `indexes.digest` is deterministic keyed
material, not plaintext and not a reversible token. PostgreSQL stores these
values but does not possess the Vectis key material needed to interpret
encrypted fields.

## Failure Modes

- **PostgreSQL unavailable:** Vectis startup or storage-backed operations fail,
  and readiness does not claim healthy storage.
- **Schema missing or incompatible:** startup fails during schema validation;
  Vectis does not silently create or repair tables.
- **Insufficient grants:** the corresponding storage operation fails. Keep the
  documented runtime grants together as one contract.
- **Wrong or lost init material:** persisted operational keys cannot be
  decrypted, even when the PostgreSQL rows are intact.
- **Database restored without matching init material:** the restored encrypted
  rows remain unusable.
- **Old SQLite state:** changing `VECTIS_STORAGE` does not copy it. Migration
  must be designed and performed separately.

For broader recovery behavior, see
[High Availability And Disaster Recovery](../HA_DR.md).

## What You Learned

You moved one Vectis node from SQLite to PostgreSQL and proved the change end to
end:

- **why the switch** — a shared database server replaces a single local file, so
  more than one node can use the same state; this is the groundwork for
  clustering;
- **least privilege at the database** — a schema-owner role creates the tables,
  and Vectis runs as a separate, weaker role that can only read and write rows,
  so a leaked runtime credential cannot reshape or drop the schema;
- **what Vectis stores** — encrypted keys, encrypted token plaintext, and keyed
  blind-index digests; PostgreSQL holds the rows but never the key material to
  read them;
- **durable state** — an operational key, a reversible token, and a blind index
  all survived a full restart, because they live in the database, not in process
  memory;
- **signed policy, again** — editing `config-postgres.json` only proposed the
  change; validate → sign → reload is what made it real.

## Cleanup

Stop Vectis gracefully before removing the lab database:

```sh
kill -TERM "$VECTIS_PID"
wait "$VECTIS_PID"
docker rm -f vectis-postgres-lab
```

The final Docker command permanently removes the tutorial database because no
volume was attached. After confirming that no needed test material remains,
you can remove `$HOME/vectis-postgres-lab` manually.

Continue with [Clustering And HA Foundations](ClusteringHA.md) to add a second
Vectis replica to this PostgreSQL lab. For the formal shared-storage model, see
[Clustering](../Clustering.md). For Kubernetes deployment values, use the
[Helm chart documentation](../../charts/vectis/README.md).
