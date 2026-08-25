# Backup And Recovery Tutorial

This tutorial builds a small Vectis lab, protects synthetic data, backs the
node up, then rebuilds the workspace from the recovery set. Recovery is proved
by decoding a token and verifying a blind index created before the simulated
loss.

The lab covers SQLite and PostgreSQL. Pick one backend and follow only the
blocks for that backend. To keep the focus on recovery mechanics, Vectis runs
in `dev` mode over loopback HTTP. A production recovery set must also include
the TLS material and external operational controls used by that deployment.

## How This Lab Works

Vectis storage contains protected records:

- operational keys and token payloads are encrypted before storage;
- blind indexes are deterministic keyed digests, not ciphertext, and reveal
  equality and frequency within the same profile.

The stored records depend on the matching `init` identity. Restoring the
database without that identity and its unseal method does not restore a usable
Vectis node.

Four rules carry the tutorial:

- **Storage and cryptographic identity form one recovery boundary.** They must
  be backed up coherently and restored together.
- **The unseal key needs separate custody.** Do not store it as plaintext beside
  the database backup.
- **Signed policy is a pair.** `config.json` and `config_sign.json` are one
  versioned unit.
- **A backup is useful only after a restore test.** This lab recreates the node
  and performs operations against data captured before the loss.

## What A Recovery Set Contains

The exact recovery set depends on the deployment:

| Item | Purpose | This lab |
|---|---|---|
| SQLite snapshot or PostgreSQL dump | durable `opskeys`, `tokens`, and `indexes` state | backed up |
| `init.json` | encrypted Vectis identity and internal key material | backed up |
| unseal key or provider state | unlocks `init.json` | encrypted under separate custody |
| `config.json` and `config_sign.json` | signed policy | backed up as one pair |
| process configuration and API-key material | reconstructs runtime authentication and storage access | encrypted under separate custody |
| `init_pub.json` | public verification material, including audit verification | backed up |
| TLS certificate and private key | restores HTTPS service identity in `prod` | omitted because this lab uses `dev` |
| audit records | preserves evidence when required by policy | exported after graceful shutdown |

The data backup and custody backup together form the recovery set, but they
should not share the same security domain in a real deployment. API client
credentials outside the Vectis node also need their own distribution and
recovery process.

See [HA_DR.md](../HA_DR.md) for the complete operational model.

## Prerequisites

Use a Linux system with:

- a verified `vectis` binary outside the lab workspace;
- Bash, `jq`, `tar`, `sha256sum`, and `age`;
- for SQLite: `sqlite3`;
- for PostgreSQL: `psql`, `pg_dump`, `pg_restore`, and the owner and runtime
  roles created in
  [PostgreSQL.md](PostgreSQL.md#create-the-schema-and-runtime-role).

The PostgreSQL examples use the synthetic credentials from that tutorial:

```text
schema owner: vectis_owner / vectis-owner-lab-only
runtime role: vectis_usr / vectis-runtime-lab-only
```

For an existing PostgreSQL service, override the endpoint and passwords below.
This tutorial keeps the database and role names fixed to those provisioned by
the PostgreSQL tutorial. The `PGADMIN_USER` account must be allowed to create and
drop databases. On the local Docker server `vectis_owner` is the superuser, so it
qualifies; on a managed server that role is usually a plain owner without
create-database rights, so point `PGADMIN_USER`/`PGADMIN_PASSWORD` at an
administrative account (for example `postgres`) instead.

## Create Isolated Paths

Keep the live node, data backup, and custody backup in separate directories.
The separation is local for this exercise; real backups should use separate
storage and access controls.

```sh
export VECTIS_SOURCE_BIN=/path/to/verified/vectis
export BACKEND=sqlite # use: sqlite or postgres

export LAB="$HOME/vectis-backup-lab"
export DATA_BACKUP="$HOME/vectis-backup-data"
export CUSTODY_BACKUP="$HOME/vectis-backup-custody"

test "$LAB" != "$DATA_BACKUP"
test "$LAB" != "$CUSTODY_BACKUP"
test "$DATA_BACKUP" != "$CUSTODY_BACKUP"

mkdir -p "$LAB"/{db,logs} "$DATA_BACKUP" "$CUSTODY_BACKUP"
chmod 700 "$LAB" "$LAB/db" "$LAB/logs" "$DATA_BACKUP" "$CUSTODY_BACKUP"
install -m 0755 "$VECTIS_SOURCE_BIN" "$LAB/vectis"
cd "$LAB"
```

For PostgreSQL, define the connection details. These defaults match the local
Docker server from the PostgreSQL tutorial:

```sh
if [ "$BACKEND" = postgres ]; then
  export PGHOST="${PGHOST:-127.0.0.1}"
  export PGPORT="${PGPORT:-5432}"
  export PGDATABASE=vectis_backup_lab
  export PGADMIN_DATABASE=postgres
  export PGADMIN_USER=vectis_owner
  export PGADMIN_PASSWORD="${PGADMIN_PASSWORD:-vectis-owner-lab-only}"
  export PGOWNER_USER=vectis_owner
  export PGOWNER_PASSWORD="${PGOWNER_PASSWORD:-vectis-owner-lab-only}"
  export PGRUNTIME_USER=vectis_usr
  export PGRUNTIME_PASSWORD="${PGRUNTIME_PASSWORD:-vectis-runtime-lab-only}"

  ENCODED_RUNTIME_PASSWORD="$(printf '%s' "$PGRUNTIME_PASSWORD" | jq -sRr @uri)"
  export VECTIS_POSTGRES_DSN="postgresql://${PGRUNTIME_USER}:${ENCODED_RUNTIME_PASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}"
fi
```

## Initialize The Node

For SQLite, create the exact Vectis schema without requiring a source checkout:

```sh
if [ "$BACKEND" = sqlite ]; then
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
fi
```

For PostgreSQL, create a dedicated lab database and the exact Vectis schema.
The fixed name prevents this exercise from targeting the `vectis` database
used by the preceding tutorial or another deployment:

```sh
if [ "$BACKEND" = postgres ]; then
  PGPASSWORD="$PGADMIN_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGADMIN_USER" -d "$PGADMIN_DATABASE" <<'SQL'
DROP DATABASE IF EXISTS vectis_backup_lab WITH (FORCE);
CREATE DATABASE vectis_backup_lab OWNER vectis_owner;
SQL

  PGPASSWORD="$PGOWNER_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGOWNER_USER" -d "$PGDATABASE" <<'SQL'
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

REVOKE CONNECT ON DATABASE vectis_backup_lab FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE vectis_backup_lab TO vectis_usr;
GRANT USAGE ON SCHEMA public TO vectis_usr;
GRANT SELECT, INSERT, UPDATE ON TABLE public.opskeys TO vectis_usr;
GRANT SELECT, INSERT, DELETE ON TABLE public.tokens TO vectis_usr;
GRANT SELECT, INSERT ON TABLE public.indexes TO vectis_usr;
SQL
fi
```

Confirm the PostgreSQL runtime role can reach the prepared schema:

```sh
if [ "$BACKEND" = postgres ]; then
  PGPASSWORD="$PGRUNTIME_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGRUNTIME_USER" -d "$PGDATABASE" -c '\dt public.*'
fi
```

Initialize Vectis and capture its generated secrets:

```sh
if [ "$BACKEND" = sqlite ]; then
  INIT_OUTPUT="$(VECTIS_STORAGE=sqlite VECTIS_SQLITE_PATH=db/data.db ./vectis init)"
else
  INIT_OUTPUT="$(VECTIS_STORAGE=postgres VECTIS_POSTGRES_DSN="$VECTIS_POSTGRES_DSN" ./vectis init)"
fi

value() {
  printf '%s\n' "$INIT_OUTPUT" |
    awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }'
}

printf '%s\n' "$(value VECTIS_UNSEAL_KEY)" > .unseal_key
chmod 600 .unseal_key
ROOT_APIKEY="$(value VECTIS_APIKEY)"
ROOT_APIKEY_HASH="$(value VECTIS_APIKEY_HASH)"
test -n "$ROOT_APIKEY"
test -n "$ROOT_APIKEY_HASH"
```

Create one unambiguous process configuration for the selected backend:

```sh
{
  cat <<EOF
VECTIS_MODE=dev
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3010
VECTIS_API_URL=http://127.0.0.1:3010
VECTIS_INIT_KEYS_FILE=init.json
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
VECTIS_LOG_TARGET=file
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.log
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_APIKEY=$ROOT_APIKEY
VECTIS_APIKEY_HASH=$ROOT_APIKEY_HASH
EOF

  if [ "$BACKEND" = sqlite ]; then
    cat <<EOF
VECTIS_STORAGE=sqlite
VECTIS_SQLITE_PATH=db/data.db
EOF
  else
    cat <<EOF
VECTIS_STORAGE=postgres
VECTIS_POSTGRES_DSN=$VECTIS_POSTGRES_DSN
EOF
  fi
} > .env
chmod 600 .env
```

## Seed State To Recover

Start the node and create an operational key, a reversible token, and a blind
index. Together they exercise all three storage tables.

```sh
./vectis serve >logs/vectis.log 2>&1 &
VECTIS_PID=$!
for _ in $(seq 1 60); do
  ./vectis health ready >/dev/null 2>&1 && break
  sleep 0.5
done
./vectis health ready
```

Create a least-privilege application credential and signed profiles:

```sh
KID="$(./vectis keys create --tag backup-lab \
  --profile hybrid-standard-v1 --output json | jq -r .kid)"

APP_OUTPUT="$(./vectis apikey create --output json)"
APP_APIKEY="$(printf '%s\n' "$APP_OUTPUT" | jq -r .VECTIS_APIKEY)"
APP_APIKEY_HASH="$(printf '%s\n' "$APP_OUTPUT" | jq -r .VECTIS_APIKEY_HASH)"

./vectis config init
./vectis config permissions add \
  --client app --apikey-hash "$APP_APIKEY_HASH" --status active
for ACTION in token-encode token-decode index-create index-verify; do
  ./vectis config permissions grant app --kid "$KID" --action "$ACTION"
done
./vectis config token add --name backup-token-v1 --kid "$KID" \
  --token-prefix tok --token-len 32 --max-plaintext-len 128 --one-time false
./vectis config mac add --name backup-index-v1 --kid "$KID" \
  --context 'purpose=backup-lab'
./vectis config validate
./vectis config sign
./vectis config reload
```

Create the records that will prove recovery:

```sh
run_as_app() {
  VECTIS_APIKEY="$APP_APIKEY" ./vectis "$@"
}

TOKEN="$(run_as_app token encode "$KID" \
  --json '{"ref":"seed","profile":"backup-token-v1","plaintext":"account-000042"}' \
  --output json | jq -r .token)"

run_as_app index create "$KID" \
  --json '{"ref":"seed","profile":"backup-index-v1","plaintext":"account-000099"}'
```

Do not create keys, tokens, indexes, or policy changes after this point until
the recovery set is complete. This creates a clear consistency boundary for
the lab. Real systems need a documented snapshot and policy-version boundary.

## Back Up Storage

SQLite uses its online backup command instead of copying a live database file:

```sh
if [ "$BACKEND" = sqlite ]; then
  sqlite3 db/data.db ".backup '$DATA_BACKUP/data.db'"
  chmod 600 "$DATA_BACKUP/data.db"
fi
```

PostgreSQL uses a consistent logical dump taken by the schema owner:

```sh
if [ "$BACKEND" = postgres ]; then
  PGPASSWORD="$PGOWNER_PASSWORD" \
    pg_dump --format=custom --file="$DATA_BACKUP/vectis.dump" \
    -h "$PGHOST" -p "$PGPORT" -U "$PGOWNER_USER" "$PGDATABASE"
  chmod 600 "$DATA_BACKUP/vectis.dump"
fi
```

The PostgreSQL dump covers the Vectis database. PostgreSQL cluster recovery,
including roles and their credentials, remains part of the PostgreSQL
platform's own DR plan. If the whole cluster is lost, recreate the owner and
runtime roles from [PostgreSQL.md](PostgreSQL.md) before restoring this dump.

## Back Up Identity And Policy

Copy the encrypted identity, public verification material, and signed policy
pair into the data backup:

```sh
install -m 0600 init.json "$DATA_BACKUP/init.json"
install -m 0644 init_pub.json "$DATA_BACKUP/init_pub.json"
install -m 0600 config.json "$DATA_BACKUP/config.json"
install -m 0600 config_sign.json "$DATA_BACKUP/config_sign.json"
```

## Protect Runtime Secrets And Recovery Evidence

The process configuration contains authentication and storage credentials, and
the unseal key unlocks the node identity. Store them under separate encrypted
custody. The small verification file contains only synthetic lab values needed
to prove the restore without relying on shell variables that survived the
simulated loss.

```sh
cat > .recovery-check.env <<EOF
RECOVERY_KID=$KID
RECOVERY_TOKEN=$TOKEN
RECOVERY_APP_APIKEY=$APP_APIKEY
EOF
chmod 600 .recovery-check.env

tar -cf - .env .unseal_key .recovery-check.env |
  age -p -o "$CUSTODY_BACKUP/runtime-secrets.tar.age"
chmod 600 "$CUSTODY_BACKUP/runtime-secrets.tar.age"
rm -f .recovery-check.env
```

`age -p` protects the archive according to the strength and custody of the
passphrase. In a real deployment, prefer a dedicated secret manager or an
organization-controlled `age` recipient. Vectis does not currently provide
built-in KMS or HSM auto-unseal.

Do not store the custody archive and data backup under the same credentials or
in the same backup system in production.

## Finalize And Check The Recovery Set

Stop Vectis gracefully so its local audit writer can flush and checkpoint:

```sh
kill -TERM "$VECTIS_PID"
wait "$VECTIS_PID"
unset VECTIS_PID
```

Verify the closed audit chain, then copy it as recovery evidence:

```sh
./vectis audit verify --file logs/audit.log
install -m 0600 logs/audit.log "$DATA_BACKUP/audit.log"
```

The audit copy is evidence, not service state. A restored node starts a new
local audit-chain segment. Production deployments should also retain audit
records in an external collector.

Create and verify a checksum manifest for the data backup:

```sh
if [ "$BACKEND" = sqlite ]; then
  (
    cd "$DATA_BACKUP"
    LC_ALL=C sha256sum data.db init.json init_pub.json \
      config.json config_sign.json audit.log | LC_ALL=C sort -k2 > SHA256SUMS
    sha256sum -c SHA256SUMS
  )
else
  (
    cd "$DATA_BACKUP"
    LC_ALL=C sha256sum vectis.dump init.json init_pub.json \
      config.json config_sign.json audit.log | LC_ALL=C sort -k2 > SHA256SUMS
    sha256sum -c SHA256SUMS
  )
fi
```

The data backup and encrypted custody archive now form the lab's recovery set.
The checksum manifest detects accidental corruption. A production backup system
must also authenticate that manifest or protect it with immutable retention and
access controls so an attacker cannot replace both a file and its checksum.

## Simulate Loss

Drop only the Vectis database for the PostgreSQL path. The PostgreSQL server and
cluster roles remain available; full PostgreSQL cluster recovery is outside
this tutorial.

```sh
if [ "$BACKEND" = postgres ]; then
  PGPASSWORD="$PGADMIN_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGADMIN_USER" -d "$PGADMIN_DATABASE" \
    -c 'DROP DATABASE vectis_backup_lab WITH (FORCE);'
fi
```

Remove and recreate the live workspace. The guard prevents an accidental
deletion if `LAB` was changed to an unexpected path.

```sh
cd "$HOME"
test "$LAB" = "$HOME/vectis-backup-lab"
rm -rf -- "$LAB"
mkdir -p "$LAB"/{db,logs}
chmod 700 "$LAB" "$LAB/db" "$LAB/logs"
install -m 0755 "$VECTIS_SOURCE_BIN" "$LAB/vectis"
cd "$LAB"

unset INIT_OUTPUT ROOT_APIKEY ROOT_APIKEY_HASH APP_OUTPUT APP_APIKEY
unset APP_APIKEY_HASH KID TOKEN
```

At this point, no live Vectis files or verification values remain. Recovery
uses only the two backup locations and external PostgreSQL administration.

## Restore Storage

Verify the data backup before using it:

```sh
(
  cd "$DATA_BACKUP"
  sha256sum -c SHA256SUMS
)
```

Restore SQLite with restrictive permissions:

```sh
if [ "$BACKEND" = sqlite ]; then
  install -m 0600 "$DATA_BACKUP/data.db" db/data.db
fi
```

For PostgreSQL, recreate the database, restore the dump as the schema owner,
and reapply database and schema hardening. Database-level access controls are
not completely represented by a single-database dump.

```sh
if [ "$BACKEND" = postgres ]; then
  PGPASSWORD="$PGADMIN_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGADMIN_USER" -d "$PGADMIN_DATABASE" \
    -c 'CREATE DATABASE vectis_backup_lab OWNER vectis_owner;'

  PGPASSWORD="$PGOWNER_PASSWORD" \
    pg_restore --exit-on-error --no-owner --role="$PGOWNER_USER" \
    -h "$PGHOST" -p "$PGPORT" -U "$PGOWNER_USER" \
    -d "$PGDATABASE" "$DATA_BACKUP/vectis.dump"

  PGPASSWORD="$PGOWNER_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGOWNER_USER" -d "$PGDATABASE" <<SQL
REVOKE CONNECT ON DATABASE vectis_backup_lab FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE vectis_backup_lab TO vectis_usr;
GRANT USAGE ON SCHEMA public TO vectis_usr;
GRANT SELECT, INSERT, UPDATE ON TABLE public.opskeys TO vectis_usr;
GRANT SELECT, INSERT, DELETE ON TABLE public.tokens TO vectis_usr;
GRANT SELECT, INSERT ON TABLE public.indexes TO vectis_usr;
SQL
fi
```

Verify that the runtime role can use the tables but cannot create schema
objects:

```sh
if [ "$BACKEND" = postgres ]; then
  PGPASSWORD="$PGRUNTIME_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGRUNTIME_USER" -d "$PGDATABASE" <<'SQL'
SELECT has_schema_privilege(current_user, 'public', 'CREATE')
       AS can_create_schema_objects;
SELECT has_table_privilege(current_user, 'public.opskeys', 'SELECT')
       AND has_table_privilege(current_user, 'public.tokens', 'DELETE')
       AND has_table_privilege(current_user, 'public.indexes', 'INSERT')
       AS required_runtime_access;
SQL
fi
```

The expected results are `f` and `t`.

## Restore Identity, Policy, And Runtime Secrets

Restore the non-secret data files:

```sh
install -m 0600 "$DATA_BACKUP/init.json" init.json
install -m 0644 "$DATA_BACKUP/init_pub.json" init_pub.json
install -m 0600 "$DATA_BACKUP/config.json" config.json
install -m 0600 "$DATA_BACKUP/config_sign.json" config_sign.json
```

Decrypt the custody archive into the new workspace:

```sh
age -d "$CUSTODY_BACKUP/runtime-secrets.tar.age" | tar -xf -
chmod 600 .env .unseal_key .recovery-check.env
```

Read the synthetic verification values without sourcing the file as shell code:

```sh
recovery_value() {
  sed -n "s/^$1=//p" .recovery-check.env | head -n 1
}

KID="$(recovery_value RECOVERY_KID)"
TOKEN="$(recovery_value RECOVERY_TOKEN)"
APP_APIKEY="$(recovery_value RECOVERY_APP_APIKEY)"
test -n "$KID"
test -n "$TOKEN"
test -n "$APP_APIKEY"
rm -f .recovery-check.env

./vectis audit verify --file "$DATA_BACKUP/audit.log"
```

## Verify Recovery

Start the reconstructed node and use only recovered values:

```sh
./vectis serve >logs/vectis-restored.log 2>&1 &
VECTIS_PID=$!
for _ in $(seq 1 60); do
  ./vectis health ready >/dev/null 2>&1 && break
  sleep 0.5
done
./vectis health ready
./vectis keys list

run_as_app() {
  VECTIS_APIKEY="$APP_APIKEY" ./vectis "$@"
}

run_as_app token decode \
  --json "{\"ref\":\"verify\",\"kid\":\"$KID\",\"profile\":\"backup-token-v1\",\"token\":\"$TOKEN\"}"
run_as_app index verify \
  --json "{\"ref\":\"verify\",\"kid\":\"$KID\",\"profile\":\"backup-index-v1\",\"plaintext\":\"account-000099\"}"
```

The token decode should return `account-000042`, the index verification should
report `matched: true`, and `keys list` should contain the recovered KID.

## Prove A Mismatched Identity Fails Closed

Stop the recovered node before running the isolated negative test:

```sh
kill -TERM "$VECTIS_PID"
wait "$VECTIS_PID"
unset VECTIS_PID
```

Create a separate workspace with the restored storage and signed policy, but a
new identity. This workspace uses its own paths, port, logs, and audit file.

```sh
MISMATCH="$HOME/vectis-backup-mismatch"
rm -rf -- "$MISMATCH"
mkdir -p "$MISMATCH"/{db,logs}
chmod 700 "$MISMATCH" "$MISMATCH/db" "$MISMATCH/logs"
install -m 0755 "$VECTIS_SOURCE_BIN" "$MISMATCH/vectis"
install -m 0600 "$DATA_BACKUP/config.json" "$MISMATCH/config.json"
install -m 0600 "$DATA_BACKUP/config_sign.json" "$MISMATCH/config_sign.json"

if [ "$BACKEND" = sqlite ]; then
  install -m 0600 "$DATA_BACKUP/data.db" "$MISMATCH/db/data.db"
fi

cd "$MISMATCH"
if [ "$BACKEND" = sqlite ]; then
  MISMATCH_INIT="$(VECTIS_STORAGE=sqlite VECTIS_SQLITE_PATH=db/data.db ./vectis init)"
else
  MISMATCH_INIT="$(VECTIS_STORAGE=postgres VECTIS_POSTGRES_DSN="$VECTIS_POSTGRES_DSN" ./vectis init)"
fi

mismatch_value() {
  printf '%s\n' "$MISMATCH_INIT" |
    awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }'
}

printf '%s\n' "$(mismatch_value VECTIS_UNSEAL_KEY)" > .unseal_key
chmod 600 .unseal_key
MISMATCH_APIKEY="$(mismatch_value VECTIS_APIKEY)"
MISMATCH_APIKEY_HASH="$(mismatch_value VECTIS_APIKEY_HASH)"

{
  cat <<EOF
VECTIS_MODE=dev
VECTIS_HTTP_BIND_ADDR=127.0.0.1:3011
VECTIS_API_URL=http://127.0.0.1:3011
VECTIS_INIT_KEYS_FILE=init.json
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json
VECTIS_LOG_TARGET=file
VECTIS_LOG_DIR=logs
VECTIS_LOG_FILE=vectis.log
VECTIS_AUDIT_LOG_FILE=audit.log
VECTIS_APIKEY=$MISMATCH_APIKEY
VECTIS_APIKEY_HASH=$MISMATCH_APIKEY_HASH
EOF
  if [ "$BACKEND" = sqlite ]; then
    printf '%s\n' 'VECTIS_STORAGE=sqlite' 'VECTIS_SQLITE_PATH=db/data.db'
  else
    printf '%s\n' 'VECTIS_STORAGE=postgres' \
      "VECTIS_POSTGRES_DSN=$VECTIS_POSTGRES_DSN"
  fi
} > .env
chmod 600 .env

set +e
./vectis serve >logs/mismatch.log 2>&1
MISMATCH_STATUS=$?
set -e

test "$MISMATCH_STATUS" -ne 0
grep -F 'config signature verification failed' logs/mismatch.log
cd "$LAB"
```

The new identity cannot verify the policy signed by the recovered identity.
Vectis exits before serving requests. Operational-key rows also fail to decrypt
under the new identity, so regenerating `init` is not a recovery strategy.

## Recovery Boundaries

Backups have explicit limits:

- **Loss of the unseal key can make the recovery set unusable.** Vectis has no
  recovery backdoor.
- **One-time token consumption is not rollback-resistant.** Restoring an older
  snapshot can revive a token whose deletion occurred after that snapshot.
  Deployments requiring non-rollbackable consumption need an external ledger;
  see [HA_DR.md](../HA_DR.md#one-time-tokens-after-restore).
- **A restore reflects the snapshot boundary.** Later keys, lifecycle changes,
  tokens, indexes, and policy updates are absent.
- **Blind-index disclosure remains after backup theft.** Keyed digests do not
  expose plaintext directly, but they preserve equality patterns.
- **A database dump is not complete PostgreSQL DR.** Roles, credentials,
  replication, WAL retention, and PostgreSQL HA belong to the database platform.
- **A backup is not high availability.** It restores lost state; it does not
  keep a service available during failure.

## What You Learned

This lab demonstrated that:

- storage, identity, signed policy, and operational secrets form one coherent
  recovery boundary;
- SQLite and PostgreSQL use different snapshot mechanisms but share the same
  Vectis identity and policy recovery model;
- unseal and API-key material need protected custody separate from data backups;
- a recovery test must reconstruct the workspace rather than reuse surviving
  process state;
- the recovered node can use pre-disaster records, while a fresh identity fails
  closed.

## Cleanup

The recovered node was stopped before the mismatch test. Remove the two live
workspaces after confirming they contain no needed material:

```sh
if [ "$BACKEND" = postgres ]; then
  PGPASSWORD="$PGADMIN_PASSWORD" \
    psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" \
    -U "$PGADMIN_USER" -d "$PGADMIN_DATABASE" \
    -c 'DROP DATABASE IF EXISTS vectis_backup_lab WITH (FORCE);'
fi

rm -rf -- "$LAB" "$HOME/vectis-backup-mismatch"
```

Keep or securely dispose of `$DATA_BACKUP` and `$CUSTODY_BACKUP` according to
the purpose of the exercise. For a real recovery set, never delete the last
verified copy and never place custody material in version control.

Continue with [Clustering And HA Foundations](ClusteringHA.md) for the
multi-node model, or read [HA_DR.md](../HA_DR.md) for the full operational
reference.
