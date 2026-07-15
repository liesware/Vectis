# Clustering

## Purpose

This document explains how Vectis behaves when more than one node serves the
same logical deployment.

Vectis clustering is simple on purpose:

> Storage is shared. Runtime state is local. Reload is explicit.

The cluster does not turn Vectis into a distributed database, queue, scheduler,
or coordinator. It only lets multiple Vectis processes use the same durable key
storage while keeping each node's runtime state predictable.

## Non-Goals

Vectis clustering does not provide:

- leader election;
- automatic state replication between nodes;
- automatic PostgreSQL table creation or migrations;
- built-in PostgreSQL high availability;
- queue semantics;
- distributed config management;
- cache invalidation broadcasts.

Those are separate operational systems. Vectis should work with them, not absorb
them.

## Node Model

Nodes in the same logical Vectis cluster share the same init material.

That means each node must have access to matching:

- encrypted init key material;
- unseal method;
- HKDF-derived internal key behavior;
- storage encryption keys derived from the init material.

Each node still has its own memory. `KeysDbState` is node-local runtime state.
It is not a cluster-wide cache and it is not automatically synchronized.

## Shared Storage

PostgreSQL is the shared durable backend for clustered deployments. It stores
encrypted operational key material in `opskeys` and encrypted reversible
tokenization payloads in `tokens`.

PostgreSQL is durable storage. It is not automatic live state.

If a node writes a key to PostgreSQL, other nodes can load that key, but they do
not receive it automatically. They see it after an explicit reload or after a
missing-key lazy-load.

The current PostgreSQL schema is:

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
```

`keys`, `properties`, and `tokens.data` are encrypted by Vectis before storage.
PostgreSQL does not need to understand their contents.

## Key Loading

Vectis loads operational keys in three ways:

1. On startup, the node loads keys it can decrypt from storage.
2. If an operation references a `kid` that is not in local memory, the node
   attempts to load that specific key from storage.
3. `POST /keys/reload` explicitly reloads key state from storage into the node.

`GET /keys` lists node-local loaded keys. It does not list every key in shared
storage.

This is intentional. The endpoint reports what this node is currently carrying
in memory.

## Config Model

`config.json` and `config_sign.json` are per-node.

Nodes may use identical signed config files, or they may intentionally use
different signed config files. That is an operational decision.

Config controls:

- local final app routes;
- remote Vectis routes;
- API key permissions.
- FPE profiles;
- tokenization profiles.

`POST /config/reload` reloads config only on the node that receives the request.
There is no cluster-wide config reload.

## Lifecycle Semantics

Lifecycle state is loaded into local memory with the rest of the key properties.

If another node changes a key lifecycle state in PostgreSQL, this node does not
automatically receive that change if the key is already loaded. This node observes
the change after:

- `POST /keys/reload`;
- a restart;
- a missing-key lazy-load for a key not already in memory.

This keeps behavior explicit. It avoids hidden cache invalidation rules.

## High Availability

High availability is covered in [doc/HA_DR.md](HA_DR.md).

The short version is: run more than one Vectis node behind a load balancer, use
PostgreSQL with its own HA design, and rely on readiness checks to remove nodes
that cannot reach storage. Vectis does not elect leaders, replicate PostgreSQL,
or coordinate node membership.

## Disaster Recovery

Disaster recovery is covered in [doc/HA_DR.md](HA_DR.md).

The short version is: back up PostgreSQL and the matching cryptographic root
material together. A PostgreSQL backup without the matching init material cannot
recover stored operational keys.

## Database Ownership

Vectis ships SQL reference files. It does not apply migrations and does not
create PostgreSQL tables at runtime.

The DBA or operator owns:

- database creation;
- schema application;
- grants and roles;
- backups;
- PostgreSQL HA;
- PostgreSQL monitoring;
- tuning and maintenance.

Vectis owns:

- connecting to storage;
- validating the expected schema;
- encrypting data before storage;
- reading and writing rows through the storage contract;
- reporting storage readiness.

For runtime access, Vectis needs `SELECT`, `INSERT`, and `UPDATE` on
`public.opskeys`, plus `SELECT` and `INSERT` on `public.tokens`. It does not
need schema creation privileges.

## Failure Modes

Important cluster failure modes:

- storage down: readiness should fail and storage-backed operations fail;
- schema mismatch: startup should fail with a clear storage error;
- missing key: the node attempts lazy-load; if storage does not contain it, the
  operation fails as not found;
- stale local state: a key already loaded in memory remains as-is until reload,
  restart, or replacement;
- invalid config: runtime config reload fails and keeps previous config;
- lost init material: stored operational keys cannot be decrypted;
- lost database: loaded memory may exist briefly, but durable key state is gone.

These failure modes are meant to be visible, not hidden.

## Operational Checklist

For PostgreSQL-backed clustering:

1. Create the PostgreSQL database.
2. Apply `src/db/postgres_schema.sql` manually.
3. Grant runtime permissions to the Vectis database user.
4. Distribute matching init material to each Vectis node.
5. Configure each node with `VECTIS_STORAGE=postgres`.
6. Set `VECTIS_POSTGRES_DSN` for each node.
7. Provide each node's signed config files.
8. Start each node.
9. Check `/healthz/ready`.
10. Use `POST /keys/reload` when a node must explicitly refresh key state.
11. Use `POST /config/reload` when a node must explicitly refresh signed config.

Runtime PostgreSQL grants should be limited to:

```sql
GRANT USAGE ON SCHEMA public TO vectis_usr;
GRANT SELECT, INSERT, UPDATE ON TABLE public.opskeys TO vectis_usr;
```

## Future Work

Possible future clustering work:

- HSM/KMS-backed unseal;
- mTLS between nodes;
- queue transport for protected messages;
- distributed config delivery;
- optional cache invalidation;
- richer operational runbooks;
- explicit backup and restore test scripts.

These should remain integrations. Vectis should stay focused on protecting data
objects.
