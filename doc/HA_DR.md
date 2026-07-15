# High Availability And Disaster Recovery

## Purpose

This document explains how to keep Vectis available when something fails, and
how to recover it after data loss, corruption, or operator error.

It does not replace [doc/Clustering.md](Clustering.md). Clustering explains the
multi-node model:

> Storage is shared. Runtime state is local. Reload is explicit.

HA/DR builds on that rule. PostgreSQL helps Vectis run across nodes, but
PostgreSQL alone is not a full HA or DR plan. Recovery also depends on matching
cryptographic material, signed config, operational secrets, and logs.

## Critical Recovery Set

A useful Vectis recovery set includes:

- `init.json`;
- the unseal key or unseal provider state;
- `config.json`;
- `config_sign.json`;
- PostgreSQL `opskeys` and `tokens`;
- API key distribution material;
- TLS certificate and key material when running in `prod`;
- audit logs if they are required for investigation or compliance.

These items must match. Vectis stores operational keys encrypted. A database
backup that cannot be decrypted is not useful recovery data.

> A PostgreSQL backup without the matching init material is not a Vectis recovery backup.

Do not treat `config.json` alone as the policy source. The signed pair is the
unit: `config.json` plus `config_sign.json`.

## High Availability Model

SQLite is single-node storage for local development, tests, and small lab use.
It is not a real HA backend for Vectis.

PostgreSQL is the shared storage backend for multi-node deployments. A highly
available Vectis deployment needs:

- two or more Vectis nodes;
- matching init material available to every node;
- a load balancer in front of the nodes;
- PostgreSQL deployed with its own HA design;
- readiness checks wired into traffic routing;
- logs and audit records collected outside the pod or process.

Each Vectis node keeps its own in-memory state:

- loaded operational keys in `KeysDbState`;
- signed config state for routes, remote routes, and permissions;
- signed config state for FPE and tokenization profiles;
- local HTTP runtime state.

If one node creates or updates a key, PostgreSQL stores the durable row. Other
nodes do not immediately receive that change. They observe it after:

- startup;
- `POST /keys/reload`;
- a missing-key lazy-load;
- restart.

If config changes, each node must receive the new signed files and run
`POST /config/reload`, or restart with those files present.

`/healthz/ready` must fail when storage is unavailable. A node without storage
should not receive normal traffic.

The Helm chart follows this model: PostgreSQL only, `Deployment`, logs to
stdout by default, no embedded PostgreSQL, and no automatic schema management.

## Disaster Recovery Model

Recovery is not just restoring PostgreSQL. Recovery means restoring a coherent
set of data and cryptographic state.

Recommended restore order:

1. Restore PostgreSQL and verify the `opskeys` and `tokens` tables exist.
2. Restore `init.json` and the matching unseal method.
3. Restore `config.json` and `config_sign.json`.
4. Restore TLS material and runtime secrets if used.
5. Start Vectis nodes.
6. Check `/healthz/ready`.
7. Run explicit reloads if needed: `POST /keys/reload` and `POST /config/reload`.
8. Validate keys, routes, permissions, and one complete message flow.

After restore, assume node-local memory may be stale until reload or restart.
Do not rely on old pods carrying correct state.

## Failure Scenarios

### Node Down

Expected behavior: the load balancer or orchestrator removes the failed node
and routes traffic to other ready nodes.

Recovery:

- restart or replace the node;
- confirm it can unseal;
- confirm `/healthz/ready`;
- confirm it loaded expected keys and config.

### PostgreSQL Down

Expected behavior: readiness fails and storage-backed operations fail.

Recovery:

- recover PostgreSQL through its own HA system;
- confirm Vectis readiness;
- run a key lookup or `/keys/reload` smoke check.

### PostgreSQL Restored

Expected behavior: nodes may have stale memory compared with restored storage.

Recovery:

- restart Vectis nodes, or explicitly run `POST /keys/reload` on each node;
- validate lifecycle state for sensitive keys;
- validate token decode for any tokenized fields that must be recoverable;
- run message and signing smoke tests.

### Config Invalid Or Suspicious Rollback

Expected behavior: startup fails if present config is invalid, and config reload
fails while keeping previous runtime state.

Recovery:

- inspect `config.json` and `config_sign.json`;
- re-sign only after confirming the config is intended;
- run `vectis config sign`;
- run `vectis config reload` on each node that should use it.

Vectis does not currently enforce config freshness or anti-rollback counters.
Operators must control signed config distribution.

### Unseal Key Lost

Expected behavior: Vectis cannot decrypt init material and cannot derive the
internal storage keys.

Recovery:

- restore the unseal key or provider state from backup;
- if no backup exists, stored operational keys are not recoverable.

Do not regenerate init material and expect old storage rows to decrypt.

### Init Material Lost

Expected behavior: PostgreSQL rows remain encrypted but unusable.

Recovery:

- restore matching `init.json` from backup;
- restore matching unseal key or provider state;
- validate startup and key loading.

### Storage Corrupt Or Key Not Decryptable

Expected behavior: affected key loads fail. Startup or reload may skip or fail
depending on the path and error.

Recovery:

- inspect storage health;
- restore from a known-good database backup;
- verify matching init material;
- reload keys and validate affected `kid` values.

### Audit Logs Lost

Expected behavior: Vectis can continue running, but the security trail is
incomplete.

Recovery:

- recover from the external log system if available;
- document the gap;
- confirm current logging target and collector behavior.

When `VECTIS_LOG_TARGET=stdout`, audit events are mixed with operational logs in
the container stream and are distinguished by:

```json
"target": "vectis::audit"
```

## RPO And RTO

Vectis does not promise built-in RPO or RTO values. Those come from the
operational environment.

Suggested expectations:

- dev/lab: manual recovery, best effort, no HA expectation;
- controlled pilot: tested PostgreSQL backups, documented restore steps, signed
  config backups, and secret recovery procedure;
- production future: PostgreSQL HA, external secret management, tested restore,
  centralized logs, and regular recovery drills.

Vectis does not implement:

- backup management;
- PostgreSQL replication;
- leader election;
- quorum;
- node membership;
- config freshness counters;
- automatic cluster-wide reload;
- automatic audit log archival.

## Operational Checks

After startup, failover, restore, or planned maintenance, check:

```sh
vectis health ready
vectis keys list
vectis routes list
vectis remote-routes list
vectis permissions list
```

If using HTTP directly:

```sh
curl -sS http://127.0.0.1:3000/healthz/ready
curl -sS http://127.0.0.1:3000/metrics
```

For functional smoke tests, validate:

- `GET /pub/{kid}` for a known loaded key;
- `POST /sign/{kid}`;
- `POST /sign/verification`;
- `POST /message/internal/encrypt/{kid}`;
- `POST /message/internal/decrypt`;
- one remote message send through a configured `remote_routes` entry.

If the smoke test fails after restore, do not assume the database is the only
problem. Check init material, unseal state, signed config, lifecycle state,
remote routes, and final app reachability.
