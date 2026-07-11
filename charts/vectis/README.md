# Vectis Helm Chart

This chart deploys Vectis on Kubernetes.

It is intentionally small:

- PostgreSQL only;
- no PostgreSQL installation;
- no database migrations;
- no generated init material;
- all Vectis runtime configuration is treated as Kubernetes Secret data.

## Required Secret Keys

The runtime Secret must contain:

```text
init.json
.unseal_key
config.json
config_sign.json
VECTIS_APIKEY_HASH
VECTIS_POSTGRES_DSN
```

When `vectis.mode=prod` and `vectis.tls.enabled=true`, it must also contain:

```text
tls.crt
tls.key
```

The Secret is mounted at `/opt/vectis/conf` with mode `0640`. Kubernetes mounts
Secret files as root-owned files and uses `fsGroup` to make them readable by the
nonroot Vectis process. Vectis allows `0600`, `0400`, `0640`, and `0440` for
`init.json` and `.unseal_key`; it rejects group write, execute bits, and any
access for others.

## Existing Secret

Recommended for production:

```sh
kubectl create secret generic vectis-runtime \
  --from-file=init.json=./init.json \
  --from-file=.unseal_key=./.unseal_key \
  --from-file=config.json=./config.json \
  --from-file=config_sign.json=./config_sign.json \
  --from-literal=VECTIS_APIKEY_HASH="$VECTIS_APIKEY_HASH" \
  --from-literal=VECTIS_POSTGRES_DSN="$VECTIS_POSTGRES_DSN"

helm install vectis charts/vectis \
  --set image.repository=vectis-image \
  --set image.tag=local \
  --set secrets.existingSecret=vectis-runtime
```

## Inline Secret Values

Useful for local or simple deployments:

```sh
helm install vectis charts/vectis \
  --set image.repository=vectis-image \
  --set image.tag=local \
  --set-file secrets.initJson=./init.json \
  --set-file secrets.unsealKey=./.unseal_key \
  --set-file secrets.configJson=./config.json \
  --set-file secrets.configSignJson=./config_sign.json \
  --set secrets.apiKeyHash="$VECTIS_APIKEY_HASH" \
  --set secrets.postgresDsn="$VECTIS_POSTGRES_DSN"
```

Helm stores release data in the cluster. For production, prefer an existing
Secret managed by your normal secret-management system.

## PostgreSQL

The chart does not install PostgreSQL and does not create tables. The DBA or
operator must apply the reference schema before Vectis starts:

```sh
psql "$VECTIS_POSTGRES_DSN" -f src/db/postgres_schema.sql
```

## Logging

The chart sets:

```text
VECTIS_LOG_TARGET=stdout
```

Operational logs and audit events are emitted as JSON lines to stdout. Audit
events are distinguished by:

```json
{"target":"vectis::audit"}
```

## Checks

```sh
helm lint charts/vectis
helm template vectis charts/vectis
kubectl logs deploy/vectis
kubectl port-forward svc/vectis 3000:3000
curl -sS http://127.0.0.1:3000/healthz/ready
```
