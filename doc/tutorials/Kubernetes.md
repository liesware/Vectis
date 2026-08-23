# Kubernetes Deployment From A Vectis Management Host

This tutorial deploys a new Vectis installation to Kubernetes from a separate
administrative machine. The management host creates and signs cluster identity
and policy, then distributes versioned artifacts through Kubernetes and Helm.
It is not part of the application data path.

```text
Vectis management host
        |
        | kubectl + Helm
        v
Versioned Kubernetes Secret
        |
        v
Vectis Deployment
  +-- Pod A
  +-- Pod B
        |
        v
Configured PostgreSQL
```

Vectis follows the normal replicated-application model in Kubernetes. Pods are
symmetric request processors, PostgreSQL owns durable concurrency and
transaction semantics, and Kubernetes owns scheduling, probes, replacement,
and Service routing.

## How This Deployment Works

Kubernetes runs and replaces the Vectis pods; Vectis protects the data. The two
jobs never overlap. Four ideas carry the tutorial:

- **A management host, separate from the pods.** One administrative machine holds
  the cluster identity and root key, signs policy, and publishes it. It never
  serves application traffic, so a compromised pod cannot mint new policy.
- **Configuration travels as a Secret.** Vectis's identity, signed config, and
  database DSN are packed into a Kubernetes Secret and mounted into every pod;
  the pods themselves are identical and disposable.
- **Policy updates ship as new Secret versions.** Because each Secret is
  immutable, a change is a new, separately named version — you roll the pods onto
  it, and you could roll back by pointing at the previous one.
- **The pods are interchangeable.** Both connect to the same PostgreSQL database
  with the same identity, so work done through one pod is visible through the
  other — exactly what you verify near the end.

Each section below is one of these ideas made concrete.

## Purpose And Boundaries

The management host is the administrative trust boundary for this deployment.
It:

- creates the Vectis init identity once;
- retains the root API key and recovery material;
- creates application API keys;
- edits, validates, and signs policy;
- publishes immutable runtime Secrets;
- performs Helm upgrades and administrative smoke tests.

It does not run `vectis serve` and does not process production FPE,
tokenization, index, messaging, or other application workflows. The synthetic
operations later in this tutorial only verify the deployment.

This tutorial does not install or operate PostgreSQL. It also leaves Ingress,
Gateway API, PostgreSQL HA, NetworkPolicy, GitOps, external secret managers,
and KMS/HSM auto-unseal to the deployment platform.

## Prerequisites

Use a Linux management host with:

- a verified Vectis release binary;
- a Vectis source checkout matching the selected image version;
- Bash, Git, `kubectl`, Helm, OpenSSL, `curl`, and `jq`;
- permission to create the lab namespace and administer resources inside it;
- network access to the configured PostgreSQL runtime endpoint.

The Kubernetes cluster must be reachable through `kubectl`. PostgreSQL must be
reachable from both the management host and the Kubernetes pods, and must have:

- an empty Vectis database;
- the schema from `src/db/postgres_schema.sql`;
- the least-privilege runtime role and grants from the
  [PostgreSQL tutorial](PostgreSQL.md#create-the-schema-and-runtime-role).

Do not point a newly initialized deployment at rows encrypted by another
Vectis identity. The new init material cannot decrypt them.

Select the released image version without a leading `v`, the matching source
checkout, and the PostgreSQL DSN:

```sh
export VECTIS_VERSION=X.Y.Z
export VECTIS_SOURCE="$HOME/src/Vectis"
export VECTIS_POSTGRES_DSN='postgresql://vectis_usr:replace-me@postgres.example.internal:5432/vectis'

test -n "$VECTIS_VERSION"
test "$VECTIS_VERSION" != X.Y.Z
test -f "$VECTIS_SOURCE/charts/vectis/Chart.yaml"
test "$(git -C "$VECTIS_SOURCE" describe --tags --exact-match)" = \
  "v$VECTIS_VERSION"
test -n "$VECTIS_POSTGRES_DSN"
```

The tutorial uses `docker.io/liesware/vectis:${VECTIS_VERSION}`. Do not use the
mutable `:test` tag for this deployment. If the binary is not already in the
source checkout, place the verified release binary in the workspace during the
next step.

The current PostgreSQL client does not provide direct PostgreSQL TLS. The DSN
must resolve to a protected private endpoint or to an authenticated TLS
connector supplied by the deployment. Do not expose plaintext PostgreSQL to an
untrusted network.

## Create A Local Cluster With kind

The Prerequisites assume a Kubernetes cluster reachable through `kubectl`. For
evaluation you can create one locally with [kind](https://kind.sigs.k8s.io/)
(Kubernetes in Docker): it runs a throwaway cluster inside your container
runtime, so nothing here touches a shared or production cluster.

This section assumes you already have a container runtime that kind supports
(such as Docker or Podman) running, and the `kind` binary installed. Everything
below is a lab cluster — create it, use it, and delete it when the tutorial
ends.

Create a named cluster so it is easy to target and remove later:

```sh
export KIND_CLUSTER=vectis-lab
kind create cluster --name "$KIND_CLUSTER"
```

kind writes a `kind-vectis-lab` context into your kubeconfig and switches
`kubectl` to it. Confirm the cluster is reachable — this is exactly the
"reachable through `kubectl`" prerequisite above:

```sh
kubectl config current-context
kubectl cluster-info --context "kind-$KIND_CLUSTER"
kubectl get nodes
```

The node must reach `Ready` before you continue.

The tutorial pulls `docker.io/liesware/vectis:${VECTIS_VERSION}` from a public
registry, which the kind node pulls on its own — no extra step. Only if you
deploy a locally built image (not covered here) would you first load it into the
node with `kind load docker-image`.

PostgreSQL stays external to the cluster. As the Prerequisites state, it must be
reachable from the kind node — that is, from inside the pods — not only from your
management host: a `127.0.0.1` DSN that works on the host does not resolve inside
a pod. Point `VECTIS_POSTGRES_DSN` at an address the pods can reach.

When the tutorial is complete, delete the whole lab cluster in one step:

```sh
kind delete cluster --name "$KIND_CLUSTER"
```

## Prepare The Management Host

Create a restricted workspace and install the verified binary there:

```sh
MGMT="$HOME/vectis-management"
mkdir -p "$MGMT"/{logs,tls}
chmod 700 "$MGMT" "$MGMT/logs" "$MGMT/tls"

install -m 0755 /path/to/verified/vectis "$MGMT/vectis"
cd "$MGMT"
./vectis version
```

The reported version must equal `VECTIS_VERSION`.

Create the local administrative environment. It does not start a server, but
local config validation uses PostgreSQL to confirm referenced KIDs:

```sh
cat > .env <<EOF
VECTIS_MODE=dev
VECTIS_API_URL=https://localhost:3000
VECTIS_TIMEOUT_SECONDS=30
VECTIS_TLS_SKIP_VERIFY=true

VECTIS_INIT_KEYS_FILE=init.json
VECTIS_INIT_PUBLIC_KEYS_FILE=init_pub.json
VECTIS_UNSEAL_KEY_FILE=.unseal_key
VECTIS_CONFIG_PATH=config.json
VECTIS_CONFIG_SIGN_PATH=config_sign.json

VECTIS_STORAGE=postgres
VECTIS_POSTGRES_DSN=$VECTIS_POSTGRES_DSN

VECTIS_PROTOCOL_VERSION=v1
VECTIS_SENDER_HOSTNAME=vectis-management.local
VECTIS_RECEIVER_HOSTNAME=vectis-management.local
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-standard-v1
VECTIS_CRYPTO_POLICY=profile-only
VECTIS_PLAINTEXT_MESSAGE=vectis-kubernetes-management-self-test
EOF

chmod 600 .env
```

## Create The Cluster Identity

Run init once on the management host and capture the printed credentials:

```sh
cd "$MGMT"
INIT_OUTPUT="$(./vectis init)"

ROOT_UNSEAL_KEY="$(printf '%s\n' "$INIT_OUTPUT" |
  sed -n 's/^VECTIS_UNSEAL_KEY=//p' | head -n 1)"
ROOT_APIKEY="$(printf '%s\n' "$INIT_OUTPUT" |
  sed -n 's/^VECTIS_APIKEY=//p' | head -n 1)"
ROOT_APIKEY_HASH="$(printf '%s\n' "$INIT_OUTPUT" |
  sed -n 's/^VECTIS_APIKEY_HASH=//p' | head -n 1)"

test -n "$ROOT_UNSEAL_KEY"
test -n "$ROOT_APIKEY"
test -n "$ROOT_APIKEY_HASH"

printf '%s' "$ROOT_UNSEAL_KEY" > .unseal_key
printf '%s' "$ROOT_APIKEY" > .root_apikey
printf '%s' "$ROOT_APIKEY_HASH" > .root_apikey_hash
printf '%s' "$VECTIS_POSTGRES_DSN" > .postgres_dsn
chmod 600 .unseal_key .root_apikey .root_apikey_hash .postgres_dsn

printf '\nVECTIS_APIKEY_HASH=%s\n' "$ROOT_APIKEY_HASH" >> .env
unset ROOT_UNSEAL_KEY ROOT_APIKEY ROOT_APIKEY_HASH INIT_OUTPUT
```

`init.json`, `.unseal_key`, and `.root_apikey` are high-value administrative
material. Back them up through separate protected channels. The root API key
remains only on the management host; Kubernetes receives its verifier.

Create and sign an empty initial policy:

```sh
./vectis config init
./vectis config validate
./vectis config sign
```

The empty signed config allows Vectis to start before an operational KID
exists. Application profiles are added after bootstrap.

## Create Service TLS

Generate one short-lived lab certificate for the Vectis Service. All replicas
present this service identity. The key uses the named `prime256v1` curve:

```sh
cat > tls/openssl.cnf <<'EOF'
[req]
prompt = no
distinguished_name = subject
x509_extensions = server

[subject]
CN = vectis.vectis.svc

[server]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = vectis.vectis.svc
DNS.3 = vectis.vectis.svc.cluster.local
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

openssl x509 -in tls/server-cert.pem -noout -subject -dates -ext subjectAltName
```

This self-signed certificate is only for the lab. Production clients and
upstreams should validate a certificate issued by the deployment's trusted CA.

## Create The Initial Runtime Secret

Create the namespace and define a helper that publishes one immutable Secret
version. A Kubernetes *Secret* is an object that stores sensitive configuration
(here, Vectis's init material, signed config, and DSN) and mounts it into pods;
*immutable* means it cannot be changed in place, so each update ships as a new,
separately named version — which is exactly how this tutorial rolls out policy
later. The helper sends files directly to the Kubernetes API and does not write a
plaintext Secret manifest to disk:

```sh
kubectl create namespace vectis

create_runtime_secret() {
  secret_name="$1"

  kubectl -n vectis create secret generic "$secret_name" \
    --from-file=init.json=init.json \
    --from-file=.unseal_key=.unseal_key \
    --from-file=config.json=config.json \
    --from-file=config_sign.json=config_sign.json \
    --from-file=VECTIS_APIKEY_HASH=.root_apikey_hash \
    --from-file=VECTIS_POSTGRES_DSN=.postgres_dsn \
    --from-file=tls.crt=tls/server-cert.pem \
    --from-file=tls.key=tls/server-key.pem

  kubectl -n vectis patch secret "$secret_name" \
    --type=merge \
    -p '{"immutable":true}'
}

create_runtime_secret vectis-runtime-v1
kubectl -n vectis get secret vectis-runtime-v1 \
  -o jsonpath='{.immutable}{"\n"}'
```

The final command must print `true`.

The current chart mounts `init.json` and `.unseal_key` from the same Kubernetes
Secret. This is operationally simple, but it is not a split trust boundary:
any principal able to read the Secret can obtain both the encrypted identity
and the material needed to unseal it. Restrict namespace RBAC and etcd access.
KMS/HSM auto-unseal remains future work.

Kubernetes Secrets are an API and distribution mechanism, not encryption by
themselves. The cluster must enable appropriate encryption at rest and control
access to Secret reads.

## Configure The Helm Release

Create version-neutral values for two production-mode replicas. Preferred
anti-affinity — a scheduling hint that asks Kubernetes to place replicas on
different nodes — spreads the replicas across a multi-node cluster without making
a single-node lab unschedulable:

```sh
cat > values-kubernetes.yaml <<EOF
fullnameOverride: vectis

replicaCount: 2

image:
  repository: docker.io/liesware/vectis
  tag: "$VECTIS_VERSION"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 3000

vectis:
  mode: prod
  publicAddr: vectis.vectis.svc:3000
  storage: postgres
  tls:
    enabled: true

secrets:
  existingSecret: vectis-runtime-v1

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: vectis
              app.kubernetes.io/instance: vectis
          topologyKey: kubernetes.io/hostname
EOF
```

Validate rendered resources before creating them:

```sh
helm lint "$VECTIS_SOURCE/charts/vectis" \
  -f values-kubernetes.yaml

helm template vectis "$VECTIS_SOURCE/charts/vectis" \
  --namespace vectis \
  -f values-kubernetes.yaml >/dev/null
```

Install and wait for every replica to become ready:

```sh
helm install vectis "$VECTIS_SOURCE/charts/vectis" \
  --namespace vectis \
  -f values-kubernetes.yaml \
  --atomic \
  --wait \
  --timeout 5m

kubectl -n vectis rollout status deployment/vectis --timeout=5m
kubectl -n vectis get pods -l app.kubernetes.io/instance=vectis -o wide
kubectl -n vectis get service vectis
kubectl -n vectis get endpointslice \
  -l kubernetes.io/service-name=vectis
```

There must be two ready pods and two ready Service endpoints. If startup fails,
inspect all replica logs without printing the runtime Secret:

```sh
kubectl -n vectis logs \
  -l app.kubernetes.io/instance=vectis \
  --all-containers=true \
  --prefix=true \
  --tail=200
```

Preferred anti-affinity is best effort. The current chart does not create a
`PodDisruptionBudget`, and a cluster with one worker can still lose both
replicas during a node outage or maintenance event. Replica count is only one
part of an HA design.

## Bootstrap Through The Service

Port-forward the ClusterIP Service for administrative access from the management
host. `kubectl port-forward` opens a temporary local tunnel from your machine to
a Service that is otherwise only reachable inside the cluster, so the management
host can talk to Vectis as if it were local:

```sh
kubectl -n vectis port-forward service/vectis 3000:3000 \
  >logs/service-port-forward.log 2>&1 &
SERVICE_FORWARD_PID=$!

for attempt in $(seq 1 60); do
  curl --insecure --fail --silent \
    https://localhost:3000/healthz/ready >/dev/null && break
  sleep 1
done
```

Define an administrator helper. The root API key is read from its protected
local file and is not placed in Kubernetes:

```sh
admin() {
  VECTIS_API_URL=https://localhost:3000 \
    VECTIS_APIKEY="$(sed -n '1p' .root_apikey)" \
    ./vectis "$@"
}

admin health startup
admin health live
admin health ready
admin test init
```

`kubectl port-forward service/vectis` selects a backing pod for the tunnel. It
is a reproducible administrative access path, but it is not proof that client
requests are being balanced across replicas.

Create the first operational key through the Service and retain its KID:

```sh
KEY_RESPONSE="$(admin keys create \
  --tag kubernetes-lab \
  --profile hybrid-standard-v1 \
  --output json)"

printf '%s\n' "$KEY_RESPONSE" | jq .
KID="$(printf '%s\n' "$KEY_RESPONSE" | jq -r '.kid')"
test -n "$KID"
test "$KID" != null
```

The request may reach either pod. The encrypted key is written to PostgreSQL;
there is no writer leader.

## Create Application Policy

Create a least-privilege application credential locally:

```sh
APP_KEY_OUTPUT="$(./vectis apikey create --output json)"
APP_APIKEY="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r '.VECTIS_APIKEY')"
APP_APIKEY_HASH="$(printf '%s\n' "$APP_KEY_OUTPUT" | jq -r '.VECTIS_APIKEY_HASH')"

test -n "$APP_APIKEY"
test -n "$APP_APIKEY_HASH"
test "$APP_APIKEY" != null
test "$APP_APIKEY_HASH" != null

printf '%s' "$APP_APIKEY" > .app_apikey
printf '%s' "$APP_APIKEY_HASH" > .app_apikey_hash
chmod 600 .app_apikey .app_apikey_hash
unset APP_APIKEY APP_APIKEY_HASH APP_KEY_OUTPUT
```

Add only the profiles and permissions used by this tutorial:

```sh
./vectis config permissions add \
  --client kubernetes-app \
  --apikey-hash "$(sed -n '1p' .app_apikey_hash)" \
  --status active

for ACTION in token-encode token-decode index-create index-verify; do
  ./vectis config permissions grant kubernetes-app \
    --kid "$KID" \
    --action "$ACTION"
done

./vectis config token add \
  --name kubernetes-token-v1 \
  --kid "$KID" \
  --token-prefix tok_k8s \
  --token-len 32 \
  --max-plaintext-len 128 \
  --one-time false

./vectis config mac add \
  --name kubernetes-index-v1 \
  --kid "$KID" \
  --context 'tenant=lab;field=account;purpose=blind-index;version=1'

./vectis config list
./vectis config validate
./vectis config sign
```

`config validate` uses the management host's PostgreSQL access to confirm that
the referenced KID exists and is compatible with these profiles.

## Roll Out Signed Policy V2

Publish a new immutable Secret containing the complete signed pair and the
unchanged cluster identity:

```sh
create_runtime_secret vectis-runtime-v2
```

Change the Secret reference through Helm. A new Secret name changes the Pod
template, so Kubernetes replaces every replica and each new process verifies
the same config during startup:

```sh
helm upgrade vectis "$VECTIS_SOURCE/charts/vectis" \
  --namespace vectis \
  -f values-kubernetes.yaml \
  --set secrets.existingSecret=vectis-runtime-v2 \
  --atomic \
  --wait \
  --timeout 5m

kubectl -n vectis rollout status deployment/vectis --timeout=5m
kubectl -n vectis get pods -l app.kubernetes.io/instance=vectis

sed -i \
  's/existingSecret: vectis-runtime-v1/existingSecret: vectis-runtime-v2/' \
  values-kubernetes.yaml
```

Do not send `config reload` through the Service as a cluster update mechanism.
One balanced request reaches one pod. Versioned Secrets plus a Deployment
rollout make policy activation explicit for every replica and retain a clear
rollback target.

The original service port-forward may end when its selected pod is replaced.
Restart it against the updated Deployment:

```sh
kill "$SERVICE_FORWARD_PID" 2>/dev/null || true
wait "$SERVICE_FORWARD_PID" 2>/dev/null || true

kubectl -n vectis port-forward service/vectis 3000:3000 \
  >logs/service-port-forward-v2.log 2>&1 &
SERVICE_FORWARD_PID=$!

for attempt in $(seq 1 60); do
  admin health ready >/dev/null 2>&1 && break
  sleep 1
done

admin permissions list
```

## Verify Both Pods Directly

Select two ready pods and create a separate tunnel to each one. The command below
asks Kubernetes for the pods, keeps only the ones that are running and `Ready`,
and stores their names; the `test` line then confirms exactly two are up before
continuing:

```sh
mapfile -t PODS < <(
  kubectl -n vectis get pods \
    -l app.kubernetes.io/instance=vectis \
    -o json |
    jq -r '.items[]
      | select(.metadata.deletionTimestamp == null)
      | select(any(.status.conditions[]?;
          .type == "Ready" and .status == "True"))
      | .metadata.name'
)

test "${#PODS[@]}" -eq 2
POD_A="${PODS[0]}"
POD_B="${PODS[1]}"

kubectl -n vectis port-forward "pod/$POD_A" 3443:3000 \
  >logs/pod-a-port-forward.log 2>&1 &
POD_A_FORWARD_PID=$!

kubectl -n vectis port-forward "pod/$POD_B" 3444:3000 \
  >logs/pod-b-port-forward.log 2>&1 &
POD_B_FORWARD_PID=$!

for attempt in $(seq 1 60); do
  curl --insecure --fail --silent \
    https://localhost:3443/healthz/ready >/dev/null && break
  sleep 1
done

for attempt in $(seq 1 60); do
  curl --insecure --fail --silent \
    https://localhost:3444/healthz/ready >/dev/null && break
  sleep 1
done
```

Define application helpers for the two explicit pods:

```sh
app_a() {
  VECTIS_API_URL=https://localhost:3443 \
    VECTIS_APIKEY="$(sed -n '1p' .app_apikey)" \
    ./vectis "$@"
}

app_b() {
  VECTIS_API_URL=https://localhost:3444 \
    VECTIS_APIKEY="$(sed -n '1p' .app_apikey)" \
    ./vectis "$@"
}
```

This is the point of running two pods: each is an interchangeable worker, and
work done on one is usable on the other because both share one identity and one
PostgreSQL backend. A token is a random ticket standing in for a stored value —
create it through pod A and redeem it through pod B:

```sh
TOKEN_RESPONSE="$(app_a token encode "$KID" \
  --json '{"ref":"k8s-token-create","profile":"kubernetes-token-v1","plaintext":"account-000314","metadata":{"source":"kubernetes-pod-a"}}')"

printf '%s\n' "$TOKEN_RESPONSE" | jq .
TOKEN="$(printf '%s\n' "$TOKEN_RESPONSE" | jq -r '.token')"
test -n "$TOKEN"
test "$TOKEN" != null

app_b token decode \
  --json "{\"ref\":\"k8s-token-decode\",\"kid\":\"$KID\",\"profile\":\"kubernetes-token-v1\",\"token\":\"$TOKEN\"}"
```

Create a blind index through B and verify it through A:

```sh
app_b index create "$KID" \
  --json '{"ref":"k8s-index-create","profile":"kubernetes-index-v1","plaintext":"account-000271"}'

app_a index verify \
  --json "{\"ref\":\"k8s-index-verify\",\"kid\":\"$KID\",\"profile\":\"kubernetes-index-v1\",\"plaintext\":\"account-000271\"}"
```

The token decode must return `account-000314`, and index verification must
report `matched: true`. These workflows prove that both pods can read and
write durable state through the same PostgreSQL backend.

Stop the direct pod tunnels before replacing a pod:

```sh
kill "$POD_A_FORWARD_PID" "$POD_B_FORWARD_PID" 2>/dev/null || true
wait "$POD_A_FORWARD_PID" 2>/dev/null || true
wait "$POD_B_FORWARD_PID" 2>/dev/null || true
```

## Exercise Pod Replacement

Delete pod A and let the Deployment restore the desired replica count:

```sh
kubectl -n vectis delete pod "$POD_A" --wait=false
kubectl -n vectis rollout status deployment/vectis --timeout=5m

kubectl -n vectis get pods \
  -l app.kubernetes.io/instance=vectis \
  -o wide

kubectl -n vectis get endpointslice \
  -l kubernetes.io/service-name=vectis
```

There must again be two ready pods and ready Service endpoints. Restart the
Service tunnel if necessary, then verify durable state through the common
endpoint:

```sh
kill "$SERVICE_FORWARD_PID" 2>/dev/null || true
wait "$SERVICE_FORWARD_PID" 2>/dev/null || true

kubectl -n vectis port-forward service/vectis 3000:3000 \
  >logs/service-port-forward-replacement.log 2>&1 &
SERVICE_FORWARD_PID=$!

for attempt in $(seq 1 60); do
  admin health ready >/dev/null 2>&1 && break
  sleep 1
done

service_app() {
  VECTIS_API_URL=https://localhost:3000 \
    VECTIS_APIKEY="$(sed -n '1p' .app_apikey)" \
    ./vectis "$@"
}

service_app index verify \
  --json "{\"ref\":\"k8s-after-replacement\",\"kid\":\"$KID\",\"profile\":\"kubernetes-index-v1\",\"plaintext\":\"account-000271\"}"
```

The response must still report `matched: true`. Pod replacement does not
remove PostgreSQL state or alter the shared Vectis identity.

## Understand Runtime State

Every ready pod may process reads and writes. There is no leader and no
read-only replica role inside Vectis. PostgreSQL enforces durable constraints
and transaction semantics.

Runtime memory remains local:

- signed config is loaded independently by each process;
- operational keys and lifecycle properties are cached per pod;
- logs and audit sequences belong to the pod that emitted them;
- `GET /keys` reports the selected pod's loaded keys, not a cluster inventory.

A missing KID may be lazy-loaded from PostgreSQL. Existing local state changes
after restart, explicit `keys reload`, or another documented reload boundary.
Shared storage is not automatic memory synchronization.

The ClusterIP Service provides the normal in-cluster endpoint. Any compatible
Ingress, Gateway API implementation, or external HTTP load balancer can front
that Service. Vectis does not require sticky sessions, but clients and proxies
must not automatically retry non-idempotent POST operations.

## Rollback And Config History

Inspect Helm revisions and retain old immutable Secrets:

```sh
helm -n vectis history vectis
kubectl -n vectis get secret vectis-runtime-v1 vectis-runtime-v2
```

To restore a previous release revision after reviewing its config and Secret:

```sh
helm -n vectis rollback vectis PREVIOUS_REVISION \
  --wait \
  --timeout 5m
```

Replace `PREVIOUS_REVISION` with a revision from `helm history`. Vectis verifies
the signature of the restored config, but it does not currently enforce config
freshness or anti-rollback counters. Rollback authorization and change control
remain operator responsibilities. If the rollback becomes the desired state,
update `values-kubernetes.yaml` to reference the restored Secret before the next
Helm upgrade.

## Logs And Audit

The chart sends operational logs and audit records to stdout. Inspect each pod
without treating the combined output as one hash chain:

```sh
kubectl -n vectis logs \
  -l app.kubernetes.io/instance=vectis \
  --all-containers=true \
  --prefix=true \
  --tail=200
```

Each pod has its own audit sequence and process lifetime. Pod deletion also
deletes its local stdout history unless the platform collector has already
persisted it. Production deployments need an external log collector that
preserves pod identity and audit ordering. Keep `init_pub.json` independently
so exported audit evidence can be verified offline.

## Shut Down Or Continue

Stop the local tunnel and remove application secrets from the shell:

```sh
kill "$SERVICE_FORWARD_PID" 2>/dev/null || true
wait "$SERVICE_FORWARD_PID" 2>/dev/null || true

unset ROOT_APIKEY ROOT_APIKEY_HASH KEY_RESPONSE
unset KID TOKEN TOKEN_RESPONSE
```

Leave the release and Secrets in place if this is a continuing lab. To remove
only Kubernetes resources created by the tutorial:

```sh
helm -n vectis uninstall vectis
kubectl delete namespace vectis
```

This does not remove PostgreSQL rows or management-host identity. Deleting the
management workspace without a protected backup makes the encrypted database
unrecoverable.

## What This Lab Proved

- A management host can remain outside the application data path.
- One init identity and one signed policy can serve multiple Kubernetes pods.
- Versioned immutable Secrets make config rollout and rollback explicit.
- Every ready pod can read and write through PostgreSQL.
- Tokens and blind indexes remain usable across pod boundaries.
- Kubernetes can replace a failed process without replacing durable state.
- Full HA still requires PostgreSQL HA, traffic management, secret protection,
  and durable observability supplied by the deployment platform.

For the underlying state model, continue with [Clustering](../Clustering.md)
and [High Availability And Disaster Recovery](../HA_DR.md).
