# Vectis Tutorials

These tutorials continue where [Getting Started](../GettingStarted.md) leaves
off. Getting Started taught the core model on one local node — keys, profiles,
signed policy, the unseal key, and the audit chain. Each tutorial here takes one
step outward (a real database, a second node, a Kubernetes deployment) and, like
Getting Started, explains *why* before *how*: every new idea gets a short, plain
definition the first time it appears, so you finish understanding the change, not
just having run it.

You will get the most from them if you have done Getting Started first, but each
one re-grounds the concepts it relies on rather than assuming you remember them.

## Available Tutorials

- [PostgreSQL](PostgreSQL.md): run a Vectis node with a least-privilege
  PostgreSQL backend and verify durable key, token, and blind-index state.
- [Clustering And HA Foundations](ClusteringHA.md): add a second Vectis replica,
  distribute signed policy, balance traffic with Nginx, exercise cross-node
  state, and test manual failover.
- [Kubernetes Deployment](Kubernetes.md): use a dedicated Vectis management
  host to publish signed policy, deploy replicas with Helm, and exercise pod
  replacement.

For design and operational guarantees rather than step-by-step labs, use the
main reference documents:

- [Clustering](../Clustering.md): shared storage and multi-node behavior;
- [High Availability And Disaster Recovery](../HA_DR.md): availability,
  backup, restore, and recovery boundaries;
- [Helm Chart](../../charts/vectis/README.md): Kubernetes deployment values and
  operational requirements.
