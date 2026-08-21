# Changelog

This changelog records notable public changes to Vectis. It is maintained
manually for releases; the Git history remains the detailed engineering record.

## Unreleased

Changes staged for v0.9.0, the first official release.

## v0.8.5 - 2026-08-21

Pre-release of Vectis. This tag exists to exercise the release pipeline end
to end — binary packaging, container publication, checksums, and provenance
attestations. It ships the initial public feature set described below, but
v0.9.0 will be the first official release.

### Added

- Signed configuration, operational crypto profiles, key lifecycle controls,
  permissions, HTTP APIs, and CLI workflows for sensitive-data protection.
- Local FPE, reversible tokenization with optional one-time consumption,
  display masking, deterministic MACs, blind indexes, keyed commitments, and
  authenticated Shamir secret sharing.
- Hybrid EdDSA plus ML-DSA signatures, protected messaging, compact signed
  artifacts, and offline SLH-DSA artifact signing.
- Hash-chained audit JSONL with hybrid-signed checkpoints and offline
  verification.
- Local time attestation using authenticated NTS and verified Roughtime
  evidence.

### Security

- Signed configuration validation, strict input parsing, storage-row validation
  before cryptographic use, and explicit key lifecycle enforcement.
- Hybrid crypto profiles spanning performance, standard, high-assurance, and
  long-term configurations.

### Operational

- SQLite and PostgreSQL storage support for operational keys, token data, and
  blind-index membership records.
- Local demos, HTTP and CLI test suites, native fuzz targets, OpenAPI coverage,
  and an isolated k6 performance harness.

### Compatibility

- This is the first public tag; there is no prior public release API or
  config contract to preserve.
- API and signed-config formats remain experimental and may change in a future
  pre-1.0 release. Breaking changes will be documented here.

### Known Limitations

- Vectis has not completed an external security audit.
- It does not provide mTLS, Vault/KMS/HSM auto-unseal, Merkle proofs, or
  external anchoring for audit checkpoints.
- Run Vectis as one layer of a defense-in-depth architecture, not as the only
  control protecting sensitive data.

See [README.md](README.md), [doc/API.md](doc/API.md),
[doc/ThreatModel.md](doc/ThreatModel.md), and [SECURITY.md](SECURITY.md) for
the current product, threat-model, and vulnerability-reporting guidance.
