# Changelog

This changelog records notable public changes to Vectis. It is maintained
manually for releases; the Git history remains the detailed engineering record.

## Unreleased

Changes staged for v0.9.0, the first official release.

### Security

- Updated rustls to 0.23.45 to address RUSTSEC-2026-0285.

### Performance
- Key reload no longer decrypts keys sequentially on the async runtime. Keys are now
  decrypted concurrently on the blocking pool with a bounded window, removing head-of-line
  blocking during startup and `POST /keys/reload`. Original key ordering and per-key
  skip-on-failure behavior are preserved.
- Cryptographic operations now run on the blocking pool under a global concurrency
  limit (`VECTIS_MAX_CONCURRENT_CRYPTO`, default: CPU cores − 1). Requests beyond the
  limit are rejected with `429 Too Many Requests`. Key-set loading at startup and on
  reload now decrypts keys concurrently instead of sequentially, and the three internal
  message endpoints no longer block the async runtime.  

## Main
- Update from 1.97.1 to 1.98
- fuzz testing improvements
- cargo fuzz improvements

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
