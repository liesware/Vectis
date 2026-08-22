# Vectis

[![Rust CI](https://github.com/liesware/Vectis/actions/workflows/Rust.yml/badge.svg?branch=main)](https://github.com/liesware/Vectis/actions/workflows/Rust.yml)
[![CodeQL](https://github.com/liesware/Vectis/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/liesware/Vectis/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/liesware/Vectis/badge)](https://scorecard.dev/viewer/?uri=github.com/liesware/Vectis)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14194/badge)](https://www.bestpractices.dev/projects/14194)
<!-- [![Release](https://img.shields.io/github/v/release/liesware/Vectis?sort=semver)](https://github.com/liesware/Vectis/releases/latest) -->
[![License](https://img.shields.io/github/license/liesware/Vectis)](https://github.com/liesware/Vectis/blob/main/LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/liesware/vectis)](https://hub.docker.com/r/liesware/vectis)

<p align="left">
  <img width="300" alt="Vectis logo" src="logo.png">
</p>

Vectis is an **open source advanced data protection toolkit**:
format-preserving encryption, reversible tokenization, masking, MACs, blind
indexes, commitments, secret sharing, and post-quantum protected
messaging/signing — governed by an operator-signed configuration, served through
a consistent HTTP and CLI interface.

Vectis can also attest its local clock on demand with authenticated NTS and
verified Roughtime evidence. The optional signed `time_attestation` config
section overrides its Cloudflare defaults.

**Sensitive input in, safe representation out.** Every Vectis operation
exchanges a sensitive value for a representation that is safe to store, move,
index, display, or share — and keeps only the properties your workflow needs:
a ciphertext that preserves the original format, a token you can reverse
under policy, a digest you can search without revealing, a commitment you can
prove later, shares no single holder can read, a protected message only the
registered peer can open.

> In Latin, *vectis* can mean a lever, crowbar, fastening bar, or carrying pole:
> a simple tool used to move something heavy with controlled force.

> **Status: in progress.** Vectis is under active development and has not yet
> completed an external security audit. Everything Vectis does is in this
> repository, free and Apache-2.0 licensed — use it, self-host it, break it,
> and open an issue with what you find. For production use, see
> [Security Status](#security-status).

## Contents

- [Origins](#origins)
- [Why Vectis?](#why-vectis)
- [Philosophy And Scope](#philosophy)
- [Current Capabilities](#what-vectis-does-today)
- [High-Level Flow And Demos](#high-level-flow)
- [Quick Start](#quick-start)
- [Build From Source](#build-from-source)
- [CLI And API](#cli-and-api)
- [Configuration](#configuration)
- [Crypto Profiles](#crypto-profiles)
- [Testing And Documentation](#testing)
- [Security Status](#security-status)
- [Community](#community)
- [Enterprise](#enterprise)
- [License](#license)

## Origins

Vectis exists because of a licensing gap. Format-preserving encryption,
reversible tokenization, masking, and encryption as a service have been
available in commercial data-protection platforms for years — but almost
always as enterprise add-ons, licensed separately, with implementations that
were never open source for a community to inherit, audit, or build on.

Vectis is not a fork of anything. It is an independent, from-scratch, open
source implementation of that category, with its own trust model and its own
scope. The jobs those platforms do well — secrets management, key custody,
transport security — remain deliberately out of Vectis's scope: it is
designed to run alongside them, not against them.

## Why Vectis?

Modern systems already use important security controls:

- TLS;
- encrypted disks;
- cloud KMS;
- HSMs;
- secrets managers;
- access control;
- database encryption;
- traditional DLP tools.

Those controls are necessary, but sensitive data can still appear in plaintext
inside application payloads, logs, queues, databases, backups, internal APIs, and
temporary processing steps.

Vectis answers a different question:

> What if sensitive data stayed protected as a data object while it moves
> through an application workflow?

**TLS protects the connection. Vectis protects the data object itself** —
before it is stored, after it is queued, while it is logged, wherever it
moves once the transport session is over.

Advanced data protection — tokenization, format-preserving encryption, masking,
encryption as a service — has traditionally shipped as expensive enterprise
licensing. Vectis provides that capability as free, self-hosted, open source
software, and leaves every other job (secrets, transport, key custody) to the
tools that already do it well.

Not sure which primitive solves your problem? See the how-to-choose table in
[doc/UseCases.md](doc/UseCases.md).

## Philosophy

Vectis tries to stay close to the Unix philosophy. Peter H. Salus summarized it
in 1994, crediting Doug McIlroy:

```text
Write programs that do one thing and do it well.
Write programs to work together.
Write programs to handle text streams, because that is a universal interface.
```

Vectis has one narrow job: provide composable cryptographic protection for
sensitive data workflows. It does not try to replace TLS, KMS, HSMs, databases,
access control, or traditional DLP tools. Those systems already have their own
jobs.

Vectis exposes HTTP, CLI commands, JSON, OpenAPI, logs, and metrics because
plain interfaces are easier to inspect, automate, and combine. Future
capabilities such as stronger clustering, HSM/KMS support, mTLS, or additional
distributed storage should exist only when the operating environment requires
them, not as product tiers or decorative complexity.

## Scope And Boundaries

The philosophy above is also the decision rule for Vectis's scope. Every
proposed capability starts with one question:

> **Does this belong in the Vectis layer, or are we taking work away from
> something that already solves it well?**

Usefulness alone does not place a feature inside Vectis. It belongs here only
when its security property must be enforced at Vectis's data-protection
boundary.

**Vectis should grow by deepening its responsibility, not by widening it.**

## What Vectis Does Today

Vectis currently provides an HTTP service and CLI for cryptographic data
protection primitives and workflows.

**Cryptography**

- hybrid post-quantum key establishment with XECDH + ML-KEM;
- dual signatures with EdDSA and ML-DSA, both required to verify;
- authenticated encryption for protected payloads;
- canonical JSON signing with explicit protocol versioning bound to signatures;
- selectable crypto profiles (see [Crypto Profiles](#crypto-profiles)).

**Protocol and trust**

- protected messages between Vectis instances, verified before decryption;
- one operator-signed config file (routes, remote routes, permissions, FPE
  profiles, tokenization profiles, MAC profiles, commitment profiles, sharing
  profiles, and masking profiles); its registered
  `remote_routes` are the only source of peer public keys — no trust-on-first-use
  path;
- local re-encryption before final app delivery: the receiving application
  never gets remote plaintext directly;
- public key publication by `kid`;
- internal encrypt/decrypt endpoints for local protected data;
- local FF1 format-preserving encryption for signed field profiles;
- local reversible random tokenization for signed token profiles;
- local MAC create/verify for signed MAC profiles;
- local keyed cryptographic commitments with random openings;
- local blind indexes that reuse signed MAC profiles and persist deterministic
  membership digests;
- local display masking for signed masking profiles;
- local stateless authenticated Shamir secret sharing for signed sharing
  profiles.
- local offline SLH-DSA-SHAKE-256s artifact signing with encrypted private keys
  and public-key-only verification.

**Key management**

- encrypted local init key material;
- HKDF-derived internal keys for storage encryption and API key verification;
- operational key creation and validation;
- encrypted key lifecycle metadata and runtime lifecycle enforcement;
- SQLite/PostgreSQL-backed storage for encrypted operational keys, encrypted
  tokenization payloads, and blind index digests behind a storage abstraction.

**Operations and observability**

- startup, liveness, and readiness health probes;
- a hash-chained security audit JSONL stream with hybrid-signed checkpoints, per-request correlation ids, and offline verification.
- a Prometheus `/metrics` endpoint for operational observability;
- local CLI commands plus CLI commands that act as an HTTP API client;
- OpenAPI and environment variable documentation.

## What Vectis Is Not

Vectis is not a replacement for:

- TLS;
- KMS;
- HSMs;
- secrets managers;
- database encryption;
- access control;
- traditional DLP products.

Vectis does not currently provide Merkle proofs, external anchoring for its
audit-chain checkpoints, Vault/KMS/HSM auto-unseal, or mTLS.

Vectis is intended to complement existing security controls by providing
cryptographic protection for sensitive data workflows. It should work with
other tools, not absorb their responsibilities.

## High-Level Flow

```text
Application / CLI
        |
        | operation + bounded input
        v
      Vectis
        |
        | validate input
        | authenticate and authorize
        | resolve signed policy and profiles
        | enforce key lifecycle
        v
Cryptographic capability
        |
        +-- FPE / tokenization / masking
        +-- MAC / blind indexes / commitments
        +-- secret sharing / signatures
        +-- internal encryption / protected messages
        v
Protected output / verification result / shares / peer delivery
```

FPE, masking, MAC, commitments, and secret sharing return their results directly.
Tokenization stores the plaintext in encrypted form, while blind indexes persist
deterministic digests for membership checks. Protected messaging resolves
authorized peers from signed configuration and locally re-encrypts a verified
message before final application delivery.

## Protected Messaging Flow

```text
Application A
    |
    | private record / sensitive payload
    v
Vectis A
    |
    | hybrid KEM + authenticated encryption + signatures
    v
Vectis B
    |
    | verify + decrypt + local re-encrypt
    v
Application B
    |
    | local decrypt through Vectis B
    v
Recovered private record / sensitive payload
```

The receiving application does not receive remote plaintext directly. It receives
a local encrypted delivery and must ask its local Vectis instance to decrypt it.

## Clinical Data Exchange Demo

The repository includes a two-site clinical demo:

- Clinic A reads a patient record JSON file.
- Vectis A protects and sends the record.
- Vectis B verifies, decrypts, and re-encrypts the record for Clinic B.
- Clinic B's final app calls local Vectis to decrypt and print the recovered
  record.

See [demo/message/README.md](demo/message/README.md).

Quick demo setup:

```sh
bash demo/message/setup.sh
bash demo/message/create-keys.sh
bash demo/message/configure-routes.sh
```

Then run the four demo processes:

```sh
bash demo/message/start-vectis-a.sh
bash demo/message/start-vectis-b.sh
bash demo/message/start-app-a.sh
bash demo/message/start-app-b.sh
```

In the Clinic A terminal:

```text
clinic-a file: ../personaldata.json
```

## Local Data Protection Demo

The repository also includes a single-node local demo over SQLite and HTTP. It
shows field-level protection with three synthetic categories: credit card PAN,
SSN, and bank account values.

The demo exercises:

- FPE encrypt/decrypt;
- reversible token encode/decode;
- MAC create/verify;
- blind index create/verify;
- `/message/internal` encrypt/decrypt;
- sign and verification.

See [demo/local/README.md](demo/local/README.md).

Quick local demo setup:

```sh
bash demo/local/setup.sh
bash demo/local/create-keys.sh
bash demo/local/configure-config.sh
```

Then run the local Vectis instance and demo runner:

```sh
bash demo/local/start-vectis.sh
uv run demo/local/run-demo.py
```

## Quick Start

Requirements:

- [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/);
- `sha256sum`;
- `tar`.

Open the [Vectis releases page](https://github.com/liesware/Vectis/releases)
and download these three files from the release you want to install:

- `vectis-linux-amd64-vX.Y.Z.tar.gz`;
- `SHA256SUMS`;
- `SHA256SUMS.sigstore.json`.

Place them in one directory, replace `X.Y.Z` below with the downloaded release,
and derive its exact Git tag from the archive name:

```sh
ARCHIVE="vectis-linux-amd64-vX.Y.Z.tar.gz"
RELEASE_TAG="${ARCHIVE#vectis-linux-amd64-}"
RELEASE_TAG="${RELEASE_TAG%.tar.gz}"
```

Verify that the checksum manifest was signed by the Vectis release workflow:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity \
    "https://github.com/liesware/Vectis/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

Verify the selected archive, extract it, and inspect the binary:

```sh
EXPECTED="$(awk -v file="$ARCHIVE" '$2 == file { print $1 }' SHA256SUMS)"
test -n "$EXPECTED"
printf '%s  %s\n' "$EXPECTED" "$ARCHIVE" | sha256sum -c -

tar -xzf "$ARCHIVE"
BIN="$(tar -tzf "$ARCHIVE" | grep -m1 '/vectis$')"
"./${BIN}" version
```

Cosign authenticates `SHA256SUMS`; the checksum then binds the downloaded
archive to that signed manifest. Continue with [Getting Started](doc/GettingStarted.md)
to initialize SQLite, configure local TLS, and tour Vectis capabilities on
Linux.

## Build From Source

Vectis uses the Rust toolchain pinned in `rust-toolchain.toml` and builds its
vendored Botan dependency from source. Building locally is useful for
development, but it is distinct from verifying an official release artifact.

See [Building From Source](doc/Build.md) for platform dependencies, build
commands, tests, and the release binary location.

## CLI And API

The CLI is primarily an HTTP client for the local Vectis service. Initialization,
API-key creation, local config editing and signing, and offline artifact signing
run locally.

See the [CLI reference](doc/CLI.md), [API reference](doc/API.md), and
[OpenAPI specification](doc/openapi.yaml) for the complete contracts.

## Configuration

Vectis separates signed policy from process configuration. The signed
`config.json` contains routes, peers, permissions, and capability profiles; its
complete schema is documented in the [API reference](doc/API.md).

Process settings use the `VECTIS_` prefix. Vectis reads them from process
environment variables first, then `.env`, then built-in defaults.

The essentials to get a local instance running:

- `VECTIS_HTTP_BIND_ADDR`: listen address, default `127.0.0.1:3000`;
- `VECTIS_MODE`: `dev` (HTTP) or `prod` (HTTPS, requires TLS cert and key);
- `VECTIS_INIT_KEYS_FILE`: encrypted init key material, default `init.json`;
- `VECTIS_INIT_PUBLIC_KEYS_FILE`: public init verification keys, default `init_pub.json`;
- `VECTIS_UNSEAL_KEY_FILE`: unseal key file, default `.unseal_key`;
- `VECTIS_STORAGE`: `sqlite` by default, or `postgres` for shared storage;
- `VECTIS_SQLITE_PATH`: SQLite operational key storage, default `src/db/data.db`
  in dev builds;
- `VECTIS_POSTGRES_DSN`: PostgreSQL DSN when `VECTIS_STORAGE=postgres`;
- `VECTIS_CONFIG_PATH`: signed config file, default `config.json`.

See [doc/ENV.md](doc/ENV.md) for the full list and expected values.

## Crypto Profiles

`POST /keys` supports crypto profiles:

- `hybrid-performance-v1`;
- `hybrid-standard-v1`;
- `hybrid-high-assurance-v1`;
- `hybrid-long-term-v1`.

By default, Vectis uses profile-only policy:

```text
VECTIS_DEFAULT_CRYPTO_PROFILE=hybrid-performance-v1
VECTIS_CRYPTO_POLICY=profile-only
```

In development and tests, individual algorithm overrides can be enabled with:

```text
VECTIS_CRYPTO_POLICY=allow-overrides
```

## Testing

See [doc/Test.md](doc/Test.md) for the full testing strategy, including Rust
checks, Python HTTP workflows with `uv`, Schemathesis OpenAPI fuzzing, and
native `cargo-fuzz` targets.

## Documentation

- [doc/GettingStarted.md](doc/GettingStarted.md): verified binary installation,
  local TLS/SQLite bootstrap, and capability tour.
- [doc/Build.md](doc/Build.md): source build requirements and commands.
- [doc/API.md](doc/API.md): HTTP API and CLI mapping.
- [doc/UseCases.md](doc/UseCases.md): real-world use cases per feature.
- [doc/CLI.md](doc/CLI.md): CLI behavior, commands, output, and environment.
- [doc/ENV.md](doc/ENV.md): environment variables and expected values.
- [doc/Test.md](doc/Test.md): testing strategy and test commands.
- [doc/Clustering.md](doc/Clustering.md): multi-node behavior and shared
  storage model.
- [doc/HA_DR.md](doc/HA_DR.md): high availability, backups, restore, and
  recovery limits.
- [doc/openapi.yaml](doc/openapi.yaml): OpenAPI specification.
- [doc/Reference.md](doc/Reference.md): architecture and design reference.
- [doc/Internal.md](doc/Internal.md): implementation flows and internal invariants.
- [doc/Design.md](doc/Design.md): reusable design principles distilled from this project.
- [CHANGELOG.md](CHANGELOG.md): notable public changes by release.
- [SECURITY.md](SECURITY.md): supported versions and private vulnerability reporting.
- [demo/message/README.md](demo/message/README.md): clinical data exchange demo.
- [demo/local/README.md](demo/local/README.md): local FPE, tokenization, MAC,
  masking, commitments, secret sharing, blind indexes, internal message, and
  sign demo.
- [charts/vectis/README.md](charts/vectis/README.md): Kubernetes Helm chart.

## Security Status

Vectis is under active development. It has not yet completed an external
security audit, and its APIs and operational model may still evolve as the
project matures.

Vectis v0.8.5 completed a source-backed security self-assessment. No Critical
or High severity vulnerabilities were identified. See
[Security Self-Assessment](doc/SelfAssessment.md) for its scope and limitations.
Review the [Threat Model](doc/ThreatModel.md) for assets, trust boundaries,
mitigations, and residual risks.

For suspected vulnerabilities, follow the private reporting process in
[SECURITY.md](SECURITY.md). Do not publish unpatched security details in a
public issue.

The project publishes an OpenPGP public key for encrypted security
communications and independent identity verification:

- [OpenPGP public key](public-key.asc)
- Fingerprint:
  `B24F 5892 7262 09ED 7C7F 6A8A 367C 0B31 BA81 6201 AB79 A095 B6`

Release artifacts are authenticated separately through Cosign and GitHub
artifact attestations.

Today, Vectis is a natural fit for evaluation, demos, internal testing, and
PoCs. If you take it further, follow the same practice you would with any
security tool, audited or not: run it as one layer in a defense-in-depth
architecture, never as the only control in front of sensitive data. The
threat model, explicit assumptions, and known limitations are documented in
[doc/ThreatModel.md](doc/ThreatModel.md) — deployments designed against it
do better.

For production deployments with support — stable builds, a deployment review
against the threat model, and a direct line to the author — see
[Enterprise](#enterprise).

## Community

Issues, questions, and experience reports are welcome — breaking Vectis in
interesting ways is a contribution. If you're evaluating it for your use
case and something is unclear, open an issue: unclear docs are bugs too.

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing code, protocol, or
documentation changes.

## Enterprise

Vectis is fully open source: every feature lives in this repository, and that
will not change. What the author offers commercially is what cannot be
downloaded — time and accountability:

- **Stable and LTS binaries** with backported security fixes;
- **private builds and custom integrations** (storage backends, SDKs,
  deployment tooling);
- **deployment review** of your architecture against the threat model;
- **priority support** with a direct line to the author;
- **design-partner program**: early access, roadmap influence, and joint
  prioritization of the external security audit.

Contact: [liesware@protonmail.com](mailto:liesware@protonmail.com)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

Copyright and attribution notices are available in [NOTICE](NOTICE).

## Afterword

Dedicated to the anonymous heroes who write free software, explore mathematics,
share knowledge, and make the world more capable without asking to be known.

To everyone who believes that privacy and knowledge are things we build, not
merely things we request.
