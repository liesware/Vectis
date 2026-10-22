# Building Vectis From Source

## Purpose

Use a source build when developing, reviewing, testing, or modifying Vectis.
Users who only need to run Vectis should prefer the signed release artifacts in
the [Quick Start](../README.md#quick-start).

Building source from the repository demonstrates what your local toolchain
produced. It does not replace verification of the checksums, Cosign bundle, and
GitHub provenance attached to an official release.

## Rust Toolchain

Vectis pins Rust `1.98.0` in `rust-toolchain.toml`. A rustup-managed `cargo`
automatically selects that toolchain while inside the repository.

Install rustup from its official distribution channel, then confirm the active
toolchain:

```sh
rustup show active-toolchain
rustc --version
cargo --version
```

Do not replace the pinned toolchain with an unreviewed `stable` update when
producing release artifacts.

## System Dependencies

Vectis enables the `vendored` feature of the Rust Botan binding. Botan is built
from source as part of the Cargo build, so a C/C++ build environment is
required.

On Debian 13 or a compatible Debian/Ubuntu system:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential \
  clang \
  cmake \
  git \
  libsqlite3-dev \
  pkg-config \
  python3 \
  sqlite3 \
  xz-utils
```

On macOS, install the Xcode command-line tools and the remaining packages with
Homebrew:

```sh
xcode-select --install
brew install cmake pkg-config sqlite
```

The Xcode command-line tools provide Clang and the native linker. PostgreSQL
client tools are needed only for PostgreSQL operations and integration tests,
not for a normal SQLite build.

## Build

Clone the repository and let `rust-toolchain.toml` select the pinned compiler:

```sh
git clone https://github.com/liesware/Vectis.git
cd Vectis
cargo build --release --locked
```

The resulting binary is:

```text
target/release/vectis
```

Run the release smoke test:

```sh
target/release/vectis version
```

## Verify The Source Build

Run the standard checks before proposing or distributing a source build:

```sh
cargo fmt -- --check
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
git diff --check
```

The full testing strategy, including Python integration tests, Schemathesis,
coverage, and cargo-fuzz, is documented in [Test.md](Test.md).

## Release SBOMs

Official binary and image builds use **cargo-auditable 0.7.7** with
`cargo auditable build --release --locked`. It embeds Rust dependency metadata
in the executable; normal development builds do not need this tool. **Trivy
0.70.0** inventories that executable or the final image and converts one complete
JSON inventory to **CycloneDX 1.6 JSON** and **SPDX 2.3 JSON**. SBOM generation
is part of release workflows only, not SCA.

Executable inventories use Trivy's `rootfs` mode on the single binary: `fs`
mode disables its individual-binary analyzers. The cargo-auditable version is
recorded from the pinned installation, since `cargo auditable --version`
forwards to Cargo and reports Cargo's version rather than its own.

Each binary archive has three sibling release assets, using the same basename:

```text
vectis-linux-amd64-v<VERSION>.tar.gz
vectis-linux-amd64-v<VERSION>.cdx.json
vectis-linux-amd64-v<VERSION>.spdx.json
vectis-linux-amd64-v<VERSION>.build-info.json
```

The same set is produced for Linux ARM64 and macOS ARM64. The signed
`SHA256SUMS` covers all four files per platform. Verify its existing Cosign
identity as described in [GettingStarted.md](GettingStarted.md), then download
the desired assets and verify their checksums. Build metadata records the
commit, platform, tool versions, executable hash and archive hash. Archive
contents and existing provenance remain unchanged.

For images, inventories include detected operating-system packages and Rust
dependencies, separately for AMD64 and ARM64. Published candidates are scanned
by immutable digest. Both SBOMs are attached as Cosign attestations and verified
before the multiarch tag is promoted. Attestations are separate registry objects,
not additional platforms in the two-platform manifest. Existing provenance of
the published manifest is retained.

To verify an image SBOM, use the platform digest, not a mutable tag:

```sh
cosign verify-attestation --type cyclonedx \
  --certificate-identity 'https://github.com/liesware/Vectis/.github/workflows/release-image.yml@refs/tags/v<VERSION>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  docker.io/liesware/vectis@sha256:<PLATFORM_DIGEST>
```

Use `--type spdxjson` for SPDX. The manual test-image identity ends in
`@refs/heads/main` instead. The verified DSSE payload contains the subject digest
and SBOM predicate; check that the subject matches the image you intend to use.
The workflows also compare the verified predicate with the generated document.

Botan is vendored C++, so Rust metadata is not an exhaustive native-library
inventory. Separate build evidence records the `botan`, `botan-sys` and
`botan-src` crate versions and the native version, source URL and verified
tarball SHA-256 from the resolved `botan-src/release.toml`. Source overrides are
rejected. Images include this evidence at `/opt/vectis/share/build-info.json`;
external image evidence associates it with the immutable image reference.

Manual binary builds and non-publishing image runs produce downloadable Actions
artifacts; SBOM evidence is retained for **30 days**, including available partial
diagnostics on failure. The non-publishing image inventory uses the local image
ID. Neither SBOM existence nor its signature proves absence of vulnerabilities,
complete native coverage or reproducibility. Existing security gates remain
separate and unchanged.

## Run From The Source Tree

Commands may be executed directly with the release binary:

```sh
target/release/vectis help
target/release/vectis init
target/release/vectis serve
```

Keep runtime state outside `target/`. The [Getting Started](GettingStarted.md)
tutorial shows a self-contained workspace with SQLite, local TLS, signed config,
logs, and audit data.
