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
