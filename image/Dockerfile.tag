# syntax=docker/dockerfile:1
FROM debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        clang \
        cmake \
        curl \
        g++ \
        gcc \
        git \
        libc6-dev \
        libsqlite3-dev \
        make \
        pkg-config \
        postgresql-client \
        python3 \
        sqlite3 \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain 1.98.0

ENV CARGO_AUDITABLE_VERSION=0.7.7
RUN cargo install cargo-auditable --version "$CARGO_AUDITABLE_VERSION" --locked

FROM builder AS package

ARG VECTIS_BUILD_COMMIT
ARG TARGETPLATFORM

WORKDIR /workspace/vectis

COPY . .

RUN test -z "${BOTAN_SRC_DIR+x}" \
    && test -z "${BOTAN_SRC_TARBALL+x}" \
    && cargo auditable build --release --locked \
    && mkdir -p \
        /tmp/vectis-root/opt/vectis/bin \
        /tmp/vectis-root/opt/vectis/conf \
        /tmp/vectis-root/opt/vectis/log \
        /tmp/vectis-root/opt/vectis/data \
        /tmp/vectis-root/opt/vectis/tmp \
        /tmp/vectis-root/opt/vectis/share \
    && cp /workspace/vectis/target/release/vectis /tmp/vectis-root/opt/vectis/bin/vectis \
    && cp /workspace/vectis/src/db/sqlite_schema.sql /tmp/vectis-root/opt/vectis/data/sqlite_schema.sql \
    && cp /workspace/vectis/src/db/postgres_schema.sql /tmp/vectis-root/opt/vectis/data/postgres_schema.sql

RUN BUILD_COMMIT="$VECTIS_BUILD_COMMIT" BUILD_PLATFORM="$TARGETPLATFORM" \
    SBOM_BINARY=/tmp/vectis-root/opt/vectis/bin/vectis \
    SBOM_INFO=/tmp/vectis-root/opt/vectis/share/build-info.json python3 - <<'PY'
import hashlib, json, os, re, subprocess, tomllib
from pathlib import Path

for name in ("BOTAN_SRC_DIR", "BOTAN_SRC_TARBALL"):
    if name in os.environ:
        raise SystemExit(f"{name} overrides are prohibited for release builds")
def sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()
metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"]))
packages = metadata["packages"]
def package(name):
    matches = [p for p in packages if p["name"] == name]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one resolved {name} package")
    return matches[0]
botan = {name: package(name) for name in ("botan", "botan-sys", "botan-src")}
source_dir = Path(botan["botan-src"]["manifest_path"]).parent
release = tomllib.loads((source_dir / "release.toml").read_text())
version, checksum = release["version"], release["sha256"]
if not re.fullmatch(r"[0-9a-f]{64}", checksum):
    raise SystemExit("invalid Botan source checksum")
tarball = source_dir / "vendor" / f"Botan-{version}.tar.xz"
if sha256(tarball) != checksum:
    raise SystemExit("Botan source checksum mismatch")
binary = Path(os.environ["SBOM_BINARY"])
info = {
    "schema_version": 1, "commit": os.environ["BUILD_COMMIT"],
    "platform": os.environ["BUILD_PLATFORM"], "version": package("vectis")["version"],
    "tools": {tool: subprocess.check_output(command, text=True).strip() for tool, command in {
        "rustc": ["rustc", "--version"], "cargo": ["cargo", "--version"]}.items()},
    "cargo_auditable_version_source": "pinned installation",
    "binary": {"name": "vectis", "sha256": sha256(binary)},
    "botan": {"crates": {name: p["version"] for name, p in botan.items()},
        "native_version": version, "source_url": release["url"].replace("{version}", version),
        "source_sha256": checksum},
    "coverage": "Rust dependency metadata; native Botan evidence recorded separately, not an exhaustive native inventory"
}
info["tools"]["cargo-auditable"] = os.environ["CARGO_AUDITABLE_VERSION"]
if os.environ.get("SBOM_ARCHIVE"):
    archive = Path(os.environ["SBOM_ARCHIVE"])
    info["archive"] = {"name": archive.name, "sha256": sha256(archive)}
if os.environ.get("SBOM_BASE"):
    info["sbom"] = {kind: {"name": path.name, "sha256": sha256(path)}
        for kind, path in ((kind, Path(os.environ["SBOM_BASE"] + suffix))
            for kind, suffix in (("cyclonedx", ".cdx.json"), ("spdx", ".spdx.json")))}
Path(os.environ["SBOM_INFO"]).write_text(json.dumps(info, indent=2) + "\n")
PY

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime

ENV VECTIS_HTTP_BIND_ADDR=0.0.0.0:3000
ENV VECTIS_INIT_KEYS_FILE=/opt/vectis/conf/init.json
ENV VECTIS_UNSEAL_KEY_FILE=/opt/vectis/conf/.unseal_key
ENV VECTIS_CONFIG_PATH=/opt/vectis/conf/config.json
ENV VECTIS_CONFIG_SIGN_PATH=/opt/vectis/conf/config_sign.json
ENV VECTIS_LOG_DIR=/opt/vectis/log
ENV VECTIS_SQLITE_PATH=/opt/vectis/data/data.db
ENV TMPDIR=/opt/vectis/tmp

WORKDIR /opt/vectis

COPY --from=package --chown=nonroot:nonroot /tmp/vectis-root/opt/vectis /opt/vectis

EXPOSE 3000

USER nonroot:nonroot

ENTRYPOINT ["/opt/vectis/bin/vectis"]
CMD ["serve"]
