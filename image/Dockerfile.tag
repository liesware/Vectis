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

FROM builder AS package

WORKDIR /workspace/vectis

COPY . .

RUN cargo build --release --locked \
    && mkdir -p \
        /tmp/vectis-root/opt/vectis/bin \
        /tmp/vectis-root/opt/vectis/conf \
        /tmp/vectis-root/opt/vectis/log \
        /tmp/vectis-root/opt/vectis/data \
        /tmp/vectis-root/opt/vectis/tmp \
    && cp /workspace/vectis/target/release/vectis /tmp/vectis-root/opt/vectis/bin/vectis \
    && cp /workspace/vectis/src/db/sqlite_schema.sql /tmp/vectis-root/opt/vectis/data/sqlite_schema.sql \
    && cp /workspace/vectis/src/db/postgres_schema.sql /tmp/vectis-root/opt/vectis/data/postgres_schema.sql

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
