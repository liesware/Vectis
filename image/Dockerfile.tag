FROM debian:13@sha256:fac46bff2e02f51425b6e33b0e1169f55dfb053d83511ca28aa50c09fd5ed7a4 AS builder

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
    | sh -s -- -y --profile minimal --default-toolchain stable

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

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:d97bc0a941b8d4be647dc0ee75b264ddbb772f1ac5ba690a4309c00723b23775 AS runtime

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
