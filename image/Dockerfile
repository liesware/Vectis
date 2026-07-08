FROM vectis-dev:debian13 AS builder

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

FROM gcr.io/distroless/cc-debian13:nonroot

ENV VECTIS_HTTP_BIND_ADDR=0.0.0.0:3000
ENV VECTIS_INIT_KEYS_FILE=/opt/vectis/conf/init.json
ENV VECTIS_UNSEAL_KEY_FILE=/opt/vectis/conf/.unseal_key
ENV VECTIS_CONFIG_PATH=/opt/vectis/conf/config.json
ENV VECTIS_CONFIG_SIGN_PATH=/opt/vectis/conf/config_sign.json
ENV VECTIS_LOG_DIR=/opt/vectis/log
ENV VECTIS_SQLITE_PATH=/opt/vectis/data/data.db
ENV TMPDIR=/opt/vectis/tmp

WORKDIR /opt/vectis

COPY --from=builder --chown=nonroot:nonroot /tmp/vectis-root/opt/vectis /opt/vectis

EXPOSE 3000

USER nonroot:nonroot

ENTRYPOINT ["/opt/vectis/bin/vectis"]
CMD ["serve"]
