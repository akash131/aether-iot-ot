# syntax=docker/dockerfile:1.7
# Aether IoT/OT Security: control plane and workers (serve), edge
# appliance (edge), migrations and platform registration.
# Build: docker build -t aether-iot-ot:latest .
# Run:   docker run ... aether-iot-ot serve | edge | migrate | register-policy-types

ARG RUST_VERSION=1
FROM rust:${RUST_VERSION}-bookworm AS build
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY migrations ./migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p iot-service \
 && cp target/release/aether-iot /usr/local/bin/aether-iot

FROM debian:bookworm-slim AS runtime
# nftables is used by the edge appliance in enforcing mode (IOT_EDGE_ENFORCE).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini curl nftables \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10008 --home /nonexistent aether-iot \
 && mkdir -p /var/lib/aether-iot /var/spool/aether-iot \
 && chown aether-iot /var/lib/aether-iot /var/spool/aether-iot
COPY --from=build /usr/local/bin/aether-iot /usr/local/bin/aether-iot
ENV IOT_BIND=0.0.0.0:8096 \
    IOT_LOG_JSON=1 \
    IOT_ENV=production \
    IOT_STATE_DIR=/var/lib/aether-iot
USER aether-iot
EXPOSE 8096
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s CMD curl -fsS http://127.0.0.1:8096/health/ready || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/aether-iot"]
CMD ["serve"]
