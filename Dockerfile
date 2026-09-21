# ree0xQ collector — single-host container image.
#
# Multi-stage build: a Rust builder stage compiles `ree0xq-server`
# from the workspace sources, then a slim Debian runtime carries
# only the static binary, `ca-certificates`, and `tini` for PID 1.
#
# Produces an image that runs as a non-root user, exposes the V1
# REST API on :8090, and answers `/healthz` for the orchestrator's
# liveness probe. The default deadline matches the NSA CNSA 2.0
# browser/server-class deadline (2030-01-01); override either with
# `command:` arguments in the compose file or by passing them as
# the container CMD.

# Pin to the toolchain the workspace is developed against (host
# is 1.95). The floor recorded in Cargo.toml is 1.78, but several
# transitive deps (clap_lex ≥ 1.1, etc.) now require edition2024
# which stabilised in 1.85. Keeping the image one minor behind
# the host lets the build use upstream-supported Cargo features
# without chasing a moving target every release.
ARG RUST_VERSION=1.90
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

WORKDIR /src

# Workspace manifests first so dependency resolution can be cached
# in its own layer; the next time source files change we only
# recompile what actually changed.
COPY Cargo.toml Cargo.lock ./
COPY crates/ree0xq-core/Cargo.toml      crates/ree0xq-core/
COPY crates/ree0xq-server/Cargo.toml    crates/ree0xq-server/
COPY crates/ree0xq-net/Cargo.toml       crates/ree0xq-net/
COPY crates/ree0xq-cert/Cargo.toml      crates/ree0xq-cert/
COPY crates/ree0xq-chain/Cargo.toml     crates/ree0xq-chain/
COPY crates/ree0xq-id/Cargo.toml        crates/ree0xq-id/
COPY crates/ree0xq-qkd/Cargo.toml       crates/ree0xq-qkd/
COPY crates/ree0xq-agility/Cargo.toml   crates/ree0xq-agility/

# Now bring in the real sources and build the server binary.
COPY crates ./crates
RUN cargo build --release --locked -p ree0xq-server --bin ree0xq-server


FROM debian:${DEBIAN_VERSION}-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ree0xq \
    && useradd  --system --uid 10001 --gid ree0xq \
                --home-dir /var/lib/ree0xq --shell /sbin/nologin \
                ree0xq \
    && mkdir -p /var/lib/ree0xq \
    && chown ree0xq:ree0xq /var/lib/ree0xq

COPY --from=builder /src/target/release/ree0xq-server /usr/local/bin/ree0xq-server

USER ree0xq
WORKDIR /var/lib/ree0xq

ENV RUST_LOG=info,ree0xq_server=info

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8090/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ree0xq-server"]
CMD ["--listen", "0.0.0.0:8090"]
