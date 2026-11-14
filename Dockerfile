# Multi-stage build for pii-shield's HTTP/MCP server.
#
# Builder: compiles the release binary. Runtime: distroless CC ships the
# glibc runtime (needed for c deps) plus CA certs, and runs as `nonroot`.

FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# Fetch dependencies first for layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/pii-core/Cargo.toml     crates/pii-core/Cargo.toml
COPY crates/pii-wasm/Cargo.toml     crates/pii-wasm/Cargo.toml
COPY crates/pii-ffi/Cargo.toml      crates/pii-ffi/Cargo.toml
COPY crates/pii-mcp-proxy/Cargo.toml crates/pii-mcp-proxy/Cargo.toml
COPY crates/pii-store-redis/Cargo.toml crates/pii-store-redis/Cargo.toml
COPY crates/pii-server/Cargo.toml   crates/pii-server/Cargo.toml

# Stub sources so `cargo build` can link the workspace and populate the
# dependency cache without compiling project code.
RUN for crate in pii-core pii-wasm pii-ffi pii-store-redis pii-server; do \
      mkdir -p crates/$crate/src && \
      echo "" > crates/$crate/src/lib.rs; \
    done && \
    mkdir -p crates/pii-mcp-proxy/src/bin && \
    echo "fn main() {}" > crates/pii-mcp-proxy/src/main.rs && \
    echo "fn main() {}" > crates/pii-mcp-proxy/src/bin/mock_mcp_server.rs && \
    echo "fn main() {}" > crates/pii-server/src/main.rs && \
    mkdir -p crates/pii-core/benches && \
    echo "fn main() {}" > crates/pii-core/benches/scanner_bench.rs

RUN cargo build --release --locked -p pii-server

# Copy the real sources and clear stub fingerprints so Cargo always recompiles
# workspace crates regardless of host file mtimes.
COPY crates/ crates/

RUN rm -rf target/release/.fingerprint/pii-* \
           target/release/deps/libpii_* \
           target/release/deps/pii_* \
           target/release/pii-server && \
    cargo build --release --locked --bin pii-server && \
    strip target/release/pii-server

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /app/target/release/pii-server /usr/local/bin/pii-server

USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/pii-server"]
