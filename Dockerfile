# Build Stage
FROM docker.io/library/rust:1.76-slim-bookworm AS builder

WORKDIR /usr/src/nova-kms-rust

# Install required build dependencies (like pkg-config and libssl-dev for ring)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src src

# Build the release binary
RUN cargo build --release --bin nova-kms-rust

# Runtime Stage
FROM docker.io/library/debian:bookworm-slim

# Install runtime dependencies for openssl/tls
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/nova-kms-rust/target/release/nova-kms-rust /app/nova-kms-rust

# Expose default KMS port (8000)
EXPOSE 8000

ENV RUST_LOG=info
CMD ["/app/nova-kms-rust"]
