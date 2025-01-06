# Stage 1: Builder
FROM rust:1.75.0-slim AS builder

# Set build environment variables
ENV CARGO_HOME=/usr/local/cargo \
    RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C codegen-units=1 -C lto=fat" \
    RUST_MIN_STACK=8388608 \
    CARGO_NET_GIT_FETCH_WITH_CLI=true

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt clippy

# Create build directory
WORKDIR /build

# Copy project files
COPY src/backend/Cargo.toml src/backend/rust-toolchain.toml ./
COPY src/backend/src ./src

# Build release binary with optimizations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --all-features \
    && strip target/release/guardian-cli \
    && mv target/release/guardian-cli /usr/local/bin/ \
    # Verify binary
    && cargo verify-project \
    && sha256sum /usr/local/bin/guardian-cli > /usr/local/bin/guardian-cli.sha256

# Stage 2: Runtime
FROM freebsd/freebsd-base:13.2-RELEASE

# Set runtime environment variables
ENV RUST_LOG=info \
    RUST_BACKTRACE=0 \
    GUARDIAN_CONFIG=/etc/guardian/config.toml \
    GUARDIAN_MAX_THREADS=8 \
    PATH="/usr/local/bin:$PATH"

# Create non-root user and group
RUN pw addgroup guardian \
    && pw adduser -g guardian -s /usr/sbin/nologin -d /nonexistent -c "Guardian Service" guardian \
    # Create required directories
    && mkdir -p /etc/guardian /var/lib/guardian /var/log/guardian \
    && chown -R guardian:guardian /var/lib/guardian /var/log/guardian \
    && chmod 750 /var/lib/guardian /var/log/guardian \
    && chmod 550 /etc/guardian

# Configure FreeBSD jail parameters
COPY --chmod=0400 <<EOF /etc/jail.conf
guardian {
    path = "/";
    host.hostname = "guardian";
    ip4 = "inherit";
    interface = "lo0";
    allow.raw_sockets = false;
    allow.sysvipc = false;
    allow.mount = false;
    allow.mount.devfs = false;
    enforce_statfs = 2;
    children.max = 0;
    securelevel = 3;
}
EOF

# Copy binary from builder
COPY --from=builder --chown=guardian:guardian /usr/local/bin/guardian-cli /usr/local/bin/
COPY --from=builder --chown=guardian:guardian /usr/local/bin/guardian-cli.sha256 /usr/local/bin/

# Verify binary checksum
RUN sha256sum -c /usr/local/bin/guardian-cli.sha256 \
    && chmod 0550 /usr/local/bin/guardian-cli \
    && rm /usr/local/bin/guardian-cli.sha256

# Configure resource limits
RUN echo "guardian soft nofile 1024" >> /etc/security/limits.conf \
    && echo "guardian hard nofile 4096" >> /etc/security/limits.conf \
    && echo "guardian soft nproc 64" >> /etc/security/limits.conf \
    && echo "guardian hard nproc 128" >> /etc/security/limits.conf

# Expose ports for gRPC and metrics
EXPOSE 50051/tcp 9090/tcp

# Set up volumes
VOLUME ["/etc/guardian", "/var/lib/guardian", "/var/log/guardian"]

# Configure healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD guardian-cli status --json || exit 1

# Switch to non-root user
USER guardian:guardian

# Set entrypoint
ENTRYPOINT ["guardian-cli"]
CMD ["serve"]