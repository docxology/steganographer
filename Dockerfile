FROM rust:1.99-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS builder

# Install GStreamer development libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgstreamer1.0-dev \
    libgstreamer-plugins-base1.0-dev \
    g++ \
    nasm \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source
COPY Cargo.toml Cargo.lock ./
COPY steganographer-core/ ./steganographer-core/
COPY steganographer-gst/ ./steganographer-gst/
# Keep build.rs, src/cli.rs and examples together: Cargo discovers the release
# helper target, and the CLI build generates manuals/completions from its schema.
COPY steganographer-cli/ ./steganographer-cli/
COPY steganographer-dashboard/ ./steganographer-dashboard/
# Cargo resolves every workspace member before building, so the wasm crate's
# manifest must be present even though the CLI build never targets wasm32.
COPY steganographer-wasm/ ./steganographer-wasm/
COPY config/ ./config/
COPY docs/ ./docs/
# Master config: copied into the runtime stage below.
COPY steganographer.toml ./

# Build release binary
RUN cargo build --release -p steganographer-cli --all-features --locked

# Runtime stage
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

# Install GStreamer runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgstreamer1.0-0 \
    libgstreamer-plugins-base1.0-0 \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-libav \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/sh stego
COPY --from=builder /build/target/release/steganographer /usr/local/bin/steganographer
COPY --from=builder /build/config/ /app/config/
COPY --from=builder /build/steganographer.toml /app/

WORKDIR /app

# Run as non-root user
USER stego

EXPOSE 8080

ENTRYPOINT ["steganographer"]
CMD ["--config", "config/example.toml", "dashboard", "--port", "8080", "--host", "127.0.0.1"]
