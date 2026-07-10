FROM rust:1.97-slim AS builder

# Install GStreamer development libraries
RUN apt-get update && apt-get install -y \
    libgstreamer1.0-dev \
    libgstreamer-plugins-base1.0-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source
COPY Cargo.toml Cargo.lock ./
COPY steganographer-core/ ./steganographer-core/
COPY steganographer-gst/ ./steganographer-gst/
COPY steganographer-cli/ ./steganographer-cli/
COPY steganographer-dashboard/ ./steganographer-dashboard/
COPY config/ ./config/
COPY docs/ ./docs/

# Build release binary
RUN cargo build --release -p steganographer-cli

# Runtime stage
FROM debian:bookworm-slim

# Install GStreamer runtime
RUN apt-get update && apt-get install -y \
    libgstreamer1.0-0 \
    libgstreamer-plugins-base1.0-0 \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-libav \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/steganographer /usr/local/bin/steganographer
COPY --from=builder /build/config/ /app/config/
COPY --from=builder /build/steganographer.toml /app/

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["steganographer"]
CMD ["--config", "config/example.toml", "dashboard", "--port", "8080"]
