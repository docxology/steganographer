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
# NOTE: For production, pin the base image by digest instead of tag:
#   FROM debian:bookworm-slim@sha256:<actual-digest>
# The tag is used here for maintainability — verify the digest with:
#   docker pull debian:bookworm-slim && docker inspect --format='{{index .RepoDigests 0}}' debian:bookworm-slim
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
