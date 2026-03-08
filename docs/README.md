# Steganographer Documentation

Comprehensive documentation for the steganographer toolkit — a Rust workspace for real-time steganographic watermarking of video and audio streams with cryptographic authentication.

## Dashboard Preview

![Dashboard with QR overlay and verification data](images/dashboard-qr-overlay.png)

*Live dashboard showing webcam feed with QR data matrix overlay (left) and real-time verification data with config controls (right).*

## Table of Contents

### Theory & Foundations

| Document | Description |
| ---------- | ------------- |
| [Steganography Theory](steganography-theory.md) | Deep dive into information hiding: history, information-theoretic security, spatial/frequency domain techniques, steganalysis, and modern advances |
| [Cryptography](cryptography.md) | BLAKE3 hashing, Ed25519/Ethereum signing, payload format, Kerckhoffs' principle, and post-quantum considerations |
| [Algorithms](algorithms.md) | LSB video/audio steganography, text overlay, info bar, QR data matrix, embedding protocols, capacity math |

### Core Concepts

| Document | Description |
| --- | --- |
| [Architecture](architecture.md) | System design, four-crate structure, data flow, threading models, dashboard websocket architecture |
| [Security](security.md) | Security model, threat analysis, steganalysis resistance, dashboard security, and hardening guidelines |
| [Threat Model](threat-model.md) | Adversary model, 8 threat categories, security boundaries, use-case scenarios, and residual risk analysis |

### User Guides

| Document | Description |
| --- | --- |
| [Getting Started](getting-started.md) | Installation, first build, quick tutorial, dashboard quickstart, and pipeline customization |
| [CLI Reference](cli-reference.md) | Complete command-line interface documentation with all options and examples |
| [Configuration](configuration.md) | Full TOML config format with pipeline, stego, overlay, and live dashboard settings |

### Integration

| Document | Description |
| --- | --- |
| [GStreamer Integration](gstreamer.md) | Pipeline architecture, AppSink/AppSrc, config-driven pipeline construction |
| [Platform Guide](platforms.md) | Linux v4l2, macOS AVFoundation, virtual devices, audio routing, Docker |

### Development

| Document | Description |
| --- | --- |
| [API Reference](api-reference.md) | Complete Rust API: types, traits, structs, methods, dashboard endpoints, and `LiveConfig` |
| [Contributing](contributing.md) | Development workflow, coding standards, testing, adding new algorithms |
| [Roadmap](roadmap.md) | Planned features, extension points, and future work |
| [FAQ](faq.md) | 30+ Q&As on concepts, build, usage, crypto, dashboard, and configuration |

## Quick Links

- **Run**: `./run.sh` (interactive menu, reads `steganographer.toml`)
- **Dashboard**: `./run.sh` → option `d` or `a` (launches web GUI at `http://localhost:8080`)
- **Build**: `cargo build --workspace`
- **Test**: `cargo test --workspace` (132 tests across 4 crates)
- **CLI**: `cargo run -p steganographer-cli -- --help`
- **Config**: [`steganographer.toml`](../steganographer.toml) (master config)
- **Example**: [`config/example.toml`](../config/example.toml)

## Architecture at a Glance

```mermaid
block-beta
    columns 3
    CLI["steganographer-cli\nClap CLI · Config · Logs · Menu"]:3
    GST["steganographer-gst\nGStreamer · AppSink · AppSrc"]:1
    DASH["steganographer-dashboard\nAxum GUI · WebSocket · QR Overlay"]:1
    space:1
    CORE["steganographer-core\nConfig · Crypto · LSB · Overlay · InfoBar · Metrics"]:3
    style CLI fill:#5c1a1a,stroke:#a33c3c,color:#fff
    style GST fill:#1a3a5c,stroke:#2d6da3,color:#fff
    style DASH fill:#3d1a3d,stroke:#7a3c7a,color:#fff
    style CORE fill:#2d5016,stroke:#4a8c2a,color:#fff
```

## Dashboard Features

| Feature | Description |
| --------- | ------------- |
| **Live Feed** | Zero-latency webcam via `requestAnimationFrame` |
| **QR Overlay** | Data matrix encoding frame index, BLAKE3 hash, timestamp, backend |
| **Opacity Slider** | Controls QR overlay visibility (0.0–1.0) |
| **Verification Data** | Right panel shows status banner, hash, latency, scrolling log |
| **Config Controls** | LSB bits, sign backend, overlay text, sign rate — all live |
| **MetaMask** | Connect Ethereum wallet for secp256k1 signing |
| **Stego Info** | Capacity, utilization, payload size — recalculated in real time |
| **Audio Tab** | Microphone capture, waveform/spectrum visualization, audio LSB signing |
| **Docs Tab** | Browse all 17 project docs in-dashboard with syntax highlighting |
| **Dynamic LSB** | Encode/decode handlers stay in sync when LSB slider changes (1–4 bits) |
| **Signature Preview** | Decoded payload shows first 16 bytes of Ed25519/secp256k1 signature |
| **Record & Save** | Record signed video (WebM) or audio (WAV) with embedded integrity data |
| **Tooltips** | Detailed mouseover explanations on every control for all experience levels |

## Test Summary

```text
steganographer-core (unit):    56 tests (crypto, LSB, overlay, config, audio, metrics, signer_backend)
steganographer-core (integ):   58 tests (E2E, pipeline, template, info_bar, signer_backend)
steganographer-dashboard:      12 tests (LiveConfig, DashboardState, router, API)
steganographer-gst:             1 test  (plugin skeleton)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total:                        132 tests, 0 failures
```
