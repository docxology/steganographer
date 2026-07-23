# steganographer-dashboard

![CI](https://github.com/docxology/steganographer/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-23-brightgreen)
Web-based live dashboard for real-time round-trip steganography verification with three tabs: **Video**, **Audio**, and **Documentation**.

## Features

- **Three-tab interface**: Video | Audio | Documentation — switch between media and docs
- **Dual-panel encode/decode**: Left panel shows raw feed, right panel shows decoded payload + verification
- **Dynamic LSB configuration**: Change LSB bits (1–4) live via slider — encode and decode stay in sync
- **Signature preview**: First 16 bytes of the Ed25519/secp256k1 signature displayed in decoded payload
- **Audio steganography**: Microphone capture → LSB embed/extract → real-time waveform + spectrum visualization
- **Audio recording**: Record and export WAV files from microphone capture
- **Documentation viewer**: Browse and read all project markdown docs with syntax highlighting
- **Live configuration**: Opacity, LSB bits, overlay text, sign rate, QR scale, resolution — all hot-configurable
- **Signing backend selector**: Ed25519 or Ethereum (secp256k1) with MetaMask integration
- **Premium dark theme**: Gray/black/red glassmorphism, smooth animations, responsive layout
- **Metrics display**: FPS, signing latency, verification success/fail rates, capacity utilization

## Usage

```bash
# Via CLI
cargo run -p steganographer-cli -- dashboard --port 8080 --backend ed25519

# Via run.sh (option 'd' or 'a' for run-all)
./run.sh
```

Then open `http://localhost:8080` in your browser.

## Architecture

```text
Browser (Webcam + Microphone via Web APIs)
    ↕ WebSocket (video: JPEG frames / audio: PCM chunks)
Axum Server (lib.rs → ws_handler.rs)
    ↕ Shared State (DashboardState, LiveConfig)
steganographer-core (LsbVideo, LsbAudio, Signer, StegoMetrics)
```

## API

| Endpoint | Description |
| ---------- | ------------- |
| `GET /` | Dashboard HTML page (Video + Audio + Docs tabs) |
| `WS /ws/encode` | Video encode stream (JPEG → LSB embed + sign) |
| `WS /ws/decode` | Video decode stream (extract → verify → signature preview) |
| `WS /ws/audio/encode` | Audio encode stream (PCM → LSB embed + sign) |
| `WS /ws/audio/decode` | Audio decode stream (extract → verify → signature preview) |
| `GET /api/metrics` | JSON metrics snapshot |
| `GET/POST /api/config` | Get/update live config |
| `GET /api/docs` | List available documentation files |
| `GET /api/docs/:name` | Return markdown content of a doc file |

## Tests

12 tests in `tests/dashboard_tests.rs` covering LiveConfig serialization, DashboardState construction, router creation, HTTP API endpoints (session, config GET/POST, docs, metrics), and static asset serving.

## Dependencies

- `steganographer-core` — metrics, signing backends, LSB modules
- `axum` 0.8 (with `ws` feature) — HTTP/WebSocket server
- `tokio` — async runtime
- `tower-http` — CORS layer
- `serde_json` — JSON serialization
- `image` — JPEG ↔ RGB frame conversion
- `base64` — binary frame encoding
