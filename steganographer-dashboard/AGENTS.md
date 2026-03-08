# AGENTS.md — steganographer-dashboard

## Purpose

Web-based live dashboard for real-time round-trip steganography verification. Serves a single-page application via Axum with three tabs (Video, Audio, Documentation) that displays encode and decode panels side-by-side with frame-level metrics, live configuration controls, and signature preview.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/lib.rs` | ~270 | `DashboardState`, `LiveConfig`, `create_router()`, `start_server()`, `api_session()`, embedded static assets, docs API |
| `src/ws_handler.rs` | ~660 | `handle_encode_socket()`, `handle_decode_socket()`, `handle_audio_encode_socket()`, `handle_audio_decode_socket()`, `EncodedFrame`, `EncodedAudioChunk` |
| `src/static/index.html` | ~690 | Three-tab layout (Video/Audio/Docs), dual encode/decode panels, live config controls, copy-to-clipboard, kbd hints, footer verified counter |
| `src/static/style.css` | ~1790 | Premium dark theme (gray/black/red), glassmorphism, responsive layout, micro-animations, help tooltips, copy-btn, kbd-hint, export-btn |
| `src/static/app.js` | ~1000 | Webcam capture, WebSocket encode/decode, metrics rendering, live config sync, video recording, keyboard shortcuts, session export, copy-to-clipboard, help tooltip positioning |
| `src/static/audio_tab.js` | ~710 | Microphone capture via Web Audio API, waveform/spectrum visualization, audio WebSocket encode/decode, WAV recording/export |
| `src/static/docs_tab.js` | ~250 | Documentation viewer: fetches markdown list from API, renders with marked.js + highlight.js |
| `tests/dashboard_tests.rs` | ~395 | 12 tests for router creation, static asset serving, API endpoints |

## Routes

| Path | Method | Handler |
| ------ | -------- | --------- |
| `/` | GET | Serve `index.html` (Video + Audio + Docs tabs) |
| `/style.css` | GET | Serve stylesheet |
| `/app.js` | GET | Serve video tab JavaScript |
| `/audio_tab.js` | GET | Serve audio tab JavaScript |
| `/docs_tab.js` | GET | Serve docs tab JavaScript |
| `/ws/encode` | WS | Video encode — JPEG → LSB embed + sign → encoded frame |
| `/ws/decode` | WS | Video decode — extract LSB payload → verify signature → result + signature preview |
| `/ws/audio/encode` | WS | Audio encode — PCM → LSB embed + sign → signed chunk |
| `/ws/audio/decode` | WS | Audio decode — extract LSB payload → verify signature → result + signature preview |
| `/api/metrics` | GET | JSON metrics (frames, FPS, latency) |
| `/api/config` | GET/POST | Get/update live config (lsbBits, opacity, overlay, signRate, qrScale, resolution) |
| `/api/session` | GET | Session stats: uptime, config snapshot, metrics, backend, identity |
| `/api/docs` | GET | List available documentation files |
| `/api/docs/:name` | GET | Return raw markdown content of a doc file |

## Dynamic LSB Configuration

The dashboard supports live LSB bit-depth changes (1–4) via the UI slider. Both encode and decode handlers read the current `lsb_bits` from `DashboardState.live_config` each frame, ensuring encode/decode are always in sync. Audio uses `EncodedAudioChunk.lsb_bits` for the same purpose.

## Tech Stack

- **Axum 0.8** with WebSocket support
- **tokio** async runtime
- **tower-http** CORS layer
- **image** crate for JPEG ↔ RGB conversion
- **base64** for binary frame encoding
- Static assets embedded via `include_str!`

## Test Coverage

12 tests in `tests/dashboard_tests.rs`
