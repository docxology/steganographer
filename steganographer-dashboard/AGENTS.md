# AGENTS.md — steganographer-dashboard

## Purpose

Web-based live dashboard for real-time round-trip steganography verification. Serves a single-page application via Axum with three tabs (Video, Audio, Documentation, plus an OpenTimestamps panel) that displays encode and decode panels side-by-side with frame-level metrics, live configuration controls, and signature preview. Decode handlers perform **real signature verification** against the pre-embed bytes using the session-wide keypair's public half.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/lib.rs` | 606 | `DashboardState` (incl. `signer`, `audio_key`, `ots_config`, `ots_client`), `LiveConfig`, `create_router()`, `start_server()`, `check_auth()`, `validate_live_config()`, OTS endpoints, embedded static assets, docs API |
| `src/ws_handler.rs` | 1288 | `ws_encode_handler()`, `ws_decode_handler()`, `ws_audio_encode_handler()`, `ws_audio_decode_handler()`, `ws_gate()` (origin 403 + `?token=`/`bearer-<token>` 401), `verify_signature()`, `EncodedFrame`/`EncodedAudioChunk` (pre-embed snapshots), `ots_metrics_json()` |
| `src/static/index.html` | 783 | Three-tab layout (Video/Audio/Docs), dual encode/decode panels, live config controls, copy-to-clipboard, kbd hints, footer verified counter |
| `src/static/style.css` | 2621 | Premium dark theme (gray/black/red), glassmorphism, responsive layout, micro-animations, help tooltips, copy-btn, kbd-hint, export-btn |
| `src/static/app.js` | 1484 | Webcam capture, WebSocket encode/decode, metrics rendering, live config sync, video recording, keyboard shortcuts, session export, copy-to-clipboard, help tooltip positioning |
| `src/static/audio_tab.js` | 719 | Microphone capture via Web Audio API, waveform/spectrum visualization, audio WebSocket encode/decode, WAV recording/export |
| `src/static/docs_tab.js` | 261 | Documentation viewer: fetches markdown list from API, renders with marked.js |
| `src/static/js/ots.js` | 165 | OpenTimestamps status/stamp/verify client for the OTS panel |
| `tests/dashboard_tests.rs` | 880 | 23 tests for router creation, static asset serving, API endpoints |

## Routes

| Path | Method | Handler |
| ------ | -------- | --------- |
| `/` | GET | Serve `index.html` (Video + Audio + Docs tabs) |
| `/style.css` | GET | Serve stylesheet |
| `/app.js` | GET | Serve video tab JavaScript |
| `/audio_tab.js` | GET | Serve audio tab JavaScript |
| `/docs_tab.js` | GET | Serve docs tab JavaScript |
| `/ots.js` | GET | Serve OpenTimestamps panel JavaScript |
| `/ws/encode` | WS | Video encode — JPEG → LSB embed + sign → encoded frame |
| `/ws/decode` | WS | Video decode — extract LSB payload → verify signature → result + signature preview |
| `/ws/audio/encode` | WS | Audio encode — PCM → LSB embed + sign → signed chunk |
| `/ws/audio/decode` | WS | Audio decode — extract LSB payload → verify signature → result + signature preview |
| `/api/metrics` | GET | JSON metrics (frames, FPS, latency) |
| `/api/metrics/reset` | POST | Reset metrics counters |
| `/api/config` | GET/POST | Get/update live config (lsbBits, opacity, overlay, signRate, qrScale, resolution, stegoType, hashAlgorithm, encrypt, ecc; POST validated: lsbBits 1–4, opacity 0.0–1.0, signRateMs ≥ 50) |
| `/api/session` | GET | Session stats: uptime, config snapshot, metrics, backend, identity |
| `/api/version` | GET | Version info |
| `/api/docs` | GET | List available documentation files |
| `/api/docs/{name}` | GET | Return raw markdown content of a doc file |
| `/ots/status` | GET | OpenTimestamps configuration status |
| `/ots/stamp` | POST | Stamp a payload's Merkle root |
| `/ots/verify` | POST | Verify an OTS proof |

## Dynamic LSB Configuration

The dashboard supports live LSB bit-depth changes (1–4) via the UI slider. Both encode and decode handlers read the current `lsb_bits` from `DashboardState.live_config` each frame, ensuring encode/decode are always in sync. Audio uses `EncodedAudioChunk.lsb_bits` for the same purpose.

## Security
- **Default bind**: `127.0.0.1` (local-only). Use `--host 0.0.0.0` for network access.
- **Auth**: `--auth-token <token>` enables Bearer token auth on the guarded POST routes (`/api/config`, `/api/metrics/reset`, `/ots/stamp`, `/ots/verify`). Token comparison is constant-time via `subtle::ConstantTimeEq`.
- **WebSocket gates** (`ws_gate`, before the upgrade): cross-site `Origin` headers are rejected with HTTP 403 unless the origin host is loopback (`127.0.0.1`/`::1`/`localhost`) or matches the request's `Host` header; when `auth_token` is set, the upgrade additionally requires `?token=<token>` (minimal percent-decoding) **or** a `Sec-WebSocket-Protocol: bearer-<token>` subprotocol, else HTTP 401. Accepted upgrades get a 4 MiB decoded-message cap and a 1 MiB WS-frame cap (plus 4096×4096 image and 10 s/384 kHz audio sanity caps inside the handlers).
- **Real verification**: video/audio decode handlers verify the extracted `SignaturePayload` against the pre-embed pixel/sample snapshot (`signed_rgb` / `signed_samples`) using `DashboardState.signer`'s public half — a tampered frame flips `verified` to `false`. The session-wide `audio_key` (32 random bytes at startup) is shared by the audio encode/decode handlers.
- **CORS**: Restricted to GET/POST methods with Content-Type header. No permissive cross-origin access.
- **Warning**: Binding `0.0.0.0` without `--auth-token` logs a security warning.

## Tech Stack

- **Axum 0.8** with WebSocket support
- **tokio** async runtime
- **tower-http** CORS layer
- **image** crate for JPEG ↔ RGB conversion
- **base64** for binary frame encoding
- Static assets embedded via `include_str!`

## Test Coverage

23 tests in `tests/dashboard_tests.rs`
