# AGENTS.md — steganographer-dashboard

## Purpose

Web-based live dashboard for real-time round-trip steganography verification. Serves a single-page application via Axum with three tabs (Video, Audio, Documentation, plus an OpenTimestamps panel) that displays encode and decode panels side-by-side with frame-level metrics, live configuration controls, and signature preview. Decode handlers perform **real signature verification** against the pre-embed bytes using the session-wide keypair's public half.

## Module Map

| File | Lines | Key Functions |
| ------ | ------- | --------------- |
| `src/lib.rs` | 648 | `DashboardState` (incl. `signer`, `audio_key`, `ots_config`, `ots_client`), `LiveConfig` (incl. `transport: Transport`), `create_router()`, `start_server()`, `check_auth()`, `validate_live_config()`, OTS endpoints, embedded static assets, docs API |
| `src/ws_handler.rs` | 1367 | `ws_encode_handler()`, `ws_decode_handler()`, `ws_audio_encode_handler()`, `ws_audio_decode_handler()`, `ws_gate()` (origin 403 + `?token=`/`bearer-<token>` 401), shared `FramePipeline`/`FrameVerifier` (sign → LSB embed → verify, reused by the WebRTC path), `verify_signature()`, `EncodedFrame`/`EncodedAudioChunk` (pre-embed snapshots), `ots_metrics_json()` |
| `src/webrtc.rs` | 409 | `api_webrtc_offer()` (WHIP-style POST, auth-gated, non-trickle answer), `WebrtcHandler` (`on_data_channel` frame loop), `reap_connection()` — webrtc-rs 0.21 data-channel transport into the shared pipeline |

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
| `/api/config` | GET/POST | Get/update live config (lsbBits, opacity, overlay, signRate, qrScale, resolution, stegoType, hashAlgorithm, encrypt, ecc, transport; POST validated: lsbBits 1–4, opacity 0.0–1.0, signRateMs ≥ 50, transport ∈ {websocket, webrtc}) |
| `/api/session` | GET | Session stats: uptime, config snapshot, metrics, backend, identity |
| `/api/version` | GET | Version info |
| `/api/docs` | GET | List available documentation files |
| `/api/docs/{name}` | GET | Return raw markdown content of a doc file |
| `/ots/status` | GET | OpenTimestamps configuration status |
| `/ots/stamp` | POST | Stamp a payload's Merkle root |
| `/ots/verify` | POST | Verify an OTS proof |
| `/api/webrtc/offer` | POST | WHIP-style signaling: browser SDP offer in, non-trickle answer out; data channel feeds the encode pipeline |

## Dynamic LSB Configuration

The dashboard supports live LSB bit-depth changes (1–4) via the UI slider. Both encode and decode handlers read the current `lsb_bits` from `DashboardState.live_config` each frame, ensuring encode/decode are always in sync. Audio uses `EncodedAudioChunk.lsb_bits` for the same purpose.

## Security
- **Default bind**: `127.0.0.1` (local-only). Use `--host 0.0.0.0` for network access.
- **Auth**: `--auth-token <token>` enables Bearer token auth on the guarded POST routes (`/api/config`, `/api/metrics/reset`, `/ots/stamp`, `/ots/verify`, `/api/webrtc/offer`). Token comparison is constant-time via `subtle::ConstantTimeEq`. The WebRTC signaling POST needs no Origin check: a POST carries no ambient credentials and the response is unreadable cross-origin without CORS headers.
- **WebRTC transport** (`transport: "webrtc"` in live config, or the UI toggle): data-channel messages reuse the WS size caps (4 MiB message, 4096×4096 image); answer PCs are closed by a reaper on disconnect/failure/data-channel-close or after a 60 s never-connected deadline.
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

52 tests in `tests/dashboard_tests.rs` (plus 6 WebRTC/transport tests: transport serde, signaling auth/type/SDP validation, config transport field, and an in-process two-PeerConnection data-channel round trip through the real endpoint)
