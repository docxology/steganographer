# AGENTS.md — steganographer-dashboard

## Purpose

Axum dashboard with Video, Audio and Documentation tabs plus an OpenTimestamps panel. Live signing supports **Ed25519 + BLAKE3 + LSB only**. Verification extracts from the actual delivered lossless PNG / signed PCM, not a private pre-embed snapshot. UI verification labels are server-reported, not browser-side cryptographic verification of exported archives.

## Module Map

| File | Responsibility |
| --- | --- |
| `src/lib.rs` | `LiveConfig`, `DashboardState`, router, config/session/version/docs handlers, mutation auth/Origin policy and OTS integration |
| `src/ws_handler.rs` | WebSocket gates, shared bounded signing pipeline, delivered-artifact extraction/verification, public identity, cache revisions and async verify slots |
| `src/webrtc.rs` | Feature-gated SDP/data-channel transport, bounded assembly/admission/replies, shared encoder, peer/publisher lifecycle cleanup |
| `src/static/app.js` | Video lifecycle, transport policy, config hydration/serialized updates, preview, server-result matching and stored-ZIP artifact archives |
| `src/static/audio_tab.js` | Microphone lifecycle, bounded audio requests, returned signed-PCM playback/archives and server-reported verification |
| `src/static/docs_tab.js` | Markdown navigation, sanitized rendering or safe text fallback |
| `src/static/ots.js` | Real OTS status/stamp/verify UI; pending is not verified |

## Routes

| Path | Purpose |
| --- | --- |
| `/`, `/style.css`, `/app.js`, `/audio_tab.js`, `/docs_tab.js`, `/ots.js` | Embedded UI assets |
| `/ws/encode`, `/ws/decode` | Image input → signed PNG; extraction/verification results |
| `/ws/audio/encode`, `/ws/audio/decode` | PCM input → actual signed PCM; extraction/verification results |
| `/api/config` | GET/POST snake_case live config; unsupported settings reject |
| `/api/session`, `/api/version`, `/api/metrics` | Runtime identity/config/version and server metrics |
| `/api/metrics/reset` | Guarded metrics reset |
| `/api/docs`, `/api/docs/{name}` | Documentation inventory and Markdown |
| `/api/webrtc/config` | Bearer-protected when configured; ICE capabilities, actual identity and default transport |
| `/api/webrtc/offer` | Guarded SDP offer; shared signed-media data-channel pipeline when compiled |
| `/ots/status`, `/ots/stamp`, `/ots/verify` | Current media commitment availability, bounded real proof operations |

## Signed Media and Identity Contract

- State owns one actual Ed25519 signer. Advertised `public_key`/identity must match it and stay stable for the runtime. Do not generate a decorative second identity. A runtime public key is not independently established person/organization identity; caller applications must pin a trusted key separately.
- Video responses retain base64 `frame`, with `image_mime: "image/png"`, dimensions, frame index, LSB bit depth, public key and payload/commitment metadata. Verification decodes the exact delivered PNG, extracts the payload and recomputes kernel-canonical media binding.
- Audio responses contain the actual signed `pcm_s16le`, sample rate/channels, frame index, LSB bit depth, public key and public `embedding_key` extraction metadata. Never verify or export unsigned microphone originals instead.
- Canonical media excludes kernel-owned low-bit regions. Neither this signature nor generic payload signatures authenticate every file/container byte or arbitrary metadata field. Exact-artifact OTS commitments are a distinct scope.
- Cache revisions are server-wide monotonic values, separate from connection-local sequence/frame indices. Results must match both artifact index and revision; a reconnect/config change cannot relabel stale verification as current. Use the artifact's bit depth, not latest config.
- Encode reconnect increments target ownership: even a genuine verified global
  cached reply is History until a new artifact in the current encode epoch.

## UI and Archive Contract

- Preview opacity is display-only. Signed visual overlays, QR, MetaMask and Ethereum dashboard modes are unavailable; do not reinstate decorative controls that pretend to work. Library signing backends are not dashboard support.
- Capture is sampled and backpressured, not continuous proof. Client signing has one in-flight request and lifecycle/request generations; stale async work must not draw, verify or archive into a new session.
- Record stores exact returned PNG snapshots or signed PCM wrapped in WAV chunks in a bounded stored-ZIP with `manifest.json`. Include per-artifact public key, index, revision, bit depth and audio extraction metadata. No VP9/WebM re-encoding or original-microphone export as signed evidence.
- Manifest metadata and session/metric exports are not independent trust evidence. The browser does not independently verify archives. Downloaded PNG/WAV entries require separate extraction/signature verification with an independently trusted public key; gaps and sampling remain relevant.
- Entry/byte caps stop recording visibly before the next artifact, not silently drop it. Do not hardcode release validation counters in UI/docs.
- Pending encode belongs to its submission, independently of decode-channel
  reconnect. Decode disconnect clears its verdict, never frees encode ownership.
- Archive identity/generation is captured at submission; later recording start
  cannot adopt the earlier reply. Audio aggregates count each artifact once,
  with repeated cached verification replies idempotent.
- Markdown HTML enters the DOM only after sanitization. Missing/failed renderer or sanitizer falls back to text, including offline use. Never insert raw `marked` output.

## Configuration, Authentication and Transport

- Hydrate all supported live settings before serialized full-object POSTs. API fields are snake_case. Reject unsupported backend/hash/kernel/encryption/ECC selections rather than treating them as ignored switches.
- Default bind is loopback. Bearer auth guards mutation routes and `/api/webrtc/config` when configured; public GET routes are not all protected. Tokenless mutations reject foreign browser Origin. WebSocket upgrades require allowed Origin and configured token via query/subprotocol. Absent Origin is permitted for nonbrowser use; it does not prove local identity.
- CORS is not authentication. Network exposure needs deliberate token/TLS/reverse-proxy policy; warning on a tokenless non-loopback bind does not make it safe.
- Video preference precedence: URL query > saved choice > server default. Only `auto` falls back from WebRTC to WebSocket. Pinned WebRTC fails visibly, and fallback must not overwrite the saved choice. Audio remains WebSocket.
- WebSocket message/image/audio bounds, encoder admission, bounded verification queues and WebRTC chunk/reply/admission limits are required. Overload reports failure instead of unbounded queueing. Verification waits use async notification/deadlines, not reactor-blocking sleeps.
- Stop/failure/reconnect must clear signing state, timers, sockets, peers, chunk assemblies, tracks and publishers. Server peers close on failure/disconnect/idle or never-connected timeout, including failed signaling paths.
- RTC encode requests are UTF-8 JSON (`kind`, `msg_id`, `sent_unix_ms`,
  `jpeg_b64`); the historical field contains PNG bytes from the browser.
  Binary framing is `STGO[4] | u64 id | u32 index | u32 count`, big-endian,
  20-byte header, ≤16 KiB total/chunk. Reassembled JSON/base64 is ≤4 MiB.
  Measure actual serialized bytes before any chunks; oversize error reports
  actual/maximum and recommends smaller resolution or WebSocket selection.
  WS accepts raw binary images; it has its own limits. Signed replies are PNG.

## OTS Boundary

Stamp latest delivered signed PNG bytes for video or raw signed PCM for audio,
not the WAV export wrapper; reject absent media. Pending is not Bitcoin-confirmed.
Verification trusts configured Esplora, not independent full-node validation.
Shared `verify_with_upgrade` skips calendars for Bitcoin-attested proofs but
still verifies headers, returning optional changed bytes for append-only storage.

## Validation

Parent/integration owner runs checks after edits land. Relevant checks cover delivered PNG/PCM verification and tampering, runtime identity consistency, config changes/reconnects and revision matching, HTTP/WS auth/Origin gates, real RTC interop/bounds/cleanup, safe Markdown fallback and archive extraction with the independent CLI. Canonical final counts live in root `AGENTS.md`, not here.
