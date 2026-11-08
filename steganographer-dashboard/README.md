# steganographer-dashboard

Video, Audio and Documentation tabs with a separate OpenTimestamps panel.
The live signing contract is **Ed25519 + BLAKE3 + LSB**, not Ethereum/MetaMask,
visual signed overlays, live encryption or ECC. Opacity affects preview only.

## Run

```bash
cargo run -p steganographer-cli -- dashboard --port 8080 --backend ed25519
```

Open `http://localhost:8080`. Camera/microphone permissions and secure browser
context still apply. Default binding is loopback. Deliberate network exposure
needs token/TLS/origin policy; CORS is not authentication. Configured bearer
auth protects mutations and `/api/webrtc/config`; public GET routes are not
blanket-protected. WebSocket upgrades enforce Origin and configured tokens.

## Delivered artifacts and ownership

The server signs kernel-canonical media and verifies extraction from the actual
delivered lossless PNG or signed S16LE PCM, not pre-embed originals. Its advertised
public key is that same runtime signer, not an independently established identity.
Per-artifact LSB bits, index and global cache revision drive verification.
The latest-completed server cache is global, not browser-private.

The browser owns one outstanding encode request across capture/encode/transport
generations. A decode disconnect clears its verdict, not encode request ownership;
encode reconnect invalidates the current target. Old cached replies remain History
until an artifact from the current encode epoch is accepted. Audio aggregates
count each accepted artifact/verdict once, not once per repeated cache reply.

Record exports a bounded stored-ZIP of sampled signed PNGs or returned signed PCM
wrapped in WAV chunks, with extraction metadata in `manifest.json`. Archive
ownership is captured at submission: starting/stopping a recording cannot adopt
an earlier request's reply. These are not continuous media recordings. Original
microphone input and lossy H.264 preview are not signed evidence. UI labels,
metrics and manifests are server-reported, not browser cryptographic verification.
Verify exported entries independently using a separately trusted public key.

## Transport

WebSocket video accepts raw binary encoded images (the browser sends PNG), and
returns JSON containing base64 signed PNG. Audio uses WebSocket PCM requests.
Optional WebRTC negotiates through `/api/webrtc/offer`; exact artifacts travel
on its data channel as UTF-8 JSON, with `kind: "encode"`, `msg_id`,
`sent_unix_ms` and `jpeg_b64` (historical name; browser bytes are PNG), or
`kind: "decode_poll"`. It is not a raw binary JPEG protocol.

Binary RTC chunks use a 20-byte big-endian header:
`STGO[4] | msg_id:u64 | chunk_index:u32 | chunk_count:u32 | payload`.
Whole chunks are at most 16 KiB; the **entire serialized JSON/base64** request
must fit 4,194,304 bytes. The browser checks before any chunk is sent, reports
actual/maximum bytes and advises smaller resolution or WebSocket selection.
WebSocket has separate raw-image/message/frame limits, not unlimited capacity.
Small server replies may be text JSON; large replies use STGO chunks. Assembly,
work queues, replies and peer lifetimes are bounded. Optional RTP H.264 is preview.
Only auto transport falls back; pinned WebRTC fails visibly. Fallback does not
replace the saved preference. Audio remains WebSocket.

## HTTP and OTS

- `/api/config`: validated snake_case full-object GET/POST; hydrate before updates.
- `/api/session`, `/api/version`, `/api/metrics`, `/api/metrics/reset`: runtime information.
- `/api/docs`, `/api/docs/{name}`: Markdown, rendered only after sanitization;
  missing/failed renderer or sanitizer falls back to text.
- `/ots/status`, `/ots/stamp`, `/ots/verify`: real detached-proof operations.
  Video commits delivered PNG bytes; audio commits raw signed PCM, **not** the
  WAV export wrapper. Pending is not Bitcoin-confirmed; verification trusts the
  configured Esplora provider, not independent full-node validation.

See [API Reference](../docs/api-reference.md), [Architecture](../docs/architecture.md)
and [OTS Integration](../docs/ots-integration.md). Test totals and observed host
scope live in root [AGENTS.md](../AGENTS.md), not static badges here.
