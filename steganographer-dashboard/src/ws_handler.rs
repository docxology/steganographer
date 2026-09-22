//! WebSocket handlers for streaming encoded/decoded video and audio frames.
//!
//! Channels:
//! - `/ws/encode` — receives raw JPEG frames from browser webcam, applies LSB stego + signing,
//!   sends back the encoded frame as base64 JPEG plus metrics.
//! - `/ws/decode` — receives the same encoded frame, extracts LSB payload, verifies signature,
//!   sends verification result plus decoded frame.
//! - `/ws/audio/encode` — receives PCM audio chunks, applies LSB audio stego + signing.
//! - `/ws/audio/decode` — extracts audio payload, verifies signature.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, State,
    },
    http::{header::HOST, header::ORIGIN, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use image::{ImageFormat, ImageReader, Limits};
use std::collections::VecDeque;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use steganographer_core::audio::AudioBuffer;
use steganographer_core::lsb_audio::LsbAudio;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::AudioStegoModule;
use steganographer_core::{Signer, Verifier, VideoFormat, VideoFrame, VideoStegoModule};

use super::DashboardState;

/// Maximum decoded WebSocket message size (4 MiB) — bounds client-controlled
/// allocation for JPEG frames / PCM chunks. Also reused as the data-channel
/// message cap on the WebRTC transport.
pub(crate) const WS_MAX_MESSAGE_SIZE: usize = 1 << 22;
/// Maximum WebSocket frame size (1 MiB).
pub(crate) const WS_MAX_FRAME_SIZE: usize = 1 << 20;
/// Maximum image dimension accepted for client-supplied JPEG frames —
/// guards against decompression bombs (a few MB of JPEG can decode to
/// gigabytes of pixels without limits).
pub(crate) const IMAGE_MAX_DIMENSION: u32 = 4096;
/// Maximum audio chunk duration accepted from clients (seconds × sample rate
/// × channels) — bounds the ~4× base64/PCM amplification per message.
const AUDIO_MAX_DURATION_SECS: u64 = 10;
/// Maximum audio sample rate accepted from clients (Hz).
const AUDIO_MAX_SAMPLE_RATE: u32 = 384_000;

/// Extract the host part (no port, no IPv6 brackets) from a URL authority.
fn authority_host(authority: &str) -> String {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: "[::1]:8080" or "[::1]"
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => rest,
        }
    } else {
        match authority.split_once(':') {
            Some((h, _)) => h,
            None => authority,
        }
    };
    host.to_ascii_lowercase()
}

/// Decide whether a WebSocket upgrade's Origin is acceptable.
///
/// CORS does not apply to WebSocket upgrades, so cross-site WebSocket
/// hijacking (CSWSH) must be blocked here. Allowed:
/// - no Origin header (non-browser client), or
/// - Origin host is a loopback address (127.0.0.1, ::1, localhost), or
/// - Origin host equals the request's Host header (same-host deployment,
///   port-insensitive to tolerate reverse proxies).
fn origin_allowed(origin: Option<&HeaderValue>, host: Option<&HeaderValue>) -> bool {
    let Some(origin) = origin.and_then(|o| o.to_str().ok()) else {
        return true; // absent or non-UTF-8 origin: not a browser-driven CSWSH
    };
    let authority = match origin.split_once("://") {
        Some((_, rest)) => rest.split(['/', '?', '#']).next().unwrap_or(rest),
        None => origin,
    };
    let origin_host = authority_host(authority);
    if matches!(origin_host.as_str(), "127.0.0.1" | "::1" | "localhost") {
        return true;
    }
    let Some(host) = host.and_then(|h| h.to_str().ok()) else {
        return false;
    };
    authority_host(host) == origin_host
}

/// Read the `token` query parameter (minimal percent-decoding) from a raw
/// query string.
fn query_token(raw_query: Option<&str>) -> Option<String> {
    let q = raw_query?;
    for pair in q.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k != "token" {
            continue;
        }
        let mut out = Vec::with_capacity(v.len());
        let bytes = v.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' if i + 2 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                    out.push(u8::from_str_radix(hex, 16).ok()?);
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        return String::from_utf8(out).ok();
    }
    None
}

/// Gate a WebSocket upgrade before it is performed:
///
/// Returns `true` when the gate passes, `false` otherwise.
#[allow(clippy::result_large_err)] // axum Response bodies are inherently large
fn ws_gate(
    headers: &HeaderMap,
    raw_query: Option<&str>,
    state: &DashboardState,
) -> Result<(), Response> {
    if !origin_allowed(headers.get(ORIGIN), headers.get(HOST)) {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            serde_json::json!({
                "status": "error",
                "message": "Cross-origin WebSocket connections are not allowed",
            })
            .to_string(),
        )
            .into_response());
    }

    if let Some(expected) = &state.auth_token {
        let token_ok =
            |t: &str| subtle::ConstantTimeEq::ct_eq(t.as_bytes(), expected.as_bytes()).into();
        let query_ok = query_token(raw_query).is_some_and(|t| token_ok(&t));
        let subproto_ok = headers
            .get_all("sec-websocket-protocol")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|p| token_ok(p.trim().strip_prefix("bearer-").unwrap_or("")));
        if !query_ok && !subproto_ok {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                serde_json::json!({
                    "status": "error",
                    "message": "WebSocket requires a token: pass ?token=<token> or Sec-WebSocket-Protocol: bearer-<token>",
                })
                .to_string(),
            )
                .into_response());
        }
    }
    Ok(())
}

/// Apply size caps and, when auth is configured, select the accepted
/// `bearer-<token>` subprotocol for the (already gate-passed) upgrade.
fn ws_configure(
    mut ws: WebSocketUpgrade,
    headers: &HeaderMap,
    state: &DashboardState,
) -> WebSocketUpgrade {
    ws = ws
        .max_message_size(WS_MAX_MESSAGE_SIZE)
        .max_frame_size(WS_MAX_FRAME_SIZE);
    if let Some(expected) = &state.auth_token {
        let token_ok =
            |t: &str| subtle::ConstantTimeEq::ct_eq(t.as_bytes(), expected.as_bytes()).into();
        let subproto = format!("bearer-{}", expected);
        let subproto_ok = headers
            .get_all("sec-websocket-protocol")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|p| token_ok(p.trim().strip_prefix("bearer-").unwrap_or("")));
        if subproto_ok {
            // Echo the accepted bearer subprotocol back to the client.
            ws = ws.protocols([subproto]);
        }
    }
    ws
}

/// Extract the WebSocket upgrade AFTER the gate has passed. Returns the
#[allow(clippy::result_large_err)]
async fn ws_extract(req: axum::extract::Request) -> Result<WebSocketUpgrade, Response> {
    let (mut parts, _body) = req.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => Ok(ws),
        Err(rejection) => Err(rejection.into_response()),
    }
}

/// Build an OTS metrics JSON object for inclusion in WebSocket replies.
/// Provides the explicit fields `ots_proofs_count`, `ots_last_timestamp`,
/// and `ots_verified` for the dashboard UI.
pub(crate) fn ots_metrics_json(state: &DashboardState) -> serde_json::Value {
    serde_json::json!({
        "ots_proofs_count": state.metrics.ots_proofs_generated(),
        "ots_last_timestamp": state.metrics.ots_last_timestamp(),
        "ots_verified": state.metrics.ots_last_verified(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHARED VIDEO FRAME PIPELINE (used by both the WebSocket and WebRTC paths)
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-stream video pipeline state: frame counter, LSB module and the LSB
/// bit-depth it was built with. The WebSocket encode handler runs one
/// `FramePipeline` per connection; the WebRTC data-channel handler runs the
/// equivalent `EncodeSession` (both feed an identical sign → LSB-embed →
/// re-encode pipeline signing with the session-wide `state.signer`).
pub(crate) struct FramePipeline {
    frame_counter: u64,
    lsb: LsbVideo,
    current_lsb_bits: u8,
}

impl FramePipeline {
    pub(crate) fn new() -> Self {
        Self {
            frame_counter: 0,
            lsb: LsbVideo::new(1),
            current_lsb_bits: 1,
        }
    }

    /// Encode one client-supplied JPEG frame: decode (with decompression-bomb
    /// guard), sign the pre-embed pixels, LSB-embed the payload, re-encode the
    /// post-embed image as JPEG, and store the result in
    /// `state.last_encoded_frame` for the decode/verify path.
    ///
    /// Returns the `encoded_frame` reply JSON (the same message shape as the
    /// WebSocket path) on success, or an `error` reply JSON on failure.
    pub(crate) fn encode_frame(
        &mut self,
        state: &DashboardState,
        jpeg_bytes: &[u8],
    ) -> Result<serde_json::Value, serde_json::Value> {
        let frame_idx = self.frame_counter;
        self.frame_counter += 1;

        // Decompression-bomb guard: reject frames that decode beyond the
        // 4096×4096 limit instead of allocating unbounded pixels.
        let mut reader = ImageReader::with_format(Cursor::new(jpeg_bytes), ImageFormat::Jpeg);
        let mut limits = Limits::default();
        limits.max_image_width = Some(IMAGE_MAX_DIMENSION);
        limits.max_image_height = Some(IMAGE_MAX_DIMENSION);
        reader.limits(limits);
        let rgb_image = match reader.decode() {
            Ok(img) => img.to_rgb8(),
            Err(e) => {
                log::warn!("Failed to decode JPEG frame: {}", e);
                return Err(serde_json::json!({
                    "type": "error",
                    "message": format!("failed to decode JPEG frame: {e}"),
                }));
            }
        };

        let width = rgb_image.width();
        let height = rgb_image.height();
        let mut rgb_data = rgb_image.into_raw();
        // Snapshot the pre-embed pixels: this is exactly what the signature
        // is computed over (embedding modifies LSBs afterwards).
        let signed_rgb = rgb_data.clone();

        let sign_start = Instant::now();
        let payload = state.signer.sign_frame(frame_idx, &rgb_data, None);
        let sign_duration = sign_start.elapsed();
        state.metrics.record_sign_duration(sign_duration);

        // Update LSB bits from live config if changed. The API validates
        // 1..=4, but clamp defensively so a stale/other-source config can
        // never reach the panicking constructor.
        {
            let cfg = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
            let bits = cfg.lsb_bits.clamp(1, 4);
            if bits != self.current_lsb_bits {
                self.current_lsb_bits = bits;
                self.lsb = LsbVideo::new(bits);
                log::info!(
                    "Video encode: LSB bits updated to {}",
                    self.current_lsb_bits
                );
            }
        }

        let embed_start = Instant::now();
        {
            let mut frame = VideoFrame {
                width,
                height,
                stride: width * 3,
                format: VideoFormat::Rgb8,
                data: &mut rgb_data,
                frame_index: frame_idx,
            };
            if let Err(e) = self.lsb.embed(&mut frame, Some(&payload)) {
                log::warn!("LSB embed failed: {}", e);
                return Err(serde_json::json!({
                    "type": "error",
                    "message": format!("LSB embed failed: {e}"),
                }));
            }
        }
        let embed_duration = embed_start.elapsed();
        state.metrics.record_embed_duration(embed_duration);
        state.metrics.record_frame();

        let encoded_image = image::RgbImage::from_raw(width, height, rgb_data.clone())
            .expect("invalid raw RGB dimensions");
        let mut jpeg_out = Cursor::new(Vec::new());
        if encoded_image
            .write_to(&mut jpeg_out, ImageFormat::Jpeg)
            .is_err()
        {
            log::warn!("Failed to re-encode JPEG");
            return Err(serde_json::json!({
                "type": "error",
                "message": "failed to re-encode JPEG",
            }));
        }

        let encoded_jpeg = jpeg_out.into_inner();
        let b64_frame = base64_encode(&encoded_jpeg);

        // Store the frame for the decode side and hand verification off to
        // the bounded async worker (sign + embed stay on the critical path;
        // extract + BLAKE3 + Ed25519 do not).
        store_frame_and_enqueue_verify(
            state,
            frame_idx,
            rgb_data,
            signed_rgb,
            width,
            height,
            self.current_lsb_bits,
        );

        let metrics_json = state.metrics.to_json();
        Ok(serde_json::json!({
            "type": "encoded_frame",
            "frame": b64_frame,
            "width": width,
            "height": height,
            "frame_index": frame_idx,
            "sign_us": sign_duration.as_micros() as u64,
            "embed_us": embed_duration.as_micros() as u64,
            "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
            "backend": state.signing_backend,
            "identity": state.identity,
            "ots": ots_metrics_json(state),
        }))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ASYNCHRONOUS FRAME VERIFICATION (bounded worker, drop-oldest backpressure)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Signature verification (LSB extract + BLAKE3 + Ed25519) costs ~60-80 ms per
// 720p frame and previously ran synchronously inside the encode/decode
// pipelines, capping throughput at ~1 fps. Verification is now decoupled:
//
// - The encode path (sign + embed) stays synchronous and submits each stored
//   frame to a dedicated worker thread through a BOUNDED queue
//   (`VERIFY_QUEUE_CAP` = 4 entries, ~4 × verify latency of backlog).
//   Backpressure policy: drop-OLDEST — when the queue is full the oldest
//   queued (not yet verified) frame is discarded to make room, so the newest
//   frame is always the one verified and JPEG intake never queues unboundedly.
//   Dropped frames are simply never verified (no metric is recorded for them);
//   the decode side reports them as stale.
// - The worker performs the REAL verification (LSB extraction + signature
//   check against the pre-embed bytes) and records the per-frame outcome
//   (`frames_verified_ok` / `frames_verified_fail` / verify latency) plus the
//   result into the frame's `VerifySlot`.
// - The decode-poll path reports the LATEST verification result by frame
//   counter instead of re-verifying synchronously. If the result for the
//   freshest stored frame is not ready yet, the poll waits briefly (bounded)
//   and otherwise reports `verified: false` + `verified_stale: true` with
//   `payload_found: false` — consumers keep the existing field names; only
//   additive fields (`verified_stale`, `payload.stale`) were introduced.

/// Maximum frames allowed to sit in the asynchronous verify queue. At the
/// measured ~60-80 ms per verification this bounds the backlog at ~0.3 s.
const VERIFY_QUEUE_CAP: usize = 4;

/// Outcome of one asynchronous verification of an actually-embedded frame.
#[derive(Clone)]
pub(crate) struct VerifyOutcome {
    frame_index: u64,
    verified: bool,
    payload_info: Option<serde_json::Value>,
    verify_us: u64,
}

/// Per-frame slot holding the latest completed asynchronous verification
/// result. Shared between the encode handler (via the stored
/// [`EncodedFrame`]) and the decode-poll path.
#[derive(Default)]
pub struct VerifySlot {
    latest: std::sync::Mutex<Option<VerifyOutcome>>,
}

impl VerifySlot {
    /// Wait (bounded) until the slot carries a verification result for
    /// `frame_index`. Returns the matching outcome, or `None` on timeout.
    fn wait_for(&self, frame_index: u64, timeout: std::time::Duration) -> Option<VerifyOutcome> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let guard = self.latest.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(o) = guard.as_ref() {
                    if o.frame_index == frame_index {
                        return Some(o.clone());
                    }
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// One encoded frame awaiting asynchronous verification.
struct VerifyJob {
    frame_index: u64,
    /// Pre-embed pixels: exactly what the signature covers.
    signed_rgb: Vec<u8>,
    /// Post-embed pixels: LSB extraction source.
    rgb_data: Vec<u8>,
    width: u32,
    height: u32,
    lsb_bits: u8,
    /// Ed25519 public key bytes of the session-wide signer.
    verify_key: [u8; 32],
    metrics: Arc<steganographer_core::StegoMetrics>,
    slot: Arc<VerifySlot>,
}

/// Run one verification job: extract the LSB payload from the post-embed
/// pixels, verify the signature against the pre-embed bytes, update the
/// verification metrics (real outcomes of actually-embedded frames), and
/// publish the result into the job's slot.
fn run_verify(job: VerifyJob) {
    let VerifyJob {
        frame_index,
        signed_rgb,
        rgb_data,
        width,
        height,
        lsb_bits,
        verify_key,
        metrics,
        slot,
    } = job;
    let verify_start = Instant::now();
    let mut data = rgb_data;
    let frame = VideoFrame {
        width,
        height,
        stride: width * 3,
        format: VideoFormat::Rgb8,
        data: &mut data,
        frame_index,
    };
    let lsb = LsbVideo::new(lsb_bits);
    let (verified, payload_info) = match lsb.extract(&frame) {
        Ok(Some(payload)) => {
            // Real signature verification against the pre-embed pixels the
            // signature covers (finding a payload is not proof of
            // authenticity).
            let verified = Verifier::from_bytes(&verify_key)
                .map(|v| v.verify(&payload, &signed_rgb, None))
                .unwrap_or(false);
            let hash_hex: String = payload.hash.iter().map(|b| format!("{b:02x}")).collect();
            let sig_preview: String = payload
                .signature
                .to_bytes()
                .iter()
                .take(16)
                .map(|b| format!("{b:02x}"))
                .collect();
            let sig_full: String = payload
                .signature
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            (
                verified,
                Some(serde_json::json!({
                    "payload_found": true,
                    "frame_index": payload.frame_index,
                    "hash": hash_hex,
                    "signature_preview": sig_preview,
                    "signature_full": sig_full,
                })),
            )
        }
        Ok(None) => (
            false,
            Some(serde_json::json!({"payload_found": false, "error": "no payload found"})),
        ),
        Err(e) => (
            false,
            Some(serde_json::json!({"payload_found": false, "error": e.to_string()})),
        ),
    };
    metrics.record_verify_duration(verify_start.elapsed());
    if verified {
        metrics.record_verify_ok();
    } else {
        metrics.record_verify_fail();
    }
    *slot.latest.lock().unwrap_or_else(|e| e.into_inner()) = Some(VerifyOutcome {
        frame_index,
        verified,
        payload_info,
        verify_us: verify_start.elapsed().as_micros() as u64,
    });
}

/// Dedicated verification worker: bounded queue + drop-oldest backpressure.
struct VerifyEngine {
    queue: std::sync::Mutex<VecDeque<VerifyJob>>,
    cv: std::sync::Condvar,
}

static VERIFY_ENGINE: std::sync::LazyLock<Arc<VerifyEngine>> = std::sync::LazyLock::new(|| {
    let engine = Arc::new(VerifyEngine {
        queue: std::sync::Mutex::new(VecDeque::new()),
        cv: std::sync::Condvar::new(),
    });
    let worker = engine.clone();
    // Dedicated worker thread: verification is CPU-bound and fully
    // detached from the async encode/decode paths.
    let _ = std::thread::Builder::new()
        .name("frame-verify-worker".into())
        .spawn(move || verify_worker_loop(worker));
    engine
});

/// Accessor for the process-wide verification worker engine.
fn verify_engine() -> &'static Arc<VerifyEngine> {
    &VERIFY_ENGINE
}

fn verify_worker_loop(engine: Arc<VerifyEngine>) {
    loop {
        let job = {
            let mut q = engine.queue.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(job) = q.pop_front() {
                    break job;
                }
                q = engine.cv.wait(q).unwrap_or_else(|e| e.into_inner());
            }
        };
        // A panicking job (e.g. a bad bit-depth slipping through) must never
        // take down the shared worker permanently.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_verify(job)));
    }
}

/// Pure bounded-queue push used by [`enqueue_verify`]. Pushes `job` onto
/// `queue`, dropping the OLDEST queued job when the queue is already at
/// `cap`. Returns `true` when an oldest job was dropped.
fn queue_push(queue: &mut VecDeque<VerifyJob>, job: VerifyJob, cap: usize) -> bool {
    let mut dropped_oldest = false;
    if queue.len() >= cap {
        queue.pop_front();
        dropped_oldest = true;
    }
    queue.push_back(job);
    dropped_oldest
}

/// Submit one freshly embedded frame for asynchronous verification.
///
/// The queue is bounded at [`VERIFY_QUEUE_CAP`]; when full, the OLDEST
/// queued frame is dropped so the newest frame is always verified. Returns
/// `true` when an oldest job was dropped under backpressure.
fn enqueue_verify(job: VerifyJob) -> bool {
    let engine = verify_engine();
    let mut q = engine.queue.lock().unwrap_or_else(|e| e.into_inner());
    let dropped = queue_push(&mut q, job, VERIFY_QUEUE_CAP);
    drop(q);
    engine.cv.notify_one();
    if dropped {
        log::warn!("Verify queue full: dropped oldest pending verification");
    }
    dropped
}

/// Store a freshly embedded frame for the decode side and hand verification
/// off to the bounded async worker (drop-oldest backpressure). Returns the
/// slot the decode-poll path reads the verification result from.
fn store_frame_and_enqueue_verify(
    state: &DashboardState,
    frame_idx: u64,
    rgb_data: Vec<u8>,
    signed_rgb: Vec<u8>,
    width: u32,
    height: u32,
    lsb_bits: u8,
) -> std::sync::Arc<VerifySlot> {
    let slot = std::sync::Arc::new(VerifySlot::default());
    {
        let mut last = state
            .last_encoded_frame
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *last = Some(EncodedFrame {
            // Post-embed pixels: extraction source and displayed image. The
            // worker extracts from its own copy; the stored frame serves the
            // decode-side display.
            rgb_data: rgb_data.clone(),
            width,
            height,
            frame_index: frame_idx,
            verify: slot.clone(),
        });
    }
    let _ = enqueue_verify(VerifyJob {
        frame_index: frame_idx,
        signed_rgb,
        rgb_data,
        width,
        height,
        lsb_bits,
        verify_key: state.signer.verifying_key().to_bytes(),
        metrics: state.metrics.clone(),
        slot: slot.clone(),
    });
    slot
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIDEO WEBSOCKET UPGRADE HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

/// WebSocket upgrade handler for the encode (left panel) feed.
pub async fn ws_encode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    let headers = req.headers().clone();
    let query = req.uri().query().map(str::to_owned);
    if let Err(resp) = ws_gate(&headers, query.as_deref(), &state) {
        return resp;
    }
    let ws = match ws_extract(req).await {
        Ok(ws) => ws,
        Err(resp) => return resp,
    };
    let ws = ws_configure(ws, &headers, &state);
    ws.on_upgrade(move |socket| handle_encode_socket(socket, state))
}

/// WebSocket upgrade handler for the decode (right panel) feed.
pub async fn ws_decode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    let headers = req.headers().clone();
    let query = req.uri().query().map(str::to_owned);
    if let Err(resp) = ws_gate(&headers, query.as_deref(), &state) {
        return resp;
    }
    let ws = match ws_extract(req).await {
        Ok(ws) => ws,
        Err(resp) => return resp,
    };
    let ws = ws_configure(ws, &headers, &state);
    ws.on_upgrade(move |socket| handle_decode_socket(socket, state))
}

/// WebSocket upgrade handler for audio encode.
pub async fn ws_audio_encode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    let headers = req.headers().clone();
    let query = req.uri().query().map(str::to_owned);
    if let Err(resp) = ws_gate(&headers, query.as_deref(), &state) {
        return resp;
    }
    let ws = match ws_extract(req).await {
        Ok(ws) => ws,
        Err(resp) => return resp,
    };
    let ws = ws_configure(ws, &headers, &state);
    ws.on_upgrade(move |socket| handle_audio_encode_socket(socket, state))
}

/// WebSocket upgrade handler for audio decode.
pub async fn ws_audio_decode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    let headers = req.headers().clone();
    let query = req.uri().query().map(str::to_owned);
    if let Err(resp) = ws_gate(&headers, query.as_deref(), &state) {
        return resp;
    }
    let ws = match ws_extract(req).await {
        Ok(ws) => ws,
        Err(resp) => return resp,
    };
    let ws = ws_configure(ws, &headers, &state);
    ws.on_upgrade(move |socket| handle_audio_decode_socket(socket, state))
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIDEO ENCODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-connection encode pipeline state shared by the WebSocket and
/// WebRTC DataChannel transports.
///
/// Signing uses the session-wide [`DashboardState::signer`] (what the
/// verify worker checks against), so the session carries only per-frame
/// pipeline state: the LSB module, its active bit depth, and the frame
/// counter.
pub struct EncodeSession {
    lsb: LsbVideo,
    current_lsb_bits: u8,
    frame_counter: AtomicU64,
}

impl EncodeSession {
    /// Create a fresh encode session (1-bit LSB, frame 0).
    pub fn new() -> Self {
        Self {
            lsb: LsbVideo::new(1),
            current_lsb_bits: 1,
            frame_counter: AtomicU64::new(0),
        }
    }
}

impl Default for EncodeSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Process one JPEG frame through the encode pipeline (stego embed + sign).
///
/// Returns the JSON reply that both the WebSocket and WebRTC transports
/// send back to the client, or `None` if the frame could not be decoded,
/// embedded, or re-encoded. Also records the frame into
/// `DashboardState::last_encoded_frame` for the decode side.
pub fn process_encode_frame(
    state: &DashboardState,
    session: &mut EncodeSession,
    jpeg_bytes: &[u8],
) -> Option<serde_json::Value> {
    if jpeg_bytes.is_empty() {
        return None;
    }

    let frame_idx = session.frame_counter.fetch_add(1, Ordering::Relaxed);

    let decode_result =
        ImageReader::with_format(Cursor::new(jpeg_bytes), ImageFormat::Jpeg).decode();

    let rgb_image = match decode_result {
        Ok(img) => img.to_rgb8(),
        Err(e) => {
            log::warn!("Failed to decode JPEG frame: {}", e);
            return None;
        }
    };

    let width = rgb_image.width();
    let height = rgb_image.height();
    let mut rgb_data = rgb_image.into_raw();
    // Pre-embed snapshot: exactly what the signature covers (embedding
    // modifies LSBs afterwards), kept for decode-side verification.
    let signed_rgb = rgb_data.clone();

    let sign_start = Instant::now();
    let payload = state.signer.sign_frame(frame_idx, &rgb_data, None);
    let sign_duration = sign_start.elapsed();
    state.metrics.record_sign_duration(sign_duration);

    // Update LSB bits from live config if changed. The API validates
    // 1..=4, but clamp defensively so a stale/other-source config can
    // never reach the panicking constructor.
    {
        let cfg = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
        let bits = cfg.lsb_bits.clamp(1, 4);
        if bits != session.current_lsb_bits {
            session.current_lsb_bits = bits;
            session.lsb = LsbVideo::new(session.current_lsb_bits);
            log::info!(
                "Video encode: LSB bits updated to {}",
                session.current_lsb_bits
            );
        }
    }

    let embed_start = Instant::now();
    {
        let mut frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut rgb_data,
            frame_index: frame_idx,
        };
        if let Err(e) = session.lsb.embed(&mut frame, Some(&payload)) {
            log::warn!("LSB embed failed: {}", e);
            return None;
        }
    }
    let embed_duration = embed_start.elapsed();
    state.metrics.record_embed_duration(embed_duration);
    state.metrics.record_frame();

    let encoded_image = image::RgbImage::from_raw(width, height, rgb_data.clone())
        .expect("invalid raw RGB dimensions");
    let mut jpeg_out = Cursor::new(Vec::new());
    if encoded_image
        .write_to(&mut jpeg_out, ImageFormat::Jpeg)
        .is_err()
    {
        log::warn!("Failed to re-encode JPEG");
        return None;
    }

    let encoded_jpeg = jpeg_out.into_inner();
    let b64_frame = base64_encode(&encoded_jpeg);

    // Store the frame for the decode side and hand verification off to the
    // bounded async worker (never blocks intake: sign + embed stay on the
    // critical path; extract + BLAKE3 + Ed25519 do not).
    store_frame_and_enqueue_verify(
        state,
        frame_idx,
        rgb_data,
        signed_rgb,
        width,
        height,
        session.current_lsb_bits,
    );

    let metrics_json = state.metrics.to_json();
    Some(serde_json::json!({
        "type": "encoded_frame",
        "frame": b64_frame,
        "width": width,
        "height": height,
        "frame_index": frame_idx,
        "sign_us": sign_duration.as_micros() as u64,
        "embed_us": embed_duration.as_micros() as u64,
        "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
        "backend": state.signing_backend,
        "identity": state.identity,
        "ots": ots_metrics_json(state),
    }))
}

/// Handle the encode WebSocket — thin wrapper around [`process_encode_frame`].
async fn handle_encode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Encode WebSocket client connected");

    // Single session-wide keypair: what the encode side signs, the decode
    // side verifies against the same public half (state.signer).
    let mut pipeline = FramePipeline::new();

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Encode WebSocket client disconnected");
                break;
            }
        };

        let jpeg_bytes = match msg {
            Message::Binary(data) => data.to_vec(),
            Message::Text(text) => {
                if text.contains("ping") {
                    let metrics_json = state.metrics.to_json();
                    let reply = serde_json::json!({
                        "type": "metrics",
                        "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
                        "backend": state.signing_backend,
                        "identity": state.identity,
                        "ots": ots_metrics_json(&state),
                    });
                    let _ = socket.send(Message::Text(reply.to_string().into())).await;
                }
                continue;
            }
            Message::Ping(_) => continue,
            Message::Pong(_) => continue,
            Message::Close(_) => break,
        };

        if jpeg_bytes.is_empty() {
            continue;
        }

        let reply = match pipeline.encode_frame(&state, &jpeg_bytes) {
            Ok(reply) => reply,
            Err(reply) => reply,
        };

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Encode WebSocket client disconnected");
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIDEO DECODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// True when a text message is a documented decode trigger: the literal
/// `"poll"` (video decode UI) or `{"type": "decode_request"}` (audio decode
/// UI). Anything else is client chatter and must not run a decode cycle.
fn is_decode_trigger(text: &str) -> bool {
    let t = text.trim();
    if t == "poll" {
        return true;
    }
    serde_json::from_str::<serde_json::Value>(t)
        .ok()
        .map(|v| v.get("type").and_then(|t| t.as_str()) == Some("decode_request"))
        .unwrap_or(false)
}

/// Drain queued messages without running more decode cycles: every queued
/// trigger collapses into the cycle about to run against the freshest stored
/// frame. Returns true when the peer closed or the connection is gone.
async fn drain_queued(socket: &mut WebSocket) -> bool {
    loop {
        match tokio::time::timeout(std::time::Duration::ZERO, socket.recv()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return true,
            Ok(Some(Ok(_))) => {}   // redundant trigger/data — already covered
            Err(_) => return false, // no more queued messages right now
        }
    }
}
/// Handle the decode WebSocket — reports the latest asynchronous verification
/// result for the stored frame and streams it to the right panel (the same
/// pipeline as the WebRTC decode poll).
async fn handle_decode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Decode WebSocket client connected");

    let mut session = DecodeSession::new();

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Decode WebSocket client disconnected");
                break;
            }
        };

        // Amperage gate: only documented triggers ("poll", or
        // {"type": "decode_request"}) run a decode cycle; other messages are
        // ignored (logged at debug). The loop is sequential, so exactly one
        // decode cycle is in flight per connection; any polls that queue up
        // while a cycle runs are collapsed by `drain_queued` below instead
        // of each triggering its own cycle.
        let trigger = match &msg {
            Message::Text(t) => is_decode_trigger(t),
            Message::Binary(_) => {
                log::debug!("Decode WS: ignoring binary message (no decode trigger)");
                false
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        };
        if !trigger {
            log::debug!("Decode WS: ignoring message without poll/decode_request trigger");
            continue;
        }

        let reply = process_decode_poll(&state, &mut session);

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Decode WebSocket client disconnected");
            break;
        }

        // Collapse polls queued while this cycle was in flight: the cycle
        // just completed already reflects the latest stored frame, so skip
        // per-message decode work for the backlog. Returns true on close.
        if drain_queued(&mut socket).await {
            break;
        }
    }
}
/// Per-connection decode-poll metadata shared by the WebSocket and WebRTC
/// DataChannel transports. Verification itself runs on the async worker;
/// the session only tracks the configured LSB bit depth for reply metadata.
pub struct DecodeSession {
    current_lsb_bits: u8,
}

impl DecodeSession {
    /// Create a fresh decode session (1-bit LSB default).
    pub fn new() -> Self {
        Self {
            current_lsb_bits: 1,
        }
    }
}

impl Default for DecodeSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Run one decode poll: report the LATEST asynchronous verification result
/// for the freshest stored frame and build the JSON reply shared by the
/// WebSocket and WebRTC transports.
///
/// The synchronous verify (LSB extract + BLAKE3 + Ed25519) no longer runs on
/// the poll path — it happens on the bounded worker thread. The poll waits
/// briefly (bounded by `DECODE_VERIFY_WAIT`) for the worker's result of the
/// current frame; if it is not ready yet the reply carries
/// `verified: false` + `verified_stale: true` (additive field; existing field
/// names unchanged).
pub fn process_decode_poll(
    state: &DashboardState,
    session: &mut DecodeSession,
) -> serde_json::Value {
    /// Bounded wait for the async verifier to publish the current frame's
    /// result. Typically <100 ms (one verification); only pays on the
    /// low-rate decode-poll path, never on frame intake.
    const DECODE_VERIFY_WAIT: std::time::Duration = std::time::Duration::from_millis(1000);

    let encoded = {
        let last = state
            .last_encoded_frame
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        last.clone()
    };

    let Some(ef) = encoded else {
        let metrics_json = state.metrics.to_json();
        return serde_json::json!({
            "type": "verify_status",
            "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
            "backend": state.signing_backend,
            "waiting": true,
            "ots": ots_metrics_json(state),
        });
    };
    // Reply metadata only: the actual extraction runs on the verify worker
    // with the frame's own bit depth.
    {
        let cfg = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
        session.current_lsb_bits = cfg.lsb_bits;
    }

    // Latest verification result by frame counter. Bounded wait for the
    // async worker; stale if it does not land in time.
    let outcome = ef.verify.wait_for(ef.frame_index, DECODE_VERIFY_WAIT);
    let verified_stale = outcome.is_none();
    let (verified, payload_info, verify_us) = match outcome {
        Some(o) => (
            o.verified,
            o.payload_info
                .unwrap_or_else(|| serde_json::json!({"payload_found": false})),
            o.verify_us,
        ),
        None => (
            false,
            serde_json::json!({
                "payload_found": false,
                "error": "verification pending",
                "stale": true,
            }),
            0,
        ),
    };

    let decoded_image = image::RgbImage::from_raw(ef.width, ef.height, ef.rgb_data)
        .expect("invalid raw RGB dimensions");
    let mut jpeg_out = Cursor::new(Vec::new());
    let _ = decoded_image.write_to(&mut jpeg_out, ImageFormat::Jpeg);
    let b64_frame = base64_encode(&jpeg_out.into_inner());

    let metrics_json = state.metrics.to_json();
    let now = {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        // Simple ISO 8601 UTC timestamp
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        format!("{:02}:{:02}:{:02}.{:03}Z", h, m, s, d.subsec_millis())
    };
    serde_json::json!({
        "type": "decoded_frame",
        "frame": b64_frame,
        "width": ef.width,
        "height": ef.height,
        "verified": verified,
        "verified_stale": verified_stale,
        "payload": payload_info,
        "verify_us": verify_us,
        "timestamp": now,
        "lsb_bits": session.current_lsb_bits,
        "data": serde_json::from_str::<serde_json::Value>(&metrics_json).unwrap_or_default(),
        "backend": state.signing_backend,
        "ots": ots_metrics_json(state),
    })
}

/// Verify an extracted [`steganographer_core::crypto::SignaturePayload`]
/// against the pre-embed bytes its signature covers, using the session-wide
/// keypair's public half. This is the exact computation both decode handlers
/// perform; exposed so security tests can pin the tamper property: altering
/// the signed bytes MUST flip the result to `false`.
pub fn verify_signature(
    signer: &Signer,
    payload: &steganographer_core::SignaturePayload,
    signed_bytes: &[u8],
) -> bool {
    Verifier::new(signer.verifying_key()).verify(payload, signed_bytes, None)
}

/// Send a JSON error message to a WebSocket client. Returns `true` when the
/// message was delivered; `false` when the connection is gone.
async fn ws_send_error(socket: &mut WebSocket, message: String) -> bool {
    let err = serde_json::json!({ "type": "error", "message": message });
    socket
        .send(Message::Text(err.to_string().into()))
        .await
        .is_ok()
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO ENCODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle the audio encode WebSocket — receives PCM audio chunks from the browser,
/// applies LSB audio steganography + cryptographic signing.
async fn handle_audio_encode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Audio Encode WebSocket client connected");

    let chunk_counter = AtomicU64::new(0);
    // Session-wide keypair and audio key from DashboardState: the audio
    // decode handler verifies against the very same signer.
    let audio_key = state.audio_key;
    let mut lsb_audio = LsbAudio::new(1, audio_key);

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Audio Encode WebSocket disconnected");
                break;
            }
        };

        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
            _ => continue,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Audio encode: invalid JSON: {}", e);
                continue;
            }
        };

        if parsed.get("type").and_then(|v| v.as_str()) != Some("audio_frame") {
            continue;
        }

        let chunk_idx = chunk_counter.fetch_add(1, Ordering::Relaxed);
        let sample_rate = parsed
            .get("sample_rate")
            .and_then(|v| v.as_u64())
            .unwrap_or(44100) as u32;
        let channels = parsed.get("channels").and_then(|v| v.as_u64()).unwrap_or(1) as u16;
        let lsb_bits = parsed.get("lsb_bits").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

        // Sanity caps: reject client values that would blow up work or reach
        // panicking constructors downstream. Errors are reported on the
        // socket and the message is skipped, never aborting the connection.
        if channels == 0 || channels > 2 {
            if !ws_send_error(
                &mut socket,
                format!("audio channels must be 1-2, got {channels}"),
            )
            .await
            {
                break;
            }
            continue;
        }
        if sample_rate == 0 || sample_rate > AUDIO_MAX_SAMPLE_RATE {
            if !ws_send_error(
                &mut socket,
                format!(
                    "audio sample_rate must be 1-{} Hz, got {sample_rate}",
                    AUDIO_MAX_SAMPLE_RATE
                ),
            )
            .await
            {
                break;
            }
            continue;
        }
        if lsb_bits > 4 {
            if !ws_send_error(
                &mut socket,
                format!("audio lsb_bits must be 1-4, got {lsb_bits}"),
            )
            .await
            {
                break;
            }
            continue;
        }
        let lsb_bits = lsb_bits.max(1); // clamp below-range up to 1

        let pcm_b64 = match parsed.get("pcm_base64").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let pcm_bytes = match base64_decode(pcm_b64) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("Audio encode: base64 decode failed: {}", e);
                continue;
            }
        };

        let (pcm_chunks, _remainder) = pcm_bytes.as_chunks::<2>();
        let mut samples: Vec<i16> = pcm_chunks.iter().map(|c| i16::from_le_bytes(*c)).collect();

        if samples.is_empty() {
            continue;
        }

        // Sample-count cap: at most 10 seconds of audio
        // (duration × sample rate × channels) per chunk — bounds the ~4×
        // base64→PCM amplification and embed/verify work per message.
        if samples.len() as u64 > AUDIO_MAX_DURATION_SECS * sample_rate as u64 * channels as u64 {
            if !ws_send_error(
                &mut socket,
                format!(
                    "audio chunk too long: {} samples exceeds 10s × {sample_rate} Hz × {channels} ch",
                    samples.len()
                ),
            )
            .await
            {
                break;
            }
            continue;
        }

        // Update LSB bits if changed
        if lsb_bits != lsb_audio.bits() {
            lsb_audio = LsbAudio::new(lsb_bits, audio_key);
        }

        // Sign the audio chunk with the session-wide signer
        let sign_start = Instant::now();
        let sample_bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let payload = state.signer.sign_frame(chunk_idx, &sample_bytes, None);
        let sign_duration = sign_start.elapsed();

        // Snapshot the pre-embed samples: exactly what the signature covers
        // (embedding modifies sample LSBs afterwards).
        let signed_samples: Vec<i16> = samples.clone();

        // Embed payload
        let embed_start = Instant::now();
        {
            let mut buf = AudioBuffer {
                channels,
                sample_rate,
                samples: &mut samples,
                frame_index: chunk_idx,
            };
            if let Err(e) = lsb_audio.embed(&mut buf, Some(&payload)) {
                log::warn!("Audio LSB embed failed: {}", e);
                continue;
            }
        }
        let embed_duration = embed_start.elapsed();

        // Store for decode handler
        {
            let mut last = state
                .last_encoded_audio
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *last = Some(EncodedAudioChunk {
                // Post-embed samples: extraction source.
                samples: samples.clone(),
                // Pre-embed samples: what the signature covers, used by the
                // decode handler for real verification.
                signed_samples,
                sample_rate,
                channels,
                chunk_index: chunk_idx,
                lsb_bits,
            });
        }

        let reply = serde_json::json!({
            "type": "audio_signed",
            "chunk_index": chunk_idx,
            "sign_us": sign_duration.as_micros() as u64,
            "embed_us": embed_duration.as_micros() as u64,
            "sample_count": samples.len(),
            "backend": state.signing_backend,
        });

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Audio Encode WebSocket disconnected");
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO DECODE HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle the audio decode WebSocket — extracts audio LSB payloads and verifies.
async fn handle_audio_decode_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    log::info!("Audio Decode WebSocket client connected");

    let mut lsb_audio: Option<LsbAudio> = None;
    let mut current_lsb_bits: u8 = 1;

    loop {
        let msg = match socket.recv().await {
            Some(Ok(msg)) => msg,
            _ => {
                log::info!("Audio Decode WebSocket disconnected");
                break;
            }
        };

        // Amperage gate: only documented triggers ("poll" or
        // {"type": "decode_request"}) run a decode cycle; other messages are
        // ignored (logged at debug). One decode cycle in flight per
        // connection; queued polls are collapsed after each cycle.
        let trigger = match &msg {
            Message::Text(t) => is_decode_trigger(t),
            Message::Binary(_) => {
                log::debug!("Audio decode WS: ignoring binary message (no decode trigger)");
                false
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        };
        if !trigger {
            log::debug!("Audio decode WS: ignoring message without decode_request trigger");
            continue;
        }

        let encoded = {
            let last = state
                .last_encoded_audio
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            last.clone()
        };

        let reply = if let Some(ea) = encoded {
            let verify_start = Instant::now();
            let mut samples_copy = ea.samples.clone();
            let buf = AudioBuffer {
                channels: ea.channels,
                sample_rate: ea.sample_rate,
                samples: &mut samples_copy,
                frame_index: ea.chunk_index,
            };

            // Update LSB bits from stored chunk if changed (session-wide
            // audio key from state, matching what the encode side used)
            if ea.lsb_bits != current_lsb_bits || lsb_audio.is_none() {
                current_lsb_bits = ea.lsb_bits;
                lsb_audio = Some(LsbAudio::new(current_lsb_bits, state.audio_key));
                log::info!("Audio decode: LSB bits updated to {}", current_lsb_bits);
            }

            let extracted = lsb_audio.as_ref().unwrap().extract(&buf);

            // Real signature verification against the pre-embed samples the
            // signature covers, using the session-wide keypair's public half.
            let (verified, payload_info) = match extracted {
                Ok(Some(payload)) => {
                    let verified =
                        verify_signature(&state.signer, &payload, &ea.signed_sample_bytes());
                    if verified {
                        state.metrics.record_verify_ok();
                    } else {
                        state.metrics.record_verify_fail();
                    }
                    let hash_hex: String =
                        payload.hash.iter().map(|b| format!("{:02x}", b)).collect();
                    let sig_preview: String = payload
                        .signature
                        .to_bytes()
                        .iter()
                        .take(16)
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    let sig_full: String = payload
                        .signature
                        .to_bytes()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    (
                        verified,
                        serde_json::json!({
                            "payload_found": true,
                            "chunk_index": payload.frame_index,
                            "hash": hash_hex,
                            "signature_preview": sig_preview,
                            "signature_full": sig_full,
                        }),
                    )
                }
                Ok(None) => {
                    state.metrics.record_verify_fail();
                    (
                        false,
                        serde_json::json!({"payload_found": false, "error": "no audio payload found"}),
                    )
                }
                Err(e) => {
                    state.metrics.record_verify_fail();
                    (
                        false,
                        serde_json::json!({"payload_found": false, "error": e.to_string()}),
                    )
                }
            };
            let verify_duration = verify_start.elapsed();
            state.metrics.record_verify_duration(verify_duration);

            let now_ts = {
                let d = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let secs = d.as_secs();
                let s = secs % 60;
                let m = (secs / 60) % 60;
                let h = (secs / 3600) % 24;
                format!("{:02}:{:02}:{:02}.{:03}Z", h, m, s, d.subsec_millis())
            };
            serde_json::json!({
                "type": "audio_verify",
                "verified": verified,
                "payload": payload_info,
                "verify_us": verify_duration.as_micros() as u64,
                "timestamp": now_ts,
                "lsb_bits": current_lsb_bits,
                "backend": state.signing_backend,
                "sample_count": ea.samples.len(),
                "sample_rate": ea.sample_rate,
            })
        } else {
            serde_json::json!({
                "type": "audio_verify",
                "verified": false,
                "waiting": true,
                "backend": state.signing_backend,
            })
        };

        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            log::info!("Audio Decode WebSocket disconnected");
            break;
        }

        // Collapse polls queued while this cycle was in flight; returns
        // true on close.
        if drain_queued(&mut socket).await {
            break;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHARED TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Encoded video frame data stored for cross-WS-handler sharing.
#[derive(Clone)]
pub struct EncodedFrame {
    /// Post-embed pixels: extraction source and displayed image.
    pub rgb_data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub frame_index: u64,
    /// Async verification slot: filled by the bounded verify worker once the
    /// frame's signature has been checked against the pre-embed pixels.
    pub verify: std::sync::Arc<VerifySlot>,
}

/// Encoded audio chunk data stored for cross-WS-handler sharing.
#[derive(Clone)]
pub struct EncodedAudioChunk {
    /// Post-embed samples: extraction source.
    pub samples: Vec<i16>,
    /// Pre-embed samples: exactly what the signature covers; used by the
    /// decode handler for real signature verification.
    pub signed_samples: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u16,
    pub chunk_index: u64,
    pub lsb_bits: u8,
}

impl EncodedAudioChunk {
    /// Little-endian bytes of the pre-embed samples (what the signature
    /// was computed over).
    pub fn signed_sample_bytes(&self) -> Vec<u8> {
        self.signed_samples
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect()
    }
}

/// Base64-encode bytes (standard encoding).
pub(crate) fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Base64-decode a string to bytes.
pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Origin check (CSWSH defense) ─────────────────────────────────────

    fn origin(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    #[test]
    fn origin_absent_is_allowed() {
        assert!(origin_allowed(None, Some(&origin("127.0.0.1:8080"))));
        assert!(origin_allowed(None, None));
    }

    #[test]
    fn origin_same_host_is_allowed() {
        assert!(origin_allowed(
            Some(&origin("http://127.0.0.1:8080")),
            Some(&origin("127.0.0.1:8080"))
        ));
        assert!(origin_allowed(
            Some(&origin("http://myhost.example.com:9999")),
            Some(&origin("myhost.example.com:9999"))
        ));
        // Port-insensitive: reverse proxies commonly rewrite ports.
        assert!(origin_allowed(
            Some(&origin("http://myhost.example.com:3000")),
            Some(&origin("myhost.example.com:8080"))
        ));
    }

    #[test]
    fn origin_loopback_is_allowed() {
        for o in [
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://[::1]:4200",
            "https://localhost",
        ] {
            assert!(
                origin_allowed(Some(&origin(o)), Some(&origin("10.0.0.5:8080"))),
                "loopback origin {o} must be accepted"
            );
        }
    }

    #[test]
    fn origin_cross_site_is_rejected() {
        assert!(!origin_allowed(
            Some(&origin("http://evil.example.com")),
            Some(&origin("127.0.0.1:8080"))
        ));
        assert!(!origin_allowed(
            Some(&origin("http://127.0.0.1.evil.com")),
            Some(&origin("127.0.0.1:8080"))
        ));
        assert!(!origin_allowed(Some(&origin("http://evil.com")), None));
    }

    #[test]
    fn authority_host_strips_ports_and_brackets() {
        assert_eq!(authority_host("127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(authority_host("[::1]:8080"), "::1");
        assert_eq!(authority_host("[::1]"), "::1");
        assert_eq!(authority_host("localhost"), "localhost");
        assert_eq!(authority_host("Example.COM"), "example.com");
    }

    // ─── Poll gating (decode amperage) ────────────────────────────────────

    #[test]
    fn decode_triggers_match_documented_protocol() {
        assert!(is_decode_trigger("poll"));
        assert!(is_decode_trigger(" poll "));
        assert!(is_decode_trigger(r#"{"type": "decode_request"}"#));
        assert!(!is_decode_trigger(""));
        assert!(!is_decode_trigger("hello"));
        assert!(!is_decode_trigger(r#"{"type": "other"}"#));
        assert!(!is_decode_trigger("not json"));
    }

    // ─── Query token parsing ──────────────────────────────────────────────

    #[test]
    fn query_token_parses_and_percent_decodes() {
        assert_eq!(
            query_token(Some("token=abc123")),
            Some("abc123".to_string())
        );
        assert_eq!(
            query_token(Some("a=1&token=ab%20cd")),
            Some("ab cd".to_string())
        );
        assert_eq!(query_token(Some("other=x&token=t")), Some("t".to_string()));
        assert_eq!(query_token(Some("other=x")), None);
        assert_eq!(query_token(None), None);
    }

    // ─── Tamper detection (real signature verification) ───────────────────

    /// Mirrors the encode → store → decode wiring: the payload is signed over
    /// pre-embed bytes, embedded into the frame, extracted again, and
    /// verified against the stored pre-embed bytes. Tampering with those
    /// stored bytes MUST yield verified=false.
    #[test]
    fn tampered_frame_fails_verification() {
        let signer = Signer::generate();
        let original: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let payload = signer.sign_frame(7, &original, None);

        // Embed exactly like handle_encode_socket does.
        let mut data = original.clone();
        let mut frame = VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 7,
        };
        let mut lsb = LsbVideo::new(1);
        lsb.embed(&mut frame, Some(&payload)).unwrap();

        // Extract exactly like handle_decode_socket does (from post-embed).
        let mut extract_data = data.clone();
        let extract_frame = VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format: VideoFormat::Rgb8,
            data: &mut extract_data,
            frame_index: 7,
        };
        let extracted = lsb
            .extract(&extract_frame)
            .unwrap()
            .expect("payload extracts");

        // Untampered stored pre-embed bytes verify.
        assert!(verify_signature(&signer, &extracted, &original));

        // Tampering one pixel byte of the signed data must flip to false.
        let mut tampered = original.clone();
        tampered[2048] ^= 0x40;
        assert!(!verify_signature(&signer, &extracted, &tampered));

        // The post-embed frame still extracts the same payload even though
        // its LSBs differ from the signed snapshot (why the decode handlers
        // verify against the stored pre-embed bytes).
        let _ = extract_frame;
    }

    // ─── Asynchronous verification (bounded worker, drop-oldest) ──────────

    fn dummy_job(frame_index: u64) -> VerifyJob {
        VerifyJob {
            frame_index,
            signed_rgb: Vec::new(),
            rgb_data: Vec::new(),
            width: 1,
            height: 1,
            lsb_bits: 1,
            verify_key: [0u8; 32],
            metrics: Arc::new(steganographer_core::StegoMetrics::new()),
            slot: Arc::new(VerifySlot::default()),
        }
    }

    /// Bounded verify queue: capacity 4, drop-OLDEST when full.
    #[test]
    fn verify_queue_drops_oldest_under_backpressure() {
        let mut q = VecDeque::new();
        for i in 0u64..7 {
            let dropped = queue_push(&mut q, dummy_job(i), VERIFY_QUEUE_CAP);
            if i < 4 {
                assert!(!dropped, "first 4 pushes must not drop");
            } else {
                assert!(dropped, "push {i} must evict the oldest job");
            }
        }
        assert_eq!(q.len(), VERIFY_QUEUE_CAP, "queue must stay bounded");
        assert_eq!(
            q.front().unwrap().frame_index,
            3,
            "frames 0-2 dropped first"
        );
        assert_eq!(q.back().unwrap().frame_index, 6, "newest frame always kept");
    }

    /// End-to-end async verification: sign + embed (the encode critical
    /// path), enqueue for the worker, and observe the published outcome —
    /// REAL Ed25519 verification of an actually-embedded frame.
    #[tokio::test]
    async fn async_verify_worker_publishes_outcome() {
        let signer = Signer::generate();
        let original: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let payload = signer.sign_frame(3, &original, None);

        let mut data = original.clone();
        let mut frame = VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 3,
        };
        LsbVideo::new(1).embed(&mut frame, Some(&payload)).unwrap();

        let slot = Arc::new(VerifySlot::default());
        enqueue_verify(VerifyJob {
            frame_index: 3,
            signed_rgb: original,
            rgb_data: data,
            width: 64,
            height: 64,
            lsb_bits: 1,
            verify_key: signer.verifying_key().to_bytes(),
            metrics: Arc::new(steganographer_core::StegoMetrics::new()),
            slot: slot.clone(),
        });

        // The worker runs off-thread; poll the slot like the decode-poll
        // path does (bounded wait, then stale).
        let outcome = slot
            .wait_for(3, std::time::Duration::from_secs(10))
            .expect("worker must publish the verification outcome");
        assert!(outcome.verified, "embedded frame must verify");
        assert!(outcome.payload_info.is_some());
        assert_eq!(
            outcome.payload_info.unwrap()["payload_found"],
            serde_json::json!(true)
        );
    }
}
