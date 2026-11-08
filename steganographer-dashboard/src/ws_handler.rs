//! WebSocket handlers for streaming encoded/decoded video and audio frames.
//!
//! Channels:
//! - `/ws/encode` — bounded JPEG input, canonical LSB binding, lossless signed PNG output.
//! - `/ws/decode` — reports verification of the latest delivered PNG carrier.
//!   This server-wide cache is not a claim of capture liveness or tenant isolation.
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
/// allocation for JPEG/PNG frames and PCM chunks. Also reused as the data-channel
/// message cap on the WebRTC transport.
pub(crate) const WS_MAX_MESSAGE_SIZE: usize = 1 << 22;
/// Browsers send PNG images in one frame; bound frames by the same message budget.
pub(crate) const WS_MAX_FRAME_SIZE: usize = WS_MAX_MESSAGE_SIZE;
/// Maximum image dimension accepted for client-supplied JPEG/PNG frames —
/// guards against decompression bombs (a few MB can decode to
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
pub(crate) fn origin_allowed(origin: Option<&HeaderValue>, host: Option<&HeaderValue>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let authority = match origin.split_once("://") {
        Some(("http" | "https", rest)) if !rest.contains(['/', '?', '#', '@']) => rest,
        _ => return false,
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
    let outcome = state
        .ots_outcome
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    serde_json::json!({
        "ots_proofs_count": state.metrics.ots_proofs_generated(),
        "ots_last_timestamp": state.metrics.ots_last_timestamp(),
        "ots_verified": outcome.as_ref().and_then(|o| o.get("verified")),
        "ots_pending": outcome.as_ref().and_then(|o| o.get("pending")),
        "ots_outcome": outcome,
    })
}

// Both transports use this single bounded, lossless carrier pipeline.
const VERIFY_QUEUE_CAP: usize = 4;
const MAX_REPLY_MEDIA_BYTES: usize = 3 * 1024 * 1024 - 4096;
static CACHE_REVISION: AtomicU64 = AtomicU64::new(0);
static SOCKET_ADMISSION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
static ENCODE_ADMISSION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

pub struct EncodeSession {
    frame_counter: u64,
}

impl EncodeSession {
    pub fn new() -> Self {
        Self { frame_counter: 0 }
    }
}

impl Default for EncodeSession {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct DecodeSession;

impl DecodeSession {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Clone)]
struct VerifyOutcome {
    verified: bool,
    payload_info: serde_json::Value,
    verify_us: u64,
}

#[derive(Default)]
pub struct VerifySlot {
    latest: std::sync::Mutex<Option<VerifyOutcome>>,
    notify: tokio::sync::Notify,
    dropped: std::sync::atomic::AtomicBool,
}

impl VerifySlot {
    async fn wait_for(&self, timeout: std::time::Duration) -> Option<VerifyOutcome> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Register before inspecting the slot, avoiding a lost notification.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(outcome) = self
                .latest
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                return Some(outcome);
            }
            if self.dropped.load(Ordering::Acquire) {
                return None;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }

    fn publish(&self, outcome: VerifyOutcome) {
        *self.latest.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
        self.notify.notify_waiters();
    }
}

#[derive(Clone)]
pub struct EncodedFrame {
    pub rgb_data: Arc<[u8]>,
    pub png_data: Arc<[u8]>,
    pub width: u32,
    pub height: u32,
    pub frame_index: u64,
    pub revision: u64,
    pub lsb_bits: u8,
    pub commitment: [u8; 32],
    pub verify: Arc<VerifySlot>,
}

#[derive(Clone)]
pub struct EncodedAudioChunk {
    pub samples: Arc<[i16]>,
    pub pcm_s16le: Arc<[u8]>,
    pub sample_rate: u32,
    pub channels: u16,
    pub chunk_index: u64,
    pub revision: u64,
    pub lsb_bits: u8,
    pub commitment: [u8; 32],
    pub verify: Arc<VerifySlot>,
}

fn payload_json(payload: &steganographer_core::SignaturePayload) -> serde_json::Value {
    use steganographer_core::crypto::encode_hex;
    let signature = payload.signature.to_bytes();
    serde_json::json!({
        "payload_found": true, "frame_index": payload.frame_index,
        "chunk_index": payload.frame_index,
        "hash": encode_hex(&payload.hash),
        "signature_preview": encode_hex(&signature[..16]),
        "signature_full": encode_hex(&signature),
    })
}

fn commitment(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

fn public_key(state: &DashboardState) -> String {
    steganographer_core::crypto::encode_hex(&state.signer.verifying_key().to_bytes())
}

struct VerifyJob {
    frame: EncodedFrame,
    verify_key: [u8; 32],
    metrics: Arc<steganographer_core::StegoMetrics>,
}

fn run_verify(job: VerifyJob) {
    let start = Instant::now();
    let ef = job.frame;
    let result = (|| -> anyhow::Result<(bool, serde_json::Value)> {
        steganographer_core::revocation::check_known_revocations(&job.verify_key)?;
        anyhow::ensure!(
            ef.png_data.len() <= MAX_REPLY_MEDIA_BYTES,
            "PNG exceeds media budget"
        );
        let mut reader =
            ImageReader::with_format(Cursor::new(ef.png_data.as_ref()), ImageFormat::Png);
        let mut limits = Limits::default();
        limits.max_image_width = Some(IMAGE_MAX_DIMENSION);
        limits.max_image_height = Some(IMAGE_MAX_DIMENSION);
        limits.max_alloc = Some(64 * 1024 * 1024);
        reader.limits(limits);
        // Decode the exact delivered artifact, not a private RGB reference.
        let image = reader.decode()?.to_rgb8();
        anyhow::ensure!(
            image.dimensions() == (ef.width, ef.height),
            "PNG dimensions changed"
        );
        let mut data = image.into_raw();
        let frame = VideoFrame {
            width: ef.width,
            height: ef.height,
            stride: ef.width * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: ef.frame_index,
        };
        let payload = LsbVideo::new(ef.lsb_bits)
            .extract(&frame)?
            .ok_or_else(|| anyhow::anyhow!("no payload in delivered PNG"))?;
        let canonical = steganographer_core::carrier_binding::canonicalize(
            &data,
            "lsb_video",
            ef.lsb_bits,
            ef.width,
            ef.height,
            steganographer_core::SignaturePayload::SERIALIZED_SIZE,
        )?;
        let verified = payload.frame_index == ef.frame_index
            && Verifier::from_bytes(&job.verify_key)?.verify(&payload, &canonical, None);
        Ok((verified, payload_json(&payload)))
    })();
    let (verified, payload_info) = result.unwrap_or_else(|error| {
        (
            false,
            serde_json::json!({"payload_found": false, "error": error.to_string()}),
        )
    });
    job.metrics.record_verify_duration(start.elapsed());
    if verified {
        job.metrics.record_verify_ok();
    } else {
        job.metrics.record_verify_fail();
    }
    ef.verify.publish(VerifyOutcome {
        verified,
        payload_info,
        verify_us: start.elapsed().as_micros() as u64,
    });
}

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
    std::thread::Builder::new()
        .name("frame-verify-worker".into())
        .spawn(move || loop {
            let job = {
                let mut queue = worker.queue.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if let Some(job) = queue.pop_front() {
                        break job;
                    }
                    queue = worker.cv.wait(queue).unwrap_or_else(|e| e.into_inner());
                }
            };
            run_verify(job);
        })
        .expect("start bounded frame verification worker");
    engine
});

fn push_verify(queue: &mut VecDeque<VerifyJob>, job: VerifyJob) {
    if queue.len() >= VERIFY_QUEUE_CAP {
        if let Some(old) = queue.pop_front() {
            old.frame.verify.dropped.store(true, Ordering::Release);
            old.frame.verify.notify.notify_waiters();
        }
    }
    queue.push_back(job);
}

fn enqueue_verify(job: VerifyJob) {
    let engine = &*VERIFY_ENGINE;
    let mut queue = engine.queue.lock().unwrap_or_else(|e| e.into_inner());
    push_verify(&mut queue, job);
    engine.cv.notify_one();
}

/// Decode bounded JPEG/PNG input, sign its canonical carrier and deliver lossless PNG.
/// Both transports call this exact implementation; unsupported configuration fails closed.
pub fn process_encode_frame(
    state: &DashboardState,
    session: &mut EncodeSession,
    jpeg_bytes: &[u8],
) -> Option<serde_json::Value> {
    if steganographer_core::revocation::is_known_compromised_key(
        state.signer.verifying_key().as_bytes(),
    ) {
        return None;
    }
    let _admission = ENCODE_ADMISSION.try_acquire().ok()?;
    if jpeg_bytes.is_empty() || jpeg_bytes.len() > WS_MAX_MESSAGE_SIZE {
        return None;
    }
    let cfg = state
        .live_config
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    super::validate_live_config(&cfg).ok()?;
    if state.signer.hash_algorithm().name() != "blake3" {
        return None;
    }
    let mut reader = ImageReader::new(Cursor::new(jpeg_bytes))
        .with_guessed_format()
        .ok()?;
    if !matches!(reader.format(), Some(ImageFormat::Jpeg | ImageFormat::Png)) {
        return None;
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(IMAGE_MAX_DIMENSION);
    limits.max_image_height = Some(IMAGE_MAX_DIMENSION);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().ok()?.to_rgb8();
    let (width, height) = image.dimensions();
    let mut data = image.into_raw();
    let canonical = steganographer_core::carrier_binding::canonicalize(
        &data,
        "lsb_video",
        cfg.lsb_bits,
        width,
        height,
        steganographer_core::SignaturePayload::SERIALIZED_SIZE,
    )
    .ok()?;
    let frame_index = session.frame_counter;
    session.frame_counter = session.frame_counter.checked_add(1)?;
    let sign_start = Instant::now();
    let payload = state.signer.sign_frame(frame_index, &canonical, None);
    let sign_duration = sign_start.elapsed();
    drop(canonical);
    let embed_start = Instant::now();
    LsbVideo::new(cfg.lsb_bits)
        .embed(
            &mut VideoFrame {
                width,
                height,
                stride: width * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index,
            },
            Some(&payload),
        )
        .ok()?;
    let embed_duration = embed_start.elapsed();
    let mut png = Cursor::new(Vec::new());
    // Borrow the delivered pixels; do not keep a pre-embed reference.
    use image::ImageEncoder;
    image::codecs::png::PngEncoder::new(&mut png)
        .write_image(&data, width, height, image::ExtendedColorType::Rgb8)
        .ok()?;
    let png = png.into_inner();
    if png.len() > MAX_REPLY_MEDIA_BYTES {
        return None;
    }
    let digest = commitment(&png);
    let mut reply = serde_json::json!({
        "type": "encoded_frame", "frame": base64_encode(&png), "image_mime": "image/png",
        "width": width, "height": height, "frame_index": frame_index, "lsb_bits": cfg.lsb_bits,
        "public_key": public_key(state), "identity": public_key(state), "backend": "ed25519",
        "hash_algorithm": "blake3", "payload": payload_json(&payload),
        "media_digest": steganographer_core::crypto::encode_hex(&digest),
        "sign_us": sign_duration.as_micros() as u64, "embed_us": embed_duration.as_micros() as u64,
        "data": serde_json::from_str::<serde_json::Value>(&state.metrics.to_json()).unwrap_or_default(),
        "ots": ots_metrics_json(state),
    });
    let mut last = state
        .last_encoded_frame
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let frame = EncodedFrame {
        rgb_data: data.into(),
        png_data: png.into(),
        width,
        height,
        frame_index,
        revision: CACHE_REVISION.fetch_add(1, Ordering::SeqCst) + 1,
        lsb_bits: cfg.lsb_bits,
        commitment: digest,
        verify: Arc::new(VerifySlot::default()),
    };
    reply["cache_revision"] = serde_json::json!(frame.revision);
    *last = Some(frame.clone());
    drop(last);
    enqueue_verify(VerifyJob {
        frame,
        verify_key: state.signer.verifying_key().to_bytes(),
        metrics: state.metrics.clone(),
    });
    state.metrics.record_sign_duration(sign_duration);
    state.metrics.record_embed_duration(embed_duration);
    state.metrics.record_frame();
    Some(reply)
}

pub async fn process_decode_poll(
    state: &DashboardState,
    _session: &mut DecodeSession,
) -> serde_json::Value {
    let frame = state
        .last_encoded_frame
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let Some(frame) = frame else {
        return serde_json::json!({"type": "verify_status", "waiting": true, "backend": "ed25519"});
    };
    let outcome = frame
        .verify
        .wait_for(std::time::Duration::from_secs(1))
        .await;
    serde_json::json!({
        "type": "decoded_frame", "frame": base64_encode(&frame.png_data), "image_mime": "image/png",
        "width": frame.width, "height": frame.height, "frame_index": frame.frame_index,
        "cache_revision": frame.revision, "lsb_bits": frame.lsb_bits,
        "public_key": public_key(state), "identity": public_key(state), "backend": "ed25519",
        "verified": outcome.as_ref().is_some_and(|o| o.verified), "verified_stale": outcome.is_none(),
        "payload": outcome.as_ref().map(|o| o.payload_info.clone()).unwrap_or_else(|| serde_json::json!({
            "payload_found": false, "stale": true, "error": "verification pending or evicted"
        })),
        "verify_us": outcome.as_ref().map(|o| o.verify_us).unwrap_or(0),
        "media_digest": steganographer_core::crypto::encode_hex(&frame.commitment),
        "data": serde_json::from_str::<serde_json::Value>(&state.metrics.to_json()).unwrap_or_default(),
        "ots": ots_metrics_json(state),
    })
}

/// Authenticate canonical signed bytes, including known-compromise policy.
pub fn verify_signature(
    signer: &Signer,
    payload: &steganographer_core::SignaturePayload,
    canonical: &[u8],
) -> bool {
    if steganographer_core::revocation::is_known_compromised_key(signer.verifying_key().as_bytes())
    {
        return false;
    }
    Verifier::new(signer.verifying_key()).verify(payload, canonical, None)
}

#[derive(Clone, Copy)]
enum SocketKind {
    VideoEncode,
    VideoDecode,
    AudioEncode,
    AudioDecode,
}

async fn upgrade(
    state: Arc<DashboardState>,
    req: axum::extract::Request,
    kind: SocketKind,
) -> Response {
    let headers = req.headers().clone();
    if let Err(response) = ws_gate(&headers, req.uri().query(), &state) {
        return response;
    }
    let permit = match SOCKET_ADMISSION.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let ws = match ws_extract(req).await {
        Ok(ws) => ws,
        Err(response) => return response,
    };
    ws_configure(ws, &headers, &state).on_upgrade(move |socket| async move {
        let _permit = permit;
        handle_socket(socket, state, kind).await;
    })
}

pub async fn ws_encode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    upgrade(state, req, SocketKind::VideoEncode).await
}
pub async fn ws_decode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    upgrade(state, req, SocketKind::VideoDecode).await
}
pub async fn ws_audio_encode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    upgrade(state, req, SocketKind::AudioEncode).await
}
pub async fn ws_audio_decode_handler(
    State(state): State<Arc<DashboardState>>,
    req: axum::extract::Request,
) -> Response {
    upgrade(state, req, SocketKind::AudioDecode).await
}

fn is_decode_trigger(text: &str) -> bool {
    text.trim() == "poll"
        || serde_json::from_str::<serde_json::Value>(text)
            .is_ok_and(|v| v["type"] == "decode_request")
}

async fn handle_socket(mut socket: WebSocket, state: Arc<DashboardState>, kind: SocketKind) {
    let mut encode = EncodeSession::new();
    let mut decode = DecodeSession::new();
    loop {
        let message =
            match tokio::time::timeout(std::time::Duration::from_secs(60), socket.recv()).await {
                Ok(Some(Ok(message))) => message,
                _ => break,
            };
        let reply = match (kind, message) {
            (_, Message::Close(_)) => break,
            (_, Message::Ping(_) | Message::Pong(_)) => continue,
            (SocketKind::VideoEncode, Message::Binary(bytes)) => {
                let state = state.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let reply = process_encode_frame(&state, &mut encode, &bytes);
                    (encode, reply)
                })
                .await;
                let Ok((session, reply)) = result else { break };
                encode = session;
                reply.unwrap_or_else(|| serde_json::json!({"type":"encode_error", "message":"invalid, oversized, unsupported or busy frame"}))
            }
            (SocketKind::VideoEncode, Message::Text(text)) if text.contains("ping") => {
                serde_json::json!({"type": "metrics", "backend": "ed25519", "identity": public_key(&state),
                    "data": serde_json::from_str::<serde_json::Value>(&state.metrics.to_json()).unwrap_or_default(),
                    "ots": ots_metrics_json(&state)})
            }
            (SocketKind::VideoDecode, Message::Text(text)) if is_decode_trigger(&text) => {
                process_decode_poll(&state, &mut decode).await
            }
            (SocketKind::AudioEncode, Message::Text(text)) => {
                let state = state.clone();
                let index = encode.frame_counter;
                encode.frame_counter = match index.checked_add(1) {
                    Some(next) => next,
                    None => break,
                };
                match tokio::task::spawn_blocking(move || process_audio_frame(&state, index, &text))
                    .await
                {
                    Ok(Ok(reply)) => reply,
                    Ok(Err(message)) => serde_json::json!({"type":"error", "message":message}),
                    Err(_) => break,
                }
            }
            (SocketKind::AudioDecode, Message::Text(text)) if is_decode_trigger(&text) => {
                process_audio_poll(&state).await
            }
            _ => continue,
        };
        // A slow receiver cannot retain an unbounded list of replies.
        if !matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.send(Message::Text(reply.to_string().into()))
            )
            .await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        socket.send(Message::Close(None)),
    )
    .await;
}

fn process_audio_frame(
    state: &DashboardState,
    index: u64,
    text: &str,
) -> Result<serde_json::Value, String> {
    steganographer_core::revocation::check_known_revocations(
        state.signer.verifying_key().as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let _admission = ENCODE_ADMISSION.try_acquire().map_err(|_| "encoder busy")?;
    if text.len() > WS_MAX_MESSAGE_SIZE {
        return Err("audio message too large".into());
    }
    let cfg = state
        .live_config
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    super::validate_live_config(&cfg)?;
    if state.signer.hash_algorithm().name() != "blake3" {
        return Err("unsupported signer hash algorithm".into());
    }
    let request: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "invalid audio JSON")?;
    if request["type"] != "audio_frame" {
        return Err("expected audio_frame".into());
    }
    // Check the original integers before narrowing; never wrap untrusted values.
    let sample_rate = request
        .get("sample_rate")
        .map_or(Some(44100), |v| v.as_u64())
        .ok_or("invalid sample_rate")?;
    let channels = request
        .get("channels")
        .map_or(Some(1), |v| v.as_u64())
        .ok_or("invalid channels")?;
    let bits = request
        .get("lsb_bits")
        .map_or(Some(cfg.lsb_bits as u64), |v| v.as_u64())
        .ok_or("invalid lsb_bits")?;
    if !(1..=AUDIO_MAX_SAMPLE_RATE as u64).contains(&sample_rate) {
        return Err("sample_rate out of range".into());
    }
    if !(1..=2).contains(&channels) {
        return Err("channels must be 1-2".into());
    }
    if !(1..=4).contains(&bits) {
        return Err("lsb_bits must be 1-4".into());
    }
    let bytes = base64_decode(request["pcm_base64"].as_str().ok_or("missing pcm_base64")?)
        .map_err(|_| "invalid PCM base64")?;
    if bytes.is_empty()
        || bytes.len() > MAX_REPLY_MEDIA_BYTES
        || bytes.len() % (2 * channels as usize) != 0
        || bytes.len() as u64 / 2 > AUDIO_MAX_DURATION_SECS * sample_rate * channels
    {
        return Err("invalid or oversized PCM chunk".into());
    }
    let bits = bits as u8;
    let canonical = steganographer_core::carrier_binding::canonicalize(
        &bytes,
        "lsb_audio",
        bits,
        0,
        0,
        steganographer_core::SignaturePayload::SERIALIZED_SIZE,
    )
    .map_err(|e| e.to_string())?;
    let start = Instant::now();
    let payload = state.signer.sign_frame(index, &canonical, None);
    let sign_duration = start.elapsed();
    let mut samples: Vec<i16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect();
    let start = Instant::now();
    let mut lsb = LsbAudio::new(bits, state.audio_key);
    lsb.embed(
        &mut AudioBuffer {
            channels: channels as u16,
            sample_rate: sample_rate as u32,
            samples: &mut samples,
            frame_index: index,
        },
        Some(&payload),
    )
    .map_err(|e| e.to_string())?;
    let embed_duration = start.elapsed();
    let pcm: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
    // Verify the actual returned PCM with the public key, never the original samples.
    let start = Instant::now();
    let extracted = lsb
        .extract(&AudioBuffer {
            channels: channels as u16,
            sample_rate: sample_rate as u32,
            samples: &mut samples,
            frame_index: index,
        })
        .map_err(|e| e.to_string())?
        .ok_or("no payload in embedded PCM")?;
    let actual = steganographer_core::carrier_binding::canonicalize(
        &pcm,
        "lsb_audio",
        bits,
        0,
        0,
        steganographer_core::SignaturePayload::SERIALIZED_SIZE,
    )
    .map_err(|e| e.to_string())?;
    let verified = Verifier::new(state.signer.verifying_key()).verify(&extracted, &actual, None)
        && extracted.frame_index == index;
    let verify_duration = start.elapsed();
    if !verified {
        return Err("post-embed audio verification failed".into());
    }
    let slot = Arc::new(VerifySlot::default());
    slot.publish(VerifyOutcome {
        verified,
        payload_info: payload_json(&extracted),
        verify_us: verify_duration.as_micros() as u64,
    });
    let digest = commitment(&pcm);
    let mut reply = serde_json::json!({
        "type":"audio_signed", "chunk_index":index, "frame_index":index,
        "pcm_s16le":base64_encode(&pcm), "sample_rate":sample_rate, "channels":channels,
        "sample_count":samples.len(), "lsb_bits":bits,
        "embedding_key":steganographer_core::crypto::encode_hex(&state.audio_key),
        "public_key":public_key(state), "identity":public_key(state), "backend":"ed25519",
        "payload":payload_json(&extracted), "verified":verified,
        "media_digest":steganographer_core::crypto::encode_hex(&digest),
        "sign_us":sign_duration.as_micros() as u64, "embed_us":embed_duration.as_micros() as u64,
    });
    let mut last = state
        .last_encoded_audio
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let revision = CACHE_REVISION.fetch_add(1, Ordering::SeqCst) + 1;
    reply["cache_revision"] = serde_json::json!(revision);
    *last = Some(EncodedAudioChunk {
        samples: samples.into(),
        pcm_s16le: pcm.into(),
        sample_rate: sample_rate as u32,
        channels: channels as u16,
        chunk_index: index,
        lsb_bits: bits,
        commitment: digest,
        revision,
        verify: slot,
    });
    state.metrics.record_sign_duration(sign_duration);
    state.metrics.record_embed_duration(embed_duration);
    state.metrics.record_verify_duration(verify_duration);
    state.metrics.record_verify_ok();
    state.metrics.record_frame();
    Ok(reply)
}

async fn process_audio_poll(state: &DashboardState) -> serde_json::Value {
    let chunk = state
        .last_encoded_audio
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let Some(chunk) = chunk else {
        return serde_json::json!({"type":"audio_verify", "waiting":true, "verified":false});
    };
    let outcome = chunk
        .verify
        .wait_for(std::time::Duration::from_secs(1))
        .await;
    serde_json::json!({
        "type":"audio_verify", "frame_index":chunk.chunk_index, "chunk_index":chunk.chunk_index,
        "cache_revision":chunk.revision,
        "verified":outcome.as_ref().is_some_and(|o| o.verified), "verified_stale":outcome.is_none(),
        "payload":outcome.as_ref().map(|o| o.payload_info.clone()),
        "verify_us":outcome.as_ref().map(|o| o.verify_us),
        "lsb_bits":chunk.lsb_bits, "sample_rate":chunk.sample_rate, "channels":chunk.channels,
        "sample_count":chunk.samples.len(), "public_key":public_key(state), "backend":"ed25519",
    })
}

/// Latest delivered signed artifact's SHA-256, not an elapsed-time surrogate.
pub(crate) fn latest_media_digest(state: &DashboardState) -> Option<[u8; 32]> {
    let video = state
        .last_encoded_frame
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let audio = state
        .last_encoded_audio
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match (video.as_ref(), audio.as_ref()) {
        (Some(v), Some(a)) => Some(if v.revision > a.revision {
            v.commitment
        } else {
            a.commitment
        }),
        (Some(v), None) => Some(v.commitment),
        (None, Some(a)) => Some(a.commitment),
        (None, None) => None,
    }
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use steganographer_core::carrier_binding::canonicalize;
    use steganographer_core::crypto::decode_hex;

    fn state() -> DashboardState {
        DashboardState {
            metrics: Arc::new(steganographer_core::StegoMetrics::new()),
            signing_backend: "not-the-signer".into(),
            identity: "not-the-key".into(),
            width: 64,
            height: 64,
            last_encoded_frame: std::sync::Mutex::new(None),
            last_encoded_audio: std::sync::Mutex::new(None),
            live_config: std::sync::Mutex::new(super::super::LiveConfig::default()),
            session_start: Instant::now(),
            auth_token: None,
            ots_config: steganographer_core::OtsConfig::default(),
            ots_client: None,
            ots_outcome: std::sync::Mutex::new(None),
            signer: Signer::generate(),
            audio_key: [37; 32],
            transport: super::super::TransportPolicy::Auto,
            #[cfg(feature = "webrtc")]
            webrtc_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            #[cfg(feature = "webrtc")]
            ice_servers: Vec::new(),
            #[cfg(feature = "webrtc")]
            media_publishers: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn audio_reply(state: &DashboardState, index: u64) -> serde_json::Value {
        let pcm: Vec<u8> = (0..8192i16)
            .flat_map(|s| s.wrapping_mul(7).to_le_bytes())
            .collect();
        process_audio_frame(
            state,
            index,
            &serde_json::json!({
                "type":"audio_frame", "sample_rate":48000, "channels":2, "lsb_bits":2,
                "pcm_base64":base64_encode(&pcm),
            })
            .to_string(),
        )
        .unwrap()
    }

    // The only inputs to this verifier are public reply fields. No server snapshot/keypair.
    fn verify_returned_pcm(reply: &serde_json::Value, pcm: &[u8]) -> bool {
        let key: [u8; 32] = decode_hex(reply["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let embedding_key: [u8; 32] = decode_hex(reply["embedding_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let index = reply["frame_index"].as_u64().unwrap();
        let bits = reply["lsb_bits"].as_u64().unwrap() as u8;
        let mut samples: Vec<i16> = pcm
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes([b[0], b[1]]))
            .collect();
        let payload = LsbAudio::new(bits, embedding_key)
            .extract(&AudioBuffer {
                samples: &mut samples,
                channels: reply["channels"].as_u64().unwrap() as u16,
                sample_rate: reply["sample_rate"].as_u64().unwrap() as u32,
                frame_index: index,
            })
            .unwrap()
            .unwrap();
        let canonical = canonicalize(
            pcm,
            "lsb_audio",
            bits,
            0,
            0,
            steganographer_core::SignaturePayload::SERIALIZED_SIZE,
        )
        .unwrap();
        payload.frame_index == index
            && Verifier::from_bytes(&key)
                .unwrap()
                .verify(&payload, &canonical, None)
    }

    #[tokio::test]
    async fn returned_pcm_is_independently_verifiable_and_high_bit_tamper_fails() {
        let state = state();
        let reply = audio_reply(&state, 17);
        assert_eq!(state.metrics.frames_processed(), 1);
        assert_eq!(state.metrics.frames_verified_ok(), 1);
        assert_eq!(
            state.metrics.avg_sign_latency_us(),
            reply["sign_us"].as_u64().unwrap() as f64
        );
        let pcm = base64_decode(reply["pcm_s16le"].as_str().unwrap()).unwrap();
        assert!(verify_returned_pcm(&reply, &pcm));
        let mut tampered = pcm;
        tampered[8192] ^= 0x40;
        assert!(!verify_returned_pcm(&reply, &tampered));
        assert_eq!(
            reply["media_digest"],
            steganographer_core::crypto::encode_hex(&latest_media_digest(&state).unwrap())
        );
        let before = state.metrics.frames_verified_ok();
        let first = process_audio_poll(&state).await;
        let second = process_audio_poll(&state).await;
        assert_eq!(first["frame_index"], 17);
        assert_eq!(first, second);
        assert_eq!(
            before,
            state.metrics.frames_verified_ok(),
            "polls must not count the same chunk again"
        );
        assert_eq!(state.metrics.frames_processed(), 1);
        assert!(process_audio_frame(&state, 18, r#"{"type":"audio_frame"}"#).is_err());
        assert_eq!(state.metrics.frames_processed(), 1);
        assert_eq!(
            process_audio_poll(&state).await["cache_revision"],
            reply["cache_revision"]
        );
        audio_reply(&state, 18);
        assert_eq!(state.metrics.frames_processed(), 2);
        assert_eq!(state.metrics.frames_verified_ok(), 2);
    }

    #[test]
    fn audio_rejects_narrowing_wrap_odd_pcm_and_unsupported_configuration() {
        let state = state();
        let base = serde_json::json!({"type":"audio_frame","pcm_base64":base64_encode(&[0;4096])});
        for (field, value) in [
            ("lsb_bits", 257u64),
            ("channels", 65537),
            ("sample_rate", 4295011396),
            ("lsb_bits", 0),
        ] {
            let mut request = base.clone();
            request[field] = serde_json::json!(value);
            assert!(process_audio_frame(&state, 0, &request.to_string()).is_err());
        }
        let mut request = base;
        request["pcm_base64"] = serde_json::json!(base64_encode(&[0; 4095]));
        assert!(process_audio_frame(&state, 0, &request.to_string()).is_err());
        state.live_config.lock().unwrap().encrypt = true;
        assert!(process_audio_frame(&state, 0, &request.to_string()).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_verification_wait_yields_and_notification_is_not_lost() {
        let slot = Arc::new(VerifySlot::default());
        let writer = slot.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            writer.publish(VerifyOutcome {
                verified: true,
                payload_info: serde_json::json!({}),
                verify_us: 1,
            });
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            slot.wait_for(std::time::Duration::from_secs(1)),
        )
        .await
        .unwrap()
        .unwrap();
        task.await.unwrap();
        assert!(result.verified);
        slot.dropped.store(true, Ordering::Release);
        assert!(slot.wait_for(std::time::Duration::ZERO).await.is_some());
    }

    #[tokio::test]
    async fn verifier_checks_delivered_png_even_when_cached_rgb_reference_is_unchanged() {
        let signer = Signer::generate();
        let mut data: Vec<u8> = (0..64 * 64 * 3).map(|i| (i % 251) as u8).collect();
        let canonical = canonicalize(
            &data,
            "lsb_video",
            1,
            64,
            64,
            steganographer_core::SignaturePayload::SERIALIZED_SIZE,
        )
        .unwrap();
        let payload = signer.sign_frame(7, &canonical, None);
        LsbVideo::new(1)
            .embed(
                &mut VideoFrame {
                    width: 64,
                    height: 64,
                    stride: 192,
                    format: VideoFormat::Rgb8,
                    data: &mut data,
                    frame_index: 7,
                },
                Some(&payload),
            )
            .unwrap();
        let mut image = image::RgbImage::from_raw(64, 64, data).unwrap();
        let mut png = Cursor::new(Vec::new());
        image.write_to(&mut png, ImageFormat::Png).unwrap();
        let mut frame = EncodedFrame {
            rgb_data: vec![255; 3].into(),
            png_data: png.into_inner().into(),
            width: 64,
            height: 64,
            frame_index: 7,
            revision: 1,
            lsb_bits: 1,
            commitment: [0; 32],
            verify: Arc::new(VerifySlot::default()),
        };
        let run = |frame| {
            run_verify(VerifyJob {
                frame,
                verify_key: signer.verifying_key().to_bytes(),
                metrics: Arc::new(steganographer_core::StegoMetrics::new()),
            })
        };
        run(frame.clone());
        assert!(
            frame
                .verify
                .wait_for(std::time::Duration::ZERO)
                .await
                .unwrap()
                .verified
        );
        image.as_mut()[2048] ^= 0x40;
        let mut png = Cursor::new(Vec::new());
        image.write_to(&mut png, ImageFormat::Png).unwrap();
        frame.png_data = png.into_inner().into();
        frame.verify = Arc::new(VerifySlot::default());
        run(frame.clone());
        let outcome = frame
            .verify
            .wait_for(std::time::Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            outcome.payload_info["payload_found"], true,
            "high bits preserve extraction"
        );
        assert!(
            !outcome.verified,
            "changed delivered content must fail despite unchanged cached RGB"
        );
    }

    #[tokio::test]
    async fn bounded_verification_queue_evicts_and_wakes_old_slots() {
        let mut queue = VecDeque::new();
        let mut slots = Vec::new();
        for index in 0..7 {
            let slot = Arc::new(VerifySlot::default());
            slots.push(slot.clone());
            push_verify(
                &mut queue,
                VerifyJob {
                    frame: EncodedFrame {
                        rgb_data: Arc::from([0u8; 3]),
                        png_data: Arc::from([]),
                        width: 1,
                        height: 1,
                        frame_index: index,
                        revision: index,
                        lsb_bits: 1,
                        commitment: [0; 32],
                        verify: slot,
                    },
                    verify_key: [0; 32],
                    metrics: Arc::new(steganographer_core::StegoMetrics::new()),
                },
            );
        }
        assert_eq!(queue.len(), VERIFY_QUEUE_CAP);
        assert_eq!(queue.front().unwrap().frame.frame_index, 3);
        assert_eq!(queue.back().unwrap().frame.frame_index, 6);
        for slot in &slots[..3] {
            assert!(slot.dropped.load(Ordering::Acquire));
            assert!(slot
                .wait_for(std::time::Duration::from_secs(10))
                .await
                .is_none());
        }
        assert!(!slots[6].dropped.load(Ordering::Acquire));
    }

    #[test]
    fn origin_and_token_gates_reject_foreign_browser_requests() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("127.0.0.1:8080"));
        headers.insert(ORIGIN, HeaderValue::from_static("https://foreign.example"));
        assert!(ws_gate(&headers, None, &state()).is_err());
        headers.insert(ORIGIN, HeaderValue::from_static("null"));
        assert!(ws_gate(&headers, None, &state()).is_err());
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:8080"));
        let mut state = state();
        state.auth_token = Some("secret token".into());
        assert!(ws_gate(&headers, None, &state).is_err());
        assert!(ws_gate(&headers, Some("token=secret%20token"), &state).is_ok());
        assert_eq!(query_token(Some("token=%FF")), None);
    }
}
