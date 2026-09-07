//! WebRTC DataChannel transport with WHEP-style HTTP SDP signaling.
//!
//! The route `POST /api/webrtc/offer` is registered unconditionally so the
//! browser client can probe for support; with the `webrtc` cargo feature
//! disabled the handler responds `501` and clients fall back to WebSocket.
//!
//! With the feature enabled the handler performs WHEP-style signaling:
//! the client POSTs an SDP offer, the server creates an answer, and frames
//! flow over an ordered+reliable `frames` DataChannel using the exact same
//! per-frame processing pipeline as the WebSocket handlers
//! (see [`crate::ws_handler::process_encode_frame`] and
//! [`crate::ws_handler::process_decode_poll`]).

use super::DashboardState;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
#[cfg(feature = "webrtc")]
use bytes::BytesMut;
use serde_json::json;

// ─── Binary chunk framing ─────────────────────────────────────────────────────

/// Magic prefix for every binary chunk (`STGO`).
pub const FRAMING_MAGIC: u32 = 0x5354_474F;
/// Header size: magic (4) + msg id (8) + chunk index (4) + chunk count (4).
pub const CHUNK_HEADER_BYTES: usize = 20;
/// Maximum payload bytes carried by a single chunk, so that the total chunk
/// (header + payload) stays within the 16 KiB SCTP message limit.
pub const CHUNK_PAYLOAD_MAX: usize = 16 * 1024 - CHUNK_HEADER_BYTES;
/// Sessions idle longer than this are closed and swept.
pub const SESSION_IDLE_TIMEOUT_SECS: u64 = 60;

/// Split a payload into binary chunks with the framing header
/// `[u32 magic][u64 msg_id][u32 chunk_index][u32 chunk_count][bytes]`.
#[cfg(feature = "webrtc")]
pub fn frame_chunks(msg_id: u64, payload: &[u8]) -> Vec<Vec<u8>> {
    let count = payload.len().div_ceil(CHUNK_PAYLOAD_MAX).max(1);
    let mut out = Vec::with_capacity(count);
    for (idx, chunk) in payload.chunks(CHUNK_PAYLOAD_MAX).enumerate() {
        let mut buf = Vec::with_capacity(CHUNK_HEADER_BYTES + chunk.len());
        buf.extend_from_slice(&FRAMING_MAGIC.to_be_bytes());
        buf.extend_from_slice(&msg_id.to_be_bytes());
        buf.extend_from_slice(&(idx as u32).to_be_bytes());
        buf.extend_from_slice(&(count as u32).to_be_bytes());
        buf.extend_from_slice(chunk);
        out.push(buf);
    }
    out
}

/// Reassembles chunked messages keyed by `msg_id`.
#[cfg(feature = "webrtc")]
#[derive(Default)]
pub struct Reassembler {
    partial: std::collections::HashMap<u64, PartialMessage>,
}

#[cfg(feature = "webrtc")]
struct PartialMessage {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
}

#[cfg(feature = "webrtc")]
impl Reassembler {
    /// Feed one binary chunk; returns the fully reassembled payload when the
    /// last chunk of a message arrives. Invalid chunks (bad magic, out-of-range
    /// index, or count mismatch) are dropped and reported as an error.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
        if chunk.len() < CHUNK_HEADER_BYTES {
            return Err("chunk too short");
        }
        let magic = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        if magic != FRAMING_MAGIC {
            return Err("bad magic");
        }
        let msg_id = u64::from_be_bytes(chunk[4..12].try_into().unwrap());
        let index = u32::from_be_bytes(chunk[12..16].try_into().unwrap()) as usize;
        let count = u32::from_be_bytes(chunk[16..20].try_into().unwrap()) as usize;
        if count == 0 || index >= count {
            return Err("chunk index out of range");
        }
        let partial = self
            .partial
            .entry(msg_id)
            .or_insert_with(|| PartialMessage {
                chunks: (0..count).map(|_| None).collect(),
                received: 0,
            });
        if partial.chunks.len() != count {
            self.partial.remove(&msg_id);
            return Err("chunk count mismatch");
        }
        if partial.chunks[index].is_some() {
            return Ok(None);
        }
        partial.chunks[index] = Some(chunk[CHUNK_HEADER_BYTES..].to_vec());
        partial.received += 1;
        if partial.received == count {
            let partial = self.partial.remove(&msg_id).unwrap();
            let total: usize = partial
                .chunks
                .iter()
                .map(|c| c.as_ref().unwrap().len())
                .sum();
            let mut payload = Vec::with_capacity(total);
            for c in partial.chunks {
                payload.extend_from_slice(&c.unwrap());
            }
            return Ok(Some(payload));
        }
        Ok(None)
    }
}

// ─── Session bookkeeping ──────────────────────────────────────────────────────

/// One live WebRTC session: the peer connection plus idle-tracking metadata.
#[cfg(feature = "webrtc")]
pub struct WebrtcSession {
    /// The peer connection for this session.
    pub pc: std::sync::Arc<dyn webrtc::peer_connection::PeerConnection>,
    /// Last time the session's DataChannel carried a message.
    pub last_activity: std::sync::Mutex<std::time::Instant>,
}

#[cfg(feature = "webrtc")]
impl std::fmt::Debug for WebrtcSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebrtcSession")
            .field("last_activity", &self.last_activity)
            .finish_non_exhaustive()
    }
}

/// Register a session in the shared map. Returns the generated session id.
#[cfg(feature = "webrtc")]
pub fn register_session(
    state: &DashboardState,
    pc: std::sync::Arc<dyn webrtc::peer_connection::PeerConnection>,
) -> String {
    use rand::RngCore;
    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let session_id: String = id_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    state
        .webrtc_sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            session_id.clone(),
            WebrtcSession {
                pc,
                last_activity: std::sync::Mutex::new(std::time::Instant::now()),
            },
        );
    session_id
}

/// Remove a session by id and close its peer connection. Returns true when
/// the session existed.
#[cfg(feature = "webrtc")]
pub async fn remove_session(state: &DashboardState, session_id: &str) -> bool {
    let sess = state
        .webrtc_sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(session_id);
    // Drop the media publisher; the media pump observes the session removal
    // and exits (it also removes its own entry as a belt-and-braces cleanup).
    state
        .media_publishers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(session_id);
    match sess {
        Some(sess) => {
            let _ = sess.pc.close().await;
            true
        }
        None => false,
    }
}

/// Close and drop sessions whose DataChannel has been idle beyond
/// [`SESSION_IDLE_TIMEOUT_SECS`]. Returns the number of swept sessions.
#[cfg(feature = "webrtc")]
pub async fn sweep_idle_sessions(state: &DashboardState) -> usize {
    let mut to_close = Vec::new();
    {
        let mut sessions = state
            .webrtc_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_id, sess| {
            let idle_for = sess
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed();
            if idle_for > std::time::Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS) {
                to_close.push(sess.pc.clone());
                false
            } else {
                true
            }
        });
    }
    for pc in &to_close {
        let _ = pc.close().await;
    }
    to_close.len()
}

// ─── SDP signaling handler ────────────────────────────────────────────────────

/// Request body for `POST /api/webrtc/offer`.
#[derive(Debug, serde::Deserialize)]
pub struct OfferRequest {
    /// The client's SDP offer.
    pub sdp: String,
    /// SDP type; must be `"offer"`.
    #[serde(rename = "type")]
    pub kind: String,
}

/// `POST /api/webrtc/offer` — WHEP-style SDP exchange.
///
/// With the `webrtc` feature: consumes the client offer, creates the server
/// answer, registers the session, and returns `{sdp, type: "answer", session_id}`.
/// Without the feature: returns `501` with an error body so clients can
/// fall back to WebSocket.
pub async fn api_webrtc_offer(
    State(_state): State<std::sync::Arc<DashboardState>>,
    axum::Json(req): axum::Json<OfferRequest>,
) -> Response {
    #[cfg(feature = "webrtc")]
    {
        handle_offer_with_webrtc(_state, req).await
    }
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = req;
        (
            axum::http::StatusCode::NOT_IMPLEMENTED,
            axum::Json(json!({
                "error": "webrtc feature disabled; using websocket fallback"
            })),
        )
            .into_response()
    }
}

/// `GET /api/webrtc/config` — advertised WebRTC capabilities.
///
/// Registered unconditionally so the browser can probe support. The response
/// mirrors the server's ICE server list so the client peer connection can use
/// the same STUN/TURN configuration, and whether the server publishes the
/// H.264 video track (`media`). `media` is true only when the `webrtc`
/// feature is built in AND the transport policy allows WebRTC.
pub async fn api_webrtc_config(State(state): State<std::sync::Arc<DashboardState>>) -> Response {
    #[cfg(feature = "webrtc")]
    {
        let ice_servers = state.ice_servers.clone();
        let media = state.transport != crate::TransportPolicy::Websocket;
        (axum::Json(json!({
            "ice_servers": ice_servers,
            "media": media,
        })),)
            .into_response()
    }
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = state;
        (axum::Json(json!({
            "ice_servers": [],
            "media": false,
        })),)
            .into_response()
    }
}

/// Async event handler that forwards the remote-created DataChannel to the
/// session's frame pump.
#[cfg(feature = "webrtc")]
struct SessionEventHandler {
    dc_tx:
        tokio::sync::mpsc::UnboundedSender<std::sync::Arc<dyn webrtc::data_channel::DataChannel>>,
    gather_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

#[cfg(feature = "webrtc")]
#[async_trait::async_trait]
impl webrtc::peer_connection::PeerConnectionEventHandler for SessionEventHandler {
    async fn on_data_channel(
        &self,
        data_channel: std::sync::Arc<dyn webrtc::data_channel::DataChannel>,
    ) {
        let _ = self.dc_tx.send(data_channel);
    }

    async fn on_ice_gathering_state_change(
        &self,
        state: webrtc::peer_connection::RTCIceGatheringState,
    ) {
        if state == webrtc::peer_connection::RTCIceGatheringState::Complete {
            let _ = self.gather_tx.send(());
        }
    }
}

/// Feature-gated SDP offer handling (server-side peer connection setup).
#[cfg(feature = "webrtc")]
async fn handle_offer_with_webrtc(
    state: std::sync::Arc<DashboardState>,
    req: OfferRequest,
) -> Response {
    use webrtc::peer_connection::{PeerConnection, PeerConnectionBuilder};

    if req.kind != "offer" {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "type must be \"offer\""})),
        )
            .into_response();
    }

    // Channel for the DataChannel created by the remote (browser) side.
    let (dc_tx, mut dc_rx) = tokio::sync::mpsc::unbounded_channel();

    // ICE servers come from the configured list (empty by default: localhost
    // host candidates only, no traffic beyond loopback).
    let rtc_config = webrtc::peer_connection::RTCConfigurationBuilder::new()
        .with_ice_servers(parse_ice_servers(&state.ice_servers))
        .build();
    let (gather_tx, mut gather_rx) = tokio::sync::mpsc::unbounded_channel();
    // The default MediaEngine carries no codecs; without registration the
    // video transceiver cannot be created. Only register when the offer
    // carries video and policy allows media, keeping data-only answers
    // byte-identical to the previous behavior.
    let media_candidate = req.sdp.lines().any(|l| l.starts_with("m=video"))
        && state.transport != crate::TransportPolicy::Websocket;
    let base_builder = PeerConnectionBuilder::<String>::new().with_configuration(rtc_config);
    let builder = if media_candidate {
        let mut media_engine = webrtc::peer_connection::MediaEngine::default();
        if let Err(e) = media_engine.register_default_codecs() {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({
                    "error": format!("media engine setup failed: {}", e)
                })),
            )
                .into_response();
        }
        base_builder.with_media_engine(media_engine)
    } else {
        base_builder
    };
    let pc = match builder
        .with_udp_addrs(vec!["127.0.0.1:0".to_string()])
        .with_handler(std::sync::Arc::new(SessionEventHandler {
            dc_tx,
            gather_tx,
        }))
        .build()
        .await
    {
        Ok(pc) => std::sync::Arc::new(pc) as std::sync::Arc<dyn PeerConnection>,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": format!("peer connection failed: {}", e)})),
            )
                .into_response();
        }
    };

    let offer = match webrtc::peer_connection::RTCSessionDescription::offer(req.sdp) {
        Ok(o) => o,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": format!("invalid SDP offer: {}", e)})),
            )
                .into_response();
        }
    };

    if let Err(e) = pc.set_remote_description(offer).await {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": format!("set_remote_description failed: {}", e)})),
        )
            .into_response();
    }

    // Media: when the offer carries a video m-line and the transport policy
    // allows WebRTC, answer with a sendonly H.264 track. With transport ==
    // Websocket the browser adds no video transceiver; if an offer still
    // contains one we simply do not attach a track, so the answer's video
    // m-line carries no media and the DataChannel canvas path stays the only
    // rendering surface.
    let publisher = if media_candidate {
        match setup_media_sender(&pc).await {
            Ok(p) => Some(p),
            Err(e) => {
                let _ = pc.close().await;
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({
                        "error": format!("media track setup failed: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    let answer = match pc.create_answer(None).await {
        Ok(a) => a,
        Err(e) => {
            let _ = pc.close().await;
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": format!("create_answer failed: {}", e)})),
            )
                .into_response();
        }
    };
    if let Err(e) = pc.set_local_description(answer).await {
        let _ = pc.close().await;
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": format!("set_local_description failed: {}", e)})),
        )
            .into_response();
    }

    // Resolve the negotiated H.264 payload type now that the local answer is
    // set; frames published before resolution are dropped by the publisher.
    let media_ready = if let Some(publisher) = &publisher {
        match discover_h264_payload_type(&pc).await {
            Some(pt) => {
                log::info!(
                    "WebRTC media: negotiated H.264 payload type {} (ssrc {})",
                    pt,
                    publisher.ssrc()
                );
                publisher.set_payload_type(pt);
                true
            }
            None => {
                log::warn!(
                    "WebRTC offer contained video but no H.264 packetization-mode=1 \
                     codec was negotiated; media disabled for this session"
                );
                false
            }
        }
    } else {
        false
    };

    // Wait (bounded) for ICE gathering so the answer carries loopback host
    // candidates. With no ICE servers this completes almost immediately.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), gather_rx.recv()).await;

    let local_sdp = match pc.local_description().await {
        Some(d) => d.sdp,
        None => {
            let _ = pc.close().await;
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "local description missing"})),
            )
                .into_response();
        }
    };

    let session_id = register_session(&state, pc.clone());

    if media_ready {
        if let Some(publisher) = publisher {
            state
                .media_publishers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(session_id.clone(), publisher.clone());
            tokio::spawn(run_media_pump(state.clone(), session_id.clone(), publisher));
        }
    }

    // Spawn the frame pump once the DataChannel arrives.
    let pump_state = state.clone();
    let pump_session_id = session_id.clone();
    tokio::spawn(async move {
        let dc = match tokio::time::timeout(std::time::Duration::from_secs(10), dc_rx.recv()).await
        {
            Ok(Some(dc)) => dc,
            _ => {
                log::warn!(
                    "WebRTC session {}: DataChannel never opened",
                    pump_session_id
                );
                let _ = remove_session(&pump_state, &pump_session_id).await;
                return;
            }
        };
        run_frame_pump(pump_state, pump_session_id, dc).await;
    });

    (axum::Json(json!({
        "sdp": local_sdp,
        "type": "answer",
        "session_id": session_id,
    })),)
        .into_response()
}

/// Stamp a reply with the latency echo fields and send it, chunking with the
/// binary framing header when it exceeds the 16 KiB message limit. Chunks are
/// paced so the loopback UDP buffers are not overrun.
#[cfg(feature = "webrtc")]
async fn send_reply(
    dc: &std::sync::Arc<dyn webrtc::data_channel::DataChannel>,
    session_id: &str,
    msg_id: u64,
    received_unix_ms: u64,
    mut reply: serde_json::Value,
) {
    reply["msg_id"] = json!(msg_id);
    if reply.get("received_unix_ms").is_none() {
        reply["received_unix_ms"] = json!(received_unix_ms);
    }
    let reply_bytes = reply.to_string().into_bytes();
    let send_result: Result<(), ()> = if reply_bytes.len() > CHUNK_PAYLOAD_MAX {
        // Large replies are chunked with the same binary framing.
        let reply_id = msg_id | (1 << 63);
        let mut ok = true;
        for (ci, chunk) in frame_chunks(reply_id, &reply_bytes).into_iter().enumerate() {
            if ci > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            if dc.send(BytesMut::from(&chunk[..])).await.is_err() {
                ok = false;
                break;
            }
        }
        ok.then_some(()).ok_or(())
    } else {
        dc.send_text(&reply.to_string())
            .await
            .map(|_| ())
            .map_err(|_| ())
    };
    if send_result.is_err() {
        log::info!("WebRTC session {}: send failed; closing pump", session_id);
    }
}

/// Per-session DataChannel frame pump: reassembles binary chunks, dispatches
/// encode/ping/decode_poll requests through the shared pipeline, and sends
/// replies with backpressure awareness.
///
/// Backpressure: the channel's `buffered_amount_low_threshold` is armed and
/// sends are throttled while the outstanding (unacked) byte count exceeds the
/// high-water mark, so a slow consumer cannot balloon server memory.
#[cfg(feature = "webrtc")]
async fn run_frame_pump(
    state: std::sync::Arc<DashboardState>,
    session_id: String,
    dc: std::sync::Arc<dyn webrtc::data_channel::DataChannel>,
) {
    use webrtc::data_channel::DataChannelEvent;

    use crate::ws_handler::{
        process_decode_poll, process_encode_frame, DecodeSession, EncodeSession,
    };

    log::info!("WebRTC session {} DataChannel open", session_id);

    const HIGH_WATER_BYTES: usize = 4 * 1024 * 1024;

    let _encode_session = EncodeSession::new();
    let mut decode_session = DecodeSession::new();
    let mut reassembler = Reassembler::default();

    // Backpressure thresholds (bytes): re-arm the send path once the peer
    // drains below the low threshold.
    let _ = dc.set_buffered_amount_low_threshold(64 * 1024).await;

    loop {
        let event = match dc.poll().await {
            Some(ev) => ev,
            None => break,
        };
        match event {
            DataChannelEvent::OnClose | DataChannelEvent::OnError => {
                log::info!("WebRTC session {} DataChannel closed", session_id);
                break;
            }
            DataChannelEvent::OnMessage(msg) => {
                {
                    let mut sessions = state
                        .webrtc_sessions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if let Some(sess) = sessions.get_mut(&session_id) {
                        *sess.last_activity.lock().unwrap_or_else(|e| e.into_inner()) =
                            std::time::Instant::now();
                    }
                }
                let payload = if msg.is_string {
                    // Control-plane style messages may arrive as plain text.
                    Some(msg.data.to_vec())
                } else {
                    match reassembler.push(&msg.data) {
                        Ok(p) => p,
                        Err(e) => {
                            log::warn!("WebRTC session {}: chunk dropped: {}", session_id, e);
                            None
                        }
                    }
                };
                let Some(payload) = payload else { continue };
                let request: serde_json::Value = match serde_json::from_slice(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("WebRTC session {}: invalid request JSON: {}", session_id, e);
                        continue;
                    }
                };
                let msg_id = request.get("msg_id").and_then(|v| v.as_u64()).unwrap_or(0);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let mut reply = match request.get("kind").and_then(|v| v.as_str()) {
                    Some("ping") => json!({
                        "kind": "pong",
                        "msg_id": msg_id,
                        "sent_unix_ms": request.get("sent_unix_ms").cloned().unwrap_or(json!(0)),
                        "received_unix_ms": now_ms,
                    }),
                    Some("encode") => {
                        // Heavy CPU work + the reply send run in a separate task
                        // so the pump keeps draining the DataChannel event queue
                        // under sustained frame load.
                        let b64 = request
                            .get("jpeg_b64")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        match b64 {
                            Some(b64) => {
                                let st = state.clone();
                                let dc = dc.clone();
                                let session_id = session_id.clone();
                                tokio::spawn(async move {
                                    let reply = match crate::ws_handler::base64_decode(&b64) {
                                        Ok(jpeg) => {
                                            let mut session = EncodeSession::new();
                                            tokio::task::spawn_blocking(move || {
                                                process_encode_frame(&st, &mut session, &jpeg)
                                            })
                                            .await
                                            .unwrap_or(None)
                                            .unwrap_or_else(|| {
                                                json!({"type": "encode_error", "msg_id": msg_id})
                                            })
                                        }
                                        Err(e) => json!({
                                            "type": "encode_error",
                                            "msg_id": msg_id,
                                            "error": e.to_string()
                                        }),
                                    };
                                    send_reply(&dc, &session_id, msg_id, now_ms, reply).await;
                                });
                                continue;
                            }
                            None => json!({
                                "type": "encode_error",
                                "msg_id": msg_id,
                                "error": "missing jpeg_b64"
                            }),
                        }
                    }
                    Some("decode_poll") | Some("poll") => {
                        let mut r = process_decode_poll(&state, &mut decode_session);
                        r["msg_id"] = json!(msg_id);
                        r
                    }
                    other => {
                        log::warn!("WebRTC session {}: unknown kind {:?}", session_id, other);
                        continue;
                    }
                };
                // Latency echo: stamp every reply with msg_id + received time.
                reply["msg_id"] = json!(msg_id);
                if reply.get("received_unix_ms").is_none() {
                    reply["received_unix_ms"] = json!(now_ms);
                }

                // Backpressure: wait until the peer drains before queueing more.
                while dc.outstanding_bytes().await.unwrap_or(0) > HIGH_WATER_BYTES {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                let reply_bytes = reply.to_string().into_bytes();
                let send_result: Result<(), ()> = if reply_bytes.len() > CHUNK_PAYLOAD_MAX {
                    // Large replies are chunked with the same binary framing.
                    let reply_id = msg_id | (1 << 63);
                    let mut ok = true;
                    for (ci, chunk) in frame_chunks(reply_id, &reply_bytes).into_iter().enumerate()
                    {
                        // Pace chunks so the loopback UDP buffers are not overrun.
                        if ci > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        }
                        if dc.send(BytesMut::from(&chunk[..])).await.is_err() {
                            ok = false;
                            break;
                        }
                    }
                    ok.then_some(()).ok_or(())
                } else {
                    dc.send_text(&reply.to_string())
                        .await
                        .map(|_| ())
                        .map_err(|_| ())
                };
                if send_result.is_err() {
                    log::info!("WebRTC session {}: send failed; closing pump", session_id);
                    break;
                }
                log::info!("WebRTC session {}: reply {} fully sent", session_id, msg_id);
            }
            _ => {}
        }
    }

    let _ = dc.close().await;
    let _ = remove_session(&state, &session_id).await;
}

// ─── H.264 media publishing ───────────────────────────────────────────────────
//
// When the browser's offer contains a video m-line and the transport policy
// allows WebRTC, the server answers with a sendonly H.264 track carrying the
// stego'd frames as RTP. The browser renders the track in a <video> element;
// the DataChannel canvas view remains the primary verification surface.

/// H.264 fmtp line announced for the published video track: baseline
/// constrained profile, packetization mode 1 — the profile browsers offer
/// for RTP video and the bitstream shape OpenH264 produces.
#[cfg(feature = "webrtc")]
pub const H264_FMTP: &str =
    "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";

/// Target OpenH264 bit rate.
#[cfg(feature = "webrtc")]
const MEDIA_TARGET_BITRATE_BPS: u32 = 2_500_000;
/// OpenH264 frame rate ceiling.
#[cfg(feature = "webrtc")]
const MEDIA_MAX_FPS: f32 = 30.0;
/// Periodic intra-frame interval in frames (~2 s of IDR cadence at 15 fps).
#[cfg(feature = "webrtc")]
const MEDIA_IDR_INTERVAL_FRAMES: u32 = 30;
/// Default inter-frame duration for the first published frame (15 fps).
#[cfg(feature = "webrtc")]
const MEDIA_DEFAULT_FRAME_DURATION: std::time::Duration = std::time::Duration::from_millis(66);
/// Clamp window for the RTP timestamp advance per frame.
#[cfg(feature = "webrtc")]
const MEDIA_MIN_FRAME_DURATION: std::time::Duration = std::time::Duration::from_millis(16);
#[cfg(feature = "webrtc")]
const MEDIA_MAX_FRAME_DURATION: std::time::Duration = std::time::Duration::from_millis(100);
/// How often the media pump polls the shared pipeline for new stego'd frames.
#[cfg(feature = "webrtc")]
const MEDIA_PUMP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(33);

/// Parse the configured ICE server URL list into crate `RTCIceServer`s.
///
/// Supported forms: `stun:host:port`, `stuns:host:port`, `turn:host:port`
/// with inline `user:cred@` credentials, and `turns:host:port` likewise.
/// TURN entries without credentials and URLs with unknown schemes are
/// warned about and skipped (WebRTC-style inline credentials are hoisted
/// into the `RTCIceServer` username/credential fields).
#[cfg(feature = "webrtc")]
pub fn parse_ice_servers(urls: &[String]) -> Vec<webrtc::peer_connection::RTCIceServer> {
    let mut out = Vec::new();
    for raw in urls {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((scheme, rest)) = trimmed.split_once(':') else {
            log::warn!("ICE server {:?} skipped: missing scheme", trimmed);
            continue;
        };
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "stun" | "stuns" | "turn" | "turns") {
            log::warn!("ICE server {:?} skipped: unsupported scheme", trimmed);
            continue;
        }
        let (url, username, credential) = if let Some((userinfo, host)) = rest.rsplit_once('@') {
            let (user, cred) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            (
                format!("{}:{}", scheme, host),
                user.to_string(),
                cred.to_string(),
            )
        } else {
            (trimmed.to_string(), String::new(), String::new())
        };
        if matches!(scheme.as_str(), "turn" | "turns")
            && (username.is_empty() || credential.is_empty())
        {
            log::warn!(
                "ICE server {:?} skipped: TURN requires inline user:credential",
                trimmed
            );
            continue;
        }
        out.push(webrtc::peer_connection::RTCIceServer {
            urls: vec![url],
            username,
            credential,
        });
    }
    out
}

/// Convert an RGB8 frame to planar I420 (BT.601 limited range) — the pixel
/// format OpenH264 encodes from. Chroma is 2x2 subsampled with simple
/// (unfiltered) decimation, which is visually fine for dashboard content.
#[cfg(feature = "webrtc")]
pub fn rgb_to_i420(rgb: &[u8], width: u32, height: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (w, h) = (width as usize, height as usize);
    let uv_w = w.div_ceil(2);
    let uv_h = h.div_ceil(2);
    let mut y = vec![16u8; w * h];
    let mut u = vec![128u8; uv_w * uv_h];
    let mut v = vec![128u8; uv_w * uv_h];
    for row in 0..h {
        for col in 0..w {
            let i = (row * w + col) * 3;
            let (r, g, b) = (rgb[i] as i32, rgb[i + 1] as i32, rgb[i + 2] as i32);
            y[row * w + col] = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16).clamp(0, 255) as u8;
            if row % 2 == 0 && col % 2 == 0 {
                let p = (row / 2) * uv_w + (col / 2);
                u[p] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
                v[p] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
            }
        }
    }
    (y, u, v)
}

/// Planar I420 frame implementing [`openh264::formats::YUVSource`].
#[cfg(feature = "webrtc")]
struct I420Frame {
    width: usize,
    height: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

#[cfg(feature = "webrtc")]
impl openh264::formats::YUVSource for I420Frame {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn strides(&self) -> (usize, usize, usize) {
        let uv = self.width.div_ceil(2);
        (self.width, uv, uv)
    }
    fn y(&self) -> &[u8] {
        &self.y
    }
    fn u(&self) -> &[u8] {
        &self.u
    }
    fn v(&self) -> &[u8] {
        &self.v
    }
}

/// Errors surfaced by [`MediaPublisher::publish_frame`].
#[cfg(feature = "webrtc")]
#[derive(Debug)]
pub enum MediaPublishError {
    /// The H.264 payload type has not been negotiated yet; the frame was
    /// dropped and can be republished once signaling completes.
    NotNegotiated,
    /// OpenH264 encoding failed.
    Encode(String),
    /// RTP packetization or transport write failed.
    Rtp(String),
}

#[cfg(feature = "webrtc")]
impl std::fmt::Display for MediaPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MediaPublishError::NotNegotiated => write!(f, "payload type not yet negotiated"),
            MediaPublishError::Encode(e) => write!(f, "H.264 encode failed: {}", e),
            MediaPublishError::Rtp(e) => write!(f, "RTP write failed: {}", e),
        }
    }
}

#[cfg(feature = "webrtc")]
impl std::error::Error for MediaPublishError {}

/// Lazily created encoder slot; recreated whenever the frame dimensions change.
#[cfg(feature = "webrtc")]
struct EncoderSlot {
    dims: (u32, u32),
    encoder: Option<openh264::encoder::Encoder>,
}

/// Publishes stego'd frames as the H.264 RTP video track of one WebRTC
/// session.
///
/// `publish_frame` converts RGB pixels to I420, encodes them with a
/// session-owned OpenH264 encoder, and hands the Annex-B bitstream to the
/// crate's packetizer via the wrapped `TrackLocalStaticSample`. The payload
/// type is discovered from the negotiated answer parameters after signaling
/// completes; frames published before that are rejected with
/// [`MediaPublishError::NotNegotiated`].
#[cfg(feature = "webrtc")]
pub struct MediaPublisher {
    track: std::sync::Arc<webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample>,
    ssrc: u32,
    payload_type: std::sync::atomic::AtomicU8,
    encoder: std::sync::Mutex<EncoderSlot>,
    last_frame_at: std::sync::Mutex<Option<std::time::Instant>>,
}

#[cfg(feature = "webrtc")]
impl std::fmt::Debug for MediaPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaPublisher")
            .field("ssrc", &self.ssrc)
            .field(
                "payload_type",
                &self.payload_type.load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "webrtc")]
impl MediaPublisher {
    fn new(
        track: std::sync::Arc<
            webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample,
        >,
        ssrc: u32,
    ) -> Self {
        Self {
            track,
            ssrc,
            payload_type: std::sync::atomic::AtomicU8::new(0),
            encoder: std::sync::Mutex::new(EncoderSlot {
                dims: (0, 0),
                encoder: None,
            }),
            last_frame_at: std::sync::Mutex::new(None),
        }
    }

    /// The RTP SSRC of the published stream.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The negotiated H.264 payload type; `0` until signaling completes.
    pub fn payload_type(&self) -> u8 {
        self.payload_type.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_payload_type(&self, pt: u8) {
        self.payload_type
            .store(pt, std::sync::atomic::Ordering::Relaxed);
    }

    /// Encode and publish one stego'd frame as RTP.
    ///
    /// `rgb` must be tightly packed RGB8 of the given dimensions. The RTP
    /// timestamp advance is the measured inter-frame delta, clamped to
    /// [1/60 s, 1/10 s]. A resolution change transparently recreates the
    /// encoder (logged once per change).
    pub async fn publish_frame(
        &self,
        width: u32,
        height: u32,
        rgb: &[u8],
    ) -> Result<(), MediaPublishError> {
        let pt = self.payload_type();
        if pt == 0 {
            return Err(MediaPublishError::NotNegotiated);
        }
        let expected = width as usize * height as usize * 3;
        if rgb.len() < expected {
            return Err(MediaPublishError::Encode(format!(
                "RGB buffer {} bytes, expected {} for {}x{}",
                rgb.len(),
                expected,
                width,
                height
            )));
        }

        let (y, u, v) = rgb_to_i420(rgb, width, height);
        let frame = I420Frame {
            width: width as usize,
            height: height as usize,
            y,
            u,
            v,
        };

        // Measured inter-frame delta drives the RTP timestamp clock.
        let now = std::time::Instant::now();
        let duration = {
            let mut last = self.last_frame_at.lock().unwrap_or_else(|e| e.into_inner());
            let d = match *last {
                Some(t) => now.duration_since(t),
                None => MEDIA_DEFAULT_FRAME_DURATION,
            };
            *last = Some(now);
            d.clamp(MEDIA_MIN_FRAME_DURATION, MEDIA_MAX_FRAME_DURATION)
        };

        let annexb = {
            let mut slot = self.encoder.lock().unwrap_or_else(|e| e.into_inner());
            if slot.encoder.is_none() || slot.dims != (width, height) {
                if slot.encoder.is_some() {
                    log::info!(
                        "WebRTC media: resolution changed to {}x{}; recreating H.264 encoder",
                        width,
                        height
                    );
                }
                let config = openh264::encoder::EncoderConfig::new()
                    .bitrate(openh264::encoder::BitRate::from_bps(
                        MEDIA_TARGET_BITRATE_BPS,
                    ))
                    .max_frame_rate(openh264::encoder::FrameRate::from_hz(MEDIA_MAX_FPS))
                    .rate_control_mode(openh264::encoder::RateControlMode::Bitrate)
                    .intra_frame_period(openh264::encoder::IntraFramePeriod::from_num_frames(
                        MEDIA_IDR_INTERVAL_FRAMES,
                    ));
                slot.encoder = Some(
                    openh264::encoder::Encoder::with_api_config(
                        openh264::OpenH264API::from_source(),
                        config,
                    )
                    .map_err(|e| MediaPublishError::Encode(e.to_string()))?,
                );
                slot.dims = (width, height);
            }
            let encoder = slot.encoder.as_mut().expect("encoder just created");
            let bitstream = encoder
                .encode(&frame)
                .map_err(|e| MediaPublishError::Encode(e.to_string()))?;
            annexb_from_bitstream(&bitstream)
        };

        let sample = rtc::media::Sample {
            data: bytes::Bytes::from(annexb),
            duration,
            ..Default::default()
        };
        self.track
            .write_sample(self.ssrc, pt, &sample, &[])
            .await
            .map_err(|e| MediaPublishError::Rtp(e.to_string()))
    }
}

/// Flatten an OpenH264 `EncodedBitStream` into an Annex-B byte stream
/// (each NAL unit prefixed with a 4-byte start code), the input format the
/// crate's H.264 payloader expects. OpenH264 already emits start-code
/// prefixed NAL units; the normalization is defensive so both 3- and 4-byte
/// prefixes and bare NAL bodies produce valid output.
#[cfg(feature = "webrtc")]
fn annexb_from_bitstream(bs: &openh264::encoder::EncodedBitStream<'_>) -> Vec<u8> {
    const START4: [u8; 4] = [0, 0, 0, 1];
    let mut out = Vec::new();
    for l in 0..bs.num_layers() {
        let Some(layer) = bs.layer(l) else { continue };
        for n in 0..layer.nal_count() {
            let Some(nal) = layer.nal_unit(n) else {
                continue;
            };
            if nal.starts_with(&START4) {
                out.extend_from_slice(nal);
            } else if nal.len() >= 3 && nal.starts_with(&[0, 0, 1]) {
                out.push(0);
                out.extend_from_slice(nal);
            } else if !nal.is_empty() {
                out.extend_from_slice(&START4);
                out.extend_from_slice(nal);
            }
        }
    }
    out
}

/// Create the sendonly H.264 transceiver for a media-enabled session and
/// wrap its track in a [`MediaPublisher`]. Must be called after
/// `set_remote_description` and before `create_answer`.
#[cfg(feature = "webrtc")]
async fn setup_media_sender(
    pc: &std::sync::Arc<dyn webrtc::peer_connection::PeerConnection>,
) -> Result<std::sync::Arc<MediaPublisher>, String> {
    use rand::RngCore;
    use webrtc::media_stream::track_local::TrackLocal;
    use webrtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

    let mut ssrc_bytes = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut ssrc_bytes);
    let ssrc = u32::from_be_bytes(ssrc_bytes).max(1);

    let codec = rtc::rtp_transceiver::rtp_sender::RTCRtpCodec {
        mime_type: "video/H264".to_string(),
        clock_rate: 90_000,
        channels: 0,
        sdp_fmtp_line: H264_FMTP.to_string(),
        rtcp_feedback: vec![
            rtc::rtp_transceiver::rtp_sender::RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "pli".to_string(),
            },
            rtc::rtp_transceiver::rtp_sender::RTCPFeedback {
                typ: "ccm".to_string(),
                parameter: "fir".to_string(),
            },
            rtc::rtp_transceiver::rtp_sender::RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            },
        ],
    };

    let media_track = rtc::media_stream::MediaStreamTrack::new(
        "stego".to_string(),
        "steganographer".to_string(),
        "steganographer".to_string(),
        rtc::rtp_transceiver::rtp_sender::RtpCodecKind::Video,
        vec![rtc::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters {
            rtp_coding_parameters: rtc::rtp_transceiver::rtp_sender::RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec,
            ..Default::default()
        }],
    );

    let track = std::sync::Arc::new(
        webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample::new(media_track)
            .map_err(|e| format!("track creation failed: {}", e))?,
    );
    let transceiver = pc
        .add_transceiver_from_track(
            track.clone() as std::sync::Arc<dyn TrackLocal>,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec!["stego".to_string()],
                send_encodings: vec![],
            }),
        )
        .await
        .map_err(|e| format!("add_transceiver_from_track failed: {}", e))?;
    let _ = transceiver;

    Ok(std::sync::Arc::new(MediaPublisher::new(track, ssrc)))
}

/// Find the negotiated H.264 (packetization-mode 1) payload type across the
/// peer connection's senders. Must be called after `set_local_description`
/// so the answer's codec selection is reflected in the send parameters.
#[cfg(feature = "webrtc")]
async fn discover_h264_payload_type(
    pc: &std::sync::Arc<dyn webrtc::peer_connection::PeerConnection>,
) -> Option<u8> {
    for sender in pc.get_senders().await {
        let Ok(params) = sender.get_parameters().await else {
            continue;
        };
        for codec in &params.rtp_parameters.codecs {
            if codec.rtp_codec.mime_type.eq_ignore_ascii_case("video/H264")
                && codec
                    .rtp_codec
                    .sdp_fmtp_line
                    .contains("packetization-mode=1")
            {
                return Some(codec.payload_type);
            }
        }
    }
    None
}

/// Per-session media pump: polls the shared encode pipeline for newly stego'd
/// frames and publishes them on the session's H.264 track.
///
/// The pipeline stores every encoded frame's raw stego'd pixels in
/// `DashboardState::last_encoded_frame` (shared by the WebSocket and
/// DataChannel transports), so the pump publishes with zero extra JPEG
/// decoding. Exits once the session leaves `webrtc_sessions` and removes its
/// publisher from `media_publishers`.
#[cfg(feature = "webrtc")]
async fn run_media_pump(
    state: std::sync::Arc<DashboardState>,
    session_id: String,
    publisher: std::sync::Arc<MediaPublisher>,
) {
    let mut last_published: Option<u64> = None;
    loop {
        tokio::time::sleep(MEDIA_PUMP_POLL_INTERVAL).await;
        let session_alive = state
            .webrtc_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&session_id);
        if !session_alive {
            break;
        }
        let next = {
            let guard = state
                .last_encoded_frame
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(f) if Some(f.frame_index) > last_published => {
                    Some((f.frame_index, f.width, f.height, f.rgb_data.clone()))
                }
                _ => None,
            }
        };
        let Some((frame_index, width, height, rgb)) = next else {
            continue;
        };
        match publisher.publish_frame(width, height, &rgb).await {
            Ok(()) => last_published = Some(frame_index),
            Err(MediaPublishError::NotNegotiated) => {}
            Err(e) => log::warn!("WebRTC session {}: media publish failed: {}", session_id, e),
        }
    }
    state
        .media_publishers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&session_id);
    log::info!("WebRTC session {}: media pump stopped", session_id);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "webrtc"))]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_framing_single_chunk_roundtrip() {
        let payload = b"hello frames".to_vec();
        let chunks = frame_chunks(42, &payload);
        assert_eq!(chunks.len(), 1);
        let mut re = Reassembler::default();
        let out = re.push(&chunks[0]).unwrap().expect("complete");
        assert_eq!(out, payload);
    }

    #[test]
    fn test_chunk_framing_multi_chunk_roundtrip() {
        let payload: Vec<u8> = (0..CHUNK_PAYLOAD_MAX * 3 + 123)
            .map(|i| (i % 251) as u8)
            .collect();
        let chunks = frame_chunks(7, &payload);
        assert!(chunks.len() >= 4);
        // Verify header fields of the first chunk.
        assert_eq!(
            u32::from_be_bytes(chunks[0][0..4].try_into().unwrap()),
            FRAMING_MAGIC
        );
        assert_eq!(u64::from_be_bytes(chunks[0][4..12].try_into().unwrap()), 7);
        assert_eq!(u32::from_be_bytes(chunks[0][12..16].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_be_bytes(chunks[0][16..20].try_into().unwrap()),
            chunks.len() as u32
        );
        let mut re = Reassembler::default();
        // Out-of-order delivery must still reassemble.
        let out = chunks
            .iter()
            .rev()
            .filter_map(|c| re.push(c).unwrap())
            .next()
            .expect("reassembled");
        assert_eq!(out, payload);
    }

    #[test]
    fn test_chunk_framing_rejects_bad_magic() {
        let mut re = Reassembler::default();
        assert!(re.push(b"junkjunkjunkjunkjunk").is_err());
        assert!(re.push(b"short").is_err());
    }

    #[test]
    fn test_chunk_framing_interleaved_messages() {
        let a = frame_chunks(1, &vec![0xAA; CHUNK_PAYLOAD_MAX + 10]);
        let b = frame_chunks(2, &[0xBB; 50]);
        let mut re = Reassembler::default();
        assert!(re.push(&a[0]).unwrap().is_none());
        assert!(re.push(&b[0]).unwrap().is_some()); // b completes first
        assert!(re.push(&a[1]).unwrap().is_some()); // now a
    }
}
