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

    // No ICE servers: localhost host candidates only. This dashboard is a
    // local-only tool — no STUN/TURN, no traffic beyond loopback.
    let (gather_tx, mut gather_rx) = tokio::sync::mpsc::unbounded_channel();
    let pc = match PeerConnectionBuilder::<String>::new()
        .with_configuration(webrtc::peer_connection::RTCConfiguration::default())
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
