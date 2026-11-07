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
/// Application-message limit, shared with the WebSocket transport.
pub const MESSAGE_MAX_BYTES: usize = crate::ws_handler::WS_MAX_MESSAGE_SIZE;
/// A full-sized message needs at most this many application chunks.
pub const MESSAGE_MAX_CHUNKS: usize = MESSAGE_MAX_BYTES.div_ceil(CHUNK_PAYLOAD_MAX);
/// Maximum simultaneously incomplete application messages per peer.
pub const INCOMPLETE_MESSAGE_MAX: usize = 4;
/// Aggregate payload retained by incomplete messages per peer.
pub const RETAINED_MESSAGE_MAX_BYTES: usize = MESSAGE_MAX_BYTES * 2;
/// Incomplete messages have an absolute lifetime; duplicates cannot extend it.
pub const MESSAGE_EXPIRY_SECS: u64 = 10;
/// Includes offers being negotiated, not just established peers.
#[cfg(feature = "webrtc")]
pub const WEBRTC_SESSION_MAX: usize = 16;
#[cfg(feature = "webrtc")]
const REPLY_HIGH_WATER_BYTES: usize = MESSAGE_MAX_BYTES;
#[cfg(feature = "webrtc")]
const REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(feature = "webrtc")]
static SESSION_SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(WEBRTC_SESSION_MAX);

/// Split a payload into binary chunks with the framing header
/// `[u32 magic][u64 msg_id][u32 chunk_index][u32 chunk_count][bytes]`.
#[cfg(feature = "webrtc")]
pub fn frame_chunks(msg_id: u64, payload: &[u8]) -> Vec<Vec<u8>> {
    let count = payload.len().div_ceil(CHUNK_PAYLOAD_MAX).max(1);
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        let start = idx * CHUNK_PAYLOAD_MAX;
        let chunk = &payload[start..payload.len().min(start + CHUNK_PAYLOAD_MAX)];
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

/// Reassembles bounded application messages keyed by `msg_id`.
#[cfg(feature = "webrtc")]
#[derive(Default)]
pub struct Reassembler {
    partial: std::collections::HashMap<u64, PartialMessage>,
    retained_bytes: usize,
}

#[cfg(feature = "webrtc")]
struct PartialMessage {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
    started_at: std::time::Instant,
}

#[cfg(feature = "webrtc")]
impl Reassembler {
    fn remove(&mut self, msg_id: u64) -> Option<PartialMessage> {
        let partial = self.partial.remove(&msg_id)?;
        self.retained_bytes -= partial.bytes;
        Some(partial)
    }

    fn expire_at(&mut self, now: std::time::Instant) {
        self.partial.retain(|_, partial| {
            let keep = now.saturating_duration_since(partial.started_at)
                < std::time::Duration::from_secs(MESSAGE_EXPIRY_SECS);
            if !keep {
                self.retained_bytes -= partial.bytes;
            }
            keep
        });
    }

    /// Reject invalid or over-budget chunks before allocating or copying.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
        self.push_at(chunk, std::time::Instant::now())
    }

    fn push_at(
        &mut self,
        chunk: &[u8],
        now: std::time::Instant,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        self.expire_at(now);
        if chunk.len() < CHUNK_HEADER_BYTES {
            return Err("chunk too short");
        }
        if chunk.len() > CHUNK_HEADER_BYTES + CHUNK_PAYLOAD_MAX {
            return Err("chunk too large");
        }
        let magic = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        if magic != FRAMING_MAGIC {
            return Err("bad magic");
        }
        let msg_id = u64::from_be_bytes(chunk[4..12].try_into().unwrap());
        let index = u32::from_be_bytes(chunk[12..16].try_into().unwrap()) as usize;
        let count = u32::from_be_bytes(chunk[16..20].try_into().unwrap()) as usize;
        if count == 0 || count > MESSAGE_MAX_CHUNKS || index >= count {
            self.remove(msg_id);
            return Err("chunk count or index out of range");
        }
        if let Some(partial) = self.partial.get(&msg_id) {
            if partial.chunks.len() != count {
                self.remove(msg_id);
                return Err("chunk count mismatch");
            }
            if partial.chunks[index].is_some() {
                return Ok(None);
            }
        } else if self.partial.len() >= INCOMPLETE_MESSAGE_MAX {
            return Err("too many incomplete messages");
        }
        let payload = &chunk[CHUNK_HEADER_BYTES..];
        let message_bytes = self.partial.get(&msg_id).map_or(0, |p| p.bytes);
        if message_bytes + payload.len() > MESSAGE_MAX_BYTES {
            self.remove(msg_id);
            return Err("message too large");
        }
        if self.retained_bytes + payload.len() > RETAINED_MESSAGE_MAX_BYTES {
            self.remove(msg_id);
            return Err("retained message budget exceeded");
        }
        let partial = self
            .partial
            .entry(msg_id)
            .or_insert_with(|| PartialMessage {
                chunks: (0..count).map(|_| None).collect(),
                received: 0,
                bytes: 0,
                started_at: now,
            });
        partial.chunks[index] = Some(payload.to_vec());
        partial.received += 1;
        partial.bytes += payload.len();
        self.retained_bytes += payload.len();
        if partial.received == count {
            let partial = self.remove(msg_id).unwrap();
            let mut payload = Vec::with_capacity(partial.bytes);
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
    control: std::sync::Arc<SessionControl>,
}

#[cfg(feature = "webrtc")]
impl std::fmt::Debug for WebrtcSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebrtcSession")
            .field("last_activity", &self.last_activity)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "webrtc")]
struct SessionControl {
    stopped: tokio::sync::watch::Sender<bool>,
    encode_drain: tokio::sync::Mutex<()>,
    media_drain: tokio::sync::Mutex<()>,
    _slot: tokio::sync::SemaphorePermit<'static>,
}

#[cfg(feature = "webrtc")]
impl SessionControl {
    fn new(slot: tokio::sync::SemaphorePermit<'static>) -> Self {
        let (stopped, _) = tokio::sync::watch::channel(false);
        Self {
            stopped,
            encode_drain: tokio::sync::Mutex::new(()),
            media_drain: tokio::sync::Mutex::new(()),
            _slot: slot,
        }
    }

    fn stop(&self) {
        self.stopped.send_replace(true);
    }

    fn is_stopped(&self) -> bool {
        *self.stopped.borrow()
    }

    async fn cancelled(&self) {
        let mut receiver = self.stopped.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                break;
            }
        }
    }
}

/// Cancellation of an HTTP request must not detach an unclosed peer driver.
#[cfg(feature = "webrtc")]
struct OfferPeerGuard {
    pc: Option<std::sync::Arc<dyn webrtc::peer_connection::PeerConnection>>,
    control: std::sync::Arc<SessionControl>,
}

#[cfg(feature = "webrtc")]
impl OfferPeerGuard {
    async fn close(&mut self) {
        if let Some(pc) = &self.pc {
            self.control.stop();
            let _ = pc.close().await;
        }
        self.pc = None;
    }
}

#[cfg(feature = "webrtc")]
impl Drop for OfferPeerGuard {
    fn drop(&mut self) {
        if let Some(pc) = self.pc.take() {
            self.control.stop();
            let control = self.control.clone();
            tokio::spawn(async move {
                let _ = pc.close().await;
                drop(control);
            });
        }
    }
}

/// Register a peer only after signaling has successfully completed.
#[cfg(feature = "webrtc")]
fn register_session(
    state: &DashboardState,
    pc: std::sync::Arc<dyn webrtc::peer_connection::PeerConnection>,
    control: std::sync::Arc<SessionControl>,
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
                control,
            },
        );
    session_id
}

/// Stop admission, close the peer, and drain its owned work before removal.
#[cfg(feature = "webrtc")]
pub async fn remove_session(state: &DashboardState, session_id: &str) -> bool {
    let session = {
        let sessions = state
            .webrtc_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions
            .get(session_id)
            .map(|sess| (sess.pc.clone(), sess.control.clone()))
    };
    let Some((pc, control)) = session else {
        return false;
    };
    control.stop();
    let _ = pc.close().await;
    // spawn_blocking cannot be cancelled once running. Its owning pump always
    // joins it while holding this gate, so no removed session can publish.
    let _encode = control.encode_drain.lock().await;
    let _media = control.media_drain.lock().await;
    let publisher = state
        .media_publishers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(session_id);
    if let Some(publisher) = publisher {
        publisher.close();
    }
    state
        .webrtc_sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(session_id);
    true
}

/// Close idle peers through the same publisher/work-draining removal path.
#[cfg(feature = "webrtc")]
pub async fn sweep_idle_sessions(state: &DashboardState) -> usize {
    let expired: Vec<_> = state
        .webrtc_sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|(_, sess)| {
            sess.last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed()
                >= std::time::Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS)
        })
        .map(|(id, _)| id.clone())
        .collect();
    let mut removed = 0;
    for id in expired {
        removed += usize::from(remove_session(state, &id).await);
    }
    removed
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

/// `GET /api/webrtc/config` — bearer-protected transport capabilities.
///
/// TURN credentials are necessary for authorized peers, not public metadata.
/// The H.264 track is a lossy preview and does not preserve LSB evidence.
pub async fn api_webrtc_config(
    State(state): State<std::sync::Arc<DashboardState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !crate::check_auth(&headers, &state.auth_token) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "Unauthorized"})),
        )
            .into_response();
    }
    #[cfg(feature = "webrtc")]
    let ice_servers = state.ice_servers.clone();
    #[cfg(not(feature = "webrtc"))]
    let ice_servers: Vec<String> = Vec::new();
    let webrtc = cfg!(feature = "webrtc");
    let media = webrtc && state.transport != crate::TransportPolicy::Websocket;
    axum::Json(json!({
        "default_transport": state.transport.as_str(),
        "ice_servers": ice_servers,
        "webrtc": webrtc,
        "data_channel": webrtc,
        "media": media,
        "capabilities": {
            "websocket": true,
            "webrtc": webrtc,
            "rtp_preview": media,
            "signed_media": "image/png",
        },
    }))
    .into_response()
}

/// Async event handler that forwards the remote-created DataChannel to the
/// session's frame pump.
#[cfg(feature = "webrtc")]
struct SessionEventHandler {
    dc_tx: tokio::sync::mpsc::Sender<std::sync::Arc<dyn webrtc::data_channel::DataChannel>>,
    gather_tx: tokio::sync::mpsc::Sender<()>,
    channel_seen: std::sync::atomic::AtomicBool,
    control: std::sync::Arc<SessionControl>,
}

#[cfg(feature = "webrtc")]
#[async_trait::async_trait]
impl webrtc::peer_connection::PeerConnectionEventHandler for SessionEventHandler {
    async fn on_data_channel(
        &self,
        data_channel: std::sync::Arc<dyn webrtc::data_channel::DataChannel>,
    ) {
        if self.control.is_stopped()
            || self
                .channel_seen
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = data_channel.close().await;
            return;
        }
        if let Err(error) = self.dc_tx.try_send(data_channel) {
            let _ = error.into_inner().close().await;
            self.control.stop();
        }
    }

    async fn on_ice_gathering_state_change(
        &self,
        state: webrtc::peer_connection::RTCIceGatheringState,
    ) {
        if state == webrtc::peer_connection::RTCIceGatheringState::Complete {
            let _ = self.gather_tx.try_send(());
        }
    }

    async fn on_connection_state_change(
        &self,
        state: webrtc::peer_connection::RTCPeerConnectionState,
    ) {
        use webrtc::peer_connection::RTCPeerConnectionState;
        if matches!(
            state,
            RTCPeerConnectionState::Disconnected
                | RTCPeerConnectionState::Failed
                | RTCPeerConnectionState::Closed
        ) {
            self.control.stop();
        }
    }

    async fn on_ice_connection_state_change(
        &self,
        state: webrtc::peer_connection::RTCIceConnectionState,
    ) {
        use webrtc::peer_connection::RTCIceConnectionState;
        if matches!(
            state,
            RTCIceConnectionState::Disconnected
                | RTCIceConnectionState::Failed
                | RTCIceConnectionState::Closed
        ) {
            self.control.stop();
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

    // Parse strictly before allocating sockets or starting a peer driver.
    let media_candidate = req.sdp.lines().any(|l| l.starts_with("m=video"))
        && state.transport != crate::TransportPolicy::Websocket;
    let offer = match webrtc::peer_connection::RTCSessionDescription::offer(req.sdp) {
        Ok(offer) => offer,
        Err(error) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": format!("invalid SDP offer: {}", error)})),
            )
                .into_response();
        }
    };
    let slot = match SESSION_SLOTS.try_acquire() {
        Ok(slot) => slot,
        Err(_) => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(json!({"error": "WebRTC session limit reached"})),
            )
                .into_response();
        }
    };
    let control = std::sync::Arc::new(SessionControl::new(slot));
    let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel(1);

    // ICE servers come from the configured list (empty by default: localhost
    // host candidates only, no traffic beyond loopback).
    let rtc_config = webrtc::peer_connection::RTCConfigurationBuilder::new()
        .with_ice_servers(parse_ice_servers(&state.ice_servers))
        .build();
    let (gather_tx, mut gather_rx) = tokio::sync::mpsc::channel(1);
    // The default MediaEngine carries no codecs; without registration the
    // video transceiver cannot be created. Only register when the offer
    // carries video and policy allows media, keeping data-only answers
    // byte-identical to the previous behavior.
    let base_builder = PeerConnectionBuilder::<String>::new()
        .with_configuration(rtc_config)
        .with_data_channel_send_buffer_limit(REPLY_HIGH_WATER_BYTES);
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
            channel_seen: std::sync::atomic::AtomicBool::new(false),
            control: control.clone(),
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

    let mut guard = OfferPeerGuard {
        pc: Some(pc.clone()),
        control: control.clone(),
    };

    if let Err(e) = pc.set_remote_description(offer).await {
        guard.close().await;
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
                guard.close().await;
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
            guard.close().await;
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": format!("create_answer failed: {}", e)})),
            )
                .into_response();
        }
    };
    if let Err(e) = pc.set_local_description(answer).await {
        guard.close().await;
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
            guard.close().await;
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "local description missing"})),
            )
                .into_response();
        }
    };

    if control.is_stopped() {
        guard.close().await;
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "peer closed during negotiation"})),
        )
            .into_response();
    }
    let session_id = register_session(&state, pc.clone(), control.clone());

    if media_ready {
        if let Some(publisher) = publisher {
            state
                .media_publishers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(session_id.clone(), publisher.clone());
            tokio::spawn(run_media_pump(
                state.clone(),
                session_id.clone(),
                publisher,
                control.clone(),
            ));
        }
    }

    // Spawn the frame pump once the DataChannel arrives.
    let pump_state = state.clone();
    let pump_session_id = session_id.clone();
    tokio::spawn(async move {
        let dc = tokio::select! {
            biased;
            _ = control.cancelled() => None,
            result = tokio::time::timeout(std::time::Duration::from_secs(10), dc_rx.recv()) => {
                result.ok().flatten()
            }
        };
        match dc {
            Some(dc) => run_frame_pump(pump_state, pump_session_id, dc, control).await,
            None => {
                let _ = remove_session(&pump_state, &pump_session_id).await;
            }
        }
    });
    // The bounded session pump now owns explicit close/drain on every exit.
    guard.pc = None;

    (axum::Json(json!({
        "sdp": local_sdp,
        "type": "answer",
        "session_id": session_id,
    })),)
        .into_response()
}

/// All replies share one sequential sender and a strict outstanding-byte budget.
#[cfg(feature = "webrtc")]
async fn send_reply(
    dc: &std::sync::Arc<dyn webrtc::data_channel::DataChannel>,
    control: &SessionControl,
    msg_id: u64,
    received_unix_ms: u64,
    mut reply: serde_json::Value,
) -> Result<(), &'static str> {
    reply["msg_id"] = json!(msg_id);
    if reply.get("received_unix_ms").is_none() {
        reply["received_unix_ms"] = json!(received_unix_ms);
    }
    let reply_text = reply.to_string();
    if reply_text.len() > MESSAGE_MAX_BYTES {
        return Err("reply exceeds message limit");
    }
    let send = async {
        if reply_text.len() <= CHUNK_PAYLOAD_MAX {
            wait_reply_capacity(dc, reply_text.len()).await?;
            dc.send_text(&reply_text)
                .await
                .map_err(|_| "reply send failed")?;
        } else {
            let count = reply_text.len().div_ceil(CHUNK_PAYLOAD_MAX);
            for (index, payload) in reply_text.as_bytes().chunks(CHUNK_PAYLOAD_MAX).enumerate() {
                let len = CHUNK_HEADER_BYTES + payload.len();
                wait_reply_capacity(dc, len).await?;
                // Build only the next chunk, rather than copying the whole reply
                // into another vector of chunks retained until its final send.
                let mut chunk = BytesMut::with_capacity(len);
                chunk.extend_from_slice(&FRAMING_MAGIC.to_be_bytes());
                chunk.extend_from_slice(&(msg_id | (1 << 63)).to_be_bytes());
                chunk.extend_from_slice(&(index as u32).to_be_bytes());
                chunk.extend_from_slice(&(count as u32).to_be_bytes());
                chunk.extend_from_slice(payload);
                dc.send(chunk).await.map_err(|_| "reply send failed")?;
            }
        }
        Ok(())
    };
    tokio::select! {
        biased;
        _ = control.cancelled() => Err("session closed"),
        result = tokio::time::timeout(REPLY_TIMEOUT, send) => {
            result.map_err(|_| "reply drain timed out")?
        }
    }
}

#[cfg(feature = "webrtc")]
fn reply_fits_budget(outstanding: usize, bytes: usize) -> bool {
    outstanding
        .checked_add(bytes)
        .is_some_and(|total| total <= REPLY_HIGH_WATER_BYTES)
}

#[cfg(feature = "webrtc")]
async fn wait_reply_capacity(
    dc: &std::sync::Arc<dyn webrtc::data_channel::DataChannel>,
    bytes: usize,
) -> Result<(), &'static str> {
    loop {
        let outstanding = dc.outstanding_bytes().await.map_err(|_| "channel closed")?;
        if reply_fits_budget(outstanding, bytes) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

// Deserialize only the protocol fields: ignored JSON must not expand into a
// retained Value tree alongside the bounded image/reassembly buffers.
#[cfg(feature = "webrtc")]
#[derive(serde::Deserialize)]
struct FrameRequest {
    kind: String,
    #[serde(default)]
    msg_id: u64,
    #[serde(default)]
    sent_unix_ms: u64,
    #[serde(default)]
    jpeg_b64: Option<String>,
}

/// One admitted request and one joined encode job per peer, with no detached
/// encode or send tasks. Not polling while busy lets the dependency's bounded
/// receive queue apply SCTP backpressure instead of building an application queue.
/// This bounds retained work, not queue residence time: an open-loop producer
/// offering frames faster than lossless encoding must wait for reliable delivery.
#[cfg(feature = "webrtc")]
async fn run_frame_pump(
    state: std::sync::Arc<DashboardState>,
    session_id: String,
    dc: std::sync::Arc<dyn webrtc::data_channel::DataChannel>,
    control: std::sync::Arc<SessionControl>,
) {
    use crate::ws_handler::{
        process_decode_poll, process_encode_frame, DecodeSession, EncodeSession,
    };
    use webrtc::data_channel::DataChannelEvent;

    let mut encode_session = Some(EncodeSession::new());
    let mut decode_session = DecodeSession::new();
    let mut reassembler = Reassembler::default();
    let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let event = tokio::select! {
            biased;
            _ = control.cancelled() => break,
            _ = maintenance.tick() => {
                reassembler.expire_at(std::time::Instant::now());
                let expired = {
                    let sessions = state.webrtc_sessions.lock().unwrap_or_else(|e| e.into_inner());
                    sessions.get(&session_id).is_none_or(|session| {
                        session.last_activity.lock().unwrap_or_else(|e| e.into_inner()).elapsed()
                            >= std::time::Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS)
                    })
                };
                if expired {
                    break;
                }
                continue;
            }
            event = dc.poll() => match event {
                Some(event) => event,
                None => break,
            }
        };
        match event {
            DataChannelEvent::OnClose | DataChannelEvent::OnError => break,
            DataChannelEvent::OnMessage(msg) => {
                {
                    let sessions = state
                        .webrtc_sessions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let Some(session) = sessions.get(&session_id) else {
                        break;
                    };
                    *session
                        .last_activity
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = std::time::Instant::now();
                }
                let payload = if msg.is_string {
                    if msg.data.len() > MESSAGE_MAX_BYTES {
                        break;
                    }
                    std::borrow::Cow::Borrowed(msg.data.as_ref())
                } else {
                    match reassembler.push(&msg.data) {
                        Ok(Some(payload)) => std::borrow::Cow::Owned(payload),
                        Ok(None) => continue,
                        Err(error) => {
                            log::warn!("WebRTC session {}: invalid chunk: {}", session_id, error);
                            break;
                        }
                    }
                };
                let mut request: FrameRequest = match serde_json::from_slice(payload.as_ref()) {
                    Ok(request) => request,
                    Err(_) => break,
                };
                drop(payload);
                let msg_id = request.msg_id;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                // Admission precedes base64 decode and blocking work, and applies
                // equally to ping, encode, and decode replies.
                let admitted = tokio::select! {
                    biased;
                    _ = control.cancelled() => false,
                    result = tokio::time::timeout(
                        REPLY_TIMEOUT,
                        wait_reply_capacity(&dc, CHUNK_HEADER_BYTES + CHUNK_PAYLOAD_MAX),
                    ) => matches!(result, Ok(Ok(()))),
                };
                if !admitted {
                    break;
                }
                let reply = match request.kind.as_str() {
                    "ping" => json!({
                        "kind": "pong",
                        "sent_unix_ms": request.sent_unix_ms,
                    }),
                    "encode" => {
                        match request.jpeg_b64.take() {
                            Some(b64) => {
                                let _drain = control.encode_drain.lock().await;
                                if control.is_stopped() {
                                    break;
                                }
                                let mut session =
                                    encode_session.take().expect("joined encode session");
                                let encode_state = state.clone();
                                let encode_control = control.clone();
                                let job = tokio::task::spawn_blocking(move || {
                                    let reply = if encode_control.is_stopped() {
                                        None
                                    } else {
                                        match crate::ws_handler::base64_decode(&b64) {
                                            Ok(jpeg) if jpeg.len() <= MESSAGE_MAX_BYTES => {
                                                process_encode_frame(
                                                    &encode_state,
                                                    &mut session,
                                                    &jpeg,
                                                )
                                            }
                                            _ => None,
                                        }
                                    };
                                    (session, reply)
                                });
                                // Always join: cancelling spawn_blocking would detach
                                // an encoder that can still mutate the shared cache.
                                match job.await {
                                    Ok((session, reply)) => {
                                        encode_session = Some(session);
                                        reply.unwrap_or_else(|| {
                                            json!({
                                                "type": "encode_error",
                                                "error": "invalid image or unsupported frame",
                                            })
                                        })
                                    }
                                    Err(error) => {
                                        log::warn!(
                                            "WebRTC session {}: encode job failed: {}",
                                            session_id,
                                            error
                                        );
                                        break;
                                    }
                                }
                            }
                            _ => json!({"type": "encode_error", "error": "missing jpeg_b64"}),
                        }
                    }
                    "decode_poll" | "poll" => {
                        process_decode_poll(&state, &mut decode_session).await
                    }
                    _ => json!({"type": "error", "error": "unknown request kind"}),
                };
                if let Err(error) = send_reply(&dc, &control, msg_id, now_ms, reply).await {
                    log::info!("WebRTC session {}: {}", session_id, error);
                    break;
                }
            }
            _ => {}
        }
    }
    control.stop();
    let _ = dc.close().await;
    let _ = remove_session(&state, &session_id).await;
}

// ─── H.264 media publishing ───────────────────────────────────────────────────
//
// When the browser's offer contains a video m-line and the transport policy
// allows WebRTC, the server answers with a sendonly H.264 track carrying the
// rendered preview frames as RTP. H.264 does not retain LSB signatures:
// only the lossless PNG delivered over the DataChannel is signed evidence.

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

/// Publishes a lossy H.264 preview for one WebRTC session, not signed evidence.
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
    closed: std::sync::atomic::AtomicBool,
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
            closed: std::sync::atomic::AtomicBool::new(false),
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

    fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.encoder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .encoder = None;
    }

    /// Encode and publish one preview frame as RTP (LSB data is not preserved).
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
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(MediaPublishError::Rtp("publisher closed".into()));
        }
        if width == 0
            || height == 0
            || width > crate::ws_handler::IMAGE_MAX_DIMENSION
            || height > crate::ws_handler::IMAGE_MAX_DIMENSION
        {
            return Err(MediaPublishError::Encode("invalid frame dimensions".into()));
        }
        let expected = width as usize * height as usize * 3;
        if rgb.len() != expected {
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
            ..rtc::media::Sample::new(now)
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
        webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample::new(
            std::time::Instant::now(),
            media_track,
        )
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

/// Publish new cache revisions as a lossy preview. Revisions, unlike encoder
/// frame indices, remain monotonic when an encoder reconnects or is replaced.
#[cfg(feature = "webrtc")]
async fn run_media_pump(
    state: std::sync::Arc<DashboardState>,
    session_id: String,
    publisher: std::sync::Arc<MediaPublisher>,
    control: std::sync::Arc<SessionControl>,
) {
    let mut last_published: Option<u64> = None;
    loop {
        tokio::select! {
            biased;
            _ = control.cancelled() => break,
            _ = tokio::time::sleep(MEDIA_PUMP_POLL_INTERVAL) => {}
        }
        let _drain = control.media_drain.lock().await;
        if control.is_stopped() {
            break;
        }
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
                Some(frame) if Some(frame.revision) > last_published => Some((
                    frame.revision,
                    frame.width,
                    frame.height,
                    frame.rgb_data.clone(),
                )),
                _ => None,
            }
        };
        let Some((revision, width, height, rgb)) = next else {
            continue;
        };
        match tokio::time::timeout(REPLY_TIMEOUT, publisher.publish_frame(width, height, &rgb))
            .await
        {
            Ok(Ok(())) => last_published = Some(revision),
            Ok(Err(MediaPublishError::NotNegotiated)) => {}
            result => {
                log::warn!(
                    "WebRTC session {}: media publishing stopped: {:?}",
                    session_id,
                    result
                );
                control.stop();
                break;
            }
        }
    }
    publisher.close();
    state
        .media_publishers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&session_id);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "webrtc"))]
mod tests {
    use super::*;

    static LIFECYCLE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn test_state() -> std::sync::Arc<DashboardState> {
        use std::sync::{Arc, Mutex};
        let signer = steganographer_core::Signer::generate();
        Arc::new(DashboardState {
            metrics: Arc::new(steganographer_core::StegoMetrics::new()),
            signing_backend: "ed25519".into(),
            identity: steganographer_core::crypto::encode_hex(&signer.verifying_key().to_bytes()),
            width: 320,
            height: 240,
            last_encoded_frame: Mutex::new(None),
            last_encoded_audio: Mutex::new(None),
            live_config: Mutex::new(crate::LiveConfig::default()),
            session_start: std::time::Instant::now(),
            auth_token: None,
            ots_config: steganographer_core::OtsConfig::default(),
            ots_client: None,
            ots_outcome: Mutex::new(None),
            signer,
            audio_key: [7; 32],
            transport: crate::TransportPolicy::Auto,
            webrtc_sessions: Mutex::new(std::collections::HashMap::new()),
            ice_servers: Vec::new(),
            media_publishers: Mutex::new(std::collections::HashMap::new()),
        })
    }

    async fn test_peer(
        control: std::sync::Arc<SessionControl>,
    ) -> std::sync::Arc<dyn webrtc::peer_connection::PeerConnection> {
        let mut media_engine = webrtc::peer_connection::MediaEngine::default();
        media_engine.register_default_codecs().unwrap();
        let (dc_tx, _) = tokio::sync::mpsc::channel(1);
        let (gather_tx, _) = tokio::sync::mpsc::channel(1);
        std::sync::Arc::new(
            webrtc::peer_connection::PeerConnectionBuilder::<String>::new()
                .with_media_engine(media_engine)
                .with_data_channel_send_buffer_limit(REPLY_HIGH_WATER_BYTES)
                .with_udp_addrs(vec!["127.0.0.1:0".to_string()])
                .with_handler(std::sync::Arc::new(SessionEventHandler {
                    dc_tx,
                    gather_tx,
                    channel_seen: std::sync::atomic::AtomicBool::new(false),
                    control,
                }))
                .build()
                .await
                .unwrap(),
        )
    }

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

    fn chunk(msg_id: u64, index: u32, count: u32, payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::with_capacity(CHUNK_HEADER_BYTES + payload.len());
        chunk.extend_from_slice(&FRAMING_MAGIC.to_be_bytes());
        chunk.extend_from_slice(&msg_id.to_be_bytes());
        chunk.extend_from_slice(&index.to_be_bytes());
        chunk.extend_from_slice(&count.to_be_bytes());
        chunk.extend_from_slice(payload);
        chunk
    }

    #[test]
    fn chunk_counts_are_rejected_before_partial_allocation() {
        let mut re = Reassembler::default();
        for count in [0, MESSAGE_MAX_CHUNKS as u32 + 1, u32::MAX] {
            assert!(re.push(&chunk(1, 0, count, &[])).is_err());
            assert!(re.partial.is_empty());
            assert_eq!(re.retained_bytes, 0);
        }
        assert!(re.push(&chunk(1, 2, 2, &[])).is_err());
        assert!(re
            .push(&chunk(1, 0, 1, &vec![0; CHUNK_PAYLOAD_MAX + 1]))
            .is_err());
        assert!(re.partial.is_empty());
    }

    #[test]
    fn incomplete_message_count_has_a_fixed_bound() {
        let mut re = Reassembler::default();
        for msg_id in 0..INCOMPLETE_MESSAGE_MAX as u64 {
            assert!(re.push(&chunk(msg_id, 0, 2, &[1])).unwrap().is_none());
        }
        assert!(re.push(&chunk(100, 0, 2, &[1])).is_err());
        assert_eq!(re.partial.len(), INCOMPLETE_MESSAGE_MAX);
        assert_eq!(re.retained_bytes, INCOMPLETE_MESSAGE_MAX);
    }

    #[test]
    fn message_bytes_are_bounded_even_with_a_valid_chunk_count() {
        let mut re = Reassembler::default();
        let payload = vec![7; CHUNK_PAYLOAD_MAX];
        for index in 0..MESSAGE_MAX_CHUNKS as u32 - 1 {
            assert!(re
                .push(&chunk(1, index, MESSAGE_MAX_CHUNKS as u32, &payload))
                .unwrap()
                .is_none());
        }
        assert!(re
            .push(&chunk(
                1,
                MESSAGE_MAX_CHUNKS as u32 - 1,
                MESSAGE_MAX_CHUNKS as u32,
                &payload,
            ))
            .is_err());
        assert!(re.partial.is_empty());
        assert_eq!(re.retained_bytes, 0);
    }

    #[test]
    fn aggregate_retained_bytes_are_bounded_across_messages() {
        let mut re = Reassembler::default();
        let payload = vec![7; CHUNK_PAYLOAD_MAX];
        for msg_id in 0..2 {
            for index in 0..MESSAGE_MAX_CHUNKS as u32 - 1 {
                assert!(re
                    .push(&chunk(msg_id, index, MESSAGE_MAX_CHUNKS as u32, &payload))
                    .unwrap()
                    .is_none());
            }
        }
        let retained = re.retained_bytes;
        assert!(retained <= RETAINED_MESSAGE_MAX_BYTES);
        assert!(re
            .push(&chunk(3, 0, MESSAGE_MAX_CHUNKS as u32, &payload))
            .is_err());
        assert_eq!(re.retained_bytes, retained);
        assert_eq!(re.partial.len(), 2);
    }

    #[test]
    fn duplicate_chunks_do_not_extend_absolute_expiry_or_charge_bytes() {
        let mut re = Reassembler::default();
        let now = std::time::Instant::now();
        let first = chunk(1, 0, 2, &[1, 2, 3]);
        assert!(re.push_at(&first, now).unwrap().is_none());
        assert!(re
            .push_at(
                &first,
                now + std::time::Duration::from_secs(MESSAGE_EXPIRY_SECS - 1),
            )
            .unwrap()
            .is_none());
        assert_eq!(re.retained_bytes, 3);
        re.expire_at(now + std::time::Duration::from_secs(MESSAGE_EXPIRY_SECS));
        assert!(re.partial.is_empty());
        assert_eq!(re.retained_bytes, 0);
        // An old final chunk cannot resurrect the expired first chunk.
        assert!(re
            .push_at(
                &chunk(1, 1, 2, &[4]),
                now + std::time::Duration::from_secs(MESSAGE_EXPIRY_SECS),
            )
            .unwrap()
            .is_none());
        assert_eq!(re.retained_bytes, 1);
    }

    #[test]
    fn completion_and_count_mismatch_release_retained_budget() {
        let mut re = Reassembler::default();
        assert!(re.push(&chunk(1, 0, 2, &[1, 2])).unwrap().is_none());
        assert_eq!(re.push(&chunk(1, 1, 2, &[3])).unwrap(), Some(vec![1, 2, 3]));
        assert!(re.partial.is_empty());
        assert_eq!(re.retained_bytes, 0);
        assert!(re.push(&chunk(2, 0, 2, &[1, 2])).unwrap().is_none());
        assert!(re.push(&chunk(2, 1, 3, &[3])).is_err());
        assert!(re.partial.is_empty());
        assert_eq!(re.retained_bytes, 0);
    }

    #[test]
    fn empty_payload_has_one_complete_frame() {
        let chunks = frame_chunks(1, &[]);
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            Reassembler::default().push(&chunks[0]).unwrap(),
            Some(Vec::new())
        );
    }

    #[test]
    fn exact_message_limit_roundtrips_without_retaining_completed_bytes() {
        let payload = vec![0xA5; MESSAGE_MAX_BYTES];
        let chunks = frame_chunks(1, &payload);
        assert_eq!(chunks.len(), MESSAGE_MAX_CHUNKS);
        let mut re = Reassembler::default();
        for chunk in &chunks[..chunks.len() - 1] {
            assert!(re.push(chunk).unwrap().is_none());
        }
        assert_eq!(re.push(chunks.last().unwrap()).unwrap(), Some(payload));
        assert!(re.partial.is_empty());
        assert_eq!(re.retained_bytes, 0);
    }

    #[test]
    fn expiration_releases_incomplete_slots_before_new_admission() {
        let now = std::time::Instant::now();
        let mut re = Reassembler::default();
        for msg_id in 0..INCOMPLETE_MESSAGE_MAX as u64 {
            assert!(re
                .push_at(&chunk(msg_id, 0, 2, &[1]), now)
                .unwrap()
                .is_none());
        }
        assert!(re
            .push_at(
                &chunk(100, 0, 2, &[2]),
                now + std::time::Duration::from_secs(MESSAGE_EXPIRY_SECS),
            )
            .unwrap()
            .is_none());
        assert_eq!(re.partial.len(), 1);
        assert_eq!(re.retained_bytes, 1);
    }

    #[tokio::test]
    async fn cancellation_is_latched_before_a_waiter_subscribes() {
        static SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let control = SessionControl::new(SLOT.try_acquire().unwrap());
        control.stop();
        assert!(control.is_stopped());
        tokio::time::timeout(std::time::Duration::from_millis(100), control.cancelled())
            .await
            .expect("an already stopped session must not wait for a new notification");
    }

    /// Stop consuming on a real reliable channel until the bounded reply sender
    /// encounters backpressure, then drain and verify every byte of every reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_consumer_backpressures_replies_without_loss_or_budget_overshoot() {
        use std::sync::Arc;
        use webrtc::data_channel::DataChannelEvent;
        use webrtc::peer_connection::PeerConnectionBuilder;

        static SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let control = Arc::new(SessionControl::new(SLOT.try_acquire().unwrap()));
        let (server_dc_tx, mut server_dc_rx) = tokio::sync::mpsc::channel(1);
        let (server_gather_tx, mut server_gather_rx) = tokio::sync::mpsc::channel(1);
        let server: Arc<dyn webrtc::peer_connection::PeerConnection> = Arc::new(
            PeerConnectionBuilder::<String>::new()
                .with_udp_addrs(vec!["127.0.0.1:0".into()])
                .with_data_channel_send_buffer_limit(REPLY_HIGH_WATER_BYTES)
                .with_handler(Arc::new(SessionEventHandler {
                    dc_tx: server_dc_tx,
                    gather_tx: server_gather_tx,
                    channel_seen: std::sync::atomic::AtomicBool::new(false),
                    control: control.clone(),
                }))
                .build()
                .await
                .unwrap(),
        );
        let (client_dc_tx, _client_dc_rx) = tokio::sync::mpsc::channel(1);
        let (client_gather_tx, mut client_gather_rx) = tokio::sync::mpsc::channel(1);
        let client: Arc<dyn webrtc::peer_connection::PeerConnection> = Arc::new(
            PeerConnectionBuilder::<String>::new()
                .with_udp_addrs(vec!["127.0.0.1:0".into()])
                .with_handler(Arc::new(SessionEventHandler {
                    dc_tx: client_dc_tx,
                    gather_tx: client_gather_tx,
                    channel_seen: std::sync::atomic::AtomicBool::new(false),
                    control: control.clone(),
                }))
                .build()
                .await
                .unwrap(),
        );
        let client_dc = client.create_data_channel("frames", None).await.unwrap();
        client
            .set_local_description(client.create_offer(None).await.unwrap())
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), client_gather_rx.recv())
            .await
            .unwrap()
            .unwrap();
        server
            .set_remote_description(client.local_description().await.unwrap())
            .await
            .unwrap();
        server
            .set_local_description(server.create_answer(None).await.unwrap())
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), server_gather_rx.recv())
            .await
            .unwrap()
            .unwrap();
        client
            .set_remote_description(server.local_description().await.unwrap())
            .await
            .unwrap();
        let server_dc =
            tokio::time::timeout(std::time::Duration::from_secs(10), server_dc_rx.recv())
                .await
                .unwrap()
                .unwrap();
        for dc in [&client_dc, &server_dc] {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    match dc.poll().await {
                        Some(DataChannelEvent::OnOpen) => break,
                        Some(DataChannelEvent::OnClose | DataChannelEvent::OnError) | None => {
                            panic!("channel closed during negotiation");
                        }
                        _ => {}
                    }
                }
            })
            .await
            .unwrap();
        }

        // Exceed both transport receive queues and the SCTP window, not merely
        // the application chunk size. No consumer pump may drain in this phase.
        const REPLIES: u64 = 8;
        const BODY_BYTES: usize = MESSAGE_MAX_BYTES - 4096;
        let send_dc = server_dc.clone();
        let send_control = control.clone();
        let sender = tokio::spawn(async move {
            for id in 1..=REPLIES {
                wait_reply_capacity(&send_dc, CHUNK_HEADER_BYTES + CHUNK_PAYLOAD_MAX)
                    .await
                    .unwrap();
                send_reply(
                    &send_dc,
                    &send_control,
                    id,
                    0,
                    json!({
                        "body": ((b'a' + id as u8) as char).to_string().repeat(BODY_BYTES),
                    }),
                )
                .await
                .unwrap();
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let outstanding = server_dc.outstanding_bytes().await.unwrap();
                assert!(outstanding <= REPLY_HIGH_WATER_BYTES);
                if outstanding > REPLY_HIGH_WATER_BYTES - CHUNK_HEADER_BYTES - CHUNK_PAYLOAD_MAX {
                    assert!(
                        !sender.is_finished(),
                        "consumer has not drained the offered workload"
                    );
                    break;
                }
                assert!(
                    !sender.is_finished(),
                    "workload must encounter real backpressure"
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reply queue never reached its bounded high water");

        let mut reassembler = Reassembler::default();
        for id in 1..=REPLIES {
            let payload = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    assert!(server_dc.outstanding_bytes().await.unwrap() <= REPLY_HIGH_WATER_BYTES);
                    match client_dc.poll().await {
                        Some(DataChannelEvent::OnMessage(message)) => {
                            assert!(!message.is_string, "large replies use chunk framing");
                            if let Some(payload) = reassembler.push(&message.data).unwrap() {
                                break payload;
                            }
                        }
                        Some(DataChannelEvent::OnClose | DataChannelEvent::OnError) | None => {
                            panic!("channel closed before lossless delivery");
                        }
                        _ => {}
                    }
                }
            })
            .await
            .expect("reply delivery stalled after consumer resumed");
            let reply: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(
                reply["msg_id"], id,
                "exactly one ordered reply per admission"
            );
            let body = reply["body"].as_str().unwrap().as_bytes();
            assert_eq!(body.len(), BODY_BYTES);
            assert!(body.iter().all(|&byte| byte == b'a' + id as u8));
        }
        sender.await.unwrap();
        server.close().await.unwrap();
        client.close().await.unwrap();
        assert!(server_dc.send_text("after close").await.is_err());
    }

    #[tokio::test]
    async fn config_credentials_require_the_configured_bearer_token() {
        let mut state = test_state();
        let config = std::sync::Arc::get_mut(&mut state).unwrap();
        config.auth_token = Some("dashboard-secret".into());
        config.ice_servers = vec!["turn:user:turn-secret@relay.invalid:3478".into()];
        config.transport = crate::TransportPolicy::Websocket;
        for token in [None, Some("Bearer wrong")] {
            let mut headers = axum::http::HeaderMap::new();
            if let Some(token) = token {
                headers.insert(axum::http::header::AUTHORIZATION, token.parse().unwrap());
            }
            let response = api_webrtc_config(State(state.clone()), headers).await;
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert!(!String::from_utf8_lossy(&body).contains("turn-secret"));
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer dashboard-secret".parse().unwrap(),
        );
        let response = api_webrtc_config(State(state), headers).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            response["ice_servers"][0],
            "turn:user:turn-secret@relay.invalid:3478"
        );
        assert_eq!(response["default_transport"], "websocket");
        assert_eq!(response["data_channel"], true);
        assert_eq!(response["media"], false);
        assert_eq!(response["capabilities"]["signed_media"], "image/png");
    }

    #[tokio::test]
    async fn strict_invalid_sdp_never_retains_a_session_admission() {
        let _serial = LIFECYCLE_TEST_LOCK.lock().await;
        let state = test_state();
        let before = SESSION_SLOTS.available_permits();
        for _ in 0..3 {
            let response = handle_offer_with_webrtc(
                state.clone(),
                OfferRequest {
                    kind: "offer".into(),
                    sdp: "v=0\r\no=bogus\r\n".into(),
                },
            )
            .await;
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        }
        assert!(state.webrtc_sessions.lock().unwrap().is_empty());
        assert!(state.media_publishers.lock().unwrap().is_empty());
        assert_eq!(SESSION_SLOTS.available_permits(), before);
    }

    #[tokio::test]
    async fn session_limit_rejects_an_offer_before_building_a_peer() {
        let _serial = LIFECYCLE_TEST_LOCK.lock().await;
        let _slots = SESSION_SLOTS
            .try_acquire_many(WEBRTC_SESSION_MAX as u32)
            .unwrap();
        let state = test_state();
        let response = handle_offer_with_webrtc(
            state.clone(),
            OfferRequest {
                kind: "offer".into(),
                sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".into(),
            },
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(state.webrtc_sessions.lock().unwrap().is_empty());
        assert!(state.media_publishers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn idle_pump_closes_publishers_and_drains_admitted_work_before_removal() {
        let _serial = LIFECYCLE_TEST_LOCK.lock().await;
        let state = test_state();
        let control =
            std::sync::Arc::new(SessionControl::new(SESSION_SLOTS.try_acquire().unwrap()));
        let pc = test_peer(control.clone()).await;
        let dc = pc.create_data_channel("frames", None).await.unwrap();
        let publisher = setup_media_sender(&pc).await.unwrap();
        let session_id = register_session(&state, pc, control.clone());
        state
            .media_publishers
            .lock()
            .unwrap()
            .insert(session_id.clone(), publisher.clone());
        *state.webrtc_sessions.lock().unwrap()[&session_id]
            .last_activity
            .lock()
            .unwrap() = std::time::Instant::now()
            - std::time::Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS + 1);
        let drain = control.encode_drain.lock().await;
        let pump = tokio::spawn(run_frame_pump(
            state.clone(),
            session_id.clone(),
            dc,
            control.clone(),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(3), control.cancelled())
            .await
            .unwrap();
        assert!(
            !pump.is_finished(),
            "admitted work must be drained, not detached"
        );
        assert!(state
            .webrtc_sessions
            .lock()
            .unwrap()
            .contains_key(&session_id));
        assert!(state
            .media_publishers
            .lock()
            .unwrap()
            .contains_key(&session_id));
        drop(drain);
        tokio::time::timeout(std::time::Duration::from_secs(3), pump)
            .await
            .unwrap()
            .unwrap();
        assert!(state.webrtc_sessions.lock().unwrap().is_empty());
        assert!(state.media_publishers.lock().unwrap().is_empty());
        assert!(publisher.closed.load(std::sync::atomic::Ordering::Acquire));
        assert!(publisher.encoder.lock().unwrap().encoder.is_none());
    }

    #[tokio::test]
    async fn cancelled_offer_guard_explicitly_closes_its_peer() {
        let _serial = LIFECYCLE_TEST_LOCK.lock().await;
        let control =
            std::sync::Arc::new(SessionControl::new(SESSION_SLOTS.try_acquire().unwrap()));
        let pc = test_peer(control.clone()).await;
        let dc = pc.create_data_channel("frames", None).await.unwrap();
        let guard = OfferPeerGuard {
            pc: Some(pc.clone()),
            control,
        };
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while dc.poll().await.is_some() {}
        })
        .await
        .unwrap();
        assert!(dc.send_text("after close").await.is_err());
    }

    #[tokio::test]
    async fn oversize_reply_is_rejected_without_queueing_channel_bytes() {
        let _serial = LIFECYCLE_TEST_LOCK.lock().await;
        let control =
            std::sync::Arc::new(SessionControl::new(SESSION_SLOTS.try_acquire().unwrap()));
        let pc = test_peer(control.clone()).await;
        let dc = pc.create_data_channel("frames", None).await.unwrap();
        let reply = json!({"frame": "x".repeat(MESSAGE_MAX_BYTES)});
        assert_eq!(
            send_reply(&dc, &control, 1, 0, reply).await,
            Err("reply exceeds message limit"),
        );
        assert_eq!(dc.outstanding_bytes().await.unwrap(), 0);
        pc.close().await.unwrap();
    }
}
