//! WebRTC data-channel transport for the video encode pipeline (WHIP-style).
//!
//! # Signaling
//!
//! `POST /api/webrtc/offer` accepts a browser SDP offer as JSON
//! `{"type": "offer", "sdp": "v=0 ..."}` and returns the server SDP answer as
//! `{"type": "answer", "sdp": "..."}` in a single request (WHIP-style
//! signaling). ICE candidates are exchanged non-trickle: the server waits for
//! gathering to complete and embeds the full candidate set in the answer SDP,
//! so the whole negotiation is one request. (The dashboard targets localhost
//! Chrome/Edge/Firefox; the server gathers a loopback candidate via
//! `SettingEngineBuilder::with_include_loopback_candidate(true)` because
//! loopback addresses are filtered by default per RFC 8445.)
//!
//! # Media path
//!
//! No RTP media tracks are used. The browser creates an `RTCDataChannel`
//! named `"frames"` and sends one JPEG frame per binary message — the exact
//! payload shape the `/ws/encode` WebSocket path uses. The server runs the
//! same pipeline (`ws_handler::FramePipeline`: JPEG decode → sign pre-embed
//! pixels → LSB embed → re-encode JPEG → store in `last_encoded_frame`) and
//! replies with two data-channel text messages, byte-identical to the WS
//! message shapes:
//!
//! 1. `{"type":"encoded_frame", ...}` — the encoded JPEG (base64) + metrics,
//!    identical to the `/ws/encode` reply, and
//! 2. `{"type":"decoded_frame", ...}` — the extract + signature verification
//!    result, identical to the `/ws/decode` reply, so the right verification
//!    panel works unchanged and verification state (metrics counters) updates
//!    even when no separate decode WebSocket client is connected.
//!
//! A text message `"ping"` is answered with the same `{"type":"metrics",...}`
//! reply the WS heartbeat uses.
//!
//! # Security
//!
//! The signaling endpoint reuses the same Bearer-token auth gate
//! (`check_auth`) as the other mutating POST endpoints. No Origin check is
//! required: unlike a WebSocket upgrade, a POST carries no ambient browser
//! credentials, and a cross-origin attacker who can *send* the request still
//! cannot read the JSON response cross-origin (no CORS headers on this
//! route), so the negotiated answer cannot be exfiltrated. Data-channel
//! messages pass the same size caps as WS (`WS_MAX_MESSAGE_SIZE`, plus the
//! `IMAGE_MAX_DIMENSION` decompression-bomb guard inside the pipeline).
//!
//! # Lifecycle
//!
//! Each offer spawns one answer-side [`PeerConnection`]. A reaper task owns
//! the connection and closes it when the data channel closes, when the peer
//! disconnects, when the connection fails, or when an offer never connects
//! within the negotiation timeout — abandoned offers cannot leak sockets.
//!
//! # Latency/fps verification
//!
//! End-to-end latency and FPS cannot be asserted by in-process tests; they
//! require a real browser. The orchestrator may verify them with headless
//! Chromium against the UI toggle (see the TODO Long-Term Backlog report);
//! the in-process tests prove the signaling, data-channel and pipeline
//! round trip instead.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::SettingEngineBuilder;
use webrtc::peer_connection::{
    register_default_interceptors, MediaEngine, PeerConnection, PeerConnectionBuilder,
    PeerConnectionEventHandler, RTCConfigurationBuilder, RTCIceGatheringState,
    RTCPeerConnectionState, RTCSdpType, RTCSessionDescription, Registry,
};
use webrtc::runtime::TokioRuntime;

use crate::ws_handler::{ots_metrics_json, FramePipeline, FrameVerifier, WS_MAX_MESSAGE_SIZE};
use crate::{check_auth, DashboardState};

/// Never-connected deadline: an offer that does not reach `Connected` within
/// this window has its PeerConnection closed by the reaper.
const NEGOTIATION_TIMEOUT_SECS: u64 = 60;
/// How long the server waits for ICE gathering to complete before answering.
/// Host candidates only (localhost audience) gather in well under a second.
const GATHER_TIMEOUT_SECS: u64 = 10;
/// Session lifecycle signals forwarded from the answer-side event handler to
/// the reaper task ([`reap_connection`]).
enum LifecycleEvent {
    /// Peer connection reached `Connected`: the negotiation deadline is lifted.
    Connected,
    /// Peer disconnected, failed, or the connection closed.
    Disconnected,
    /// The browser closed the data channel: the session is over.
    DataChannelClosed,
}
/// Answer-side event handler: forwards non-trickle ICE gathering completion
/// and lifecycle state to the reaper, and spawns a frame loop per data
/// channel the browser creates.
struct WebrtcHandler {
    state: Arc<DashboardState>,
    gather_tx: tokio::sync::mpsc::Sender<()>,
    lifecycle_tx: tokio::sync::mpsc::UnboundedSender<LifecycleEvent>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for WebrtcHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            // Capacity 1 + try_send: a pending notification is already
            // stored, so an extra Complete is a no-op.
            let _ = self.gather_tx.try_send(());
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        match state {
            RTCPeerConnectionState::Connected => {
                let _ = self.lifecycle_tx.send(LifecycleEvent::Connected);
            }
            RTCPeerConnectionState::Disconnected
            | RTCPeerConnectionState::Failed
            | RTCPeerConnectionState::Closed => {
                let _ = self.lifecycle_tx.send(LifecycleEvent::Disconnected);
            }
            _ => {}
        }
    }

    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        // Must spawn: blocking here would stall the peer-connection driver.
        let state = Arc::clone(&self.state);
        let lifecycle_tx = self.lifecycle_tx.clone();
        tokio::spawn(run_data_channel(state, dc, lifecycle_tx));
    }
}

/// Data-channel event loop: receives JPEG frames from the browser, runs the
/// shared encode pipeline, verifies the result, and replies with the same
/// message shapes as the WebSocket handlers.
async fn run_data_channel(
    state: Arc<DashboardState>,
    dc: Arc<dyn DataChannel>,
    lifecycle_tx: tokio::sync::mpsc::UnboundedSender<LifecycleEvent>,
) {
    let mut pipeline = FramePipeline::new();
    let mut verifier = FrameVerifier::new();

    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => {
                log::info!("WebRTC data channel open");
            }
            Some(DataChannelEvent::OnMessage(msg)) => {
                if msg.is_string {
                    let text = String::from_utf8_lossy(&msg.data);
                    // Same heartbeat contract as the encode WebSocket: a text
                    // "ping" is answered with a metrics reply.
                    if text.contains("ping") {
                        let metrics_json = state.metrics.to_json();
                        let reply = serde_json::json!({
                            "type": "metrics",
                            "data": serde_json::from_str::<serde_json::Value>(&metrics_json)
                                .unwrap_or_default(),
                            "backend": state.signing_backend,
                            "identity": state.identity,
                            "ots": ots_metrics_json(&state),
                        });
                        if dc.send_text(&reply.to_string()).await.is_err() {
                            break;
                        }
                    }
                    continue;
                }

                // Same size cap as the WebSocket path (4 MiB): bounds
                // client-controlled allocation before JPEG decoding.
                if msg.data.len() > WS_MAX_MESSAGE_SIZE {
                    let err = serde_json::json!({
                        "type": "error",
                        "message": format!(
                            "frame too large ({} bytes, max {WS_MAX_MESSAGE_SIZE})",
                            msg.data.len()
                        ),
                    });
                    if dc.send_text(&err.to_string()).await.is_err() {
                        break;
                    }
                    continue;
                }

                // Sign → LSB embed → re-encode → store — byte-identical to
                // the WS encode path's per-frame work.
                let encoded = match pipeline.encode_frame(&state, &msg.data) {
                    Ok(reply) => reply,
                    Err(err) => err,
                };
                if dc.send_text(&encoded.to_string()).await.is_err() {
                    break;
                }

                // Extract + verify the frame just embedded (updates the
                // verification metrics); mirrors the /ws/decode reply.
                let decoded = verifier.verify_latest(&state);
                if dc.send_text(&decoded.to_string()).await.is_err() {
                    break;
                }
            }
            Some(DataChannelEvent::OnClose) | Some(DataChannelEvent::OnClosing) | None => break,
            _ => {}
        }
    }

    log::info!("WebRTC data channel closed");
    let _ = lifecycle_tx.send(LifecycleEvent::DataChannelClosed);
}

/// Owns an answer-side peer connection and closes it when the session ends
/// (peer disconnect/failure, data channel closed) or when an offer never
/// connects within the negotiation timeout.
async fn reap_connection(
    pc: Arc<dyn PeerConnection>,
    mut events: tokio::sync::mpsc::UnboundedReceiver<LifecycleEvent>,
) {
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(NEGOTIATION_TIMEOUT_SECS));
    tokio::pin!(deadline);
    let mut connected = false;
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            event = events.recv() => match event {
                Some(LifecycleEvent::Connected) => {
                    // Connected: the negotiation deadline no longer applies.
                    // The reaper now closes on disconnect/failure or when the
                    // data channel closes; idle-but-connected sessions are
                    // bounded by the ICE Disconnected event instead.
                    if !connected {
                        connected = true;
                        deadline.set(tokio::time::sleep(
                            std::time::Duration::from_secs(24 * 60 * 60),
                        ));
                    }
                }
                Some(LifecycleEvent::Disconnected) | Some(LifecycleEvent::DataChannelClosed) => break,
                None => break, // handler (and connection) already gone
            },
        }
    }
    let _ = pc.close().await;
    log::info!("WebRTC peer connection closed");
}

/// Build the media engine + interceptor registry used by every answer-side
/// peer connection. Default codecs keep the answer compatible even if a
/// browser offer carries an audio/video m-line.
fn media_setup() -> Result<(MediaEngine, Registry), String> {
    let mut media = MediaEngine::default();
    media
        .register_default_codecs()
        .map_err(|e| format!("failed to register default codecs: {e}"))?;
    let registry = register_default_interceptors(Registry::new(), &mut media)
        .map_err(|e| format!("failed to register interceptors: {e}"))?;
    Ok((media, registry))
}

/// Build an answer-side peer connection.
///
/// Binds UDP on all interfaces with loopback candidate gathering enabled: the
/// dashboard's audience connects from the same machine over `127.0.0.1`, and
/// loopback addresses are filtered by default per RFC 8445.
async fn build_answer_connection(
    state: Arc<DashboardState>,
) -> Result<
    (
        Arc<dyn PeerConnection>,
        tokio::sync::mpsc::Receiver<()>,
        tokio::sync::mpsc::UnboundedReceiver<LifecycleEvent>,
    ),
    String,
> {
    let (media, registry) = media_setup()?;
    let (gather_tx, gather_rx) = tokio::sync::mpsc::channel(1);
    let (lifecycle_tx, lifecycle_rx) = tokio::sync::mpsc::unbounded_channel();
    let pc = PeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_include_loopback_candidate(true)
                .build(),
        )
        .with_handler(Arc::new(WebrtcHandler {
            state,
            gather_tx,
            lifecycle_tx,
        }))
        .with_runtime(Arc::new(TokioRuntime))
        .with_udp_addrs(vec!["0.0.0.0:0"])
        .build()
        .await
        .map_err(|e| format!("failed to build peer connection: {e}"))?;
    Ok((Arc::new(pc), gather_rx, lifecycle_rx))
}

/// WHIP-style signaling endpoint: `POST /api/webrtc/offer`.
///
/// Body: `{"type": "offer", "sdp": "v=0 ..."}` (browser SDP offer).
/// Response: `{"type": "answer", "sdp": "v=0 ..."}` with non-trickle ICE
/// (all server candidates embedded). The WebRTC transport reuses the session
/// signer and live config, so frames arriving on the data channel are
/// processed exactly like frames arriving on `/ws/encode`.
///
/// The signaling endpoint reuses the same Bearer-token auth gate as the other
/// mutating POST endpoints. No Origin check is needed: a POST carries no
/// ambient credentials and the response is not readable cross-origin without
/// CORS headers (see module docs).
pub async fn api_webrtc_offer(
    State(state): State<Arc<DashboardState>>,
    headers: axum::http::HeaderMap,
    Json(offer): Json<RTCSessionDescription>,
) -> axum::response::Response {
    if !check_auth(&headers, &state.auth_token) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            serde_json::json!({ "status": "error", "message": "Unauthorized" }).to_string(),
        )
            .into_response();
    }

    if offer.sdp_type != RTCSdpType::Offer {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({
                "status": "error",
                "message": format!("expected an SDP offer, got {:?}", offer.sdp_type),
            })
            .to_string(),
        )
            .into_response();
    }

    let (pc, mut gather_rx, lifecycle_rx) = match build_answer_connection(Arc::clone(&state)).await
    {
        Ok(parts) => parts,
        Err(msg) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "status": "error", "message": msg }).to_string(),
            )
                .into_response();
        }
    };
    if let Err(e) = pc.set_remote_description(offer).await {
        // Clean up the half-built connection; no reaper owns it yet.
        let _ = pc.close().await;
        return (
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({
                "status": "error",
                "message": format!("failed to set remote description: {e}"),
            })
            .to_string(),
        )
            .into_response();
    }
    let answer = match pc.create_answer(None).await {
        Ok(answer) => answer,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "status": "error",
                    "message": format!("failed to create answer: {e}"),
                })
                .to_string(),
            )
                .into_response();
        }
    };
    if let Err(e) = pc.set_local_description(answer).await {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "status": "error",
                "message": format!("failed to set local description: {e}"),
            })
            .to_string(),
        )
            .into_response();
    }

    // Non-trickle ICE: wait for gathering to complete so the answer SDP
    // carries every server candidate and no later signaling round is needed.
    let gathered = tokio::time::timeout(
        std::time::Duration::from_secs(GATHER_TIMEOUT_SECS),
        gather_rx.recv(),
    )
    .await
    .is_ok();
    if !gathered {
        log::warn!("WebRTC offer: ICE gathering did not complete in {GATHER_TIMEOUT_SECS}s");
    }

    let Some(answer_sdp) = pc.local_description().await else {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "status": "error",
                "message": "no local description after gathering",
            })
            .to_string(),
        )
            .into_response();
    };

    // Hand the connection to the reaper; the endpoint itself returns here.
    tokio::spawn(reap_connection(Arc::clone(&pc), lifecycle_rx));

    log::info!("WebRTC offer answered (non-trickle ICE)");
    Json(answer_sdp).into_response()
}
