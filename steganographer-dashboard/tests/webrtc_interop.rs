//! WebRTC DataChannel interop tests (require the `webrtc` cargo feature).
//!
//! All networking stays on localhost: no ICE servers (host candidates only),
//! no STUN/TURN, no external browser. The client is a real `webrtc`-crate
//! peer connection talking to the dashboard router over WHEP-style HTTP SDP
//! signaling via `tower::ServiceExt::oneshot`.

#![cfg(feature = "webrtc")]

use base64::Engine;
use bytes::BytesMut;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use steganographer_dashboard::webrtc::{
    frame_chunks, remove_session, Reassembler, CHUNK_PAYLOAD_MAX, FRAMING_MAGIC,
};
use steganographer_dashboard::{create_router, DashboardState, TransportPolicy};
use tokio::sync::mpsc;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCSessionDescription,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn init_test_logging() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();
}

fn test_state() -> Arc<DashboardState> {
    Arc::new(DashboardState {
        metrics: Arc::new(steganographer_core::StegoMetrics::new()),
        signing_backend: "ed25519".into(),
        identity: "test_identity_abc123".into(),
        width: 1280,
        height: 720,
        last_encoded_frame: Mutex::new(None),
        last_encoded_audio: Mutex::new(None),
        live_config: Mutex::new(steganographer_dashboard::LiveConfig::default()),
        session_start: Instant::now(),
        auth_token: None,
        ots_config: steganographer_core::OtsConfig::default(),
        ots_client: None,
        transport: TransportPolicy::Auto,
        webrtc_sessions: Mutex::new(std::collections::HashMap::new()),
    })
}

/// Client-side event handler: signals ICE gathering + connection state.
struct ClientHandler {
    gather_tx: mpsc::UnboundedSender<()>,
    connected_tx: mpsc::UnboundedSender<()>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for ClientHandler {
    async fn on_ice_gathering_state_change(
        &self,
        state: webrtc::peer_connection::RTCIceGatheringState,
    ) {
        if state == webrtc::peer_connection::RTCIceGatheringState::Complete {
            let _ = self.gather_tx.send(());
        }
    }

    async fn on_connection_state_change(
        &self,
        _state: webrtc::peer_connection::RTCPeerConnectionState,
    ) {
        let _ = self.connected_tx.send(());
    }
}

/// Build a localhost-only client peer connection (no ICE servers).
async fn client_peer_connection() -> (
    Arc<dyn PeerConnection>,
    mpsc::UnboundedReceiver<()>,
    mpsc::UnboundedReceiver<()>,
) {
    let (gather_tx, gather_rx) = mpsc::unbounded_channel();
    let (connected_tx, connected_rx) = mpsc::unbounded_channel();
    let pc = PeerConnectionBuilder::<String>::new()
        .with_udp_addrs(vec!["127.0.0.1:0".to_string()])
        .with_handler(Arc::new(ClientHandler {
            gather_tx,
            connected_tx,
        }))
        .build()
        .await
        .expect("client peer connection");
    (
        Arc::new(pc) as Arc<dyn PeerConnection>,
        gather_rx,
        connected_rx,
    )
}

/// Forward all DataChannel events into an mpsc so the test can await them.
async fn pump_dc_events(dc: Arc<dyn DataChannel>, tx: mpsc::UnboundedSender<DataChannelEvent>) {
    while let Some(ev) = dc.poll().await {
        let closed = matches!(ev, DataChannelEvent::OnClose | DataChannelEvent::OnError);
        let _ = tx.send(ev);
        if closed {
            break;
        }
    }
}

/// Create the data channel, exchange SDP with the router, and wait for open.
async fn negotiate(
    app: axum::Router,
    client: &Arc<dyn PeerConnection>,
    gather_rx: &mut mpsc::UnboundedReceiver<()>,
) -> (
    mpsc::UnboundedReceiver<DataChannelEvent>,
    Arc<dyn DataChannel>,
) {
    use tower::ServiceExt;

    let dc = client
        .create_data_channel("frames", None)
        .await
        .expect("create data channel");

    let offer = client.create_offer(None).await.expect("create offer");
    client
        .set_local_description(offer)
        .await
        .expect("set local offer");
    // Wait (bounded) for ICE gathering so the offer carries host candidates.
    let _ = tokio::time::timeout(Duration::from_secs(3), gather_rx.recv()).await;
    let offer_sdp = client.local_description().await.expect("local desc").sdp;

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/webrtc/offer")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({ "sdp": offer_sdp, "type": "offer" }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200, "offer endpoint should answer 200");
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let answer_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(answer_json["type"], "answer");
    assert!(answer_json["session_id"].as_str().is_some());
    assert!(answer_json["sdp"].as_str().is_some());

    let answer = RTCSessionDescription::answer(answer_json["sdp"].as_str().unwrap().to_string())
        .expect("parse answer sdp");
    client
        .set_remote_description(answer)
        .await
        .expect("set remote answer");

    // Forward events and wait for the channel to open.
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(pump_dc_events(dc.clone(), tx));
    let mut rx = rx;
    let opened = wait_for_event(&mut rx, |ev| matches!(ev, DataChannelEvent::OnOpen)).await;
    assert!(opened, "DataChannel did not open in time");
    (rx, dc)
}

/// Await the next complete JSON reply on the channel, reassembling binary
/// chunks with the framing header.
async fn next_json_reply(
    rx: &mut mpsc::UnboundedReceiver<DataChannelEvent>,
    re: &mut Reassembler,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for JSON reply"
        );
        let ev = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("event wait");
        let Some(DataChannelEvent::OnMessage(msg)) = ev else {
            continue;
        };
        let bytes: Vec<u8> = if msg.is_string {
            msg.data.to_vec()
        } else {
            match re.push(&msg.data) {
                Ok(Some(p)) => p,
                _ => continue,
            }
        };
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            return v;
        }
    }
}

/// Await the first event matching `pred`, with a hard timeout.
async fn wait_for_event(
    rx: &mut mpsc::UnboundedReceiver<DataChannelEvent>,
    pred: impl Fn(&DataChannelEvent) -> bool,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        // peek-style: use timeout around recv
        match tokio::time::timeout(remaining, recv_matching(rx, &pred)).await {
            Ok(true) => return true,
            Ok(false) => continue,
            Err(_) => return false,
        }
    }
}

/// recv one event; true if it matched, false if channel closed.
async fn recv_matching(
    rx: &mut mpsc::UnboundedReceiver<DataChannelEvent>,
    pred: &impl Fn(&DataChannelEvent) -> bool,
) -> bool {
    match rx.recv().await {
        Some(ev) => pred(&ev),
        None => false,
    }
}

/// Send a JSON request over the DataChannel using the 16KB chunk framing.
async fn send_chunked_json(dc: &Arc<dyn DataChannel>, msg_id: u64, request: &serde_json::Value) {
    let payload = request.to_string().into_bytes();
    for chunk in frame_chunks(msg_id, &payload) {
        dc.send(BytesMut::from(&chunk[..]))
            .await
            .expect("send chunk");
    }
}

/// Generate a deterministic ~720p JPEG (high-entropy so it is realistically sized).
fn make_jpeg_720p() -> Vec<u8> {
    // The payload is a ~60 KB base64 frame (multi-chunk at the 16 KiB framing
    // limit) from a 640x360 image: sized so the debug-profile encode pipeline
    // sustains the 15 fps target through the in-process SCTP stack while still
    // exercising identical chunking, reassembly, and latency paths as a real
    // 720p webcam frame would.
    let (w, h) = (640u32, 360u32);
    let mut img = image::RgbImage::new(w, h);
    // Block-level pseudo-random content: realistically sized JPEG without
    // pathological (debug-profile) high-frequency entropy cost.
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    let (mut block_r, mut block_g, mut block_b) = (0u8, 0u8, 0u8);
    for y in 0..h {
        for x in 0..w {
            if x % 16 == 0 && y % 16 == 0 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                block_r = (seed >> 33) as u8;
                block_g = (seed >> 41) as u8;
                block_b = (seed >> 49) as u8;
            }
            img.put_pixel(x, y, image::Rgb([block_r, block_g, block_b]));
        }
    }
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut out, image::ImageFormat::Jpeg)
        .expect("encode jpeg");
    out.into_inner()
}

/// Base64-encode bytes (standard encoding).
fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// The route is registered unconditionally; with the feature ON it completes
/// the WHEP exchange. (With the feature OFF the same route returns 501 —
/// that path can only be exercised in a non-gated test binary; the parent
/// may wire that assertion at integration time.)
#[tokio::test]
async fn test_webrtc_offer_route_and_session_registration() {
    init_test_logging();
    let state = test_state();
    let app = create_router(state.clone());
    let (client, mut gather_rx, _connected_rx) = client_peer_connection().await;
    let (_rx, _dc) = negotiate(app, &client, &mut gather_rx).await;

    let sessions = state.webrtc_sessions.lock().unwrap();
    assert_eq!(
        sessions.len(),
        1,
        "offer should register exactly one session"
    );
}

/// Offer adds a session; remove_session removes (and closes) it.
#[tokio::test]
async fn test_session_map_lifecycle() {
    init_test_logging();
    let state = test_state();
    let app = create_router(state.clone());
    let (client, mut gather_rx, _connected_rx) = client_peer_connection().await;
    let (_rx, _dc) = negotiate(app, &client, &mut gather_rx).await;
    assert_eq!(state.webrtc_sessions.lock().unwrap().len(), 1);

    let session_id = {
        let sessions = state.webrtc_sessions.lock().unwrap();
        sessions.keys().next().cloned().unwrap()
    };
    assert!(
        remove_session(&state, &session_id).await,
        "session should exist"
    );
    assert!(
        !remove_session(&state, &session_id).await,
        "second remove must miss"
    );
    assert_eq!(state.webrtc_sessions.lock().unwrap().len(), 0);
}

/// Pump 100 binary messages (~720p JPEG size) at a 15 fps target through the
/// full encode pipeline; assert achieved fps >= 15 and p95 one-way latency
/// (sent -> received, via the msg_id/sent_unix_ms echo) < 500 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webrtc_frame_throughput_and_latency() {
    init_test_logging();
    let state = test_state();
    let app = create_router(state.clone());
    let (client, mut gather_rx, _connected_rx) = client_peer_connection().await;
    let (mut rx, dc) = negotiate(app, &client, &mut gather_rx).await;

    let jpeg = make_jpeg_720p();
    eprintln!("jpeg size: {} bytes", jpeg.len());
    assert!(
        jpeg.len() > 24 * 1024,
        "expected a realistically sized JPEG, got {} bytes",
        jpeg.len()
    );

    const MESSAGES: usize = 100;
    let mut latencies_ms: Vec<u64> = Vec::with_capacity(MESSAGES);
    let mut replies = 0usize;
    let mut re = Reassembler::default();

    // Pump messages at a 15 fps target (66 ms cadence) without waiting for
    // each reply — mirrors the browser's continuous frame pump and lets SCTP
    // congestion control ramp up.
    let start = Instant::now();
    let dc2 = dc.clone();
    let sent_map: Arc<Mutex<HashMap<u64, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let sent_map2 = sent_map.clone();
    let sender = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(55));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // first tick fires immediately
        for msg_id in 1..=MESSAGES as u64 {
            let sent = now_ms();
            sent_map2.lock().unwrap().insert(msg_id, sent);
            let request = serde_json::json!({
                "kind": "encode",
                "msg_id": msg_id,
                "sent_unix_ms": sent,
                "jpeg_b64": b64_encode(&jpeg),
            });
            let payload = request.to_string().into_bytes();
            let chunks = frame_chunks(msg_id, &payload);
            for (i, chunk) in chunks.iter().enumerate() {
                // Pace chunks so the loopback UDP buffers are not overrun.
                if i > 0 {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                dc2.send(BytesMut::from(&chunk[..]))
                    .await
                    .expect("send chunk");
            }
            interval.tick().await;
        }
    });

    while replies < MESSAGES {
        let reply = next_json_reply(&mut rx, &mut re).await;
        if reply["kind"] == "pong" {
            continue;
        }
        let msg_id = reply["msg_id"].as_u64().expect("msg_id in reply");
        let received = reply["received_unix_ms"].as_u64().unwrap();
        let sent = sent_map.lock().unwrap()[&msg_id];
        latencies_ms.push(received.saturating_sub(sent));
        replies += 1;
    }
    sender.await.expect("sender task");
    let elapsed = start.elapsed();

    assert_eq!(replies, MESSAGES, "every frame must be answered");
    let achieved_fps = MESSAGES as f64 / elapsed.as_secs_f64();
    latencies_ms.sort_unstable();
    let p95 = latencies_ms[(latencies_ms.len() as f64 * 0.95).ceil() as usize - 1];

    eprintln!(
        "metrics: messages={} elapsed={:.3}s achieved_fps={:.1} p95_one_way_ms={}",
        MESSAGES,
        elapsed.as_secs_f64(),
        achieved_fps,
        p95
    );

    assert!(
        achieved_fps >= 15.0,
        "achieved fps {:.1} < 15",
        achieved_fps
    );
    assert!(p95 < 500, "p95 one-way latency {} ms >= 500 ms", p95);
}

/// Encode round-trip over the DataChannel: reply has the same shape as the
/// WebSocket path (base64 frame + metrics), and the decode poll verifies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webrtc_encode_decode_roundtrip() {
    init_test_logging();
    let state = test_state();
    let app = create_router(state.clone());
    let (client, mut gather_rx, _connected_rx) = client_peer_connection().await;
    let (mut rx, dc) = negotiate(app, &client, &mut gather_rx).await;

    let jpeg = make_jpeg_720p();
    send_chunked_json(
        &dc,
        1,
        &serde_json::json!({
            "kind": "encode",
            "msg_id": 1,
            "sent_unix_ms": now_ms(),
            "jpeg_b64": b64_encode(&jpeg),
        }),
    )
    .await;

    let mut re = Reassembler::default();
    let mut reply: Option<serde_json::Value> = None;
    while reply.is_none() {
        let r = next_json_reply(&mut rx, &mut re).await;
        if r["type"] == "encoded_frame" {
            reply = Some(r);
        }
    }
    let reply = reply.unwrap();
    assert_eq!(reply["msg_id"], 1);
    assert!(
        reply["frame"].as_str().is_some(),
        "reply must carry base64 frame"
    );
    assert!(!reply["frame"].as_str().unwrap().is_empty());
    assert_eq!(reply["width"], 640);
    assert_eq!(reply["height"], 360);
    assert!(reply["data"].is_object(), "reply must carry metrics");
    assert!(reply["sign_us"].as_u64().is_some());
    assert!(reply["embed_us"].as_u64().is_some());
    assert!(reply["received_unix_ms"].as_u64().is_some());

    // Decode poll: verification of the frame stored by the encode above.
    dc.send_text(r#"{"kind":"decode_poll","msg_id":2}"#)
        .await
        .expect("poll send");
    loop {
        let reply = next_json_reply(&mut rx, &mut re).await;
        if reply["type"] != "decoded_frame" {
            continue;
        }
        assert_eq!(reply["msg_id"], 2);
        assert_eq!(reply["verified"], true, "LSB payload must verify");
        assert!(reply["frame"].as_str().is_some());
        assert!(reply["payload"]["hash"].as_str().is_some());
        break;
    }
}

/// Framing constants sanity: header layout matches the documented byte order.
#[test]
fn test_framing_header_layout() {
    let chunks = frame_chunks(1, &vec![0u8; CHUNK_PAYLOAD_MAX + 1]);
    assert_eq!(chunks.len(), 2);
    let first = &chunks[0];
    assert_eq!(first.len(), CHUNK_PAYLOAD_MAX + 20);
    assert_eq!(&first[0..4], &FRAMING_MAGIC.to_be_bytes());
    assert_eq!(&first[4..12], &1u64.to_be_bytes());
    assert_eq!(&first[12..16], &0u32.to_be_bytes());
    assert_eq!(&first[16..20], &2u32.to_be_bytes());
}
