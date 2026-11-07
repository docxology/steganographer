//! # steganographer-dashboard
//!
//! Web-based live dashboard for real-time round-trip steganography verification.
//!
//! Serves a web UI on a local port that displays:
//! - **Left panel**: Live camera feed with steganographic encoding applied
//! - **Right panel**: Verification data, live config controls, verification log
//! - **Bottom bar**: Frame metrics (FPS, verify status, signing backend, latency)
//!
//! Uses Axum + WebSocket + HTML5 Canvas for low-latency frame streaming.

pub mod webrtc;
pub mod ws_handler;
#[cfg(feature = "webrtc")]
use std::collections::HashMap;

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use steganographer_core::ots_handler;
use steganographer_core::{OTSClient, OtsConfig, Signer, StegoMetrics};
use tower_http::cors::CorsLayer;

use ws_handler::{EncodedAudioChunk, EncodedFrame};

/// Live-updatable configuration from the dashboard UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveConfig {
    /// Overlay opacity (0.0–1.0).
    #[serde(default = "default_opacity")]
    pub opacity: f64,
    /// LSB bits for embedding (1–4).
    #[serde(default = "default_lsb_bits")]
    pub lsb_bits: u8,
    /// Signing backend name.
    #[serde(default = "default_backend")]
    pub signing_backend: String,
    /// Overlay text string.
    #[serde(default = "default_overlay_text")]
    pub overlay_text: String,
    /// Sign rate in milliseconds.
    #[serde(default = "default_sign_rate")]
    pub sign_rate_ms: u32,
    /// QR overlay scale (5–100% of video width).
    #[serde(default = "default_qr_scale")]
    pub qr_scale: u32,
    /// Video resolution string (e.g. "640x480").
    #[serde(default = "default_resolution")]
    pub resolution: String,
    /// Steganography type: "lsb", "spread_spectrum", "dct".
    #[serde(default = "default_stego_type")]
    pub stego_type: String,
    /// Hash algorithm: "blake3", "sha256", "sha3-256".
    #[serde(default = "default_hash_algo")]
    pub hash_algorithm: String,
    /// Enable payload encryption.
    #[serde(default, rename = "encrypt")]
    pub encrypt: bool,
    /// Enable error correction.
    #[serde(default, rename = "ecc")]
    pub ecc: bool,
    /// Transport used for the live video feed: "websocket" (default, the
    /// `/ws/encode` path) or "webrtc" (WHIP-style offer + data channel to
    /// `/api/webrtc/offer`). The audio feed always uses WebSocket.
    #[serde(default = "default_transport", rename = "transport")]
    pub transport: Transport,
}

fn default_opacity() -> f64 {
    1.0
}
fn default_lsb_bits() -> u8 {
    1
}
fn default_backend() -> String {
    "ed25519".into()
}
fn default_overlay_text() -> String {
    "CONFIDENTIAL".into()
}
fn default_sign_rate() -> u32 {
    1000
}
fn default_qr_scale() -> u32 {
    10
}
fn default_resolution() -> String {
    "640x480".into()
}
fn default_stego_type() -> String {
    "lsb".into()
}
fn default_hash_algo() -> String {
    "blake3".into()
}

fn default_transport() -> Transport {
    Transport::Websocket
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            opacity: default_opacity(),
            lsb_bits: default_lsb_bits(),
            signing_backend: default_backend(),
            overlay_text: default_overlay_text(),
            sign_rate_ms: default_sign_rate(),
            qr_scale: default_qr_scale(),
            resolution: default_resolution(),
            stego_type: default_stego_type(),
            hash_algorithm: default_hash_algo(),
            encrypt: false,
            ecc: false,
            transport: default_transport(),
        }
    }
}

/// Wire transport for the live video feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    /// Stream JPEG frames over the `/ws/encode` WebSocket (default).
    #[serde(rename = "websocket")]
    Websocket,
    /// Stream JPEG frames over a WebRTC data channel negotiated through
    /// `POST /api/webrtc/offer`.
    #[serde(rename = "webrtc")]
    Webrtc,
}

/// Transport policy for the dashboard frame pipeline.
///
/// `Auto` tries WebRTC first (when the feature is built in) and falls back
/// to WebSocket; `Websocket` and `WebRtc` pin the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TransportPolicy {
    /// Try WebRTC DataChannel, fall back to WebSocket.
    #[default]
    Auto,
    /// Always use the WebSocket transport.
    Websocket,
    /// Always use the WebRTC DataChannel transport.
    WebRtc,
}

impl TransportPolicy {
    /// Canonical lowercase CLI/URL name for this policy.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportPolicy::Auto => "auto",
            TransportPolicy::Websocket => "websocket",
            TransportPolicy::WebRtc => "webrtc",
        }
    }
}

impl From<&str> for TransportPolicy {
    fn from(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "webrtc" => TransportPolicy::WebRtc,
            "websocket" | "ws" => TransportPolicy::Websocket,
            _ => TransportPolicy::Auto,
        }
    }
}

/// Shared dashboard state accessible by all handlers.
pub struct DashboardState {
    /// Pipeline metrics collector.
    pub metrics: Arc<StegoMetrics>,
    /// Signing backend name (initial config).
    pub signing_backend: String,
    /// Public identity (hex pubkey or Ethereum address).
    pub identity: String,
    /// Video resolution.
    pub width: u32,
    pub height: u32,
    /// Last encoded frame, shared between encode and decode WebSocket handlers.
    pub last_encoded_frame: Mutex<Option<EncodedFrame>>,
    /// Last encoded audio chunk, shared between audio encode and decode handlers.
    pub last_encoded_audio: Mutex<Option<EncodedAudioChunk>>,
    /// Live-updatable configuration from the web UI.
    pub live_config: Mutex<LiveConfig>,
    /// When the dashboard session was started.
    pub session_start: std::time::Instant,
    /// Shared secret token for authenticating mutating API calls.
    /// If `None`, auth is disabled (local-only mode).
    pub auth_token: Option<String>,
    /// OpenTimestamps configuration (opt-in; disabled by default).
    pub ots_config: OtsConfig,
    /// OTS client, present only when OTS is enabled in the config.
    pub ots_client: Option<Arc<OTSClient>>,
    /// Last actual OTS operation outcome, including its digest and pending state.
    pub ots_outcome: Mutex<Option<serde_json::Value>>,
    /// Session-wide signing keypair, generated once at startup.
    /// Both video and audio WebSocket encode handlers sign with this key and
    /// the decode handlers verify against its public half, so a frame signed
    /// by the encode side verifies on the decode side (previously each WS
    /// connection generated its own keypair, making verification impossible).
    pub signer: Signer,
    /// Session-wide 32-byte key for audio LSB embedding/derivation, shared
    /// between the audio encode and decode handlers.
    pub audio_key: [u8; 32],
    /// Transport policy for the dashboard client (resolved from CLI or config).
    pub transport: TransportPolicy,
    /// Live WebRTC DataChannel sessions, keyed by session id.
    /// Present only when the `webrtc` cargo feature is enabled.
    #[cfg(feature = "webrtc")]
    pub webrtc_sessions: Mutex<HashMap<String, webrtc::WebrtcSession>>,
    /// STUN/TURN server URLs (e.g. `stun:stun.l.google.com:19302`,
    /// `turn:user:cred@host:port`) offered to WebRTC peer connections.
    /// Empty by default: the dashboard is a local-only tool and needs no
    /// external ICE infrastructure.
    #[cfg(feature = "webrtc")]
    pub ice_servers: Vec<String>,
    /// Per-session H.264 media publishers keyed by session id. Each publisher
    /// owns the `TrackLocalStaticSample` that carries the stego'd frames as an
    /// RTP video track back to the browser.
    #[cfg(feature = "webrtc")]
    pub media_publishers: Mutex<HashMap<String, std::sync::Arc<webrtc::MediaPublisher>>>,
}

/// All documentation markdown files, embedded at compile time.
static DOCS: &[(&str, &str)] = &[
    ("README.md", include_str!("../../docs/README.md")),
    ("AGENTS.md", include_str!("../../docs/AGENTS.md")),
    ("algorithms.md", include_str!("../../docs/algorithms.md")),
    (
        "api-reference.md",
        include_str!("../../docs/api-reference.md"),
    ),
    (
        "architecture.md",
        include_str!("../../docs/architecture.md"),
    ),
    (
        "cli-reference.md",
        include_str!("../../docs/cli-reference.md"),
    ),
    (
        "configuration.md",
        include_str!("../../docs/configuration.md"),
    ),
    (
        "contributing.md",
        include_str!("../../docs/contributing.md"),
    ),
    (
        "cryptography.md",
        include_str!("../../docs/cryptography.md"),
    ),
    ("faq.md", include_str!("../../docs/faq.md")),
    (
        "getting-started.md",
        include_str!("../../docs/getting-started.md"),
    ),
    ("gstreamer.md", include_str!("../../docs/gstreamer.md")),
    ("platforms.md", include_str!("../../docs/platforms.md")),
    ("roadmap.md", include_str!("../../docs/roadmap.md")),
    ("security.md", include_str!("../../docs/security.md")),
    (
        "steganography-theory.md",
        include_str!("../../docs/steganography-theory.md"),
    ),
    (
        "ots-integration.md",
        include_str!("../../docs/ots-integration.md"),
    ),
    (
        "threat-model.md",
        include_str!("../../docs/threat-model.md"),
    ),
    (
        "key-rotation.md",
        include_str!("../../docs/key-rotation.md"),
    ),
];

/// Create the Axum router, rejecting a known compromised signing identity.
pub fn create_router(state: Arc<DashboardState>) -> anyhow::Result<Router> {
    steganographer_core::revocation::check_known_revocations(
        state.signer.verifying_key().as_bytes(),
    )?;
    // Restrict CORS to localhost only — no permissive cross-origin access
    let cors = CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    Ok(Router::new()
        .route("/", get(serve_index))
        .route("/style.css", get(serve_css))
        .route("/app.js", get(serve_js))
        .route("/audio_tab.js", get(serve_audio_js))
        .route("/docs_tab.js", get(serve_docs_js))
        .route("/ots.js", get(serve_ots_js))
        .route("/ws/encode", get(ws_handler::ws_encode_handler))
        .route("/ws/decode", get(ws_handler::ws_decode_handler))
        .route("/ws/audio/encode", get(ws_handler::ws_audio_encode_handler))
        .route("/ws/audio/decode", get(ws_handler::ws_audio_decode_handler))
        .route(
            "/api/webrtc/offer",
            axum::routing::post(api_webrtc_offer_gate),
        )
        .route("/api/webrtc/config", get(webrtc::api_webrtc_config))
        .route("/api/metrics", get(api_metrics))
        .route("/api/metrics/reset", axum::routing::post(api_metrics_reset))
        .route("/api/config", get(api_config_get).post(api_config_post))
        .route("/api/session", get(api_session))
        .route("/api/version", get(api_version))
        .route("/api/docs", get(api_docs_list))
        .route("/api/docs/{name}", get(api_docs_content))
        .route("/ots/status", get(ots_status))
        .route("/ots/stamp", axum::routing::post(ots_stamp))
        .route("/ots/verify", axum::routing::post(ots_verify))
        .layer(cors)
        .with_state(state))
}

/// `POST /api/webrtc/offer` gate: enforces the hardened contract before
/// delegating to the webrtc module — whose disabled-feature stub would
/// otherwise return 501 without any auth or request validation.
async fn api_webrtc_offer_gate(
    State(state): State<Arc<DashboardState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Some(status) = mutation_denial(&headers, &state.auth_token) {
        return (
            status,
            serde_json::json!({"status": "error", "message": "Unauthorized"}).to_string(),
        )
            .into_response();
    }
    let kind = req.get("type").and_then(|t| t.as_str());
    if kind != Some("offer") {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({
                "status": "error",
                "message": format!("expected an SDP offer, got {:?}", kind.unwrap_or("missing")),
            })
            .to_string(),
        )
            .into_response();
    }
    let sdp = req.get("sdp").and_then(|s| s.as_str());
    if !sdp.is_some_and(is_well_formed_offer_sdp) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({
                "status": "error",
                "message": "malformed SDP offer",
            })
            .to_string(),
        )
            .into_response();
    }
    let offer = webrtc::OfferRequest {
        sdp: sdp.unwrap_or_default().to_owned(),
        kind: "offer".to_owned(),
    };
    webrtc::api_webrtc_offer(State(state), axum::Json(offer)).await
}

/// Minimal structural SDP check (full parsing happens in the webrtc module
/// under the `webrtc` feature): a session description starts with `v=0` and
/// carries an `o=` line.
fn is_well_formed_offer_sdp(sdp: &str) -> bool {
    let mut lines = sdp.lines();
    lines.next() == Some("v=0") && lines.any(|l| l.starts_with("o="))
}

/// Check the Authorization header against the configured auth token.
/// Returns true if auth is disabled (no token set) or the token matches.
pub(crate) fn check_auth(headers: &axum::http::HeaderMap, expected_token: &Option<String>) -> bool {
    let Some(ref token) = expected_token else {
        return true; // Auth disabled in local-only mode
    };

    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(bearer) = auth_str.strip_prefix("Bearer ") {
                return subtle::ConstantTimeEq::ct_eq(bearer.as_bytes(), token.as_bytes()).into();
            }
        }
    }
    false
}

fn mutation_denial(
    headers: &axum::http::HeaderMap,
    token: &Option<String>,
) -> Option<axum::http::StatusCode> {
    if !check_auth(headers, token) {
        return Some(axum::http::StatusCode::UNAUTHORIZED);
    }
    if token.is_none()
        && !ws_handler::origin_allowed(
            headers.get(axum::http::header::ORIGIN),
            headers.get(axum::http::header::HOST),
        )
    {
        return Some(axum::http::StatusCode::FORBIDDEN);
    }
    None
}

/// Validate client-supplied live config before it reaches panicking
/// constructors (`LsbVideo::new`/`LsbAudio::new` panic outside 1..=4) or
/// pathological values (opacity out of range, zero sign rate busy-loop).
/// Returns a user-facing error message on the first violation.
pub fn validate_live_config(cfg: &LiveConfig) -> Result<(), String> {
    if cfg.signing_backend != "ed25519"
        || cfg.stego_type != "lsb"
        || cfg.hash_algorithm != "blake3"
        || cfg.encrypt
        || cfg.ecc
    {
        return Err(
            "dashboard supports only Ed25519, BLAKE3 and LSB without encryption or ECC".into(),
        );
    }
    #[cfg(not(feature = "webrtc"))]
    if cfg.transport == Transport::Webrtc {
        return Err("WebRTC is unavailable in this build".into());
    }
    if cfg.overlay_text.len() > 4096 || !(5..=100).contains(&cfg.qr_scale) {
        return Err("overlay_text exceeds 4096 bytes or qr_scale is outside 5-100".into());
    }
    let dimensions = cfg
        .resolution
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?)));
    if !dimensions.is_some_and(|(w, h)| w > 0 && h > 0 && w <= 4096 && h <= 4096) {
        return Err("resolution must be WIDTHxHEIGHT with dimensions 1-4096".into());
    }
    if !(1..=4).contains(&cfg.lsb_bits) {
        return Err(format!(
            "lsb_bits must be between 1 and 4, got {}",
            cfg.lsb_bits
        ));
    }
    if !(0.0..=1.0).contains(&cfg.opacity) {
        return Err(format!(
            "opacity must be between 0.0 and 1.0, got {}",
            cfg.opacity
        ));
    }
    if cfg.sign_rate_ms < 50 {
        return Err(format!(
            "sign_rate_ms must be at least 50 ms to avoid a busy loop, got {}",
            cfg.sign_rate_ms
        ));
    }
    Ok(())
}
/// Start the dashboard server.
///
/// # Arguments
/// * `state` — Shared dashboard state.
/// * `port` — TCP port to listen on.
/// * `host` — Bind address. Use "127.0.0.1" for local-only (default/recommended).
///   Use "0.0.0.0" only on trusted networks with auth enabled.
pub async fn start_server(state: Arc<DashboardState>, port: u16, host: &str) -> anyhow::Result<()> {
    {
        let config = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
        validate_live_config(&config).map_err(anyhow::Error::msg)?;
    }
    anyhow::ensure!(
        state.signing_backend == "ed25519",
        "dashboard supports only Ed25519 signing"
    );
    anyhow::ensure!(
        state.signer.hash_algorithm().name() == "blake3",
        "dashboard supports only BLAKE3 signing hashes"
    );
    #[cfg(not(feature = "webrtc"))]
    anyhow::ensure!(
        state.transport != TransportPolicy::WebRtc,
        "WebRTC is unavailable in this build"
    );
    let app = create_router(state)?;
    let addr = format!("{}:{}", host, port);
    log::info!(
        "Dashboard starting at http://localhost:{} (bound to {})",
        port,
        host
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Serve the main dashboard HTML page.
async fn serve_index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

/// Serve the CSS stylesheet.
async fn serve_css() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        include_str!("static/style.css"),
    )
}

/// Serve the JavaScript application.
async fn serve_js() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("static/app.js"),
    )
}

/// Serve the Audio Tab JavaScript module.
async fn serve_audio_js() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("static/audio_tab.js"),
    )
}

/// Serve the Docs Tab JavaScript module.
async fn serve_docs_js() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("static/docs_tab.js"),
    )
}

/// Serve the OpenTimestamps dashboard UI JavaScript module.
async fn serve_ots_js() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("static/js/ots.js"),
    )
}

/// API endpoint returning live metrics as JSON.
async fn api_metrics(State(state): State<Arc<DashboardState>>) -> String {
    state.metrics.to_json()
}

/// GET /api/docs — return list of available documentation files.
async fn api_docs_list() -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    let names: Vec<&str> = DOCS.iter().map(|(name, _)| *name).collect();
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&names).unwrap_or_else(|_| "[]".into()),
    )
}

/// GET /api/docs/:name — return raw markdown content of a documentation file.
async fn api_docs_content(
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    for (doc_name, content) in DOCS.iter() {
        if *doc_name == name {
            return (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/markdown; charset=utf-8",
                )],
                *content,
            )
                .into_response();
        }
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        format!("Document '{}' not found", name),
    )
        .into_response()
}

/// GET /api/config — return current config state.
async fn api_config_get(State(state): State<Arc<DashboardState>>) -> String {
    let live = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
    let transport = match live.transport {
        Transport::Websocket => "websocket",
        Transport::Webrtc => "webrtc",
    };
    serde_json::json!({
        "signing_backend": "ed25519",
        "identity": steganographer_core::crypto::encode_hex(&state.signer.verifying_key().to_bytes()),
        "public_key": steganographer_core::crypto::encode_hex(&state.signer.verifying_key().to_bytes()),
        "width": state.width,
        "height": state.height,
        "opacity": live.opacity,
        "lsb_bits": live.lsb_bits,
        "overlay_text": live.overlay_text,
        "sign_rate_ms": live.sign_rate_ms,
        "qr_scale": live.qr_scale,
        "resolution": live.resolution,
        "default_transport": state.transport.as_str(),
        "stego_type": live.stego_type,
        "hash_algorithm": live.hash_algorithm,
        "encrypt": live.encrypt,
        "ecc": live.ecc,
        "transport": transport,
    })
    .to_string()
}

/// POST /api/config — update live configuration from the dashboard UI.
async fn api_config_post(
    State(state): State<Arc<DashboardState>>,
    headers: axum::http::HeaderMap,
    Json(new_cfg): Json<LiveConfig>,
) -> impl axum::response::IntoResponse {
    if let Some(status) = mutation_denial(&headers, &state.auth_token) {
        return (
            status,
            serde_json::json!({ "status": "error", "message": "Unauthorized" }).to_string(),
        );
    }
    if let Err(msg) = validate_live_config(&new_cfg) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({ "status": "error", "message": msg }).to_string(),
        );
    }

    log::info!(
        "Config updated: opacity={:.2}, lsb_bits={}, backend={}, overlay='{}', sign_rate={}ms, qr_scale={}%, res={}, transport={:?}",
        new_cfg.opacity, new_cfg.lsb_bits, new_cfg.signing_backend,
        new_cfg.overlay_text, new_cfg.sign_rate_ms, new_cfg.qr_scale, new_cfg.resolution,
        new_cfg.transport
    );

    let mut cfg = state.live_config.lock().unwrap_or_else(|e| e.into_inner());
    *cfg = new_cfg;

    (
        axum::http::StatusCode::OK,
        serde_json::json!({ "status": "ok" }).to_string(),
    )
}

/// GET /api/session — return session summary stats for export.
async fn api_session(State(state): State<Arc<DashboardState>>) -> String {
    let uptime = state.session_start.elapsed();
    let cfg = state
        .live_config
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let metrics = state.metrics.to_json();
    serde_json::json!({
        "uptime_secs": uptime.as_secs_f64(),
        "backend": "ed25519",
        "identity": steganographer_core::crypto::encode_hex(&state.signer.verifying_key().to_bytes()),
        "resolution": format!("{}x{}", state.width, state.height),
        "config": cfg,
        "metrics": serde_json::from_str::<serde_json::Value>(&metrics).unwrap_or_default(),
    })
    .to_string()
}

/// GET /api/version — return version and build info.
async fn api_version() -> String {
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
        "signature_payload_size": steganographer_core::SignaturePayload::SERIALIZED_SIZE,
    })
    .to_string()
}

/// POST /api/metrics/reset — reset all metrics counters.
async fn api_metrics_reset(
    State(state): State<Arc<DashboardState>>,
    headers: axum::http::HeaderMap,
) -> impl axum::response::IntoResponse {
    if let Some(status) = mutation_denial(&headers, &state.auth_token) {
        return (
            status,
            serde_json::json!({ "status": "error", "message": "Unauthorized" }).to_string(),
        );
    }
    state.metrics.reset();
    log::info!("Metrics counters reset via API");
    (
        axum::http::StatusCode::OK,
        serde_json::json!({ "status": "ok", "message": "Metrics reset" }).to_string(),
    )
}

// ─── OpenTimestamps endpoints ──────────────────────────────────────────────

fn record_ots_error(state: &DashboardState, digest: &[u8; 32], error: &str) {
    let mut slot = state.ots_outcome.lock().unwrap_or_else(|e| e.into_inner());
    let outcome = slot.get_or_insert_with(|| serde_json::json!({
        "digest": steganographer_core::crypto::encode_hex(digest), "pending":null, "verified":null,
    }));
    // A failed/rate-limited attempt must not erase a previously saved receipt.
    // Nor does it turn a network error into a cryptographic negative verdict.
    outcome["last_error"] = serde_json::json!({
        "digest":steganographer_core::crypto::encode_hex(digest), "message":error,
    });
}

/// GET /ots/status — return the current OTS configuration and readiness.
async fn ots_status(State(state): State<Arc<DashboardState>>) -> String {
    let mut body: serde_json::Value = serde_json::from_str(&ots_handler::status_handler(
        &state.ots_config,
        state.ots_client.as_deref(),
    ))
    .expect("OTS handler returns JSON");
    let digest = ws_handler::latest_media_digest(&state);
    body["has_media"] = serde_json::json!(digest.is_some());
    body["media_digest"] =
        serde_json::json!(digest.map(|d| steganographer_core::crypto::encode_hex(&d)));
    if digest.is_none() {
        body["can_stamp"] = serde_json::json!(false);
    }
    let outcome = state
        .ots_outcome
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let matching = outcome
        .as_ref()
        .filter(|outcome| outcome["digest"] == body["media_digest"]);
    body["pending"] = matching
        .and_then(|v| v.get("pending"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    body["verified"] = matching
        .and_then(|v| v.get("verified"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    body["proof"] = serde_json::json!(outcome);
    body.to_string()
}

/// POST /ots/stamp — stamp the SHA-256 of the latest delivered signed artifact.
/// An empty body selects current media; caller-provided surrogate data is rejected.
async fn ots_stamp(
    State(state): State<Arc<DashboardState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> (axum::http::StatusCode, String) {
    if let Some(status) = mutation_denial(&headers, &state.auth_token) {
        return (
            status,
            serde_json::json!({ "status": "error", "message": "Unauthorized" }).to_string(),
        );
    }
    let Some(client) = &state.ots_client else {
        // Graceful degradation: not an error, just disabled.
        return (
            axum::http::StatusCode::OK,
            serde_json::json!({
                "status": "disabled",
                "message": "OTS is disabled in configuration",
            })
            .to_string(),
        );
    };

    if !body.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"status":"error", "message":"stamp selects latest signed media; body must be empty"}).to_string());
    }
    let Some(digest) = ws_handler::latest_media_digest(&state) else {
        return (
            axum::http::StatusCode::CONFLICT,
            serde_json::json!({"status":"error", "message":"no signed media available"})
                .to_string(),
        );
    };
    match ots_handler::handle_stamp_digest(client, &digest).await {
        Ok(json) => {
            state.metrics.record_ots_proof();
            *state.ots_outcome.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(serde_json::from_str(&json).expect("OTS handler returns JSON"));
            (axum::http::StatusCode::OK, json)
        }
        Err(err) => {
            let (status, body) = ots_handler::error_to_http(&err);
            log::warn!("OTS stamp failed: {err}");
            record_ots_error(&state, &digest, &err.to_string());
            (
                axum::http::StatusCode::from_u16(status)
                    .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
                body,
            )
        }
    }
}

/// POST /ots/verify — verify a `.ots` proof file sent as the request body.
async fn ots_verify(
    State(state): State<Arc<DashboardState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> (axum::http::StatusCode, String) {
    if let Some(status) = mutation_denial(&headers, &state.auth_token) {
        return (
            status,
            serde_json::json!({ "status": "error", "message": "Unauthorized" }).to_string(),
        );
    }

    let Some(client) = &state.ots_client else {
        return (
            axum::http::StatusCode::OK,
            serde_json::json!({
                "status": "disabled",
                "message": "OTS is disabled in configuration",
            })
            .to_string(),
        );
    };

    if body.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({ "status": "error", "message": "empty proof body" }).to_string(),
        );
    }
    if body.len() > 64 * 1024 {
        return (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            serde_json::json!({"status":"error", "message":"proof body exceeds 64 KiB"})
                .to_string(),
        );
    }

    let digest = headers
        .get("x-expected-digest")
        .and_then(|value| value.to_str().ok())
        .filter(|hex| hex.len() == 64)
        .and_then(|hex| steganographer_core::crypto::decode_hex(hex).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let Some(digest) = digest else {
        return (axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"status":"error", "message":"X-Expected-Digest must contain the expected SHA-256 in hex"}).to_string());
    };
    match ots_handler::verify_handler(client, &body, &digest).await {
        Ok(json) => {
            let mut outcome: serde_json::Value =
                serde_json::from_str(&json).expect("OTS handler returns JSON");
            outcome["digest"] = serde_json::json!(steganographer_core::crypto::encode_hex(&digest));
            if outcome["pending"] != true {
                if let Some(verified) = outcome["verified"].as_bool() {
                    state
                        .metrics
                        .record_ots_verification(verified, outcome["timestamp"].as_u64());
                }
            }
            *state.ots_outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
            (axum::http::StatusCode::OK, json)
        }
        Err(err) => {
            let (status, body_str) = ots_handler::error_to_http(&err);
            log::warn!("OTS verify failed: {err}");
            record_ots_error(&state, &digest, &err.to_string());
            (
                axum::http::StatusCode::from_u16(status)
                    .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
                body_str,
            )
        }
    }
}
