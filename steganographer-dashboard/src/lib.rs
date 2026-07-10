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

pub mod ws_handler;

use axum::{
    extract::State,
    response::Html,
    routing::get,
    Json,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use steganographer_core::StegoMetrics;
use tower_http::cors::CorsLayer;

use ws_handler::{EncodedFrame, EncodedAudioChunk};

/// Live-updatable configuration from the dashboard UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveConfig {
    /// Overlay opacity (0.0–1.0).
    #[serde(default = "default_opacity")]
    pub opacity: f64,
    /// LSB bits for embedding (1–4).
    #[serde(default = "default_lsb_bits", rename = "lsbBits")]
    pub lsb_bits: u8,
    /// Signing backend name.
    #[serde(default = "default_backend", rename = "signingBackend")]
    pub signing_backend: String,
    /// Overlay text string.
    #[serde(default = "default_overlay_text", rename = "overlayText")]
    pub overlay_text: String,
    /// Sign rate in milliseconds.
    #[serde(default = "default_sign_rate", rename = "signRateMs")]
    pub sign_rate_ms: u32,
    /// QR overlay scale (5–100% of video width).
    #[serde(default = "default_qr_scale", rename = "qrScale")]
    pub qr_scale: u32,
    /// Video resolution string (e.g. "640x480").
    #[serde(default = "default_resolution")]
    pub resolution: String,
    /// Steganography type: "lsb", "spread_spectrum", "dct".
    #[serde(default = "default_stego_type", rename = "stegoType")]
    pub stego_type: String,
    /// Hash algorithm: "blake3", "sha256", "sha3-256".
    #[serde(default = "default_hash_algo", rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    /// Enable payload encryption.
    #[serde(default, rename = "encrypt")]
    pub encrypt: bool,
    /// Enable error correction.
    #[serde(default, rename = "ecc")]
    pub ecc: bool,
}

fn default_opacity() -> f64 { 1.0 }
fn default_lsb_bits() -> u8 { 1 }
fn default_backend() -> String { "ed25519".into() }
fn default_overlay_text() -> String { "CONFIDENTIAL".into() }
fn default_sign_rate() -> u32 { 1000 }
fn default_qr_scale() -> u32 { 10 }
fn default_resolution() -> String { "640x480".into() }
fn default_stego_type() -> String { "lsb".into() }
fn default_hash_algo() -> String { "blake3".into() }

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
}

/// All documentation markdown files, embedded at compile time.
static DOCS: &[(&str, &str)] = &[
    ("README.md", include_str!("../../docs/README.md")),
    ("AGENTS.md", include_str!("../../docs/AGENTS.md")),
    ("algorithms.md", include_str!("../../docs/algorithms.md")),
    ("api-reference.md", include_str!("../../docs/api-reference.md")),
    ("architecture.md", include_str!("../../docs/architecture.md")),
    ("cli-reference.md", include_str!("../../docs/cli-reference.md")),
    ("configuration.md", include_str!("../../docs/configuration.md")),
    ("contributing.md", include_str!("../../docs/contributing.md")),
    ("cryptography.md", include_str!("../../docs/cryptography.md")),
    ("faq.md", include_str!("../../docs/faq.md")),
    ("getting-started.md", include_str!("../../docs/getting-started.md")),
    ("gstreamer.md", include_str!("../../docs/gstreamer.md")),
    ("platforms.md", include_str!("../../docs/platforms.md")),
    ("roadmap.md", include_str!("../../docs/roadmap.md")),
    ("security.md", include_str!("../../docs/security.md")),
    ("steganography-theory.md", include_str!("../../docs/steganography-theory.md")),
    ("threat-model.md", include_str!("../../docs/threat-model.md")),
];

/// Create the Axum router for the dashboard.
pub fn create_router(state: Arc<DashboardState>) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/style.css", get(serve_css))
        .route("/app.js", get(serve_js))
        .route("/audio_tab.js", get(serve_audio_js))
        .route("/docs_tab.js", get(serve_docs_js))
        .route("/ws/encode", get(ws_handler::ws_encode_handler))
        .route("/ws/decode", get(ws_handler::ws_decode_handler))
        .route("/ws/audio/encode", get(ws_handler::ws_audio_encode_handler))
        .route("/ws/audio/decode", get(ws_handler::ws_audio_decode_handler))
        .route("/api/metrics", get(api_metrics))
        .route("/api/metrics/reset", axum::routing::post(api_metrics_reset))
        .route("/api/config", get(api_config_get).post(api_config_post))
        .route("/api/session", get(api_session))
        .route("/api/version", get(api_version))
        .route("/api/docs", get(api_docs_list))
        .route("/api/docs/{name}", get(api_docs_content))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Start the dashboard server.
pub async fn start_server(state: Arc<DashboardState>, port: u16) -> anyhow::Result<()> {
    let app = create_router(state);
    let addr = format!("0.0.0.0:{}", port);
    log::info!("Dashboard starting at http://localhost:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Serve the main dashboard HTML page.
async fn serve_index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

/// Serve the CSS stylesheet.
async fn serve_css() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        include_str!("static/style.css"),
    )
}

/// Serve the JavaScript application.
async fn serve_js() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("static/app.js"),
    )
}

/// Serve the Audio Tab JavaScript module.
async fn serve_audio_js() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("static/audio_tab.js"),
    )
}

/// Serve the Docs Tab JavaScript module.
async fn serve_docs_js() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("static/docs_tab.js"),
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
                [(axum::http::header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
                *content,
            ).into_response();
        }
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        format!("Document '{}' not found", name),
    ).into_response()
}

/// GET /api/config — return current config state.
async fn api_config_get(State(state): State<Arc<DashboardState>>) -> String {
    let live = state.live_config.lock().expect("live_config lock poisoned");
    serde_json::json!({
        "signing_backend": live.signing_backend,
        "identity": state.identity,
        "width": state.width,
        "height": state.height,
        "opacity": live.opacity,
        "lsb_bits": live.lsb_bits,
        "overlay_text": live.overlay_text,
        "sign_rate_ms": live.sign_rate_ms,
        "stego_type": live.stego_type,
        "hash_algorithm": live.hash_algorithm,
        "encrypt": live.encrypt,
        "ecc": live.ecc,
    })
    .to_string()
}

/// POST /api/config — update live configuration from the dashboard UI.
async fn api_config_post(
    State(state): State<Arc<DashboardState>>,
    Json(new_cfg): Json<LiveConfig>,
) -> String {
    log::info!(
        "Config updated: opacity={:.2}, lsb_bits={}, backend={}, overlay='{}', sign_rate={}ms, qr_scale={}%, res={}",
        new_cfg.opacity, new_cfg.lsb_bits, new_cfg.signing_backend,
        new_cfg.overlay_text, new_cfg.sign_rate_ms, new_cfg.qr_scale, new_cfg.resolution
    );

    let mut cfg = state.live_config.lock().expect("live_config lock poisoned");
    *cfg = new_cfg;

    serde_json::json!({ "status": "ok" }).to_string()
}

/// GET /api/session — return session summary stats for export.
async fn api_session(State(state): State<Arc<DashboardState>>) -> String {
    let uptime = state.session_start.elapsed();
    let cfg = state.live_config.lock().expect("live_config lock poisoned").clone();
    let metrics = state.metrics.to_json();
    serde_json::json!({
        "uptime_secs": uptime.as_secs_f64(),
        "backend": state.signing_backend,
        "identity": state.identity,
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
    })
    .to_string()
}

/// POST /api/metrics/reset — reset all metrics counters.
async fn api_metrics_reset(State(state): State<Arc<DashboardState>>) -> String {
    state.metrics.reset();
    log::info!("Metrics counters reset via API");
    serde_json::json!({ "status": "ok", "message": "Metrics reset" }).to_string()
}
