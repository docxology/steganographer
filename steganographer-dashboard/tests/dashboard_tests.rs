use std::sync::{Arc, Mutex};
use steganographer_dashboard::{validate_live_config, DashboardState, LiveConfig};

static FRAME_TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ─── LiveConfig Tests ─────────────────────────────────────────────────

#[test]
fn test_live_config_default() {
    let cfg = LiveConfig::default();
    assert!((cfg.opacity - 1.0).abs() < f64::EPSILON);
    assert_eq!(cfg.lsb_bits, 1);
    assert_eq!(cfg.signing_backend, "ed25519");
    assert_eq!(cfg.overlay_text, "CONFIDENTIAL");
    assert_eq!(cfg.sign_rate_ms, 1000);
}

#[test]
fn test_live_config_serialization_roundtrip() {
    let cfg = LiveConfig {
        opacity: 0.75,
        lsb_bits: 3,
        signing_backend: "ethereum".into(),
        overlay_text: "SECRET".into(),
        sign_rate_ms: 500,
        qr_scale: 25,
        resolution: "1280x720".into(),
        stego_type: "lsb".into(),
        hash_algorithm: "blake3".into(),
        encrypt: false,
        ecc: false,
        transport: steganographer_dashboard::Transport::Websocket,
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let parsed: LiveConfig = serde_json::from_str(&json).expect("deserialize");
    assert!((parsed.opacity - 0.75).abs() < f64::EPSILON);
    assert_eq!(parsed.lsb_bits, 3);
    assert_eq!(parsed.signing_backend, "ethereum");
    assert_eq!(parsed.overlay_text, "SECRET");
    assert_eq!(parsed.sign_rate_ms, 500);
}

#[test]
fn test_live_config_from_json_with_defaults() {
    let json = r#"{"opacity": 0.5}"#;
    let cfg: LiveConfig = serde_json::from_str(json).expect("parse partial");
    assert!((cfg.opacity - 0.5).abs() < f64::EPSILON);
    assert_eq!(cfg.lsb_bits, 1);
    assert_eq!(cfg.signing_backend, "ed25519");
    assert_eq!(cfg.overlay_text, "CONFIDENTIAL");
    assert_eq!(cfg.sign_rate_ms, 1000);
}

#[test]
fn test_live_config_snake_case_field_names() {
    let json = r#"{"opacity":0.8,"lsb_bits":2,"signing_backend":"ethereum","overlay_text":"TOP SECRET","sign_rate_ms":250}"#;
    let cfg: LiveConfig = serde_json::from_str(json).expect("snake_case parse");
    assert!((cfg.opacity - 0.8).abs() < f64::EPSILON);
    assert_eq!(cfg.lsb_bits, 2);
    assert_eq!(cfg.signing_backend, "ethereum");
    assert_eq!(cfg.overlay_text, "TOP SECRET");
    assert_eq!(cfg.sign_rate_ms, 250);
}

#[test]
fn test_live_config_boundary_values() {
    let json = r#"{"opacity":0.0,"lsb_bits":4,"sign_rate_ms":200}"#;
    let cfg: LiveConfig = serde_json::from_str(json).expect("parse");
    assert!((cfg.opacity - 0.0).abs() < f64::EPSILON);
    assert_eq!(cfg.lsb_bits, 4);
    assert_eq!(cfg.sign_rate_ms, 200);
}

// ─── DashboardState Tests ─────────────────────────────────────────────

#[test]
fn test_dashboard_state_construction() {
    let metrics = Arc::new(steganographer_core::StegoMetrics::new());
    let state = DashboardState {
        metrics: metrics.clone(),
        signing_backend: "ed25519".into(),
        identity: "abc123".into(),
        width: 1280,
        height: 720,
        last_encoded_frame: Mutex::new(None),
        last_encoded_audio: Mutex::new(None),
        live_config: Mutex::new(LiveConfig::default()),
        session_start: std::time::Instant::now(),
        auth_token: None,
        ots_config: steganographer_core::OtsConfig::default(),
        ots_client: None,
        ots_outcome: Mutex::new(None),
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
        transport: steganographer_dashboard::TransportPolicy::Auto,
        #[cfg(feature = "webrtc")]
        webrtc_sessions: Mutex::new(std::collections::HashMap::new()),
        #[cfg(feature = "webrtc")]
        ice_servers: Vec::new(),
        #[cfg(feature = "webrtc")]
        media_publishers: Mutex::new(std::collections::HashMap::new()),
    };
    assert_eq!(state.signing_backend, "ed25519");
    assert_eq!(state.width, 1280);
    assert!(state.last_encoded_frame.lock().unwrap().is_none());
}

#[test]
fn test_live_config_mutex_update() {
    let cfg = Mutex::new(LiveConfig::default());
    {
        let mut guard = cfg.lock().unwrap();
        guard.opacity = 0.3;
        guard.lsb_bits = 2;
    }
    let guard = cfg.lock().unwrap();
    assert!((guard.opacity - 0.3).abs() < f64::EPSILON);
    assert_eq!(guard.lsb_bits, 2);
}

#[test]
fn test_live_config_full_json_roundtrip() {
    let original = LiveConfig {
        opacity: 0.42,
        lsb_bits: 3,
        signing_backend: "ethereum".into(),
        overlay_text: "🔒 SECURE".into(),
        sign_rate_ms: 2500,
        qr_scale: 50,
        resolution: "1920x1080".into(),
        stego_type: "lsb".into(),
        hash_algorithm: "blake3".into(),
        encrypt: false,
        ecc: false,
        transport: steganographer_dashboard::Transport::Webrtc,
    };
    let json = serde_json::to_string(&original).unwrap();
    let restored: LiveConfig = serde_json::from_str(&json).unwrap();
    assert!((restored.opacity - original.opacity).abs() < f64::EPSILON);
    assert_eq!(restored.lsb_bits, original.lsb_bits);
    assert_eq!(restored.signing_backend, original.signing_backend);
    assert_eq!(restored.overlay_text, original.overlay_text);
    assert_eq!(restored.sign_rate_ms, original.sign_rate_ms);
}

// ─── Session Start Tests ──────────────────────────────────────────────

#[test]
fn test_dashboard_state_session_start() {
    let before = std::time::Instant::now();
    let state = DashboardState {
        metrics: Arc::new(steganographer_core::StegoMetrics::new()),
        signing_backend: "ed25519".into(),
        identity: "test".into(),
        width: 640,
        height: 480,
        last_encoded_frame: Mutex::new(None),
        last_encoded_audio: Mutex::new(None),
        live_config: Mutex::new(LiveConfig::default()),
        session_start: std::time::Instant::now(),
        auth_token: None,
        ots_config: steganographer_core::OtsConfig::default(),
        ots_client: None,
        ots_outcome: Mutex::new(None),
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
        transport: steganographer_dashboard::TransportPolicy::Auto,
        #[cfg(feature = "webrtc")]
        webrtc_sessions: Mutex::new(std::collections::HashMap::new()),
        #[cfg(feature = "webrtc")]
        ice_servers: Vec::new(),
        #[cfg(feature = "webrtc")]
        media_publishers: Mutex::new(std::collections::HashMap::new()),
    };
    let after = std::time::Instant::now();
    // session_start should be between before and after
    assert!(state.session_start >= before);
    assert!(state.session_start <= after);
    // Elapsed should be very small (< 1 second)
    assert!(state.session_start.elapsed().as_secs() < 1);
}

#[test]
fn test_live_config_qr_scale_resolution_defaults() {
    let cfg = LiveConfig::default();
    assert_eq!(cfg.qr_scale, 10);
    assert_eq!(cfg.resolution, "640x480");
}

#[test]
fn test_live_config_qr_scale_resolution_roundtrip() {
    let cfg = LiveConfig {
        opacity: 1.0,
        lsb_bits: 1,
        signing_backend: "ed25519".into(),
        overlay_text: "TEST".into(),
        sign_rate_ms: 1000,
        qr_scale: 75,
        resolution: "1920x1080".into(),
        stego_type: "lsb".into(),
        hash_algorithm: "blake3".into(),
        encrypt: false,
        ecc: false,
        transport: steganographer_dashboard::Transport::Websocket,
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let parsed: LiveConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.qr_scale, 75);
    assert_eq!(parsed.resolution, "1920x1080");
}

#[test]
fn test_live_config_snake_case_qr_scale() {
    let json = r#"{"opacity":1.0,"lsb_bits":1,"signing_backend":"ed25519","overlay_text":"X","sign_rate_ms":1000,"qr_scale":50,"resolution":"1280x720"}"#;
    let cfg: LiveConfig = serde_json::from_str(json).expect("parse");
    assert_eq!(cfg.qr_scale, 50);
    assert_eq!(cfg.resolution, "1280x720");
}

// ─── HTTP Handler Tests ───────────────────────────────────────────────

fn test_app() -> (axum::Router, Arc<DashboardState>) {
    test_app_with_token(None)
}

/// Helper: build a real Axum app with an optional auth token.
fn test_app_with_token(auth_token: Option<String>) -> (axum::Router, Arc<DashboardState>) {
    let state = Arc::new(DashboardState {
        metrics: Arc::new(steganographer_core::StegoMetrics::new()),
        signing_backend: "ed25519".into(),
        identity: "test_identity_abc123".into(),
        width: 640,
        height: 480,
        last_encoded_frame: Mutex::new(None),
        last_encoded_audio: Mutex::new(None),
        live_config: Mutex::new(LiveConfig::default()),
        session_start: std::time::Instant::now(),
        auth_token,
        ots_config: steganographer_core::OtsConfig::default(),
        ots_client: None,
        ots_outcome: Mutex::new(None),
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
        transport: steganographer_dashboard::TransportPolicy::Auto,
        #[cfg(feature = "webrtc")]
        webrtc_sessions: Mutex::new(std::collections::HashMap::new()),
        #[cfg(feature = "webrtc")]
        ice_servers: Vec::new(),
        #[cfg(feature = "webrtc")]
        media_publishers: Mutex::new(std::collections::HashMap::new()),
    });
    let router = steganographer_dashboard::create_router(state.clone()).unwrap();
    (router, state)
}

/// Helper: read full response body as string.
async fn body_to_string(body: axum::body::Body) -> String {
    use http_body_util::BodyExt;
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn test_api_session_response_structure() {
    use tower::ServiceExt;
    let (app, state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/session")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(json.get("uptime_secs").is_some(), "missing uptime_secs");
    assert_eq!(json["backend"], "ed25519");
    assert_eq!(
        json["identity"],
        steganographer_core::crypto::encode_hex(&state.signer.verifying_key().to_bytes())
    );
    assert_eq!(json["resolution"], "640x480");
    assert!(json.get("config").is_some(), "missing config");
    assert!(json.get("metrics").is_some(), "missing metrics");
}

#[tokio::test]
async fn test_api_config_get_returns_json() {
    use tower::ServiceExt;
    let (app, state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/config")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["signing_backend"], "ed25519");
    assert_eq!(
        json["identity"],
        steganographer_core::crypto::encode_hex(&state.signer.verifying_key().to_bytes())
    );
    assert_eq!(json["width"], 640);
    assert_eq!(json["height"], 480);
    assert_eq!(json["lsb_bits"], 1);
}

#[tokio::test]
async fn test_api_config_post_updates_config() {
    use tower::ServiceExt;
    let (app, state) = test_app();
    let new_cfg = serde_json::json!({
        "opacity": 0.5,
        "lsb_bits": 3,
        "signing_backend": "ed25519",
        "overlay_text": "UPDATED",
        "sign_rate_ms": 500,
        "qr_scale": 30,
        "resolution": "1920x1080"
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/config")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(new_cfg.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("ok"));

    // Verify state was actually updated
    let cfg = state.live_config.lock().unwrap();
    assert_eq!(cfg.lsb_bits, 3);
    assert_eq!(cfg.signing_backend, "ed25519");
    assert_eq!(cfg.overlay_text, "UPDATED");
    assert_eq!(cfg.sign_rate_ms, 500);
    assert_eq!(cfg.qr_scale, 30);
    assert_eq!(cfg.resolution, "1920x1080");
}

#[tokio::test]
async fn test_api_docs_list_returns_array() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/docs")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    let arr: Vec<String> = serde_json::from_str(&body).expect("valid JSON array");
    assert!(
        arr.contains(&"README.md".to_string()),
        "should include README.md"
    );
    assert!(
        arr.contains(&"threat-model.md".to_string()),
        "should include threat-model.md"
    );
    assert!(
        arr.len() >= 18,
        "should have at least 18 doc files, got {}",
        arr.len()
    );
}

#[tokio::test]
async fn test_api_docs_content_returns_markdown() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/docs/README.md")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/markdown"),
        "expected markdown content-type, got {}",
        ct
    );
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("Steganographer"),
        "README should mention Steganographer"
    );
}

#[tokio::test]
async fn test_api_docs_content_not_found() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/docs/nonexistent_file.md")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_serve_index_returns_html() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("<!DOCTYPE html>") || body.contains("<html"),
        "should be HTML"
    );
}

#[tokio::test]
async fn test_serve_css_returns_css() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/style.css")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/css"), "expected text/css, got {}", ct);
}

#[tokio::test]
async fn test_serve_js_returns_javascript() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/app.js")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("javascript"),
        "expected javascript content-type, got {}",
        ct
    );
}

#[tokio::test]
async fn test_api_metrics_returns_json() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/metrics")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(
        json.get("frames_processed").is_some(),
        "metrics JSON should have frames_processed field: {}",
        body
    );
}

// ─── Security Tests ───────────────────────────────────────────────────

const TEST_TOKEN: &str = "sekret";

/// Build a WebSocket-upgrade-shaped request with extra headers.
fn ws_request(path: &str, headers: &[(&str, &str)]) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "127.0.0.1:8080")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(axum::body::Body::empty()).unwrap()
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn config_body(lsb_bits: u8) -> String {
    serde_json::json!({
        "opacity": 0.5,
        "lsb_bits": lsb_bits,
        "signing_backend": "ed25519",
        "overlay_text": "X",
        "sign_rate_ms": 1000,
        "qr_scale": 10,
        "resolution": "640x480"
    })
    .to_string()
}

async fn post_config(
    app: axum::Router,
    body: String,
    auth: Option<&str>,
) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/api/config")
        .header("content-type", "application/json");
    if let Some(t) = auth {
        builder = builder.header("authorization", t);
    }
    let req = builder.body(axum::body::Body::from(body)).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_to_string(resp.into_body()).await)
}

// ─── Config validation (unit) ─────────────────────────────────────────

#[test]
fn test_config_validation_accepts_valid_ranges() {
    let mut cfg = LiveConfig::default();
    for lsb_bits in [1u8, 2, 3, 4] {
        cfg.lsb_bits = lsb_bits;
        assert!(
            validate_live_config(&cfg).is_ok(),
            "lsb_bits {lsb_bits} valid"
        );
    }
    for opacity in [0.0f64, 0.5, 1.0] {
        cfg.opacity = opacity;
        assert!(
            validate_live_config(&cfg).is_ok(),
            "opacity {opacity} valid"
        );
    }
    for rate in [50u32, 100, 1000] {
        cfg.sign_rate_ms = rate;
        assert!(
            validate_live_config(&cfg).is_ok(),
            "sign_rate_ms {rate} valid"
        );
    }
}

#[test]
fn test_config_validation_rejects_bad_lsb_bits() {
    let mut cfg = LiveConfig::default();
    for lsb_bits in [0u8, 5, 255] {
        cfg.lsb_bits = lsb_bits;
        let err = validate_live_config(&cfg).unwrap_err();
        assert!(err.contains("lsb_bits"), "error names lsb_bits: {err}");
    }
}

#[test]
fn test_config_validation_rejects_bad_opacity() {
    let mut cfg = LiveConfig::default();
    for opacity in [-0.1f64, 1.1, 42.0] {
        cfg.opacity = opacity;
        let err = validate_live_config(&cfg).unwrap_err();
        assert!(err.contains("opacity"), "error names opacity: {err}");
    }
    // NaN must be rejected too (not inside 0.0..=1.0).
    cfg.opacity = f64::NAN;
    assert!(validate_live_config(&cfg).is_err());
}

#[test]
fn test_config_validation_rejects_low_sign_rate() {
    let mut cfg = LiveConfig::default();
    for rate in [0u32, 10, 49] {
        cfg.sign_rate_ms = rate;
        let err = validate_live_config(&cfg).unwrap_err();
        assert!(
            err.contains("sign_rate_ms"),
            "error names sign_rate_ms: {err}"
        );
    }
}

// ─── POST /api/config validation (HTTP) ───────────────────────────────

#[tokio::test]
async fn test_api_config_post_rejects_lsb_bits_5() {
    let (app, _state) = test_app();
    let (status, body) = post_config(app, config_body(5), None).await;
    assert_eq!(status, 400);
    assert!(body.contains("lsb_bits"), "message names the field: {body}");
}

#[tokio::test]
async fn test_api_config_post_rejects_bad_opacity_and_rate() {
    for (field, body) in [
        (
            "opacity",
            r#"{"opacity": 1.5, "lsb_bits": 1, "sign_rate_ms": 1000}"#,
        ),
        (
            "opacity",
            r#"{"opacity": -0.1, "lsb_bits": 1, "sign_rate_ms": 1000}"#,
        ),
        (
            "sign_rate_ms",
            r#"{"opacity": 0.5, "lsb_bits": 1, "sign_rate_ms": 10}"#,
        ),
        (
            "sign_rate_ms",
            r#"{"opacity": 0.5, "lsb_bits": 1, "sign_rate_ms": 0}"#,
        ),
    ] {
        let (app, _state) = test_app();
        let (status, resp_body) = post_config(app, body.to_string(), None).await;
        assert_eq!(status, 400, "case {field}: {body}");
        assert!(
            resp_body.contains(field),
            "400 message names {field}: {resp_body}"
        );
    }
}

#[tokio::test]
async fn test_api_config_post_accepts_lsb_bits_2() {
    let (app, state) = test_app();
    let (status, body) = post_config(app, config_body(2), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(state.live_config.lock().unwrap().lsb_bits, 2);
}

// ─── Auth matrix ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_auth_matrix_api_config_post() {
    // No token → 401
    let (app, _) = test_app_with_token(Some(TEST_TOKEN.into()));
    let (status, _) = post_config(app, config_body(2), None).await;
    assert_eq!(status, 401);

    // Wrong token → 401
    let (app, _) = test_app_with_token(Some(TEST_TOKEN.into()));
    let (status, _) = post_config(app, config_body(2), Some(&bearer("wrong"))).await;
    assert_eq!(status, 401);

    // Right token → 200
    let (app, _) = test_app_with_token(Some(TEST_TOKEN.into()));
    let (status, body) = post_config(app, config_body(2), Some(&bearer(TEST_TOKEN))).await;
    assert_eq!(status, 200, "{body}");

    // Auth disabled (no token configured) → 200 without credentials
    let (app, _) = test_app();
    let (status, _) = post_config(app, config_body(2), None).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn test_auth_matrix_metrics_reset() {
    use tower::ServiceExt;
    let reset = |auth: Option<&str>| {
        let app = test_app_with_token(Some(TEST_TOKEN.into())).0;
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/api/metrics/reset");
        if let Some(t) = auth {
            builder = builder.header("authorization", t);
        }
        async move {
            app.oneshot(builder.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap()
        }
    };
    assert_eq!(reset(None).await.status(), 401);
    assert_eq!(reset(Some(&bearer("wrong"))).await.status(), 401);
    assert_eq!(reset(Some(&bearer(TEST_TOKEN))).await.status(), 200);
}

#[tokio::test]
async fn test_auth_matrix_ots_stamp() {
    use tower::ServiceExt;
    let stamp = |auth: Option<&str>| {
        let app = test_app_with_token(Some(TEST_TOKEN.into())).0;
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/ots/stamp");
        if let Some(t) = auth {
            builder = builder.header("authorization", t);
        }
        async move {
            app.oneshot(builder.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap()
        }
    };
    assert_eq!(stamp(None).await.status(), 401);
    assert_eq!(stamp(Some(&bearer("wrong"))).await.status(), 401);
    // OTS is disabled in test state → auth passes, endpoint degrades to 200.
    let resp = stamp(Some(&bearer(TEST_TOKEN))).await;
    assert_eq!(resp.status(), 200);
    assert!(body_to_string(resp.into_body()).await.contains("disabled"));
}

#[tokio::test]
async fn test_auth_matrix_ots_verify() {
    use tower::ServiceExt;
    let verify = |auth: Option<&str>, body: &'static [u8]| {
        let app = test_app_with_token(Some(TEST_TOKEN.into())).0;
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/ots/verify");
        if let Some(t) = auth {
            builder = builder.header("authorization", t);
        }
        async move {
            app.oneshot(builder.body(axum::body::Body::from(body)).unwrap())
                .await
                .unwrap()
        }
    };
    assert_eq!(verify(None, b"proof").await.status(), 401);
    assert_eq!(verify(Some(&bearer("wrong")), b"proof").await.status(), 401);
    // Right token, no OTS client → 200 disabled.
    let resp = verify(Some(&bearer(TEST_TOKEN)), b"proof").await;
    assert_eq!(resp.status(), 200);
    assert!(body_to_string(resp.into_body()).await.contains("disabled"));
}

/// /ots/verify with an OTS client present and an empty body → 400.
#[tokio::test]
async fn test_ots_verify_empty_body_400() {
    use tower::ServiceExt;
    let state = Arc::new(DashboardState {
        metrics: Arc::new(steganographer_core::StegoMetrics::new()),
        signing_backend: "ed25519".into(),
        identity: "test".into(),
        width: 640,
        height: 480,
        last_encoded_frame: Mutex::new(None),
        last_encoded_audio: Mutex::new(None),
        live_config: Mutex::new(LiveConfig::default()),
        session_start: std::time::Instant::now(),
        auth_token: Some(TEST_TOKEN.into()),
        ots_config: steganographer_core::OtsConfig::default(),
        ots_client: Some(Arc::new(
            steganographer_core::OTSClient::new(steganographer_core::OTSMethod::Bitcoin).unwrap(),
        )),
        ots_outcome: Mutex::new(None),
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
        transport: steganographer_dashboard::TransportPolicy::Auto,
        #[cfg(feature = "webrtc")]
        webrtc_sessions: Mutex::new(std::collections::HashMap::new()),
        #[cfg(feature = "webrtc")]
        ice_servers: Vec::new(),
        #[cfg(feature = "webrtc")]
        media_publishers: Mutex::new(std::collections::HashMap::new()),
    });
    let app = steganographer_dashboard::create_router(state.clone()).unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/ots/verify")
        .header("authorization", bearer(TEST_TOKEN))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
    assert!(body_to_string(resp.into_body())
        .await
        .contains("empty proof body"));
}

// ─── /api/version + /ots/status ───────────────────────────────────────

#[tokio::test]
async fn test_api_version_reports_payload_size() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/version")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(json["name"], "steganographer-dashboard");
    assert_eq!(json["signature_payload_size"], 109);
}

#[tokio::test]
async fn test_ots_status_disabled_returns_200() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/ots/status")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(json["enabled"], false);
}

// ─── WebSocket origin + token gates ───────────────────────────────────

#[tokio::test]
async fn test_ws_cross_origin_rejected_403() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = ws_request("/ws/decode", &[("origin", "http://evil.example.com")]);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_ws_same_host_origin_accepted() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = ws_request("/ws/decode", &[("origin", "http://127.0.0.1:8080")]);
    let resp = app.oneshot(req).await.unwrap();
    // tower::ServiceExt::oneshot cannot perform a real hyper upgrade, so a
    // gate-passed request reaches axum's WebSocketUpgrade extractor, which
    // answers 426 (Upgrade Required). 426 proves the origin gate passed;
    // 401/403 prove it rejected.
    assert_eq!(resp.status(), 426, "same-host must pass the origin gate");
}

#[tokio::test]
async fn test_ws_absent_and_loopback_origin_accepted() {
    use tower::ServiceExt;
    for (label, headers) in [
        ("absent origin", vec![]),
        ("loopback origin", vec![("origin", "http://localhost:5173")]),
        ("ipv6 loopback", vec![("origin", "http://[::1]:4200")]),
    ] {
        let (app, _state) = test_app();
        let resp = app
            .oneshot(ws_request("/ws/encode", &headers))
            .await
            .unwrap();
        assert_eq!(resp.status(), 426, "{label} must pass the origin gate");
    }
}

#[tokio::test]
async fn test_ws_cross_origin_rejected_on_all_four_endpoints() {
    use tower::ServiceExt;
    for path in [
        "/ws/encode",
        "/ws/decode",
        "/ws/audio/encode",
        "/ws/audio/decode",
    ] {
        let (app, _state) = test_app();
        let resp = app
            .oneshot(ws_request(path, &[("origin", "http://evil.example.com")]))
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{path} must reject cross-origin");
    }
}

#[tokio::test]
async fn test_ws_auth_token_required() {
    use tower::ServiceExt;
    let (app, _state) = test_app_with_token(Some(TEST_TOKEN.into()));
    let resp = app.oneshot(ws_request("/ws/decode", &[])).await.unwrap();
    assert_eq!(resp.status(), 401, "missing token must be rejected");

    let (app, _state) = test_app_with_token(Some(TEST_TOKEN.into()));
    let resp = app
        .oneshot(ws_request("/ws/decode?token=wrong", &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong token must be rejected");
}

#[tokio::test]
async fn test_ws_auth_token_via_query_param() {
    use tower::ServiceExt;
    let (app, _state) = test_app_with_token(Some(TEST_TOKEN.into()));
    let resp = app
        .oneshot(ws_request("/ws/decode?token=sekret", &[]))
        .await
        .unwrap();
    // oneshot cannot perform a real hyper upgrade; 426 from axum's
    // WebSocketUpgrade extractor proves the auth gate passed (401 = rejected).
    assert_eq!(resp.status(), 426, "?token= must pass the auth gate");
}

#[tokio::test]
async fn test_ws_auth_token_via_subprotocol() {
    use tower::ServiceExt;
    let (app, _state) = test_app_with_token(Some(TEST_TOKEN.into()));
    let req = ws_request("/ws/decode", &[("sec-websocket-protocol", "bearer-sekret")]);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        426,
        "bearer-<token> subprotocol must pass the auth gate"
    );
    // The Sec-WebSocket-Protocol echo only happens on a real 101 upgrade,
    // which oneshot cannot produce; the gate decision is the unit under test.
}

// ─── LiveConfig transport ─────────────────────────────────────────────

#[test]
fn test_live_config_transport_default_and_roundtrip() {
    let cfg = LiveConfig::default();
    assert_eq!(
        cfg.transport,
        steganographer_dashboard::Transport::Websocket
    );

    let cfg: LiveConfig = serde_json::from_str(r#"{"transport": "webrtc"}"#).unwrap();
    assert_eq!(cfg.transport, steganographer_dashboard::Transport::Webrtc);

    let cfg: LiveConfig = serde_json::from_str(r#"{"transport": "websocket"}"#).unwrap();
    assert_eq!(
        cfg.transport,
        steganographer_dashboard::Transport::Websocket
    );

    // Unknown transport values must be rejected at parse time.
    assert!(serde_json::from_str::<LiveConfig>(r#"{"transport": "carrier-pigeon"}"#).is_err());
}

// ─── POST /api/webrtc/offer (WHIP-style signaling) ────────────────────

async fn post_offer(
    app: axum::Router,
    body: &str,
    auth: Option<&str>,
) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt;
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/webrtc/offer")
        .header("content-type", "application/json");
    if let Some(t) = auth {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = app
        .oneshot(req.body(axum::body::Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    (status, body_to_string(resp.into_body()).await)
}

#[tokio::test]
async fn test_api_webrtc_offer_requires_auth() {
    let (app, _state) = test_app_with_token(Some(TEST_TOKEN.into()));
    // Valid offer-shaped JSON so the handler (not the extractor) rejects it.
    let (status, body) = post_offer(app, r#"{"type": "offer", "sdp": "v=0"}"#, None).await;
    assert_eq!(status, 401, "missing token must be rejected: {body}");
}

#[tokio::test]
async fn test_api_webrtc_offer_rejects_non_offer_type() {
    let (app, _state) = test_app();
    let (status, body) = post_offer(app, r#"{"type": "answer", "sdp": "v=0"}"#, None).await;
    assert_eq!(status, 400, "non-offer SDP type must be rejected: {body}");
    assert!(
        body.contains("offer"),
        "error must name the SDP type: {body}"
    );
}

#[tokio::test]
async fn test_api_webrtc_offer_rejects_malformed_sdp() {
    let (app, _state) = test_app();
    let (status, body) = post_offer(app, r#"{"type": "offer", "sdp": "not-sdp"}"#, None).await;
    assert_eq!(status, 400, "malformed SDP must be rejected: {body}");
}

#[tokio::test]
async fn test_api_config_get_includes_transport() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/config")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    let cfg: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(cfg["transport"], "websocket");
}

// ─── DataChannel encode path verification ─────────────────────────────

/// Encode a synthetic RGB8 image as JPEG — the client-side step the browser
/// performs before sending a frame over the DataChannel.
fn test_jpeg(width: u32, height: u32) -> Vec<u8> {
    let img = image::RgbImage::from_fn(width, height, |x, y| {
        let v = ((x * 7 + y * 13) % 251) as u8;
        image::Rgb([v, v.wrapping_add(11), v.wrapping_add(29)])
    });
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut out, image::ImageFormat::Jpeg)
        .expect("jpeg encode");
    out.into_inner()
}

/// The exact per-frame pipeline the WebRTC DataChannel pump runs:
/// `process_encode_frame` (sign → embed → store → async VerifyEngine
/// enqueue) followed by the `process_decode_poll` the pump serves. A
/// synthetic frame MUST verify ok against the session-wide signer — pins
/// the data-channel signer fix (the pump path must sign with
/// `state.signer`, the same key the verify worker checks against).
#[tokio::test]
async fn test_datachannel_encode_frame_verifies() {
    let _gate = FRAME_TEST_GATE.lock().await;
    let (_app, state) = test_app();

    let jpeg = test_jpeg(320, 240);
    let mut session = steganographer_dashboard::ws_handler::EncodeSession::new();
    let reply =
        steganographer_dashboard::ws_handler::process_encode_frame(&state, &mut session, &jpeg)
            .expect("data-channel encode must succeed");
    assert_eq!(reply["type"], "encoded_frame");
    assert_eq!(reply["frame_index"], 0);

    // One pump session carries a monotonic frame counter across frames.
    let second =
        steganographer_dashboard::ws_handler::process_encode_frame(&state, &mut session, &jpeg)
            .expect("second encode must succeed");
    assert_eq!(second["frame_index"], 1);

    // The decode poll the pump serves must report a verified payload.
    let mut decode = steganographer_dashboard::ws_handler::DecodeSession::new();
    let poll = steganographer_dashboard::ws_handler::process_decode_poll(&state, &mut decode).await;
    assert_eq!(poll["type"], "decoded_frame");
    assert_eq!(poll["verified"], true, "data-channel frame must verify ok");
    assert_eq!(poll["verified_stale"], false);
    assert_eq!(poll["payload"]["payload_found"], true);
    assert!(poll["payload"]["hash"].as_str().is_some());
}

/// Verify only the returned PNG and public response metadata, with no cache/reference.
fn verify_returned_png(reply: &serde_json::Value, png: &[u8]) -> bool {
    use steganographer_core::{Verifier, VideoFormat, VideoFrame, VideoStegoModule};
    let key: [u8; 32] =
        steganographer_core::crypto::decode_hex(reply["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let image = image::load_from_memory_with_format(png, image::ImageFormat::Png)
        .unwrap()
        .to_rgb8();
    let (width, height) = image.dimensions();
    let mut data = image.into_raw();
    let bits = reply["lsb_bits"].as_u64().unwrap() as u8;
    let index = reply["frame_index"].as_u64().unwrap();
    let payload = steganographer_core::lsb_video::LsbVideo::new(bits)
        .extract(&VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: index,
        })
        .unwrap()
        .unwrap();
    let canonical = steganographer_core::carrier_binding::canonicalize(
        &data,
        "lsb_video",
        bits,
        width,
        height,
        steganographer_core::SignaturePayload::SERIALIZED_SIZE,
    )
    .unwrap();
    payload.frame_index == index
        && Verifier::from_bytes(&key)
            .unwrap()
            .verify(&payload, &canonical, None)
}

#[tokio::test]
async fn delivered_png_verifies_independently_and_binds_high_bits_and_frame_settings() {
    use steganographer_dashboard::ws_handler::{
        base64_decode, process_decode_poll, process_encode_frame, DecodeSession, EncodeSession,
    };
    let (_, state) = test_app();
    state.live_config.lock().unwrap().lsb_bits = 2;
    let _gate = FRAME_TEST_GATE.lock().await;
    let mut session = EncodeSession::new();
    let reply = process_encode_frame(&state, &mut session, &test_jpeg(128, 128)).unwrap();
    assert_eq!(reply["image_mime"], "image/png");
    let png = base64_decode(reply["frame"].as_str().unwrap()).unwrap();
    assert!(verify_returned_png(&reply, &png));
    let mut image = image::load_from_memory(&png).unwrap().to_rgb8();
    image.as_mut()[8192] ^= 0x40;
    let mut tampered = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut tampered, image::ImageFormat::Png)
        .unwrap();
    assert!(!verify_returned_png(&reply, &tampered.into_inner()));
    state.live_config.lock().unwrap().lsb_bits = 4;
    let poll = process_decode_poll(&state, &mut DecodeSession::new()).await;
    assert_eq!(
        poll["lsb_bits"], 2,
        "metadata belongs to stored carrier, not current config"
    );
    assert_eq!(
        poll["frame"], reply["frame"],
        "poll delivers the exact same lossless artifact"
    );
    assert_eq!(poll["cache_revision"], reply["cache_revision"]);
    assert!(verify_returned_png(&poll, &png));
    let revision = poll["cache_revision"].as_u64().unwrap();
    let replacement =
        process_encode_frame(&state, &mut EncodeSession::new(), &test_jpeg(128, 128)).unwrap();
    assert_eq!(replacement["frame_index"], 0);
    let poll = process_decode_poll(&state, &mut DecodeSession::new()).await;
    assert!(poll["cache_revision"].as_u64().unwrap() > revision);
}

#[test]
fn unsupported_security_choices_are_rejected_not_decoratively_stored() {
    for (field, value) in [
        ("signing_backend", serde_json::json!("ethereum")),
        ("signing_backend", serde_json::json!("metamask")),
        ("hash_algorithm", serde_json::json!("sha256")),
        ("stego_type", serde_json::json!("dct")),
        ("stego_type", serde_json::json!("spread_spectrum")),
        ("encrypt", serde_json::json!(true)),
        ("ecc", serde_json::json!(true)),
    ] {
        let mut json = serde_json::to_value(LiveConfig::default()).unwrap();
        json[field] = value;
        assert!(
            validate_live_config(&serde_json::from_value(json).unwrap()).is_err(),
            "{field}"
        );
    }
    assert!(
        serde_json::from_str::<LiveConfig>(r#"{"lsbBits":4}"#).is_err(),
        "unknown names cannot silently reset config"
    );
}

#[tokio::test]
async fn tokenless_foreign_origin_cannot_reset_metrics_or_stamp() {
    use tower::ServiceExt;
    let (app, state) = test_app();
    state.metrics.record_frame();
    for path in ["/api/metrics/reset", "/ots/stamp", "/ots/verify"] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", "127.0.0.1:8080")
                    .header("origin", "https://foreign.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    assert_eq!(state.metrics.frames_processed(), 1);
}

#[tokio::test]
async fn ice_capabilities_require_bearer_and_publish_real_server_default() {
    use tower::ServiceExt;
    let (app, _) = test_app_with_token(Some(TEST_TOKEN.into()));
    for token in [None, Some("Bearer wrong"), Some("Bearer sekret")] {
        let mut request = axum::http::Request::builder().uri("/api/webrtc/config");
        if let Some(token) = token {
            request = request.header("authorization", token);
        }
        let response = app
            .clone()
            .oneshot(request.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        if token == Some("Bearer sekret") {
            assert_eq!(response.status(), 200);
            let json: serde_json::Value =
                serde_json::from_str(&body_to_string(response.into_body()).await).unwrap();
            assert_eq!(json["default_transport"], "auto");
        } else {
            assert_eq!(response.status(), 401);
        }
    }
}

#[tokio::test]
async fn common_encoder_rejects_oversized_dimensions_and_malformed_input() {
    use steganographer_dashboard::ws_handler::{process_encode_frame, EncodeSession};
    let (_, state) = test_app();
    let _gate = FRAME_TEST_GATE.lock().await;
    assert!(
        process_encode_frame(&state, &mut EncodeSession::new(), &test_jpeg(4097, 16)).is_none()
    );
    assert!(process_encode_frame(&state, &mut EncodeSession::new(), b"invalid").is_none());
    assert!(state.last_encoded_frame.lock().unwrap().is_none());
}

/// A real calendar protocol receipt is pending, never a fabricated verified response.
#[tokio::test]
async fn stamp_commits_exact_delivered_png_and_enforces_pending_digest_and_interval() {
    use steganographer_dashboard::ws_handler::{
        base64_decode, process_encode_frame, EncodeSession,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;
    let _gate = FRAME_TEST_GATE.lock().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calendar_url = url.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let calendar = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        let digest = loop {
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0 && request.len() + count <= 8192);
            request.extend_from_slice(&chunk[..count]);
            if let Some(offset) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..offset]).unwrap();
                assert!(headers.starts_with("POST /digest HTTP/1.1\r\n"));
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                assert_eq!(length, 32);
                if request.len() >= offset + 4 + length {
                    break request[offset + 4..offset + 4 + length].to_vec();
                }
            }
        };
        // Standard pending attestation tag and URL, with short canonical varints.
        let mut tree = vec![0, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
        tree.push((calendar_url.len() + 1) as u8);
        tree.push(calendar_url.len() as u8);
        tree.extend_from_slice(calendar_url.as_bytes());
        let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.opentimestamps.v1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",tree.len());
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&tree).await.unwrap();
        sender.send(digest).unwrap();
    });
    let directory = std::env::temp_dir().join(format!(
        "steganographer-dashboard-ots-{:032x}",
        rand::random::<u128>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let (app, state) = test_app();
    drop(app);
    let mut state = Arc::try_unwrap(state).ok().unwrap();
    state.ots_config = steganographer_core::OtsConfig {
        enabled: true,
        server_url: url,
        interval_secs: 300,
        timeout_secs: 2,
        proof_dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    state.ots_client = Some(Arc::new(
        steganographer_core::OTSClient::from_config(&state.ots_config).unwrap(),
    ));
    let state = Arc::new(state);
    let app = steganographer_dashboard::create_router(state.clone()).unwrap();
    let post = || {
        axum::http::Request::builder()
            .method("POST")
            .uri("/ots/stamp")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let no_media = app.clone().oneshot(post()).await.unwrap();
    assert_eq!(no_media.status(), 409);
    let encoded =
        process_encode_frame(&state, &mut EncodeSession::new(), &test_jpeg(128, 128)).unwrap();
    let png = base64_decode(encoded["frame"].as_str().unwrap()).unwrap();
    let expected = steganographer_core::OTSClient::compute_sha256_digest(&png);
    let response = app.clone().oneshot(post()).await.unwrap();
    assert_eq!(response.status(), 200);
    let receipt: serde_json::Value =
        serde_json::from_str(&body_to_string(response.into_body()).await).unwrap();
    assert_eq!(receipt["pending"], true);
    assert_eq!(receipt["verified"], false);
    assert_eq!(
        receipt["digest"],
        steganographer_core::crypto::encode_hex(&expected)
    );
    let submitted = tokio::time::timeout(std::time::Duration::from_secs(2), receiver)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        submitted, expected,
        "calendar must not receive the raw media digest"
    );
    let proof = tokio::fs::read(receipt["proof_path"].as_str().unwrap())
        .await
        .unwrap();
    let magic = b"\0OpenTimestamps\0\0Proof\0\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
    let operations = magic.len() + 2 + 32;
    assert!(proof.len() >= operations + 35 && proof.starts_with(magic));
    assert_eq!(&proof[magic.len()..magic.len() + 2], &[1, 8]);
    assert_eq!(&proof[magic.len() + 2..operations], &expected);
    assert_eq!(&proof[operations..operations + 2], &[0xf0, 32]);
    assert_eq!(proof[operations + 34], 0x08);
    let mut blinded_input = expected.to_vec();
    blinded_input.extend_from_slice(&proof[operations + 2..operations + 34]);
    assert_eq!(
        submitted,
        steganographer_core::OTSClient::compute_sha256_digest(&blinded_input)
    );
    calendar.await.unwrap();
    let status_request = || {
        axum::http::Request::builder()
            .uri("/ots/status")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let status: serde_json::Value = serde_json::from_str(
        &body_to_string(
            app.clone()
                .oneshot(status_request())
                .await
                .unwrap()
                .into_body(),
        )
        .await,
    )
    .unwrap();
    assert_eq!(status["can_stamp"], false);
    assert_eq!(status["pending"], true);
    assert_eq!(status["verified"], false);
    assert_eq!(status["media_digest"], receipt["digest"]);
    assert_eq!(app.clone().oneshot(post()).await.unwrap().status(), 429);
    let missing = axum::http::Request::builder()
        .method("POST")
        .uri("/ots/verify")
        .body(axum::body::Body::from(proof.clone()))
        .unwrap();
    assert_eq!(app.clone().oneshot(missing).await.unwrap().status(), 400);
    let mismatch = axum::http::Request::builder()
        .method("POST")
        .uri("/ots/verify")
        .header("x-expected-digest", "00".repeat(32))
        .body(axum::body::Body::from(proof))
        .unwrap();
    assert_eq!(app.oneshot(mismatch).await.unwrap().status(), 422);
    std::fs::remove_dir_all(directory).unwrap();
}
