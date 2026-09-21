use std::sync::{Arc, Mutex};
use steganographer_dashboard::{validate_live_config, DashboardState, LiveConfig};

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
fn test_live_config_camel_case_field_names() {
    let json = r#"{"opacity":0.8,"lsbBits":2,"signingBackend":"ethereum","overlayText":"TOP SECRET","signRateMs":250}"#;
    let cfg: LiveConfig = serde_json::from_str(json).expect("camelCase parse");
    assert!((cfg.opacity - 0.8).abs() < f64::EPSILON);
    assert_eq!(cfg.lsb_bits, 2);
    assert_eq!(cfg.signing_backend, "ethereum");
    assert_eq!(cfg.overlay_text, "TOP SECRET");
    assert_eq!(cfg.sign_rate_ms, 250);
}

#[test]
fn test_live_config_boundary_values() {
    let json = r#"{"opacity":0.0,"lsbBits":4,"signRateMs":200}"#;
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
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
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
    };
    let json = serde_json::to_string(&original).unwrap();
    let restored: LiveConfig = serde_json::from_str(&json).unwrap();
    assert!((restored.opacity - original.opacity).abs() < f64::EPSILON);
    assert_eq!(restored.lsb_bits, original.lsb_bits);
    assert_eq!(restored.signing_backend, original.signing_backend);
    assert_eq!(restored.overlay_text, original.overlay_text);
    assert_eq!(restored.sign_rate_ms, original.sign_rate_ms);
}

// ─── Router Tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_router_creation() {
    let state = Arc::new(DashboardState {
        metrics: Arc::new(steganographer_core::StegoMetrics::new()),
        signing_backend: "ed25519".into(),
        identity: "test_identity".into(),
        width: 640,
        height: 480,
        last_encoded_frame: Mutex::new(None),
        last_encoded_audio: Mutex::new(None),
        live_config: Mutex::new(LiveConfig::default()),
        session_start: std::time::Instant::now(),
        auth_token: None,
        ots_config: steganographer_core::OtsConfig::default(),
        ots_client: None,
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
    });
    let _router = steganographer_dashboard::create_router(state);
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
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
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
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let parsed: LiveConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.qr_scale, 75);
    assert_eq!(parsed.resolution, "1920x1080");
}

#[test]
fn test_live_config_camel_case_qr_scale() {
    let json = r#"{"opacity":1.0,"lsbBits":1,"signingBackend":"ed25519","overlayText":"X","signRateMs":1000,"qrScale":50,"resolution":"1280x720"}"#;
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
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
    });
    let router = steganographer_dashboard::create_router(state.clone());
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
    let (app, _state) = test_app();
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
    assert_eq!(json["identity"], "test_identity_abc123");
    assert_eq!(json["resolution"], "640x480");
    assert!(json.get("config").is_some(), "missing config");
    assert!(json.get("metrics").is_some(), "missing metrics");
}

#[tokio::test]
async fn test_api_config_get_returns_json() {
    use tower::ServiceExt;
    let (app, _state) = test_app();
    let req = axum::http::Request::builder()
        .uri("/api/config")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_to_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["signing_backend"], "ed25519");
    assert_eq!(json["identity"], "test_identity_abc123");
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
        "lsbBits": 3,
        "signingBackend": "ethereum",
        "overlayText": "UPDATED",
        "signRateMs": 500,
        "qrScale": 30,
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
    assert_eq!(cfg.signing_backend, "ethereum");
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
        "lsbBits": lsb_bits,
        "signingBackend": "ed25519",
        "overlayText": "X",
        "signRateMs": 1000,
        "qrScale": 10,
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
        assert!(err.contains("lsbBits"), "error names lsbBits: {err}");
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
        assert!(err.contains("signRateMs"), "error names signRateMs: {err}");
    }
}

// ─── POST /api/config validation (HTTP) ───────────────────────────────

#[tokio::test]
async fn test_api_config_post_rejects_lsb_bits_5() {
    let (app, _state) = test_app();
    let (status, body) = post_config(app, config_body(5), None).await;
    assert_eq!(status, 400);
    assert!(body.contains("lsbBits"), "message names the field: {body}");
}

#[tokio::test]
async fn test_api_config_post_rejects_bad_opacity_and_rate() {
    for (field, body) in [
        (
            "opacity",
            r#"{"opacity": 1.5, "lsbBits": 1, "signRateMs": 1000}"#,
        ),
        (
            "opacity",
            r#"{"opacity": -0.1, "lsbBits": 1, "signRateMs": 1000}"#,
        ),
        (
            "signRateMs",
            r#"{"opacity": 0.5, "lsbBits": 1, "signRateMs": 10}"#,
        ),
        (
            "signRateMs",
            r#"{"opacity": 0.5, "lsbBits": 1, "signRateMs": 0}"#,
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
        ots_client: Some(Arc::new(steganographer_core::OTSClient::new(
            steganographer_core::OTSMethod::Bitcoin,
        ))),
        signer: steganographer_core::Signer::generate(),
        audio_key: [7u8; 32],
    });
    let app = steganographer_dashboard::create_router(state.clone());
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
