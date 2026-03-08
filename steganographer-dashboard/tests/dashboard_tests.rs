use steganographer_dashboard::{DashboardState, LiveConfig};
use std::sync::{Arc, Mutex};

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

/// Helper: build a real Axum app with test state.
fn test_app() -> (axum::Router, Arc<DashboardState>) {
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
    assert!(arr.contains(&"README.md".to_string()), "should include README.md");
    assert!(arr.contains(&"threat-model.md".to_string()), "should include threat-model.md");
    assert!(arr.len() >= 17, "should have at least 17 doc files, got {}", arr.len());
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
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("text/markdown"), "expected markdown content-type, got {}", ct);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("Steganographer"), "README should mention Steganographer");
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
    assert!(body.contains("<!DOCTYPE html>") || body.contains("<html"), "should be HTML");
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
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
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
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("javascript"), "expected javascript content-type, got {}", ct);
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
    assert!(json.get("frames_processed").is_some(),
        "metrics JSON should have frames_processed field: {}", body);
}
