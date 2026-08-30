//! Integration tests for the OpenTimestamps (OTS) client, config, and handler
//! modules.
//!
//! These tests exercise the **public API** only and require **no network
//! access** — stamping/verification calls are pointed at a dead endpoint
//! (`127.0.0.1:1`) so they fail fast and deterministically, or use the
//! synchronous save/load/parse paths that never touch the network.

use std::path::PathBuf;
use std::time::Duration;
use steganographer_core::ots_config::{
    OtsConfig, OtsSettings, DEFAULT_INTERVAL_SECS, DEFAULT_PROOF_DIR, DEFAULT_SERVER_URL,
};
use steganographer_core::ots_handler;
use steganographer_core::{OTSClient, OTSError, OTSMethod, OTSVResult};

// ─── OTSConfig ───────────────────────────────────────────────────────────

#[test]
fn test_config_defaults_are_disabled() {
    let cfg = OtsConfig::default();
    assert!(!cfg.is_enabled());
    assert_eq!(cfg.server_url, DEFAULT_SERVER_URL);
    assert_eq!(cfg.method, "bitcoin");
    assert_eq!(cfg.interval_secs, DEFAULT_INTERVAL_SECS);
    assert_eq!(cfg.proof_dir, DEFAULT_PROOF_DIR);
}

#[test]
fn test_config_from_toml_minimal() {
    let toml_str = r#"
enabled = true
"#;
    let cfg: OtsConfig = toml::from_str(toml_str).unwrap();
    assert!(cfg.is_enabled());
    // Defaults still apply for omitted fields.
    assert_eq!(cfg.server_url, DEFAULT_SERVER_URL);
    assert_eq!(cfg.method, "bitcoin");
    assert_eq!(cfg.interval_secs, DEFAULT_INTERVAL_SECS);
}

#[test]
fn test_config_from_toml_full() {
    let toml_str = r#"
enabled = true
server_url = "https://alice.btc.calendar.opentimestamps.org"
method = "ethereum"
interval_secs = 600
proof_dir = "/var/ots"
timeout_secs = 15
"#;
    let cfg: OtsConfig = toml::from_str(toml_str).unwrap();
    assert!(cfg.is_enabled());
    assert_eq!(
        cfg.server_url,
        "https://alice.btc.calendar.opentimestamps.org"
    );
    assert_eq!(cfg.method, "ethereum");
    assert_eq!(cfg.interval_secs, 600);
    assert_eq!(cfg.proof_dir, "/var/ots");
    assert_eq!(cfg.timeout_secs, 15);
    assert_eq!(cfg.method_canonical(), "ethereum");
}

#[test]
fn test_config_absent_block_is_disabled() {
    // When [ots] is absent from TOML, serde Default is used.
    let cfg = OtsConfig::default();
    assert!(!cfg.is_enabled());
}

#[test]
fn test_config_interval_timeout_clamped() {
    let cfg = OtsConfig {
        interval_secs: 0,
        timeout_secs: 0,
        ..OtsConfig::default()
    };
    assert_eq!(cfg.interval(), Duration::from_secs(1));
    assert_eq!(cfg.timeout(), Duration::from_secs(1));
}

#[test]
fn test_config_method_canonical_fallback() {
    let mut cfg = OtsConfig {
        method: "unknown-method".to_string(),
        ..Default::default()
    };
    assert_eq!(cfg.method_canonical(), "bitcoin");
    cfg.method = "ETH".to_string();
    assert_eq!(cfg.method_canonical(), "ethereum");
}

// ─── OtsSettings ─────────────────────────────────────────────────────────

#[test]
fn test_settings_from_config_enabled_ethereum() {
    let cfg = OtsConfig {
        enabled: true,
        method: "ethereum".to_string(),
        interval_secs: 120,
        ..OtsConfig::default()
    };
    let settings = OtsSettings::from_config(&cfg);
    assert!(settings.enabled);
    assert!(!settings.is_disabled());
    assert_eq!(settings.interval_secs, 120);
    assert_eq!(settings.method_tag, 1);
    assert_eq!(settings.method_name(), "ethereum");
}

#[test]
fn test_settings_from_config_disabled() {
    let cfg = OtsConfig::default();
    let settings = OtsSettings::from_config(&cfg);
    assert!(settings.is_disabled());
    assert_eq!(settings.method_name(), "bitcoin");
}

// ─── OTSMethod ───────────────────────────────────────────────────────────

#[test]
fn test_method_tag_roundtrip() {
    assert_eq!(OTSMethod::Bitcoin.tag(), 0);
    assert_eq!(OTSMethod::Ethereum.tag(), 1);
    assert_eq!(OTSMethod::from_tag(0), OTSMethod::Bitcoin);
    assert_eq!(OTSMethod::from_tag(1), OTSMethod::Ethereum);
    assert_eq!(OTSMethod::from_tag(255), OTSMethod::Bitcoin);
}

#[test]
fn test_method_parse_case_insensitive() {
    assert_eq!(OTSMethod::parse("bitcoin"), OTSMethod::Bitcoin);
    assert_eq!(OTSMethod::parse("Bitcoin"), OTSMethod::Bitcoin);
    assert_eq!(OTSMethod::parse("ETH"), OTSMethod::Ethereum);
    assert_eq!(OTSMethod::parse("ethereum"), OTSMethod::Ethereum);
    assert_eq!(OTSMethod::parse("garbage"), OTSMethod::Bitcoin);
}

#[test]
fn test_method_display() {
    assert_eq!(OTSMethod::Bitcoin.to_string(), "bitcoin");
    assert_eq!(OTSMethod::Ethereum.to_string(), "ethereum");
}

// ─── OTSClient construction ──────────────────────────────────────────────

#[test]
fn test_client_from_config_defaults() {
    let cfg = OtsConfig {
        enabled: true,
        ..OtsConfig::default()
    };
    let client = OTSClient::from_config(&cfg);
    assert_eq!(client.method(), OTSMethod::Bitcoin);
    assert!(client.can_stamp());
}

#[test]
fn test_client_from_config_ethereum_strips_trailing_slash() {
    let cfg = OtsConfig {
        enabled: true,
        method: "ethereum".to_string(),
        server_url: "https://example.com/".to_string(),
        ..OtsConfig::default()
    };
    let client = OTSClient::from_config(&cfg);
    assert_eq!(client.method(), OTSMethod::Ethereum);
}

#[test]
fn test_client_with_proof_dir_override() {
    let tmp = std::env::temp_dir().join(format!("ots_it_{}_dir", std::process::id()));
    let client = OTSClient::new(OTSMethod::Bitcoin).with_proof_dir(&tmp);
    assert_eq!(client.proof_dir(), tmp.as_path());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_client_with_server_url_override() {
    let client = OTSClient::new(OTSMethod::Bitcoin).with_server_url("https://custom.ots.server/");
    // The trailing slash is stripped internally.
    let debug = format!("{client:?}");
    assert!(debug.contains("custom.ots.server"));
}

// ─── Rate limiting ───────────────────────────────────────────────────────

#[test]
fn test_can_stamp_fresh_client() {
    let client = OTSClient::new(OTSMethod::Bitcoin).with_min_interval(Duration::from_secs(3600));
    assert!(client.can_stamp(), "fresh client should permit stamping");
}

#[test]
fn test_cannot_stamp_within_interval() {
    let client = OTSClient::new(OTSMethod::Bitcoin).with_min_interval(Duration::from_secs(3600));
    client.mark_stamped();
    assert!(
        !client.can_stamp(),
        "should not stamp within the interval window"
    );
}

#[test]
fn test_can_stamp_zero_interval() {
    let client = OTSClient::new(OTSMethod::Bitcoin).with_min_interval(Duration::from_secs(0));
    assert!(client.can_stamp());
    client.mark_stamped();
    assert!(client.can_stamp(), "zero interval always permits");
}

// ─── SHA-256 digest ──────────────────────────────────────────────────────

#[test]
fn test_compute_sha256_deterministic() {
    let d1 = OTSClient::compute_sha256_digest(b"hello");
    let d2 = OTSClient::compute_sha256_digest(b"hello");
    assert_eq!(d1, d2);
    assert_eq!(d1.len(), 32);
    assert_ne!(d1, [0u8; 32]);
}

#[test]
fn test_compute_sha256_different_inputs() {
    let d1 = OTSClient::compute_sha256_digest(b"hello");
    let d2 = OTSClient::compute_sha256_digest(b"world");
    assert_ne!(d1, d2);
}

// ─── Proof storage and retrieval ─────────────────────────────────────────

#[test]
fn test_save_and_load_proof_roundtrip() {
    let tmp = std::env::temp_dir().join(format!("ots_it_{}_save", std::process::id()));
    let client = OTSClient::new(OTSMethod::Bitcoin).with_proof_dir(&tmp);
    let proof = b"FAKE_OTS_PROOF_BODY_12345678".to_vec();
    let digest_hex = "abcdef0123456789";
    let path = client.save_proof(&proof, digest_hex).unwrap();
    assert!(path.exists());
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        "abcdef0123456789.ots"
    );

    let loaded = OTSClient::load_proof(&path).unwrap();
    assert_eq!(loaded, proof);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_save_proof_creates_missing_dir() {
    let tmp = std::env::temp_dir().join(format!("ots_it_{}_nested/deep/dir", std::process::id()));
    let client = OTSClient::new(OTSMethod::Bitcoin).with_proof_dir(&tmp);
    let proof = b"PROOF".to_vec();
    let path = client.save_proof(&proof, "deadbeef").unwrap();
    assert!(path.exists());
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("ots_it_{}_nested", std::process::id())),
    );
}

#[test]
fn test_save_proof_to_explicit_path() {
    let tmp = std::env::temp_dir().join(format!(
        "ots_it_{}_explicit/sub/proof.ots",
        std::process::id()
    ));
    let client = OTSClient::new(OTSMethod::Bitcoin);
    let proof = b"EXPLICIT_PROOF".to_vec();
    let written = client.save_proof_to(&proof, &tmp).unwrap();
    assert_eq!(written, tmp);
    let loaded = OTSClient::load_proof(&tmp).unwrap();
    assert_eq!(loaded, proof);
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("ots_it_{}_explicit", std::process::id())),
    );
}

#[test]
fn test_proof_path_for_digest() {
    let client = OTSClient::new(OTSMethod::Bitcoin).with_proof_dir(PathBuf::from("/tmp/ots_it"));
    let path = client.proof_path_for("abc123");
    assert_eq!(path, PathBuf::from("/tmp/ots_it/abc123.ots"));
}

#[test]
fn test_load_proof_missing_file_errors() {
    let result = OTSClient::load_proof(std::path::Path::new("/nonexistent/path/proof.ots"));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), OTSError::Io(_)));
}

// ─── OTSVResult ──────────────────────────────────────────────────────────

#[test]
fn test_otsv_result_no_proof() {
    let r = OTSVResult::no_proof();
    assert!(!r.verified);
    assert_eq!(r.method, "none");
    assert!(r.timestamp.is_none());
    assert!(r.details.contains("No OpenTimestamps proof"));
}

// ─── Error handling paths (no network) ───────────────────────────────────

fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(future)
}

#[test]
fn test_stamp_digest_dead_endpoint_errors() {
    let client = OTSClient::new(OTSMethod::Bitcoin)
        .with_server_url("http://127.0.0.1:1")
        .with_min_interval(Duration::from_secs(0));
    let digest = [0u8; 32];
    let result = block_on(client.stamp_digest(&digest));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            OTSError::Http(_) | OTSError::Network(_) | OTSError::ServiceUnavailable(_)
        ),
        "expected network-class error, got {err:?}"
    );
}

#[test]
fn test_stamp_data_dead_endpoint_errors() {
    let client = OTSClient::new(OTSMethod::Bitcoin)
        .with_server_url("http://127.0.0.1:1")
        .with_min_interval(Duration::from_secs(0));
    let result = block_on(client.stamp_data(b"some-merkle-root"));
    assert!(result.is_err());
}

#[test]
fn test_verify_short_proof_errors() {
    let client = OTSClient::new(OTSMethod::Bitcoin);
    let result = block_on(client.verify(b"short"));
    assert!(matches!(result, Err(OTSError::InvalidProof(_))));
}

#[test]
fn test_verify_dead_endpoint_errors() {
    let client = OTSClient::new(OTSMethod::Bitcoin).with_server_url("http://127.0.0.1:1");
    let fake_proof = vec![0u8; 100]; // long enough to pass the size check
    let result = block_on(client.verify(&fake_proof));
    assert!(result.is_err());
}

// ─── Handler functions ───────────────────────────────────────────────────

#[test]
fn test_handler_status_disabled() {
    let cfg = OtsConfig::default();
    let json = ots_handler::status_handler(&cfg, None);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["enabled"], false);
    assert_eq!(v["status"], "disabled");
}

#[test]
fn test_handler_status_ready() {
    let cfg = OtsConfig {
        enabled: true,
        ..OtsConfig::default()
    };
    let client = OTSClient::from_config(&cfg);
    let json = ots_handler::status_handler(&cfg, Some(&client));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["enabled"], true);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["can_stamp"], true);
}

#[test]
fn test_handler_stamp_dead_endpoint() {
    let client = OTSClient::new(OTSMethod::Bitcoin)
        .with_server_url("http://127.0.0.1:1")
        .with_min_interval(Duration::from_secs(0));
    let result = block_on(ots_handler::stamp_handler(&client, b"merkle-root"));
    assert!(result.is_err());
    let (status, body) = ots_handler::error_to_http(&result.unwrap_err());
    assert_eq!(status, 503);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    // Connection-refused produces an Http error ("unreachable") rather than
    // ServiceUnavailable ("unavailable"); both indicate the server is down.
    let kind = v["kind"].as_str().unwrap();
    assert!(
        kind == "unavailable" || kind == "unreachable",
        "expected unavailable or unreachable, got {kind}"
    );
}

#[test]
fn test_handler_verify_short_proof() {
    let client = OTSClient::new(OTSMethod::Bitcoin);
    let result = block_on(ots_handler::verify_handler(&client, b"short"));
    assert!(result.is_err());
    let (status, _) = ots_handler::error_to_http(&result.unwrap_err());
    assert_eq!(status, 400);
}

#[test]
fn test_handler_error_to_http_all_variants() {
    let cases = vec![
        (OTSError::ServiceUnavailable("x".into()), 503u16),
        (OTSError::Network("x".into()), 503),
        (
            OTSError::ServerStatus {
                status: 500,
                body: "x".into(),
            },
            502,
        ),
        (OTSError::InvalidProof("x".into()), 400),
        (OTSError::VerificationFailed("x".into()), 422),
        (OTSError::Io(std::io::Error::other("x")), 500),
    ];
    for (err, expected) in cases {
        let (status, body) = ots_handler::error_to_http(&err);
        assert_eq!(status, expected, "mismatch for {err:?}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "error");
        assert!(v["kind"].is_string());
    }
}

#[test]
fn test_handler_method_name() {
    assert_eq!(ots_handler::method_name(OTSMethod::Bitcoin), "bitcoin");
    assert_eq!(ots_handler::method_name(OTSMethod::Ethereum), "ethereum");
}

// ─── Debug formatting ────────────────────────────────────────────────────

#[test]
fn test_client_debug_format() {
    let client = OTSClient::new(OTSMethod::Ethereum);
    let s = format!("{client:?}");
    assert!(s.contains("OTSClient"));
    assert!(s.contains("Ethereum"));
}
