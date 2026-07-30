//! Async handler functions for OpenTimestamps stamping and verification.
//!
//! These are thin, framework-agnostic functions suitable for use behind
//! axum/actix route handlers (see the dashboard crate's OTS routes). They
//! take an [`OTSClient`] / [`OtsConfig`] and return JSON strings, keeping
//! the core crate free of any HTTP-framework dependency.
//!
//! **Graceful degradation.** When OTS is disabled (`enabled = false`), the
//! status handler reports `{"enabled": false, ...}` and the stamp/verify
//! handlers return a disabled-indicator JSON rather than an error. When the
//! OTS server is unreachable, stamp/verify return an [`OTSError`] variant the
//! caller can map to an HTTP 503 — the stego pipeline is never blocked.

use crate::ots_client::{OTSClient, OTSError, OTSMethod, OTSVResult};
use crate::ots_config::OtsConfig;

/// Build the JSON status payload describing the current OTS configuration
/// and runtime state.
///
/// `client` should be `Some` when OTS is enabled and a client was
/// constructed. When `None`, the response reports the feature as disabled
/// or unavailable.
pub fn status_handler(config: &OtsConfig, client: Option<&OTSClient>) -> String {
    let enabled = config.is_enabled();
    let can_stamp = client.map(|c| c.can_stamp()).unwrap_or(false);
    let method = config.method_canonical();
    let proofs_dir = config.proof_dir.clone();

    serde_json::json!({
        "enabled": enabled,
        "available": client.is_some(),
        "can_stamp": can_stamp,
        "method": method,
        "server_url": config.server_url,
        "interval_secs": config.interval_secs,
        "timeout_secs": config.timeout_secs,
        "proof_dir": proofs_dir,
        "status": if !enabled { "disabled" } else if client.is_some() { "ready" } else { "unavailable" },
    })
    .to_string()
}

/// Stamp a piece of data (typically the current BLAKE3 Merkle root) with the
/// OpenTimestamps service.
///
/// Returns a JSON string describing the outcome on success, or an [`OTSError`]
/// on failure. The caller is expected to map `ServiceUnavailable` /
/// `Http` errors to HTTP 503 for graceful degradation.
pub async fn stamp_handler(client: &OTSClient, data: &[u8]) -> Result<String, OTSError> {
    let digest = OTSClient::compute_sha256_digest(data);
    let digest_hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    let proof = client.stamp_digest(&digest).await?;
    let proof_path = client.save_proof(&proof, &digest_hex)?;
    client.mark_stamped();

    Ok(serde_json::json!({
        "status": "stamped",
        "method": client.method().as_str(),
        "digest": digest_hex,
        "proof_size": proof.len(),
        "proof_path": proof_path.display().to_string(),
    })
    .to_string())
}

/// Verify a `.ots` proof against the OpenTimestamps service.
///
/// `proof` is the raw bytes of the `.ots` file. Returns a JSON string
/// describing the verification result, or an [`OTSError`].
pub async fn verify_handler(client: &OTSClient, proof: &[u8]) -> Result<String, OTSError> {
    let result: OTSVResult = client.verify(proof).await?;
    Ok(serde_json::json!({
        "status": if result.verified { "verified" } else { "unverified" },
        "verified": result.verified,
        "method": result.method,
        "timestamp": result.timestamp,
        "details": result.details,
    })
    .to_string())
}

/// Convenience: convert an [`OTSError`] into a `(http_status, json_body)` tuple
/// suitable for returning from an HTTP handler. Server-side failures map to
/// 503 (so the dashboard can show "unavailable"), client-side proof issues to
/// 400, and I/O errors to 500.
pub fn error_to_http(err: &OTSError) -> (u16, String) {
    let (status, kind) = match err {
        // Any failure to reach the OTS service — connection refused, DNS,
        // timeout, an explicit 503 response, or a reqwest HTTP error — is
        // reported to the dashboard as "unavailable". The stego pipeline
        // treats all of these the same way (graceful degradation), so the
        // finer "unreachable" vs "unavailable" distinction is not useful to
        // callers. All map to HTTP 503.
        OTSError::ServiceUnavailable(_)
        | OTSError::Http(_)
        | OTSError::Network(_) => (503, "unavailable"),
        OTSError::ServerStatus { .. } => (502, "server_error"),
        OTSError::InvalidProof(_) => (400, "invalid_proof"),
        OTSError::VerificationFailed(_) => (422, "verification_failed"),
        OTSError::Io(_) => (500, "io_error"),
    };
    (
        status,
        serde_json::json!({
            "status": "error",
            "kind": kind,
            "message": err.to_string(),
        })
        .to_string(),
    )
}

/// Map an [`OTSMethod`] to its canonical string name (helper for handlers).
pub fn method_name(method: OTSMethod) -> &'static str {
    method.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_status_handler_disabled() {
        let cfg = OtsConfig::default(); // disabled
        let json = status_handler(&cfg, None);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["enabled"], false);
        assert_eq!(v["available"], false);
        assert_eq!(v["status"], "disabled");
    }

    #[test]
    fn test_status_handler_enabled_with_client() {
        let cfg = OtsConfig {
            enabled: true,
            method: "ethereum".to_string(),
            ..OtsConfig::default()
        };
        let client = OTSClient::from_config(&cfg);
        let json = status_handler(&cfg, Some(&client));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["available"], true);
        assert_eq!(v["status"], "ready");
        assert_eq!(v["method"], "ethereum");
        assert_eq!(v["can_stamp"], true);
    }

    #[test]
    fn test_status_handler_enabled_no_client() {
        let cfg = OtsConfig {
            enabled: true,
            ..OtsConfig::default()
        };
        let json = status_handler(&cfg, None);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["available"], false);
        assert_eq!(v["status"], "unavailable");
    }

    #[test]
    fn test_error_to_http_service_unavailable() {
        let err = OTSError::ServiceUnavailable("down".into());
        let (status, body) = error_to_http(&err);
        assert_eq!(status, 503);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["kind"], "unavailable");
    }

    #[test]
    fn test_error_to_http_invalid_proof() {
        let err = OTSError::InvalidProof("too short".into());
        let (status, body) = error_to_http(&err);
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["kind"], "invalid_proof");
    }

    #[test]
    fn test_error_to_http_verification_failed() {
        let err = OTSError::VerificationFailed("mismatch".into());
        let (status, _) = error_to_http(&err);
        assert_eq!(status, 422);
    }

    #[test]
    fn test_error_to_http_io() {
        let err = OTSError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
        let (status, _) = error_to_http(&err);
        assert_eq!(status, 500);
    }

    #[test]
    fn test_error_to_http_server_status() {
        let err = OTSError::ServerStatus {
            status: 404,
            body: "not found".into(),
        };
        let (status, _) = error_to_http(&err);
        assert_eq!(status, 502);
    }

    #[test]
    fn test_error_to_http_network() {
        let err = OTSError::Network("bad url".into());
        let (status, _) = error_to_http(&err);
        assert_eq!(status, 503);
    }

    #[test]
    fn test_method_name_helper() {
        assert_eq!(method_name(OTSMethod::Bitcoin), "bitcoin");
        assert_eq!(method_name(OTSMethod::Ethereum), "ethereum");
    }

    #[test]
    fn test_stamp_handler_invalid_proof_path() {
        // stamp_data with a valid digest but pointing at a dead endpoint
        // exercises the error return path without needing real network success.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = OTSClient::new(OTSMethod::Bitcoin)
            .with_server_url("http://127.0.0.1:1")
            .with_min_interval(Duration::from_secs(0));
        let result = rt.block_on(stamp_handler(&client, b"merkle-root-data"));
        assert!(result.is_err());
        let (status, _) = error_to_http(&result.unwrap_err());
        assert_eq!(status, 503);
    }

    #[test]
    fn test_verify_handler_short_proof() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = OTSClient::new(OTSMethod::Bitcoin);
        let result = rt.block_on(verify_handler(&client, b"short"));
        assert!(result.is_err());
        let (status, body) = error_to_http(&result.unwrap_err());
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["kind"], "invalid_proof");
    }
}
