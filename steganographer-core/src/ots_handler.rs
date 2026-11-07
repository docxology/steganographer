//! Framework-independent handlers for actual OpenTimestamps calendar proofs.
use crate::{
    crypto::encode_hex,
    ots_client::{OTSClient, OTSError, OTSMethod},
    ots_config::OtsConfig,
};

pub fn status_handler(config: &OtsConfig, client: Option<&OTSClient>) -> String {
    serde_json::json!({
        "enabled": config.enabled,
        "available": client.is_some(),
        "can_stamp": config.enabled && client.is_some_and(OTSClient::can_stamp),
        "method": config.method_canonical(),
        "server_url": config.server_url,
        "bitcoin_explorer_url": config.bitcoin_explorer_url,
        "verification_trust": "configured Esplora canonical-height index; not independent full-node validation",
        "interval_secs": config.interval_secs,
        "timeout_secs": config.timeout_secs,
        "proof_dir": config.proof_dir,
        "status": if !config.enabled { "disabled" } else if client.is_some() { "ready" } else { "unavailable" },
    }).to_string()
}
/// Hash explicit data. Dashboard media callers must use handle_stamp_digest
/// with the digest of their actual latest signed media, never elapsed time.
pub async fn stamp_handler(client: &OTSClient, data: &[u8]) -> Result<String, OTSError> {
    if data.is_empty() {
        return Err(OTSError::InvalidProof("no content to stamp".into()));
    }
    handle_stamp_digest(client, &OTSClient::compute_sha256_digest(data)).await
}
/// Submit an already-computed content commitment without hashing it again.
pub async fn handle_stamp_digest(
    client: &OTSClient,
    digest: &[u8; 32],
) -> Result<String, OTSError> {
    let proof = client.stamp_digest(digest).await?;
    let pending = OTSClient::validate_proof(&proof, digest)?;
    let digest_hex = encode_hex(digest);
    let proof_path = client.save_proof(&proof, &digest_hex).await?;
    Ok(serde_json::json!({
        "status": if pending { "pending" } else { "stamped" },
        "verified": false,
        "pending": pending,
        "method": "bitcoin",
        "digest": digest_hex,
        "proof_size": proof.len(),
        "proof_path": proof_path.display().to_string(),
        "details": "Calendar receipt saved; Bitcoin confirmation has not been verified",
    })
    .to_string())
}
pub async fn verify_handler(
    client: &OTSClient,
    proof: &[u8],
    expected_digest: &[u8; 32],
) -> Result<String, OTSError> {
    let result = client.verify(proof, expected_digest).await?;
    Ok(serde_json::json!({
        "status": if result.verified { "verified" } else if result.pending { "pending" } else { "unverified" },
        "verified": result.verified,
        "pending": result.pending,
        "method": result.method,
        "timestamp": result.timestamp,
        "details": result.details,
        "digest": encode_hex(expected_digest),
    }).to_string())
}
pub fn error_to_http(err: &OTSError) -> (u16, String) {
    let (status, kind) = match err {
        OTSError::Http(_)
        | OTSError::Network(_)
        | OTSError::ServiceUnavailable(_)
        | OTSError::Timeout => (503, "unavailable"),
        OTSError::ServerStatus { status, .. } if *status >= 500 => (503, "unavailable"),
        OTSError::ServerStatus { .. } => (502, "server_error"),
        OTSError::InvalidProof(_) => (400, "invalid_proof"),
        OTSError::VerificationFailed(_) => (422, "verification_failed"),
        OTSError::Configuration(_) => (400, "configuration"),
        OTSError::RateLimited => (429, "rate_limited"),
        OTSError::Io(_) => (500, "io_error"),
    };
    (
        status,
        serde_json::json!({"status":"error","kind":kind,"message":err.to_string()}).to_string(),
    )
}
pub fn method_name(method: OTSMethod) -> &'static str {
    method.as_str()
}
