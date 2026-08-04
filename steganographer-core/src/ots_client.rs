//! Async client for the OpenTimestamps (OTS) attestation REST API.
//!
//! This module provides [`OTSClient`] — a thread-safe, async-capable HTTP
//! client that stamps SHA-256 digests with the OpenTimestamps service and
//! verifies the resulting `.ots` proof files.
//!
//! ## Design
//!
//! - **No panics on external I/O.** Every fallible path returns a typed
//!   [`OTSError`] variant.
//! - **Graceful degradation.** If the OTS server is unreachable, callers are
//!   expected to continue operating without timestamp proofs — the stego
//!   pipeline is not blocked. Use [`can_stamp`](OTSClient::can_stamp) to
//!   rate-limit stamping to one per `min_interval`.
//! - **SHA-256 for OTS, BLAKE3 for the chain.** OTS protocol requires
//!   SHA-256. The proof attests to `SHA-256(merkle_root)`, where
//!   `merkle_root` is a BLAKE3 digest produced by [`crate::hash_chain`].
//! - **Proof files are external.** The full `.ots` proof is never embedded in
//!   carrier media — only a small digest + method + timestamp reference is
//!   carried in the packet envelope extension fields (see [`crate::packet`]).
//!
//! ## REST protocol
//!
//! **Stamping** — `POST {server_url}/api/v1/timestamp` with the 32-byte raw
//! SHA-256 digest as the body (`application/octet-stream`). The response is
//! the binary `.ots` proof file.
//!
//! **Verification** — `POST {server_url}/api/v1/verify` with the `.ots`
//! proof bytes as the body. The response is JSON describing the attestation.
//!
//! The default server is the public OpenTimestamps gateway
//! (`https://opentimestamps.org`). Calendar-server URLs are also accepted.

use crate::ots_config::OtsConfig;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use thiserror::Error;

/// Stamp endpoint path appended to `server_url`.
pub const STAMP_PATH: &str = "/api/v1/timestamp";
/// Verify endpoint path appended to `server_url`.
pub const VERIFY_PATH: &str = "/api/v1/verify";

/// Minimum proof size we accept from the stamping endpoint (a real OTS proof
/// is always at least a few dozen bytes; anything smaller is a server error
/// page or an empty body).
const MIN_PROOF_SIZE: usize = 8;

/// Blockchain attestation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OTSMethod {
    /// Stamp via Bitcoin (the default OTS attestation method).
    Bitcoin,
    /// Stamp via Ethereum.
    Ethereum,
}

impl OTSMethod {
    /// Lowercase canonical name used in API query parameters and JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            OTSMethod::Bitcoin => "bitcoin",
            OTSMethod::Ethereum => "ethereum",
        }
    }

    /// Numeric tag stored in the packet envelope extension field
    /// (`FIELD_OTS_METHOD`): `0 = bitcoin`, `1 = ethereum`.
    pub fn tag(&self) -> u8 {
        match self {
            OTSMethod::Bitcoin => 0,
            OTSMethod::Ethereum => 1,
        }
    }

    /// Parse a method tag back from its numeric form.
    pub fn from_tag(tag: u8) -> Self {
        match tag {
            1 => OTSMethod::Ethereum,
            _ => OTSMethod::Bitcoin,
        }
    }

    /// Parse a method from its string name (case-insensitive). Unknown
    /// values fall back to [`OTSMethod::Bitcoin`] (the safe default).
    pub fn parse(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "ethereum" | "eth" => OTSMethod::Ethereum,
            _ => OTSMethod::Bitcoin,
        }
    }
}

impl std::fmt::Display for OTSMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of a proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OTSVResult {
    /// Whether the proof was verified against the blockchain attestation.
    pub verified: bool,
    /// Attestation method name (`"bitcoin"`, `"ethereum"`, etc.).
    pub method: String,
    /// Unix timestamp (seconds) extracted from the attestation, if present.
    pub timestamp: Option<u64>,
    /// Human-readable description of the verification outcome.
    pub details: String,
}

impl OTSVResult {
    /// Build a "no proof / not verified" result for graceful degradation.
    pub fn no_proof() -> Self {
        Self {
            verified: false,
            method: "none".to_string(),
            timestamp: None,
            details: "No OpenTimestamps proof was found for this content".to_string(),
        }
    }
}

/// Errors from OTS operations. Every external-I/O failure path returns a
/// typed variant — the client never panics.
#[derive(Debug, Error)]
pub enum OTSError {
    /// The HTTP request itself failed (DNS, connection, TLS, timeout).
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The server returned a non-success HTTP status code.
    #[error("OTS server returned HTTP {status}: {body}")]
    ServerStatus { status: u16, body: String },
    /// The proof bytes returned by the server are malformed or too small.
    #[error("invalid proof format: {0}")]
    InvalidProof(String),
    /// The proof did not verify against the blockchain attestation.
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    /// A network-level error not expressible as a `reqwest::Error`
    /// (e.g. building the URL).
    #[error("network error: {0}")]
    Network(String),
    /// The OTS service is unavailable (5xx or empty response).
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    /// An I/O error while saving or loading a proof file.
    #[error("proof file I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Async HTTP client for the OpenTimestamps attestation service.
///
/// Thread-safe via an inner [`reqwest::Client`] and an
/// [`AtomicU64`] last-stamp timestamp. Safe to share across async tasks
/// (e.g. the dashboard and the GStreamer callback threads).
pub struct OTSClient {
    client: reqwest::Client,
    server_url: String,
    method: OTSMethod,
    min_interval: Duration,
    last_stamp_time: AtomicU64,
    proof_dir: PathBuf,
}

impl std::fmt::Debug for OTSClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OTSClient")
            .field("server_url", &self.server_url)
            .field("method", &self.method)
            .field("min_interval", &self.min_interval)
            .field("proof_dir", &self.proof_dir)
            .field(
                "last_stamp_time",
                &self.last_stamp_time.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl OTSClient {
    /// Create a new client with the Bitcoin method and default settings.
    pub fn new(method: OTSMethod) -> Self {
        Self::from_config(&OtsConfig {
            enabled: true,
            method: method.as_str().to_string(),
            ..OtsConfig::default()
        })
    }

    /// Build a client from a full [`OtsConfig`].
    pub fn from_config(cfg: &OtsConfig) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(cfg.timeout())
            .connect_timeout(Duration::from_secs(10));
        // Avoid leaking the user agent / accept defaults that confuse some
        // calendar servers; keep it minimal.
        builder = builder.user_agent(concat!(
            "steganographer/",
            env!("CARGO_PKG_VERSION"),
            " (ots-client)"
        ));
        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            server_url: cfg.server_url.trim_end_matches('/').to_string(),
            method: OTSMethod::parse(&cfg.method),
            min_interval: cfg.interval(),
            last_stamp_time: AtomicU64::new(0),
            proof_dir: PathBuf::from(&cfg.proof_dir),
        }
    }

    /// Override the stamping server URL (e.g. to point at a specific calendar).
    pub fn with_server_url(mut self, url: impl Into<String>) -> Self {
        self.server_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// Override the minimum interval between stamps.
    pub fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_interval = interval;
        self
    }

    /// Override the proof-file output directory.
    pub fn with_proof_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.proof_dir = dir.into();
        self
    }

    /// The configured attestation method.
    pub fn method(&self) -> OTSMethod {
        self.method
    }

    /// The configured proof-file directory.
    pub fn proof_dir(&self) -> &Path {
        &self.proof_dir
    }

    /// Compute `SHA-256(data)` and return the 32-byte digest.
    ///
    /// This is the digest that gets stamped — it is **not** the BLAKE3
    /// frame hash. Callers should pass the BLAKE3 Merkle root here so the
    /// OTS proof attests to `SHA-256(merkle_root)`.
    pub fn compute_sha256_digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Check whether enough time has elapsed since the last stamp.
    ///
    /// Returns `true` when stamping is permitted, `false` when the
    /// `min_interval` window has not yet elapsed. The check is lock-free.
    pub fn can_stamp(&self) -> bool {
        let now = current_unix_secs();
        let last = self.last_stamp_time.load(Ordering::Relaxed);
        now.saturating_sub(last) >= self.min_interval.as_secs()
    }

    /// Record that a stamp has just been issued (or attempted), updating the
    /// rate-limit clock.
    pub fn mark_stamped(&self) {
        self.last_stamp_time
            .store(current_unix_secs(), Ordering::Relaxed);
    }

    /// Stamp a pre-computed 32-byte SHA-256 digest with the OTS service.
    ///
    /// Returns the raw `.ots` proof bytes on success. The proof can then be
    /// saved with [`save_proof`](Self::save_proof) or verified with
    /// [`verify`](Self::verify).
    pub async fn stamp_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, OTSError> {
        if digest.len() != 32 {
            return Err(OTSError::InvalidProof(format!(
                "OTS digest must be 32 bytes, got {}",
                digest.len()
            )));
        }
        let url = format!("{}{}", self.server_url, STAMP_PATH);
        log::debug!("OTS stamp: POST {} (method={})", url, self.method);

        let response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .query(&[("method", self.method.as_str())])
            .body(digest.to_vec())
            .send()
            .await
            .map_err(OTSError::Http)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            if status.is_server_error() {
                return Err(OTSError::ServiceUnavailable(format!(
                    "HTTP {status}: {body}"
                )));
            }
            return Err(OTSError::ServerStatus {
                status: status.as_u16(),
                body,
            });
        }

        let proof = response.bytes().await.map_err(OTSError::Http)?.to_vec();
        if proof.len() < MIN_PROOF_SIZE {
            return Err(OTSError::InvalidProof(format!(
                "proof body too short: {} bytes",
                proof.len()
            )));
        }
        self.mark_stamped();
        Ok(proof)
    }

    /// Stamp raw data: compute `SHA-256(data)` internally, then stamp the
    /// resulting 32-byte digest.
    pub async fn stamp_data(&self, data: &[u8]) -> Result<Vec<u8>, OTSError> {
        let digest = Self::compute_sha256_digest(data);
        self.stamp_digest(&digest).await
    }

    /// Verify a `.ots` proof file against the OTS service.
    ///
    /// Returns an [`OTSVResult`] describing the attestation. The proof bytes
    /// are POSTed to the verification endpoint as `application/octet-stream`.
    pub async fn verify(&self, proof: &[u8]) -> Result<OTSVResult, OTSError> {
        if proof.len() < MIN_PROOF_SIZE {
            return Err(OTSError::InvalidProof(format!(
                "proof body too short: {} bytes",
                proof.len()
            )));
        }
        let url = format!("{}{}", self.server_url, VERIFY_PATH);
        log::debug!("OTS verify: POST {} ({} bytes)", url, proof.len());

        let response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(proof.to_vec())
            .send()
            .await
            .map_err(OTSError::Http)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            if status.is_server_error() {
                return Err(OTSError::ServiceUnavailable(format!(
                    "HTTP {status}: {body}"
                )));
            }
            return Err(OTSError::ServerStatus {
                status: status.as_u16(),
                body,
            });
        }

        // The verification endpoint returns JSON. Parse what we can, with
        // permissive defaults so an unfamiliar schema doesn't fail the whole
        // pipeline — the HTTP 200 itself is the primary success signal.
        let text = response.text().await.unwrap_or_default();
        Ok(parse_verify_response(&text, self.method))
    }

    /// Save a proof to disk under the configured `proof_dir`.
    ///
    /// The filename is derived from the hex digest so that re-stamping the
    /// same content overwrites (rather than duplicates) the proof. Returns
    /// the full path to the written file. The directory is created if it
    /// does not exist.
    pub fn save_proof(&self, proof: &[u8], digest_hex: &str) -> Result<PathBuf, OTSError> {
        std::fs::create_dir_all(&self.proof_dir)?;
        let filename = format!("{}.ots", digest_hex);
        let path = self.proof_dir.join(filename);
        std::fs::write(&path, proof)?;
        log::info!("OTS proof saved to {}", path.display());
        Ok(path)
    }

    /// Save a proof alongside a proof-file path the caller already chose.
    /// This is the lower-level variant of [`save_proof`](Self::save_proof)
    /// used by the CLI when the output path is explicit.
    pub fn save_proof_to(&self, proof: &[u8], output_path: &Path) -> Result<PathBuf, OTSError> {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(output_path, proof)?;
        Ok(output_path.to_path_buf())
    }

    /// Load a proof file from disk.
    pub fn load_proof(path: &Path) -> Result<Vec<u8>, OTSError> {
        std::fs::read(path).map_err(OTSError::Io)
    }

    /// Build the conventional proof-file path for a digest in the configured
    /// proof directory.
    pub fn proof_path_for(&self, digest_hex: &str) -> PathBuf {
        self.proof_dir.join(format!("{}.ots", digest_hex))
    }
}

/// Current UNIX timestamp in seconds (monotonic enough for rate-limiting).
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse the JSON body returned by the verification endpoint into an
/// [`OTSVResult`]. Permissive: missing fields fall back to defaults so an
/// unfamiliar schema degrades gracefully rather than failing the pipeline.
fn parse_verify_response(text: &str, default_method: OTSMethod) -> OTSVResult {
    let parse_err = |_e: &str| OTSVResult {
        verified: false,
        method: default_method.as_str().to_string(),
        timestamp: None,
        details: "verification response was not valid JSON".to_string(),
    };

    let json: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_e) => {
            // Some verification endpoints return plain text "OK". A non-JSON
            // body cannot carry a blockchain attestation timestamp, so we
            // cannot confirm verification from it. Fail closed: report it as
            // unverified rather than trusting that any non-empty body equals
            // a successful attestation.
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return parse_err("empty body");
            }
            return OTSVResult {
                verified: false,
                method: default_method.as_str().to_string(),
                timestamp: None,
                details: format!(
                    "verification response was not confirmable (non-JSON body): {trimmed}"
                ),
            };
        }
    };

    // Fail closed: only report `verified: true` when the endpoint *affirmatively*
    // signals success. A missing, null, or ambiguous field defaults to NOT
    // verified. Defaulting to `true` here would let an error-shaped or
    // uncooperative response (e.g. `{"error": "not found"}` returned with 200)
    // masquerade as a valid on-chain attestation.
    let verified = json
        .get("verified")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            // Some endpoints use "status": "verified" or "success": true.
            let status = json.get("status")?.as_str()?;
            Some(
                status.eq_ignore_ascii_case("verified")
                    || status.eq_ignore_ascii_case("ok")
                    || status.eq_ignore_ascii_case("success"),
            )
        })
        .or_else(|| json.get("success").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    let method = json
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or(default_method.as_str())
        .to_string();

    let timestamp = json.get("timestamp").and_then(|v| v.as_u64()).or_else(|| {
        // Some endpoints nest the attestation under "attestations".
        json.get("attestations")
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("timestamp"))
            .and_then(|v| v.as_u64())
    });

    let details = json
        .get("details")
        .and_then(|v| v.as_str())
        .or_else(|| json.get("message").and_then(|v| v.as_str()))
        .unwrap_or(if verified {
            "OpenTimestamps proof verified"
        } else {
            "OpenTimestamps proof did not verify"
        })
        .to_string();

    OTSVResult {
        verified,
        method,
        timestamp,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_method_roundtrip() {
        assert_eq!(OTSMethod::Bitcoin.tag(), 0);
        assert_eq!(OTSMethod::Ethereum.tag(), 1);
        assert_eq!(OTSMethod::from_tag(0), OTSMethod::Bitcoin);
        assert_eq!(OTSMethod::from_tag(1), OTSMethod::Ethereum);
        assert_eq!(OTSMethod::from_tag(99), OTSMethod::Bitcoin);
        assert_eq!(OTSMethod::parse("Bitcoin"), OTSMethod::Bitcoin);
        assert_eq!(OTSMethod::parse("ETH"), OTSMethod::Ethereum);
        assert_eq!(OTSMethod::parse("unknown"), OTSMethod::Bitcoin);
        assert_eq!(OTSMethod::Bitcoin.to_string(), "bitcoin");
        assert_eq!(OTSMethod::Ethereum.to_string(), "ethereum");
    }

    #[test]
    fn test_sha256_consistency() {
        let data = b"hello world";
        let d1 = OTSClient::compute_sha256_digest(data);
        let d2 = OTSClient::compute_sha256_digest(data);
        assert_eq!(d1, d2, "same input must produce same digest");

        // Verify the digest is 32 bytes and non-zero.
        assert_eq!(d1.len(), 32);
        assert_ne!(d1, [0u8; 32]);

        // Cross-check against an independent sha2 computation.
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, data);
        let expected = sha2::Digest::finalize(hasher);
        assert_eq!(&d1[..], &expected[..], "digest must match independent sha2");

        // Different input → different digest
        let d3 = OTSClient::compute_sha256_digest(b"hello world!");
        assert_ne!(d1, d3);
    }

    #[test]
    fn test_can_stamp_interval() {
        let client =
            OTSClient::new(OTSMethod::Bitcoin).with_min_interval(Duration::from_secs(3600));
        // Fresh client: last_stamp_time == 0, so can_stamp is true.
        assert!(client.can_stamp(), "fresh client should be able to stamp");
        client.mark_stamped();
        // Immediately after stamping, the interval window is not elapsed.
        assert!(
            !client.can_stamp(),
            "should not be able to stamp within the interval window"
        );
    }

    #[test]
    fn test_can_stamp_zero_interval() {
        let client = OTSClient::new(OTSMethod::Bitcoin).with_min_interval(Duration::from_secs(0));
        assert!(client.can_stamp());
        client.mark_stamped();
        // With a zero interval (clamped to 1s in config, but here we set 0
        // directly) stamping should be permitted again immediately.
        assert!(client.can_stamp());
    }

    #[test]
    fn test_save_and_load_proof() {
        let tmp = std::env::temp_dir().join(format!("ots_test_{}_save_load", std::process::id()));
        let client = OTSClient::new(OTSMethod::Bitcoin).with_proof_dir(&tmp);
        let proof = b"FAKE_OTS_PROOF_BODY_FOR_TESTING".to_vec();
        let digest_hex = "deadbeef";
        let path = client.save_proof(&proof, digest_hex).unwrap();
        assert!(path.exists());
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "deadbeef.ots");

        let loaded = OTSClient::load_proof(&path).unwrap();
        assert_eq!(loaded, proof);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_save_proof_to_explicit_path() {
        let tmp = std::env::temp_dir().join(format!(
            "ots_test_{}_explicit/proof.ots",
            std::process::id()
        ));
        let client = OTSClient::new(OTSMethod::Bitcoin);
        let proof = b"PROOF".to_vec();
        let written = client.save_proof_to(&proof, &tmp).unwrap();
        assert_eq!(written, tmp);
        let loaded = OTSClient::load_proof(&tmp).unwrap();
        assert_eq!(loaded, proof);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_dir(tmp.parent().unwrap());
    }

    #[test]
    fn test_proof_path_for_digest() {
        let client = OTSClient::new(OTSMethod::Bitcoin).with_proof_dir(PathBuf::from("/tmp/ots"));
        let path = client.proof_path_for("abc123");
        assert_eq!(path, PathBuf::from("/tmp/ots/abc123.ots"));
    }

    #[test]
    fn test_invalid_proof_too_short() {
        // Blocking test using tokio runtime for the async verify path.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = OTSClient::new(OTSMethod::Bitcoin);
        let result = rt.block_on(client.verify(b"short"));
        assert!(matches!(result, Err(OTSError::InvalidProof(_))));
    }

    #[test]
    fn test_parse_verify_response_json() {
        let json =
            r#"{"verified": true, "method": "bitcoin", "timestamp": 1700000000, "details": "ok"}"#;
        let r = parse_verify_response(json, OTSMethod::Bitcoin);
        assert!(r.verified);
        assert_eq!(r.method, "bitcoin");
        assert_eq!(r.timestamp, Some(1700000000));
        assert_eq!(r.details, "ok");
    }

    #[test]
    fn test_parse_verify_response_status_field() {
        let json = r#"{"status": "verified"}"#;
        let r = parse_verify_response(json, OTSMethod::Bitcoin);
        assert!(r.verified);
    }

    #[test]
    fn test_parse_verify_response_plain_text() {
        // A plain-text body cannot carry a blockchain attestation — fail closed.
        let r = parse_verify_response("OK", OTSMethod::Bitcoin);
        assert!(!r.verified);
        assert_eq!(r.method, "bitcoin");
        assert!(r.details.contains("non-JSON"));
    }

    #[test]
    fn test_parse_verify_response_empty() {
        let r = parse_verify_response("", OTSMethod::Ethereum);
        assert!(!r.verified);
        assert_eq!(r.method, "ethereum");
    }

    #[test]
    fn test_parse_verify_response_attestations_nested() {
        // A nested timestamp alone is not an affirmative success signal.
        let json = r#"{"attestations": [{"timestamp": 1234567890}]}"#;
        let r = parse_verify_response(json, OTSMethod::Bitcoin);
        assert!(
            !r.verified,
            "missing explicit verified=true must not be trusted"
        );
        assert_eq!(r.timestamp, Some(1234567890));
    }

    #[test]
    fn test_parse_verify_response_fails_closed_on_error_body() {
        // An HTTP 200 with an error-shaped body must NOT report verified.
        let json = r#"{"error": "not found"}"#;
        let r = parse_verify_response(json, OTSMethod::Bitcoin);
        assert!(!r.verified, "an error-shaped response must not attest");
    }

    #[test]
    fn test_parse_verify_response_fails_closed_on_unknown_status() {
        // A status value that is not an affirmative signal must NOT verify.
        let json = r#"{"status": "pending"}"#;
        let r = parse_verify_response(json, OTSMethod::Bitcoin);
        assert!(!r.verified, "a non-success status must not attest");
    }

    #[test]
    fn test_parse_verify_response_explicit_success_still_verifies() {
        // Affirmative signals keep working after the fail-closed change.
        let r = parse_verify_response(r#"{"verified": true}"#, OTSMethod::Bitcoin);
        assert!(r.verified);
        let r = parse_verify_response(r#"{"status": "VERIFIED"}"#, OTSMethod::Ethereum);
        assert!(r.verified);
        let r = parse_verify_response(r#"{"success": true}"#, OTSMethod::Bitcoin);
        assert!(r.verified);
    }

    #[test]
    fn test_otsv_result_no_proof() {
        let r = OTSVResult::no_proof();
        assert!(!r.verified);
        assert_eq!(r.method, "none");
        assert!(r.timestamp.is_none());
        assert!(r.details.contains("No OpenTimestamps proof"));
    }

    #[test]
    fn test_client_from_config_defaults() {
        let cfg = OtsConfig {
            enabled: true,
            ..OtsConfig::default()
        };
        let client = OTSClient::from_config(&cfg);
        assert_eq!(client.method(), OTSMethod::Bitcoin);
        assert_eq!(client.server_url, "https://opentimestamps.org");
        assert!(client.can_stamp());
    }

    #[test]
    fn test_client_from_config_ethereum() {
        let cfg = OtsConfig {
            enabled: true,
            method: "ethereum".to_string(),
            server_url: "https://example.com/".to_string(), // trailing slash stripped
            ..OtsConfig::default()
        };
        let client = OTSClient::from_config(&cfg);
        assert_eq!(client.method(), OTSMethod::Ethereum);
        assert_eq!(client.server_url, "https://example.com");
    }

    #[test]
    fn test_network_error_on_bad_host() {
        // Point the client at a non-routable address so the HTTP call fails
        // fast and deterministically with a network/HTTP error (no real
        // network access required).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = OTSClient::new(OTSMethod::Bitcoin)
            .with_server_url("http://127.0.0.1:1") // port 1 is not listening
            .with_min_interval(Duration::from_secs(0));
        let digest = [0u8; 32];
        let result = rt.block_on(client.stamp_digest(&digest));
        assert!(
            result.is_err(),
            "expected an error stamping against a dead endpoint"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OTSError::Http(_) | OTSError::Network(_) | OTSError::ServiceUnavailable(_)
            ),
            "expected a network-class error, got {err:?}"
        );
    }

    #[test]
    fn test_debug_format() {
        let client = OTSClient::new(OTSMethod::Bitcoin);
        let s = format!("{client:?}");
        assert!(s.contains("OTSClient"));
        assert!(s.contains("Bitcoin"));
    }
}
