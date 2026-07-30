//! Configuration types for the OpenTimestamps (OTS) attestation integration.
//!
//! OTS is an entirely **opt-in** feature: when `[ots]` is absent from the
//! TOML config (or `enabled = false`), the steganographer behaves exactly
//! as it did before — no network calls, no proof files, no overhead.
//!
//! When enabled, the OTS client stamps the SHA-256 of the BLAKE3 Merkle root
//! of each completed hash-chain segment (default: one stamp every 5 minutes).
//! The resulting `.ots` proof files are saved to a configurable directory and
//! are **not** embedded in the carrier media — only a small digest + method +
//! timestamp reference is carried in the packet envelope extension fields.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default OTS stamping server (the public OpenTimestamps calendar gateway).
pub const DEFAULT_SERVER_URL: &str = "https://opentimestamps.org";

/// Default minimum interval between stamps (5 minutes), in seconds.
pub const DEFAULT_INTERVAL_SECS: u64 = 300;

/// Default directory for `.ots` proof files, relative to the workdir.
pub const DEFAULT_PROOF_DIR: &str = "ots_proofs";

/// Top-level OTS configuration block, deserialized from `[ots]` in the TOML.
///
/// Every field is optional and carries a sensible default, so the block can
/// be as minimal as:
///
/// ```toml
/// [ots]
/// enabled = true
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtsConfig {
    /// Master switch. When `false` (or when the `[ots]` block is absent),
    /// the OTS feature is completely disabled and the project behaves as
    /// before. Default: `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Stamping server base URL. Default: `https://opentimestamps.org`.
    #[serde(default = "default_server_url")]
    pub server_url: String,

    /// Blockchain attestation method: `"bitcoin"` (default) or `"ethereum"`.
    #[serde(default = "default_method")]
    pub method: String,

    /// Minimum interval between stamps, in seconds. Prevents stamping every
    /// single segment. Default: 300 (5 minutes).
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    /// Directory where `.ots` proof files are written. Created if missing.
    /// Default: `ots_proofs`.
    #[serde(default = "default_proof_dir")]
    pub proof_dir: String,

    /// Request timeout in seconds for HTTP calls to the OTS server.
    /// Default: 30.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_server_url() -> String {
    DEFAULT_SERVER_URL.to_string()
}
fn default_method() -> String {
    "bitcoin".to_string()
}
fn default_interval_secs() -> u64 {
    DEFAULT_INTERVAL_SECS
}
fn default_proof_dir() -> String {
    DEFAULT_PROOF_DIR.to_string()
}
fn default_timeout_secs() -> u64 {
    30
}

impl Default for OtsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: default_server_url(),
            method: default_method(),
            interval_secs: default_interval_secs(),
            proof_dir: default_proof_dir(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

impl OtsConfig {
    /// Resolve the interval into a [`Duration`].
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs.max(1))
    }

    /// Resolve the HTTP timeout into a [`Duration`].
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.max(1))
    }

    /// Whether OTS is actually turned on.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Parse the method string into a lowercase canonical form.
    /// Returns `"bitcoin"` for any unrecognized value (the safe default).
    pub fn method_canonical(&self) -> &str {
        match self.method.to_ascii_lowercase().as_str() {
            "ethereum" | "eth" => "ethereum",
            _ => "bitcoin",
        }
    }
}

/// Resolved runtime settings derived from [`OtsConfig`].
///
/// This is the lightweight, `Copy`-able view used by hot paths (e.g. the
/// GStreamer callback threads) that don't want to hold a reference to the
/// full config struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtsSettings {
    /// Whether OTS stamping is active.
    pub enabled: bool,
    /// Minimum interval between stamps, in seconds.
    pub interval_secs: u64,
    /// Method as a small enum tag: `0 = bitcoin`, `1 = ethereum`.
    pub method_tag: u8,
}

impl OtsSettings {
    /// Build runtime settings from a full [`OtsConfig`].
    pub fn from_config(cfg: &OtsConfig) -> Self {
        Self {
            enabled: cfg.is_enabled(),
            interval_secs: cfg.interval_secs,
            method_tag: match cfg.method_canonical() {
                "ethereum" => 1,
                _ => 0,
            },
        }
    }

    /// Whether stamping is disabled.
    pub fn is_disabled(&self) -> bool {
        !self.enabled
    }

    /// Decode a method tag back to its string name.
    pub fn method_name(&self) -> &'static str {
        match self.method_tag {
            1 => "ethereum",
            _ => "bitcoin",
        }
    }
}

impl From<&OtsConfig> for OtsSettings {
    fn from(cfg: &OtsConfig) -> Self {
        Self::from_config(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_disabled() {
        let cfg = OtsConfig::default();
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.server_url, DEFAULT_SERVER_URL);
        assert_eq!(cfg.method, "bitcoin");
        assert_eq!(cfg.interval_secs, DEFAULT_INTERVAL_SECS);
        assert_eq!(cfg.proof_dir, DEFAULT_PROOF_DIR);
    }

    #[test]
    fn test_minimal_enabled_config() {
        let toml_str = r#"
enabled = true
"#;
        let cfg: OtsConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.is_enabled());
        assert_eq!(cfg.server_url, DEFAULT_SERVER_URL);
        assert_eq!(cfg.method, "bitcoin");
    }

    #[test]
    fn test_full_config() {
        let toml_str = r#"
enabled = true
server_url = "https://alice.btc.calendar.opentimestamps.org"
method = "ethereum"
interval_secs = 600
proof_dir = "/var/ots"
timeout_secs = 10
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
        assert_eq!(cfg.timeout_secs, 10);
    }

    #[test]
    fn test_method_canonical() {
        let mut cfg = OtsConfig::default();
        cfg.method = "Bitcoin".to_string();
        assert_eq!(cfg.method_canonical(), "bitcoin");
        cfg.method = "ETH".to_string();
        assert_eq!(cfg.method_canonical(), "ethereum");
        cfg.method = "unknown".to_string();
        assert_eq!(cfg.method_canonical(), "bitcoin");
    }

    #[test]
    fn test_interval_and_timeout_durations() {
        let cfg = OtsConfig {
            interval_secs: 0,
            timeout_secs: 0,
            ..OtsConfig::default()
        };
        // Clamped to at least 1 second.
        assert_eq!(cfg.interval(), Duration::from_secs(1));
        assert_eq!(cfg.timeout(), Duration::from_secs(1));
    }

    #[test]
    fn test_ots_settings_from_config() {
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
    fn test_ots_settings_disabled() {
        let cfg = OtsConfig::default();
        let settings = OtsSettings::from_config(&cfg);
        assert!(settings.is_disabled());
        assert_eq!(settings.method_name(), "bitcoin");
    }

    #[test]
    fn test_absent_ots_block_treats_as_disabled() {
        // When [ots] is entirely absent from the TOML, serde uses Default.
        let cfg = OtsConfig::default();
        assert!(!cfg.is_enabled());
    }
}
