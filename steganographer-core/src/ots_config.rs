//! Opt-in OpenTimestamps calendar settings. Only Bitcoin attestations are supported.
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_SERVER_URL: &str = "https://alice.btc.calendar.opentimestamps.org";
pub const DEFAULT_INTERVAL_SECS: u64 = 300;
pub const DEFAULT_PROOF_DIR: &str = "ots_proofs";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OtsConfig {
    pub enabled: bool,
    pub server_url: String,
    pub method: String,
    pub interval_secs: u64,
    pub proof_dir: String,
    pub timeout_secs: u64,
    /// Trusted Esplora mainnet API: supplies the canonical block at a height.
    /// This is an explicit explorer trust boundary, not full-node validation.
    pub bitcoin_explorer_url: String,
}
impl Default for OtsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: DEFAULT_SERVER_URL.into(),
            method: "bitcoin".into(),
            interval_secs: DEFAULT_INTERVAL_SECS,
            proof_dir: DEFAULT_PROOF_DIR.into(),
            timeout_secs: 30,
            bitcoin_explorer_url: "https://blockstream.info/api".into(),
        }
    }
}
impl OtsConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.method.eq_ignore_ascii_case("bitcoin"),
            "only Bitcoin OpenTimestamps attestations are supported"
        );
        anyhow::ensure!(
            (1..=86400).contains(&self.interval_secs),
            "OTS interval_secs must be 1..=86400"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.timeout_secs),
            "OTS timeout_secs must be 1..=300"
        );
        anyhow::ensure!(
            !self.proof_dir.is_empty() && !self.proof_dir.contains('\0'),
            "OTS proof_dir must be nonempty without NUL bytes"
        );
        for url in [&self.server_url, &self.bitcoin_explorer_url] {
            anyhow::ensure!(
                (url.starts_with("https://") || url.starts_with("http://"))
                    && !url.chars().any(char::is_whitespace),
                "OTS endpoints must be HTTP(S) URLs"
            );
        }
        Ok(())
    }
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// Display the configured value; validation rejects unsupported methods.
    pub fn method_canonical(&self) -> &str {
        if self.method.eq_ignore_ascii_case("bitcoin") {
            "bitcoin"
        } else {
            &self.method
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtsSettings {
    pub enabled: bool,
    pub interval_secs: u64,
    pub method_tag: u8,
}
impl OtsSettings {
    pub fn from_config(cfg: &OtsConfig) -> anyhow::Result<Self> {
        cfg.validate()?;
        Ok(Self {
            enabled: cfg.enabled,
            interval_secs: cfg.interval_secs,
            method_tag: 0,
        })
    }
    pub fn is_disabled(&self) -> bool {
        !self.enabled
    }
    pub fn method_name(&self) -> &'static str {
        if self.method_tag == 0 {
            "bitcoin"
        } else {
            "unsupported"
        }
    }
}
impl TryFrom<&OtsConfig> for OtsSettings {
    type Error = anyhow::Error;
    fn try_from(cfg: &OtsConfig) -> Result<Self, Self::Error> {
        Self::from_config(cfg)
    }
}
