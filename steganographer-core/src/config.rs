//! Configuration model for steganographer pipelines.
//!
//! Supports TOML deserialization with [`Config::from_toml`].

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::ots_config::OtsConfig;
use crate::packet::DecodeLimits;
use crate::unicode_text;

/// Top-level configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub global: GlobalConfig,
    pub video: Option<VideoConfig>,
    pub audio: Option<AudioConfig>,
    /// Optional OpenTimestamps attestation configuration.
    /// When absent or `enabled = false`, OTS is completely disabled and the
    /// project behaves exactly as before. See [`crate::ots_config`].
    #[serde(default)]
    pub ots: Option<OtsConfig>,
    /// Optional global resource ceilings mirroring the semantics of
    /// [`DecodeLimits`] (see [`LimitsConfig`]). Absent fields keep the
    /// built-in defaults, so behavior is unchanged when the table is absent.
    #[serde(default)]
    pub limits: Option<LimitsConfig>,
    /// Optional named profiles (`[profiles.<name>]`). A profile bundles
    /// limits overrides and scanner knobs; resolve it with [`Config::profile`].
    /// See [`ProfileConfig`].
    #[serde(default)]
    pub profiles: Option<BTreeMap<String, ProfileConfig>>,
}

/// Resource ceilings for packet decoding, mirroring the semantics of
/// [`DecodeLimits`] in the optional `[limits]` table. Every field is
/// optional: absent fields keep the built-in [`DecodeLimits::default`] value.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct LimitsConfig {
    /// Ceiling on the total encoded packet size.
    #[serde(default)]
    pub max_packet_len: Option<usize>,
    /// Ceiling on the encoded body length.
    #[serde(default)]
    pub max_body_len: Option<usize>,
    /// Ceiling on the declared logical payload length (`original_len`),
    /// enforced before any transform is reversed.
    #[serde(default)]
    pub max_original_len: Option<usize>,
    /// Ceiling on a single field/extension value length.
    #[serde(default)]
    pub max_field_len: Option<usize>,
    /// Ceiling on the number of extension fields.
    #[serde(default)]
    pub max_extensions: Option<usize>,
    /// Maximum parent-id chain depth a recursive decoder may expand (PKT-009).
    #[serde(default)]
    pub max_nesting_depth: Option<usize>,
    /// Maximum aggregate bytes across every nested packet in one chain
    /// (PKT-009).
    #[serde(default)]
    pub max_aggregate_nested_bytes: Option<usize>,
}

impl LimitsConfig {
    /// Validate the configured ceilings: every present value must be
    /// non-zero, and the body ceiling cannot exceed the packet ceiling
    /// (an encoded packet carries its body).
    pub fn validate(&self) -> anyhow::Result<()> {
        let fields = [
            ("max_packet_len", self.max_packet_len),
            ("max_body_len", self.max_body_len),
            ("max_original_len", self.max_original_len),
            ("max_field_len", self.max_field_len),
            ("max_extensions", self.max_extensions),
            ("max_nesting_depth", self.max_nesting_depth),
            (
                "max_aggregate_nested_bytes",
                self.max_aggregate_nested_bytes,
            ),
        ];
        for (name, value) in fields {
            if value == Some(0) {
                anyhow::bail!("limits.{name} must be greater than 0");
            }
        }
        if let (Some(body), Some(packet)) = (self.max_body_len, self.max_packet_len) {
            if body > packet {
                anyhow::bail!(
                    "limits.max_body_len ({body}) exceeds limits.max_packet_len ({packet})"
                );
            }
        }
        Ok(())
    }

    /// Apply these overrides on top of the built-in [`DecodeLimits`] defaults.
    pub fn apply_to(&self, limits: &mut DecodeLimits) {
        if let Some(v) = self.max_packet_len {
            limits.max_packet_len = v;
        }
        if let Some(v) = self.max_body_len {
            limits.max_body_len = v;
        }
        if let Some(v) = self.max_original_len {
            limits.max_original_len = v;
        }
        if let Some(v) = self.max_field_len {
            limits.max_field_len = v;
        }
        if let Some(v) = self.max_extensions {
            limits.max_extensions = v;
        }
        if let Some(v) = self.max_nesting_depth {
            limits.max_nesting_depth = v;
        }
        if let Some(v) = self.max_aggregate_nested_bytes {
            limits.max_aggregate_nested_bytes = v;
        }
    }

    /// Build a [`DecodeLimits`] from the built-in defaults plus these
    /// overrides.
    pub fn to_decode_limits(&self) -> DecodeLimits {
        let mut limits = DecodeLimits::default();
        self.apply_to(&mut limits);
        limits
    }
}

/// Scanner knobs a profile may set. Minimum viable: the detector set a scan
/// reports.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct ScanProfileConfig {
    /// Detector IDs this profile's scan reports. Omit to keep every detector.
    #[serde(default)]
    pub detectors: Option<Vec<String>>,
}

/// A named profile (`[profiles.<name>]`): limits overrides plus scanner
/// knobs. Resolve via [`Config::profile`].
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct ProfileConfig {
    /// Resource-limit overrides this profile applies.
    #[serde(default)]
    pub limits: Option<LimitsConfig>,
    /// Scanner knobs this profile applies.
    #[serde(default)]
    pub scan: Option<ScanProfileConfig>,
}

/// Detector identifiers accepted in a profile's `scan.detectors` set.
pub const SCAN_DETECTORS: [&str; 7] = [
    "statistical",
    "magic",
    unicode_text::ZERO_WIDTH,
    unicode_text::VARIATION_SELECTORS,
    unicode_text::BIDI_CONTROLS,
    unicode_text::WHITESPACE_ANOMALY,
    unicode_text::HOMOGLYPH_SUSPECT,
];

/// Global settings.
#[derive(Debug, Deserialize, Clone)]
pub struct GlobalConfig {
    /// Log level: "trace", "debug", "info", "warn", "error"
    pub log_level: Option<String>,
    /// Hash algorithm: "blake3" (default), "sha256", "sha3-256"
    #[serde(default)]
    pub hash_algorithm: Option<String>,
    /// Path to a file containing the LSB embedding key (hex, 64 chars = 32 bytes).
    /// If set, overrides the inline `key` field in LSB configs.
    #[serde(default)]
    pub key_file: Option<String>,
}

impl GlobalConfig {
    /// Get the resolved hash algorithm name, or "blake3" as default.
    pub fn hash_algorithm_name(&self) -> &str {
        self.hash_algorithm.as_deref().unwrap_or("blake3")
    }
}

/// Video pipeline configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct VideoConfig {
    /// Pipeline parameters: resolution, framerate, opacity
    #[serde(default)]
    pub pipeline: Option<VideoPipelineConfig>,
    pub input: EndpointConfig,
    pub output: EndpointConfig,
    pub stego: VideoStegoConfig,
}

/// Video pipeline parameters: resolution, framerate, overlay intensity.
#[derive(Debug, Deserialize, Clone)]
pub struct VideoPipelineConfig {
    /// Frame width in pixels (default: 640)
    pub width: Option<u32>,
    /// Frame height in pixels (default: 480)
    pub height: Option<u32>,
    /// Target framerate in fps (default: 30)
    pub framerate: Option<u32>,
    /// Overlay opacity / steganographic intensity 0.0–1.0 (default: 1.0)
    pub opacity: Option<f64>,
    /// Payload configuration
    #[serde(default)]
    pub payload: Option<PayloadConfig>,
}

/// Cryptographic payload configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct PayloadConfig {
    /// Payload type: "signature" (default) or "custom"
    pub r#type: Option<String>,
    /// Payload size in bytes (default: 109 for v2 format)
    pub size: Option<u32>,
    /// Signing backend: "ed25519" (default) or "ethereum"
    pub signing_backend: Option<String>,
    /// Enable payload encryption (ChaCha20-Poly1305)
    #[serde(default)]
    pub encrypt: Option<bool>,
    /// Encryption key (hex-encoded 32 bytes). If omitted with encrypt=true,
    /// a random key is generated (not recoverable).
    #[serde(default)]
    pub encryption_key: Option<String>,
    /// Path to a file containing the encryption key (hex, 64 chars).
    #[serde(default)]
    pub encryption_key_file: Option<String>,
    /// Error correction: "none" (default), "reed_solomon"
    #[serde(default)]
    pub error_correction: Option<String>,
    /// Number of frames to spread a single signature across (1 = single frame)
    #[serde(default)]
    pub multi_frame_spread: Option<u32>,
}

impl PayloadConfig {
    /// Whether encryption is enabled.
    pub fn encrypt_enabled(&self) -> bool {
        self.encrypt.unwrap_or(false)
    }
    /// Multi-frame spread count (default: 1 = no spreading).
    pub fn spread_count(&self) -> u32 {
        self.multi_frame_spread.unwrap_or(1).max(1)
    }
}

impl VideoPipelineConfig {
    /// Width with default fallback.
    pub fn width_or_default(&self) -> u32 {
        self.width.unwrap_or(640)
    }
    /// Height with default fallback.
    pub fn height_or_default(&self) -> u32 {
        self.height.unwrap_or(480)
    }
    /// Framerate with default fallback.
    pub fn framerate_or_default(&self) -> u32 {
        self.framerate.unwrap_or(30)
    }
    /// Opacity with default fallback.
    pub fn opacity_or_default(&self) -> f64 {
        self.opacity.unwrap_or(1.0)
    }
}

/// Audio pipeline configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct AudioConfig {
    pub input: EndpointConfig,
    pub output: EndpointConfig,
    pub stego: AudioStegoConfig,
}

/// An input or output endpoint (device, file, network, etc).
#[derive(Debug, Deserialize, Clone)]
pub struct EndpointConfig {
    /// Endpoint type: "device", "file", "network"
    pub r#type: String,
    /// Backend identifier (e.g. "v4l2", "avfoundation", "pulseaudio")
    pub backend: Option<String>,
    /// Device name or path
    pub device: Option<String>,
    /// File path (for file-based endpoints)
    pub path: Option<String>,
}

/// Video steganography configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct VideoStegoConfig {
    /// Ordered list of stego modules to apply: "lsb_signature", "overlay", "info_bar"
    pub pipeline: Vec<String>,
    /// LSB signature embedding settings
    #[serde(default)]
    pub lsb_signature: Option<LsbSignatureConfig>,
    /// Text overlay settings
    #[serde(default)]
    pub overlay: Option<OverlayConfig>,
    /// Info bar settings
    #[serde(default)]
    pub info_bar: Option<InfoBarConfig>,
}

/// Audio steganography configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct AudioStegoConfig {
    /// Ordered list of stego modules to apply: "lsb_signature"
    pub pipeline: Vec<String>,
    /// LSB signature embedding settings
    #[serde(default)]
    pub lsb_signature: Option<LsbSignatureConfig>,
}

/// Configuration for LSB-based signature embedding.
#[derive(Debug, Deserialize, Clone)]
pub struct LsbSignatureConfig {
    /// Number of LSBs to use per sample/pixel (1-4)
    pub bits: u8,
    /// Hex-encoded 32-byte key for pseudo-random index generation
    pub key: Option<String>,
    /// Path to a file containing the key (hex, 64 chars). Overrides `key`.
    #[serde(default)]
    pub key_file: Option<String>,
}

/// Configuration for text overlay watermark.
#[derive(Debug, Deserialize, Clone)]
pub struct OverlayConfig {
    /// Text to overlay (supports `{timestamp}`, `{frame}` placeholders)
    pub text: Option<String>,
    /// Position: "top-left", "top-right", "bottom-left", "bottom-right", "center"
    pub position: Option<String>,
    /// Font size in pixels
    pub font_size: Option<u32>,
}

/// Configuration for the info bar overlay.
#[derive(Debug, Deserialize, Clone)]
pub struct InfoBarConfig {
    /// Label text shown in the bar
    #[serde(default)]
    pub label: Option<String>,
    /// Whether to show the barcode (default: true)
    #[serde(default)]
    pub show_barcode: Option<bool>,
    /// Whether to show the QR code (default: true)
    #[serde(default)]
    pub show_qr: Option<bool>,
    /// Whether to show the timestamp (default: true)
    #[serde(default)]
    pub show_timestamp: Option<bool>,
}

impl InfoBarConfig {
    pub fn show_barcode(&self) -> bool {
        self.show_barcode.unwrap_or(true)
    }
    pub fn show_qr(&self) -> bool {
        self.show_qr.unwrap_or(true)
    }
    pub fn show_timestamp(&self) -> bool {
        self.show_timestamp.unwrap_or(true)
    }
    pub fn label_or_default(&self) -> &str {
        self.label.as_deref().unwrap_or("STEGANOGRAPHER")
    }
}

impl Config {
    /// Parse a TOML string into a [`Config`].
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(s)?;
        Ok(cfg)
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Get the resolved OTS configuration, or a disabled default if the
    /// `[ots]` block was absent from the TOML.
    pub fn ots_config(&self) -> OtsConfig {
        self.ots.clone().unwrap_or_default()
    }

    /// Whether OTS stamping is enabled in this configuration.
    pub fn ots_enabled(&self) -> bool {
        self.ots.as_ref().is_some_and(|o| o.is_enabled())
    }

    /// Validate the optional `[limits]` and `[profiles]` tables.
    ///
    /// Kept out of [`Config::from_toml`] so parse-time behavior is unchanged
    /// for existing configs; `config check` and profile resolution call it.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(limits) = &self.limits {
            limits
                .validate()
                .map_err(|error| anyhow::anyhow!("[limits]: {error}"))?;
        }
        if let Some(profiles) = &self.profiles {
            for (name, profile) in profiles {
                if let Some(limits) = &profile.limits {
                    limits
                        .validate()
                        .map_err(|error| anyhow::anyhow!("[profiles.{name}] limits: {error}"))?;
                }
                if let Some(detectors) = profile
                    .scan
                    .as_ref()
                    .and_then(|scan| scan.detectors.as_ref())
                {
                    if detectors.is_empty() {
                        anyhow::bail!("[profiles.{name}] scan.detectors must not be empty");
                    }
                    for detector in detectors {
                        if !SCAN_DETECTORS.contains(&detector.as_str()) {
                            anyhow::bail!(
                                "[profiles.{name}] unknown scan detector '{detector}' \
                                 (known: {})",
                                SCAN_DETECTORS.join(", ")
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolve a named profile from the `[profiles]` table.
    ///
    /// Errors when the table is absent or the name is unknown, listing the
    /// configured profiles.
    pub fn profile(&self, name: &str) -> anyhow::Result<&ProfileConfig> {
        let profiles = self
            .profiles
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no [profiles] table in configuration"))?;
        profiles.get(name).ok_or_else(|| {
            let mut names: Vec<&str> = profiles.keys().map(String::as_str).collect();
            names.sort_unstable();
            let listed = if names.is_empty() {
                "<none>".to_string()
            } else {
                names.join(", ")
            };
            anyhow::anyhow!("unknown profile '{name}' (configured: {listed})")
        })
    }
}

impl LsbSignatureConfig {
    /// Decode the hex key into a 32-byte array.
    ///
    /// Resolution order:
    /// 1. `key_file` (if set, read hex from file)
    /// 2. `key` (inline hex string)
    /// 3. Error if neither is set
    pub fn key_bytes(&self) -> anyhow::Result<[u8; 32]> {
        let hex_str = if let Some(ref path) = self.key_file {
            std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Cannot read key file '{}': {}", path, e))?
                .trim()
                .to_string()
        } else if let Some(ref key) = self.key {
            key.clone()
        } else {
            anyhow::bail!("No key or key_file specified for LSB signature config");
        };

        let bytes = hex_decode(&hex_str)?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "LSB key must be exactly 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Simple hex decoder (no external dep needed).
fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("Hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

/// Resolve a key from either an inline hex string or a file path.
///
/// Priority: file > inline hex.
pub fn resolve_key(inline_hex: Option<&str>, key_file: Option<&str>) -> anyhow::Result<[u8; 32]> {
    let hex_str = if let Some(path) = key_file {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read key file '{}': {}", path, e))?
            .trim()
            .to_string()
    } else if let Some(key) = inline_hex {
        key.to_string()
    } else {
        anyhow::bail!("No key or key_file specified");
    };

    let bytes = hex_decode(&hex_str)?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "Key must be exactly 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"
[global]
log_level = "info"
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        assert_eq!(cfg.global.log_level.as_deref(), Some("info"));
        assert!(cfg.video.is_none());
        assert!(cfg.audio.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
[global]
log_level = "debug"
hash_algorithm = "sha256"

[video]
[video.input]
type = "device"
backend = "avfoundation"
device = "FaceTime HD Camera"

[video.output]
type = "device"
backend = "v4l2loopback"
device = "/dev/video42"

[video.stego]
pipeline = ["lsb_signature", "overlay", "info_bar"]

[video.stego.lsb_signature]
bits = 2
key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[video.stego.overlay]
text = "CONFIDENTIAL {timestamp}"
position = "bottom-right"
font_size = 14

[video.stego.info_bar]
label = "SECURE STREAM"
show_barcode = true
show_qr = true
show_timestamp = false

[audio]
[audio.input]
type = "device"
backend = "pulseaudio"

[audio.output]
type = "device"
backend = "pulseaudio"

[audio.stego]
pipeline = ["lsb_signature"]

[audio.stego.lsb_signature]
bits = 1
key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        assert_eq!(cfg.global.log_level.as_deref(), Some("debug"));
        assert_eq!(cfg.global.hash_algorithm_name(), "sha256");

        let video = cfg.video.unwrap();
        assert_eq!(video.input.r#type, "device");
        assert_eq!(video.input.backend.as_deref(), Some("avfoundation"));
        assert_eq!(
            video.stego.pipeline,
            vec!["lsb_signature", "overlay", "info_bar"]
        );
        assert_eq!(video.stego.lsb_signature.as_ref().unwrap().bits, 2);
        assert_eq!(
            video.stego.overlay.as_ref().unwrap().text.as_deref(),
            Some("CONFIDENTIAL {timestamp}")
        );
        let bar_cfg = video.stego.info_bar.unwrap();
        assert_eq!(bar_cfg.label_or_default(), "SECURE STREAM");
        assert!(bar_cfg.show_barcode());
        assert!(bar_cfg.show_qr());
        assert!(!bar_cfg.show_timestamp());

        let audio = cfg.audio.unwrap();
        assert_eq!(audio.stego.pipeline, vec!["lsb_signature"]);
        assert_eq!(audio.stego.lsb_signature.as_ref().unwrap().bits, 1);
    }

    #[test]
    fn test_hex_decode_key() {
        let cfg = LsbSignatureConfig {
            bits: 1,
            key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            key_file: None,
        };
        let key = cfg.key_bytes().unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[1], 0x23);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn test_hex_decode_invalid() {
        let cfg = LsbSignatureConfig {
            bits: 1,
            key: Some("not_hex".to_string()),
            key_file: None,
        };
        assert!(cfg.key_bytes().is_err());
    }

    #[test]
    fn test_no_key_errors() {
        let cfg = LsbSignatureConfig {
            bits: 1,
            key: None,
            key_file: None,
        };
        assert!(cfg.key_bytes().is_err());
    }

    #[test]
    fn test_hash_algorithm_default() {
        let cfg = GlobalConfig {
            log_level: Some("info".to_string()),
            hash_algorithm: None,
            key_file: None,
        };
        assert_eq!(cfg.hash_algorithm_name(), "blake3");
    }

    #[test]
    fn test_config_without_ots_section() {
        let toml_str = r#"
[global]
log_level = "info"
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        assert!(cfg.ots.is_none());
        assert!(!cfg.ots_enabled());
        assert!(!cfg.ots_config().is_enabled());
    }

    #[test]
    fn test_config_with_ots_enabled() {
        let toml_str = r#"
[global]
log_level = "info"

[ots]
enabled = true
method = "ethereum"
interval_secs = 120
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        assert!(cfg.ots_enabled());
        let ots = cfg.ots_config();
        assert!(ots.is_enabled());
        assert_eq!(ots.method, "ethereum");
        assert_eq!(ots.interval_secs, 120);
    }

    #[test]
    fn test_payload_config_defaults() {
        let cfg = PayloadConfig {
            r#type: None,
            size: None,
            signing_backend: None,
            encrypt: None,
            encryption_key: None,
            encryption_key_file: None,
            error_correction: None,
            multi_frame_spread: None,
        };
        assert!(!cfg.encrypt_enabled());
        assert_eq!(cfg.spread_count(), 1);
    }

    #[test]
    fn test_payload_config_encrypt() {
        let cfg = PayloadConfig {
            r#type: None,
            size: None,
            signing_backend: None,
            encrypt: Some(true),
            encryption_key: Some("0123".to_string()),
            encryption_key_file: None,
            error_correction: None,
            multi_frame_spread: Some(5),
        };
        assert!(cfg.encrypt_enabled());
        assert_eq!(cfg.spread_count(), 5);
    }
    #[test]
    fn test_limits_and_profiles_default_to_none() {
        let cfg = Config::from_toml("[global]\nlog_level = \"info\"\n").unwrap();
        assert!(cfg.limits.is_none());
        assert!(cfg.profiles.is_none());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_parse_limits_and_profiles() {
        let toml_str = r#"
[global]
log_level = "info"

[limits]
max_body_len = 1048576
max_nesting_depth = 2

[profiles.strict]
[profiles.strict.limits]
max_body_len = 4096
max_packet_len = 8192
max_nesting_depth = 1

[profiles.strict.scan]
detectors = ["ZERO_WIDTH", "statistical"]

[profiles.loose]
[profiles.loose.scan]
detectors = ["magic"]
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        let limits = cfg.limits.as_ref().unwrap();
        assert_eq!(limits.max_body_len, Some(1048576));
        assert_eq!(limits.max_packet_len, None);
        assert_eq!(limits.max_nesting_depth, Some(2));

        let strict = cfg.profile("strict").unwrap();
        let strict_limits = strict.limits.as_ref().unwrap();
        assert_eq!(strict_limits.max_body_len, Some(4096));
        assert_eq!(strict_limits.max_packet_len, Some(8192));
        let scan = strict.scan.as_ref().unwrap();
        assert_eq!(
            scan.detectors.as_ref().unwrap(),
            &vec!["ZERO_WIDTH".to_string(), "statistical".to_string()]
        );
        assert!(cfg.validate().is_ok());

        let loose = cfg.profile("loose").unwrap();
        assert!(loose.limits.is_none());

        // Profile limits apply on top of the built-in defaults.
        let decoded = strict_limits.to_decode_limits();
        assert_eq!(decoded.max_body_len, 4096);
        assert_eq!(decoded.max_packet_len, 8192);
        assert_eq!(decoded.max_nesting_depth, 1);
        assert_eq!(decoded.max_field_len, DecodeLimits::default().max_field_len);
    }

    #[test]
    fn test_invalid_limit_value_rejected() {
        let toml_str = r#"
[global]
log_level = "info"

[limits]
max_body_len = 0
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        let error = cfg.validate().unwrap_err().to_string();
        assert!(error.contains("max_body_len"));
    }

    #[test]
    fn test_body_longer_than_packet_rejected() {
        let toml_str = r#"
[global]
log_level = "info"

[limits]
max_body_len = 8192
max_packet_len = 4096
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        let error = cfg.validate().unwrap_err().to_string();
        assert!(error.contains("max_body_len"));
        assert!(error.contains("max_packet_len"));
    }

    #[test]
    fn test_unknown_profile_rejected() {
        let toml_str = r#"
[global]
log_level = "info"

[profiles.strict]
[profiles.strict.scan]
detectors = ["statistical"]
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        let error = cfg.profile("missing").unwrap_err().to_string();
        assert!(error.contains("unknown profile 'missing'"));
        assert!(error.contains("strict"));

        // No [profiles] table at all also errors.
        let bare = Config::from_toml("[global]\nlog_level = \"info\"\n").unwrap();
        assert!(bare.profile("strict").is_err());
    }

    #[test]
    fn test_unknown_scan_detector_rejected() {
        let toml_str = r#"
[global]
log_level = "info"

[profiles.bad]
[profiles.bad.scan]
detectors = ["totally_bogus"]
"#;
        let cfg = Config::from_toml(toml_str).unwrap();
        let error = cfg.validate().unwrap_err().to_string();
        assert!(error.contains("profiles.bad"));
        assert!(error.contains("unknown scan detector"));
    }
}
