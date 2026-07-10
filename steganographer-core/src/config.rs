//! Configuration model for steganographer pipelines.
//!
//! Supports TOML deserialization with [`Config::from_toml`].

use serde::Deserialize;

/// Top-level configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub global: GlobalConfig,
    pub video: Option<VideoConfig>,
    pub audio: Option<AudioConfig>,
}

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
pub fn resolve_key(
    inline_hex: Option<&str>,
    key_file: Option<&str>,
) -> anyhow::Result<[u8; 32]> {
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
        assert_eq!(video.stego.pipeline, vec!["lsb_signature", "overlay", "info_bar"]);
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
            key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
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
}
