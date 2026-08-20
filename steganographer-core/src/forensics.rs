//! Structural forensic detectors for the standard media scan.
//!
//! Complements the statistical detectors in [`crate::steganalysis`] with cheap,
//! content-agnostic probes that need no container parsing: Shannon entropy,
//! magic-byte file identification, and embedded signature/packet-magic scanning.
//! Every probe here is non-recursive and bounded — it only looks at the bytes it
//! is given and never opens containers, follows links, or touches the network.

use crate::steganalysis::{self, CombinedResult};

/// Shannon entropy of a byte buffer, in bits per byte (`0.0 ..= 8.0`).
///
/// An empty buffer has entropy `0.0`. High entropy is expected for already
/// compressed or encrypted formats and is reported as an observation, not as a
/// detection on its own.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }
    entropy
}

/// Broad file family identified by leading magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFamily {
    Png,
    Jpeg,
    Gif,
    WebP,
    Wav,
    Bmp,
    Tiff,
    Pdf,
    Zip,
    Gzip,
    Tar,
    Ogg,
    Flac,
    Unknown,
}

impl FileFamily {
    /// Lowercase, stable identifier for reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            FileFamily::Png => "png",
            FileFamily::Jpeg => "jpeg",
            FileFamily::Gif => "gif",
            FileFamily::WebP => "webp",
            FileFamily::Wav => "wav",
            FileFamily::Bmp => "bmp",
            FileFamily::Tiff => "tiff",
            FileFamily::Pdf => "pdf",
            FileFamily::Zip => "zip",
            FileFamily::Gzip => "gzip",
            FileFamily::Tar => "tar",
            FileFamily::Ogg => "ogg",
            FileFamily::Flac => "flac",
            FileFamily::Unknown => "unknown",
        }
    }
}

/// Identify a file family from leading magic bytes.
///
/// The probe reads at most the first 12 bytes and never decodes the file.
pub fn detect_file_family(data: &[u8]) -> FileFamily {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return FileFamily::Png;
    }
    if data.starts_with(b"\xff\xd8\xff") {
        return FileFamily::Jpeg;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return FileFamily::Gif;
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return FileFamily::WebP;
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return FileFamily::Wav;
    }
    if data.starts_with(b"BM") {
        return FileFamily::Bmp;
    }
    if data.starts_with(b"II*\x00") || data.starts_with(b"MM\x00*") {
        return FileFamily::Tiff;
    }
    if data.starts_with(b"%PDF") {
        return FileFamily::Pdf;
    }
    if data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
    {
        return FileFamily::Zip;
    }
    if data.starts_with(b"\x1f\x8b") {
        return FileFamily::Gzip;
    }
    if data.starts_with(b"fLaC") {
        return FileFamily::Flac;
    }
    if data.starts_with(b"OggS") {
        return FileFamily::Ogg;
    }
    if data.len() >= 262 && &data[257..262] == b"ustar" {
        return FileFamily::Tar;
    }
    FileFamily::Unknown
}

/// An embedded steganographic magic recovered from a raw byte scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedMagic {
    /// Legacy `STEG` v2 `SignaturePayload` magic.
    LegacySignature,
    /// Generic packet `STG3` magic.
    GenericPacket,
}

impl EmbeddedMagic {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmbeddedMagic::LegacySignature => "legacy_signature",
            EmbeddedMagic::GenericPacket => "generic_packet",
        }
    }
}

/// A specific location match for an embedded magic header found inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedMagicMatch {
    pub magic: EmbeddedMagic,
    pub offset: usize,
}

/// Scan `data` for an embedded `STEG` (legacy) or `STG3` (generic) magic.
///
/// This finds signatures/packets that are stored *inline* in the raw bytes
/// (attachments, raw carriers, unencoded payloads). LSB/spectral carriers that
/// spread the payload across low bits are not detected here; those are covered
/// by the statistical detectors.
pub fn detect_embedded_magic(data: &[u8]) -> Option<EmbeddedMagic> {
    for window in data.windows(4) {
        if window == b"STEG" {
            return Some(EmbeddedMagic::LegacySignature);
        }
        if window == b"STG3" {
            return Some(EmbeddedMagic::GenericPacket);
        }
    }
    None
}

/// Find all occurrences and byte offsets of inline steganographic magics.
pub fn detect_embedded_magics_detailed(data: &[u8]) -> Vec<EmbeddedMagicMatch> {
    let mut matches = Vec::new();
    for (offset, window) in data.windows(4).enumerate() {
        if window == b"STEG" {
            matches.push(EmbeddedMagicMatch {
                magic: EmbeddedMagic::LegacySignature,
                offset,
            });
        } else if window == b"STG3" {
            matches.push(EmbeddedMagicMatch {
                magic: EmbeddedMagic::GenericPacket,
                offset,
            });
        }
    }
    matches
}

/// Aggregated forensic scan of one byte buffer.
#[derive(Debug, Clone)]
pub struct ForensicScan {
    /// Shannon entropy in bits per byte.
    pub entropy: f64,
    /// File family inferred from magic bytes.
    pub file_family: FileFamily,
    /// Embedded signature/packet magic, if present inline.
    pub embedded_magic: Option<EmbeddedMagic>,
    /// All inline embedded magic matches and their offsets.
    pub magic_matches: Vec<EmbeddedMagicMatch>,
    /// Aggregated statistical detector results.
    pub statistical: CombinedResult,
    /// `true` if any detector flags the buffer as suspicious.
    pub detected: bool,
    /// Human-readable summary of the strongest finding.
    pub message: String,
}

/// Run every forensic detector over `data`.
///
/// A buffer is reported `detected` when either the statistical detectors fire
/// or an inline `STEG`/`STG3` magic is present. Entropy and file family are
/// observations that accompany the verdict but never trigger it by themselves.
pub fn scan_bytes(data: &[u8]) -> ForensicScan {
    let statistical = steganalysis::analyze_combined(data);
    let entropy = shannon_entropy(data);
    let file_family = detect_file_family(data);
    let magic_matches = detect_embedded_magics_detailed(data);
    let embedded_magic = magic_matches.first().map(|m| m.magic);
    let detected = statistical.detected || embedded_magic.is_some();
    let message = if let Some(magic) = embedded_magic {
        format!("embedded {} magic found inline", magic.as_str())
    } else if statistical.detected {
        statistical.message.clone()
    } else {
        "no forensic indicators".to_string()
    };
    ForensicScan {
        entropy,
        file_family,
        embedded_magic,
        magic_matches,
        statistical,
        detected,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_and_constant_buffers() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        // A constant buffer has zero entropy.
        assert_eq!(shannon_entropy(&[0xAB; 256]), 0.0);
        // A buffer with 256 distinct byte values has maximal entropy (8.0).
        let all: Vec<u8> = (0u8..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn file_family_detection() {
        assert_eq!(
            detect_file_family(b"\x89PNG\r\n\x1a\nrest"),
            FileFamily::Png
        );
        assert_eq!(
            detect_file_family(b"\xff\xd8\xff\xe0rest"),
            FileFamily::Jpeg
        );
        assert_eq!(detect_file_family(b"GIF89a..."), FileFamily::Gif);
        assert_eq!(
            detect_file_family(b"RIFF\x00\x00\x00\x00WAVEfmt "),
            FileFamily::Wav
        );
        assert_eq!(
            detect_file_family(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            FileFamily::WebP
        );
        assert_eq!(detect_file_family(b"%PDF-1.7\n"), FileFamily::Pdf);
        assert_eq!(detect_file_family(b"PK\x03\x04\x14\x00"), FileFamily::Zip);
        assert_eq!(detect_file_family(b"\x1f\x8b\x08\x00"), FileFamily::Gzip);
        assert_eq!(detect_file_family(b"fLaC\x00\x00"), FileFamily::Flac);
        assert_eq!(detect_file_family(b"OggS\x00\x02"), FileFamily::Ogg);
        assert_eq!(detect_file_family(b"random bytes"), FileFamily::Unknown);
        assert_eq!(detect_file_family(b""), FileFamily::Unknown);
    }

    #[test]
    fn embedded_magic_detection() {
        assert_eq!(
            detect_embedded_magic(b"junk STEG payload"),
            Some(EmbeddedMagic::LegacySignature)
        );
        assert_eq!(
            detect_embedded_magic(b"junk STG3 payload"),
            Some(EmbeddedMagic::GenericPacket)
        );
        assert_eq!(detect_embedded_magic(b"no magic here"), None);
        assert_eq!(detect_embedded_magic(b"ST"), None);

        let detailed = detect_embedded_magics_detailed(b"header STEG ... body STG3 end");
        assert_eq!(detailed.len(), 2);
        assert_eq!(detailed[0].magic, EmbeddedMagic::LegacySignature);
        assert_eq!(detailed[0].offset, 7);
        assert_eq!(detailed[1].magic, EmbeddedMagic::GenericPacket);
        assert_eq!(detailed[1].offset, 21);
    }

    #[test]
    fn scan_detects_inline_packet_and_reports_observations() {
        let scan = scan_bytes(b"prefix STG3 packet bytes");
        assert!(scan.detected);
        assert_eq!(scan.embedded_magic, Some(EmbeddedMagic::GenericPacket));
        assert!(scan.entropy > 0.0);
        assert_eq!(scan.file_family, FileFamily::Unknown);
    }

    #[test]
    fn scan_of_plain_text_is_clean() {
        // A normal ASCII text buffer should not trigger the statistical
        // detectors nor contain an inline magic.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(50);
        let scan = scan_bytes(&data);
        assert_eq!(scan.embedded_magic, None);
        assert!(!scan.message.contains("magic"));
    }
}
