//! Zero-I/O WASM inspection facade for browser-based carrier and packet analysis.
//!
//! Provides WebAssembly-friendly inspection functions that operate on raw byte
//! buffers without filesystem, network, or OS threading requirements.

use serde::Serialize;

use crate::carrier::{
    CarrierDescriptor, CarrierEmbedder, CarrierExtractor, EmbeddingConfig, SpatialLsb,
};
use crate::forensics::{self, ForensicScan};
use crate::packet::{DecodeLimits, GenericPacket};

/// WASM-compatible structured inspection result.
#[derive(Debug, Serialize)]
pub struct WasmInspectionReport {
    pub file_family: String,
    pub entropy: f64,
    pub detected: bool,
    pub embedded_magic: Option<String>,
    pub magic_offsets: Vec<usize>,
    pub message: String,
    pub statistical_detected: bool,
    pub statistical_confidence: f64,
}

impl From<ForensicScan> for WasmInspectionReport {
    fn from(scan: ForensicScan) -> Self {
        let magic_offsets = scan.magic_matches.iter().map(|m| m.offset).collect();
        Self {
            file_family: scan.file_family.as_str().to_string(),
            entropy: scan.entropy,
            detected: scan.detected,
            embedded_magic: scan.embedded_magic.map(|m| m.as_str().to_string()),
            magic_offsets,
            message: scan.message,
            statistical_detected: scan.statistical.detected,
            statistical_confidence: scan.statistical.confidence,
        }
    }
}

/// Inspect a raw byte buffer and return structured JSON-compatible forensic metadata.
pub fn inspect_bytes(data: &[u8]) -> WasmInspectionReport {
    let scan = forensics::scan_bytes(data);
    scan.into()
}

/// Attempt to extract a generic packet from a raw RGB8 carrier in-memory.
pub fn extract_packet_rgb8(carrier: &[u8], bits: u8) -> Result<GenericPacket, String> {
    let config = EmbeddingConfig::new(bits).map_err(|e| e.to_string())?;
    let report = SpatialLsb
        .extract_packet(carrier, &config, &DecodeLimits::default())
        .map_err(|e| e.to_string())?;
    Ok(report.packet)
}

/// Calculate the exact carrier capacity in bytes for a given byte buffer length and bit depth.
pub fn capacity_rgb8(byte_len: usize, bits: u8) -> Result<usize, String> {
    let config = EmbeddingConfig::new(bits).map_err(|e| e.to_string())?;
    let desc = CarrierDescriptor::rgb8(byte_len);
    let report = SpatialLsb
        .capacity(&desc, &config)
        .map_err(|e| e.to_string())?;
    Ok(report.max_packet_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier::{CarrierEmbedder, EmbeddingConfig, SpatialLsb};
    use crate::packet::{
        AlgorithmDescriptor, DecodeLimits, GenericPacket, PayloadKind, KERNEL_SPATIAL_LSB,
        PLACEMENT_SEQUENTIAL,
    };

    #[test]
    fn test_wasm_inspection_on_clean_and_embedded_bytes() {
        let clean = b"the quick brown fox jumps over the lazy dog. ".repeat(50);
        let report = inspect_bytes(&clean);
        assert_eq!(report.embedded_magic, None);
        assert!(report.magic_offsets.is_empty());
        assert!(!report.message.contains("magic"));

        let mut embedded = clean.to_vec();
        embedded.extend_from_slice(b"STG3 embedded generic packet marker");
        let report = inspect_bytes(&embedded);
        assert_eq!(report.detected, true);
        assert_eq!(report.embedded_magic, Some("generic_packet".to_string()));
        assert!(!report.magic_offsets.is_empty());
    }

    #[test]
    fn test_wasm_capacity_and_extract() {
        let max_bytes = capacity_rgb8(1000, 2).unwrap();
        assert_eq!(max_bytes, 250);

        let packet = GenericPacket::new_untransformed(
            b"wasm payload".to_vec(),
            *b"0123456789abcdef",
            *b"nonce123",
            PayloadKind::Bytes,
            AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![1]),
            &DecodeLimits::default(),
        )
        .unwrap();

        let encoded = packet.encode(&DecodeLimits::default()).unwrap();
        let config = EmbeddingConfig::new(1).unwrap();
        let mut carrier = vec![0x7F; encoded.len() * 8 + 64];
        SpatialLsb
            .embed_packet(&mut carrier, &encoded, &config)
            .unwrap();

        let extracted = extract_packet_rgb8(&carrier, 1).unwrap();
        assert_eq!(extracted.body, b"wasm payload");
    }
}
