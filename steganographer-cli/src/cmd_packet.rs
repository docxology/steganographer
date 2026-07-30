//! Opt-in generic packet encode/decode CLI surface.

use rand::RngCore;
use serde::Serialize;
use steganographer_core::packet::{
    AlgorithmDescriptor, DecodeLimits, GenericPacket, Locator, PayloadKind, KERNEL_SPATIAL_LSB,
    PLACEMENT_SEQUENTIAL,
};
use steganographer_core::{CarrierEmbedder, CarrierExtractor, EmbeddingConfig, SpatialLsb};

use crate::media_io;

pub struct GenericEncodeOptions {
    pub payload_file: Option<String>,
    pub payload_text: Option<String>,
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub input_format: Option<String>,
}

#[derive(Debug, Serialize)]
struct GenericEncodeResult {
    protocol: &'static str,
    packet_id: String,
    payload_kind: &'static str,
    payload_bytes: usize,
    packet_bytes: usize,
    bits: u8,
    input: String,
    output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
}

#[derive(Debug, Serialize)]
struct GenericDecodeResult {
    protocol: String,
    packet_id: String,
    payload_kind: &'static str,
    payload_bytes: usize,
    packet_bytes: usize,
    bits: u8,
    input: String,
    output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ots: Option<OtsInfo>,
}

/// OTS metadata surfaced in the generic packet --json output.
#[derive(Debug, Serialize)]
struct OtsInfo {
    digest: String,
    method: String,
    timestamp: Option<u64>,
}

pub fn encode(
    input: &str,
    output: &str,
    stego_type: &str,
    bits: u8,
    format: &str,
    options: &GenericEncodeOptions,
) -> anyhow::Result<()> {
    if stego_type != "lsb_video" {
        anyhow::bail!("generic packet alpha currently supports --stego-type lsb_video only");
    }
    let (payload, payload_kind, default_filename) = match (
        options.payload_file.as_deref(),
        options.payload_text.as_deref(),
    ) {
        (Some(path), None) => (
            std::fs::read(path).map_err(|error| {
                anyhow::anyhow!("Cannot read payload file '{}': {}", path, error)
            })?,
            PayloadKind::File,
            std::path::Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned),
        ),
        (None, Some(text)) => (text.as_bytes().to_vec(), PayloadKind::Text, None),
        (Some(_), Some(_)) => {
            anyhow::bail!("--payload-file and --payload-text are mutually exclusive")
        }
        (None, None) => {
            anyhow::bail!("generic packet encoding requires --payload-file or --payload-text")
        }
    };

    let display_filename = options
        .filename
        .clone()
        .or(default_filename)
        .map(validate_display_filename)
        .transpose()?;
    let limits = DecodeLimits::default();
    let config = EmbeddingConfig::new(bits)?;
    let input_format = options
        .input_format
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));
    let mut media = media_io::read_input(input, &input_format, stego_type)?;

    let mut packet_id = [0u8; 16];
    let mut nonce = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut packet_id);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut packet = GenericPacket::new_untransformed(
        payload,
        packet_id,
        nonce,
        payload_kind,
        AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
        AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits]),
        &limits,
    )?;
    packet.envelope.mime_type = options.mime_type.clone();
    packet.envelope.filename = display_filename.clone();
    synchronize_locator(&mut packet, &limits)?;
    let packet_bytes = packet.encode(&limits)?;

    let embed_report = SpatialLsb.embed_packet(&mut media.data, &packet_bytes, &config)?;
    media_io::write_output(output, &media, stego_type)?;

    let result = GenericEncodeResult {
        protocol: "1.0-alpha",
        packet_id: hex_encode(&packet_id),
        payload_kind: payload_kind_name(payload_kind),
        payload_bytes: packet.body.len(),
        packet_bytes: embed_report.packet_bytes,
        bits,
        input: input.to_owned(),
        output: output.to_owned(),
        mime_type: options.mime_type.clone(),
        filename: display_filename,
    };
    print_encode_result(&result, format)?;
    Ok(())
}

pub fn decode(
    input: &str,
    output: &str,
    stego_type: &str,
    bits: &str,
    format: &str,
    input_format: Option<&str>,
    force: bool,
) -> anyhow::Result<()> {
    if stego_type != "lsb_video" {
        anyhow::bail!("generic packet alpha currently supports --stego-type lsb_video only");
    }
    let input_path = std::path::Path::new(input);
    let output_path = std::path::Path::new(output);
    let aliases_input = input == output
        || (output_path.exists()
            && std::fs::canonicalize(input_path).ok() == std::fs::canonicalize(output_path).ok());
    if aliases_input {
        anyhow::bail!("decoded payload output must differ from the carrier input");
    }
    if output_path.exists() && !force {
        anyhow::bail!(
            "refusing to overwrite existing payload output '{}'; pass --force to replace it",
            output
        );
    }

    let selected_format = input_format
        .map(str::to_owned)
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));
    let media = media_io::read_input(input, &selected_format, stego_type)?;
    let limits = DecodeLimits::default();
    let candidates = bits_candidates(bits)?;
    let mut extracted = None;
    let mut errors = Vec::new();
    for candidate in candidates {
        let config = EmbeddingConfig::new(candidate)?;
        match SpatialLsb.extract_packet(&media.data, &config, &limits) {
            Ok(report) => {
                extracted = Some(report);
                break;
            }
            Err(error) => errors.push(format!("{candidate} bits: {error}")),
        }
    }
    let report = extracted.ok_or_else(|| {
        anyhow::anyhow!(
            "no valid generic packet found with requested LSB strengths ({})",
            errors.join("; ")
        )
    })?;
    if report.packet.locator.flags != 0 || !report.packet.envelope.transforms.is_empty() {
        anyhow::bail!(
            "generic packet uses transforms that this alpha decoder does not support; \
             no payload was written"
        );
    }

    std::fs::write(output, &report.packet.body)?;
    let ots_meta =
        steganographer_core::OtsMetadata::from_extensions(&report.packet.envelope.extensions);
    let ots_info = if ots_meta.is_present() {
        Some(OtsInfo {
            digest: ots_meta.digest_hex.clone().unwrap_or_default(),
            method: ots_meta.method_name().to_string(),
            timestamp: ots_meta.timestamp,
        })
    } else {
        None
    };
    let result = GenericDecodeResult {
        protocol: format!(
            "{}.{}-alpha",
            report.packet.locator.protocol_major, report.packet.locator.protocol_minor
        ),
        packet_id: hex_encode(&report.packet.envelope.packet_id),
        payload_kind: payload_kind_name(report.packet.envelope.payload_kind),
        payload_bytes: report.packet.body.len(),
        packet_bytes: report.packet.encoded_len()?,
        bits: report.bits_per_unit,
        input: input.to_owned(),
        output: output.to_owned(),
        mime_type: report.packet.envelope.mime_type,
        filename: report.packet.envelope.filename,
        ots: ots_info,
    };
    print_decode_result(&result, format)?;
    Ok(())
}

fn synchronize_locator(
    packet: &mut GenericPacket,
    limits: &DecodeLimits,
) -> Result<(), steganographer_core::PacketError> {
    let envelope = packet.envelope.encode(limits)?;
    packet.locator = Locator::new(
        packet.locator.flags,
        envelope.len(),
        packet.body.len(),
        steganographer_core::packet::crc32c(&envelope),
        packet.locator.nonce,
        limits,
    )?;
    Ok(())
}

fn bits_candidates(value: &str) -> anyhow::Result<Vec<u8>> {
    if value.eq_ignore_ascii_case("auto") {
        return Ok(vec![1, 2, 3, 4]);
    }
    let bits: u8 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("--bits must be 'auto' or an integer from 1 to 4"))?;
    EmbeddingConfig::new(bits)?;
    Ok(vec![bits])
}

fn validate_display_filename(value: String) -> anyhow::Result<String> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        anyhow::bail!("packet filename must be a safe display name without path components");
    }
    Ok(value)
}

fn payload_kind_name(kind: PayloadKind) -> &'static str {
    match kind {
        PayloadKind::Bytes => "bytes",
        PayloadKind::Text => "text",
        PayloadKind::File => "file",
        PayloadKind::FrameAttestation => "frame_attestation",
        PayloadKind::Manifest => "manifest",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn print_encode_result(result: &GenericEncodeResult, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else {
        println!("Generic packet: {}", result.protocol);
        println!("Packet ID: {}", result.packet_id);
        println!(
            "Payload: {} bytes ({})",
            result.payload_bytes, result.payload_kind
        );
        println!(
            "Packet: {} bytes at {} LSB(s)",
            result.packet_bytes, result.bits
        );
        println!("Encoded carrier: {}", result.output);
    }
    Ok(())
}

fn print_decode_result(result: &GenericDecodeResult, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else {
        println!("Generic packet: {}", result.protocol);
        println!("Packet ID: {}", result.packet_id);
        println!(
            "Payload: {} bytes ({})",
            result.payload_bytes, result.payload_kind
        );
        println!("Detected LSB strength: {}", result.bits);
        println!("Decoded payload: {}", result.output);
    }
    Ok(())
}
