//! Opt-in generic packet encode/decode CLI surface.

use rand::RngCore;
use serde::Serialize;
use steganographer_core::encryption::EncryptionKey;
use steganographer_core::packet::{
    AlgorithmDescriptor, DecodeLimits, GenericPacket, Locator, PayloadKind, KERNEL_SPATIAL_LSB,
    PLACEMENT_KEYED, PLACEMENT_SEQUENTIAL,
};
use steganographer_core::transforms;
use steganographer_core::{
    CarrierEmbedder, CarrierExtractor, EmbeddingConfig, KeyedSpatialLsb, SpatialLsb,
    TransformContext, DEFAULT_ECC_CHUNK_LEN,
};

use crate::media_io;

pub struct GenericEncodeOptions {
    pub payload_file: Option<String>,
    pub payload_text: Option<String>,
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub input_format: Option<String>,
    pub encrypt: bool,
    pub encryption_key: Option<String>,
    pub encryption_key_file: Option<String>,
    pub ecc: bool,
    pub ecc_parity: usize,
    pub compress: bool,
    pub signing_key: Option<String>,
    pub embedding_key: Option<String>,
    pub embedding_key_file: Option<String>,
}

pub struct GenericDecodeOptions {
    pub decrypt: bool,
    pub decryption_key: Option<String>,
    pub decryption_key_file: Option<String>,
    pub embedding_key: Option<String>,
    pub embedding_key_file: Option<String>,
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
    encrypted: bool,
    error_corrected: bool,
    compressed: bool,
    signed: bool,
    keyed: bool,
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
    encrypted: bool,
    error_corrected: bool,
    compressed: bool,
    signed: bool,
    keyed: bool,
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
    let embedding_key = resolve_embedding_key(options)?;
    let keyed = embedding_key.is_some();
    let placement = if keyed {
        AlgorithmDescriptor::new(PLACEMENT_KEYED, 1, Vec::new())
    } else {
        AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new())
    };
    let mut packet = GenericPacket::new_untransformed(
        payload,
        packet_id,
        nonce,
        payload_kind,
        placement,
        AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits]),
        &limits,
    )?;

    // Apply opt-in transforms (sign, compress, AEAD encrypt, chunked RS ECC).
    let signer = resolve_signing_key(options)?;
    let encrypt_key = resolve_encryption_key(options)?;
    let ecc_parity = if options.ecc { options.ecc_parity } else { 0 };
    if options.ecc && !(1..=steganographer_core::MAX_ECC_PARITY).contains(&ecc_parity) {
        anyhow::bail!(
            "--ecc-parity must be in 1..={}, got {}",
            steganographer_core::MAX_ECC_PARITY,
            ecc_parity
        );
    }
    let encrypted = encrypt_key.is_some();
    let error_corrected = ecc_parity > 0;
    let context = TransformContext {
        packet_id: &packet.envelope.packet_id,
        nonce: &packet.locator.nonce,
        payload_kind: packet.envelope.payload_kind as u16,
        original_len: packet.envelope.original_len,
    };
    let (encoded_body, transforms, flags) = transforms::apply(
        &packet.body,
        &context,
        signer.as_ref(),
        options.compress,
        encrypt_key.as_ref(),
        ecc_parity,
        DEFAULT_ECC_CHUNK_LEN,
    )
    .map_err(|e| anyhow::anyhow!("transform application failed: {e}"))?;
    packet.body = encoded_body;
    packet.envelope.transforms = transforms;
    packet.locator.flags = flags
        | if keyed {
            steganographer_core::packet::FLAG_KEYED_LOCATOR
        } else {
            0
        };
    let compressed = flags & steganographer_core::packet::FLAG_COMPRESSED != 0;
    let signed = flags & steganographer_core::packet::FLAG_PAYLOAD_SIGNED != 0;

    packet.envelope.mime_type = options.mime_type.clone();
    packet.envelope.filename = display_filename.clone();
    synchronize_locator(&mut packet, &limits)?;
    let packet_bytes = packet.encode(&limits)?;

    let embed_report = match &embedding_key {
        Some(key) => {
            KeyedSpatialLsb::new(*key).embed_packet(&mut media.data, &packet_bytes, &config)?
        }
        None => SpatialLsb.embed_packet(&mut media.data, &packet_bytes, &config)?,
    };
    media_io::write_output(output, &media, stego_type)?;

    let result = GenericEncodeResult {
        protocol: "1.0-alpha",
        packet_id: hex_encode(&packet_id),
        payload_kind: payload_kind_name(payload_kind),
        payload_bytes: packet.envelope.original_len as usize,
        packet_bytes: embed_report.packet_bytes,
        bits,
        input: input.to_owned(),
        output: output.to_owned(),
        encrypted,
        error_corrected,
        compressed,
        signed,
        keyed,
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
    options: &GenericDecodeOptions,
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
    let embedding_key = resolve_embedding_key(options)?;
    let mut extracted = None;
    let mut errors = Vec::new();
    for candidate in candidates {
        let config = EmbeddingConfig::new(candidate)?;
        if let Some(key) = embedding_key {
            match KeyedSpatialLsb::new(key).extract_packet(&media.data, &config, &limits) {
                Ok(report) => {
                    extracted = Some(report);
                    break;
                }
                Err(error) => errors.push(format!("{candidate} bits (keyed): {error}")),
            }
        }
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

    // Reverse any recorded transforms (AEAD decryption, Reed-Solomon ECC) and
    // re-verify the recovered logical payload against the envelope digest.
    let decrypt_key = resolve_decryption_key(options)?;
    let context = TransformContext {
        packet_id: &report.packet.envelope.packet_id,
        nonce: &report.packet.locator.nonce,
        payload_kind: report.packet.envelope.payload_kind as u16,
        original_len: report.packet.envelope.original_len,
    };
    let payload = transforms::reverse(
        &report.packet.body,
        &context,
        decrypt_key.as_ref(),
        &report.packet.envelope.transforms,
        report.packet.envelope.original_len,
    )
    .map_err(|e| anyhow::anyhow!("transform reversal failed: {e}"))?;
    if !report.packet.envelope.content_digest.verify(&payload) {
        anyhow::bail!("recovered payload digest does not match the packet envelope");
    }

    let encrypted = report.packet.locator.flags & steganographer_core::packet::FLAG_ENCRYPTED != 0;
    let error_corrected =
        report.packet.locator.flags & steganographer_core::packet::FLAG_ERROR_CORRECTED != 0;
    let compressed =
        report.packet.locator.flags & steganographer_core::packet::FLAG_COMPRESSED != 0;
    let signed =
        report.packet.locator.flags & steganographer_core::packet::FLAG_PAYLOAD_SIGNED != 0;
    let keyed = report.packet.locator.flags & steganographer_core::packet::FLAG_KEYED_LOCATOR != 0;

    std::fs::write(output, &payload)?;
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
        payload_bytes: payload.len(),
        packet_bytes: report.packet.encoded_len()?,
        bits: report.bits_per_unit,
        input: input.to_owned(),
        output: output.to_owned(),
        encrypted,
        error_corrected,
        compressed,
        signed,
        keyed,
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

fn resolve_embedding_key<O: EmbeddingKeySource>(options: &O) -> anyhow::Result<Option<[u8; 32]>> {
    match (options.embedding_key(), options.embedding_key_file()) {
        (Some(hex), None) => steganographer_core::config::resolve_key(Some(hex), None).map(Some),
        (None, Some(path)) => steganographer_core::config::resolve_key(None, Some(path)).map(Some),
        (Some(_), Some(_)) => {
            anyhow::bail!("--embedding-key and --embedding-key-file are mutually exclusive")
        }
        (None, None) => Ok(None),
    }
}

/// Shared view of the embedding-key CLI fields used by both encode and decode.
trait EmbeddingKeySource {
    fn embedding_key(&self) -> Option<&str>;
    fn embedding_key_file(&self) -> Option<&str>;
}

impl EmbeddingKeySource for GenericEncodeOptions {
    fn embedding_key(&self) -> Option<&str> {
        self.embedding_key.as_deref()
    }

    fn embedding_key_file(&self) -> Option<&str> {
        self.embedding_key_file.as_deref()
    }
}

impl EmbeddingKeySource for GenericDecodeOptions {
    fn embedding_key(&self) -> Option<&str> {
        self.embedding_key.as_deref()
    }

    fn embedding_key_file(&self) -> Option<&str> {
        self.embedding_key_file.as_deref()
    }
}

fn resolve_signing_key(
    options: &GenericEncodeOptions,
) -> anyhow::Result<Option<ed25519_dalek::SigningKey>> {
    let Some(path) = &options.signing_key else {
        return Ok(None);
    };
    let key_hex = std::fs::read_to_string(path)?.trim().to_string();
    let key_bytes = decode_hex_32(&key_hex)?;
    Ok(Some(ed25519_dalek::SigningKey::from_bytes(&key_bytes)))
}

fn decode_hex_32(hex: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        anyhow::bail!(
            "signing key must be 32 bytes (64 hex chars), got {} bytes",
            trimmed.len() / 2
        );
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in signing key: {e}"))?;
    }
    Ok(out)
}

fn resolve_encryption_key(options: &GenericEncodeOptions) -> anyhow::Result<Option<EncryptionKey>> {
    if !options.encrypt {
        return Ok(None);
    }
    let key = if let Some(ref path) = options.encryption_key_file {
        let hex_str = std::fs::read_to_string(path)?.trim().to_string();
        EncryptionKey::from_hex(&hex_str)?
    } else if let Some(ref hex_str) = options.encryption_key {
        EncryptionKey::from_hex(hex_str)?
    } else {
        let key = EncryptionKey::generate();
        println!(
            "Generated random encryption key (hex, save it to decrypt later): {}",
            key.to_hex()
        );
        key
    };
    Ok(Some(key))
}

fn resolve_decryption_key(options: &GenericDecodeOptions) -> anyhow::Result<Option<EncryptionKey>> {
    if !options.decrypt {
        return Ok(None);
    }
    let key = if let Some(ref path) = options.decryption_key_file {
        let hex_str = std::fs::read_to_string(path)?.trim().to_string();
        EncryptionKey::from_hex(&hex_str)?
    } else if let Some(ref hex_str) = options.decryption_key {
        EncryptionKey::from_hex(hex_str)?
    } else {
        anyhow::bail!("--decrypt requires --decryption-key <hex> or --decryption-key-file <path>");
    };
    Ok(Some(key))
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
        println!(
            "Transforms: signed={}, compressed={}, encrypted={}, error_corrected={}",
            result.signed, result.compressed, result.encrypted, result.error_corrected
        );
        println!(
            "Placement: {}",
            if result.keyed { "keyed" } else { "sequential" }
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
        println!(
            "Transforms: signed={}, compressed={}, encrypted={}, error_corrected={}",
            result.signed, result.compressed, result.encrypted, result.error_corrected
        );
        println!(
            "Placement: {}",
            if result.keyed { "keyed" } else { "sequential" }
        );
        println!("Decoded payload: {}", result.output);
    }
    Ok(())
}
