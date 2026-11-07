//! Opt-in generic packet encode/decode CLI surface.

use anyhow::Context;
use rand::RngCore;
use serde::Serialize;
use std::path::Path;
use steganographer_core::crypto::{decode_hex_array, encode_hex};
use steganographer_core::encryption::EncryptionKey;
use steganographer_core::packet::{
    AlgorithmDescriptor, DecodeLimits, GenericPacket, Locator, PayloadKind, TransformDescriptor,
    KERNEL_SPATIAL_LSB, PLACEMENT_KEYED, PLACEMENT_SEQUENTIAL,
};
use steganographer_core::revocation::{RevocationList, RevokedKey};
use steganographer_core::transforms;
use steganographer_core::transforms::{parse_kdf_argon2id_params, TRANSFORM_KDF_ARGON2ID};
use steganographer_core::{
    Argon2Params, AudioSpatialLsb, CarrierEmbedder, CarrierError, CarrierExtractor,
    EmbeddingConfig, ExtractReport, KeyedAudioSpatialLsb, KeyedSpatialLsb, PacketError, SpatialLsb,
    TransformContext, DEFAULT_ECC_CHUNK_LEN,
};

use crate::media_io;

pub struct GenericEncodeOptions {
    pub payload_file: Option<String>,
    pub payload_text: Option<String>,
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub input_format: Option<String>,
    pub raw_width: Option<u32>,
    pub raw_height: Option<u32>,
    pub decode_limits: DecodeLimits,
    pub encrypt: bool,
    pub encryption_key: Option<String>,
    pub encryption_key_file: Option<String>,
    pub ecc: bool,
    pub ecc_parity: usize,
    pub compress: bool,
    pub signing_key: Option<String>,
    pub embedding_key: Option<String>,
    pub embedding_key_file: Option<String>,
    pub verify_write: bool,
    /// Password-path credentials (PKT-007): when set, the packet's AEAD key is
    /// derived with Argon2id and recorded in a KDF transform descriptor.
    /// Mutually exclusive with `--encryption-key` / `--encryption-key-file`.
    pub password: Option<String>,
    pub password_file: Option<String>,
}

pub struct GenericDecodeOptions {
    pub decrypt: bool,
    pub decryption_key: Option<String>,
    pub decryption_key_file: Option<String>,
    pub embedding_key: Option<String>,
    pub embedding_key_file: Option<String>,
    /// Password-path credentials (PKT-007): derived from the packet's KDF
    /// descriptor on decode. Mutually exclusive with
    /// `--decryption-key` / `--decryption-key-file`.
    pub password: Option<String>,
    pub password_file: Option<String>,
    pub decode_limits: DecodeLimits,
    pub trusted_signer: Option<String>,
    pub revoked_list: Option<String>,
}

pub struct ExtractOptions {
    pub stego_type: String,
    pub input_format: Option<String>,
    pub embedding_key: Option<String>,
    pub embedding_key_file: Option<String>,
    pub encryption_key: Option<String>,
    pub encryption_key_file: Option<String>,
    pub password: Option<String>,
    pub password_file: Option<String>,
    pub trusted_signer: Option<String>,
    pub revoked_list: Option<String>,
    pub decode_limits: DecodeLimits,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfInfo>,
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
    signer_public_key: Option<String>,
    signer_trusted: bool,
    keyed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfInfo>,
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

/// PKT-007 KDF descriptor report surfaced in encode/decode output.
#[derive(Debug, Serialize)]
pub(crate) struct KdfInfo {
    algorithm: &'static str,
    memory_kib: u32,
    iterations: u32,
    lanes: u8,
}

pub fn encode(
    input: &str,
    output: &str,
    stego_type: &str,
    bits: u8,
    format: &str,
    options: &GenericEncodeOptions,
) -> anyhow::Result<()> {
    if format == "json" {
        crate::envelope::activate_json_mode("encode");
    }
    validate_format(format)?;
    validate_kernel(stego_type)?;
    let audio = is_audio_kernel(stego_type);
    // PKT-007: resolve the password path up front, before any media work,
    // so conflicting credentials fail fast.
    let password_bytes = resolve_password(&options.password, &options.password_file)?;
    if password_bytes.is_some()
        && (options.encryption_key.is_some() || options.encryption_key_file.is_some())
    {
        anyhow::bail!(
            "--password/--password-file and --encryption-key/--encryption-key-file are mutually exclusive"
        );
    }
    let (payload, payload_kind, default_filename) = match (
        options.payload_file.as_deref(),
        options.payload_text.as_deref(),
    ) {
        (Some(path), None) => (
            std::fs::read(path).with_context(|| format!("Cannot read payload file '{path}'"))?,
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
    let limits = options.decode_limits;
    let config = EmbeddingConfig::new(bits)?;
    let input_format = options
        .input_format
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));
    let mut media = media_io::read_input_with_dimensions(
        input,
        &input_format,
        stego_type,
        options.raw_width,
        options.raw_height,
    )?;
    validate_media_kernel(&media, stego_type)?;
    media_io::validate_media_output(output, &media, stego_type)?;

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

    // Apply opt-in transforms (sign, compress, password-KDF + AEAD encrypt,
    // chunked RS ECC). The password path (PKT-007) implies encryption.
    let signer = resolve_signing_key(options)?;
    let encrypt_key = if password_bytes.is_some() {
        None
    } else {
        resolve_encryption_key(options, format)?
    };
    let ecc_parity = if options.ecc { options.ecc_parity } else { 0 };
    if options.ecc && !(1..=steganographer_core::MAX_ECC_PARITY).contains(&ecc_parity) {
        anyhow::bail!(
            "--ecc-parity must be in 1..={}, got {}",
            steganographer_core::MAX_ECC_PARITY,
            ecc_parity
        );
    }
    let encrypted = encrypt_key.is_some() || password_bytes.is_some();
    let error_corrected = ecc_parity > 0;
    let context = TransformContext {
        packet_id: &packet.envelope.packet_id,
        payload_kind: packet.envelope.payload_kind as u16,
        original_len: packet.envelope.original_len,
    };
    let kdf_credentials =
        password_bytes
            .as_ref()
            .map(|password| transforms::PasswordKdfCredentials {
                password,
                params: Argon2Params::default(),
            });
    let (encoded_body, transforms, flags) = transforms::apply_with_password(
        &packet.body,
        &context,
        signer.as_ref(),
        options.compress,
        kdf_credentials.as_ref(),
        encrypt_key.as_ref(),
        ecc_parity,
        DEFAULT_ECC_CHUNK_LEN,
    )
    .context("transform application failed")?;
    let kdf = kdf_report(&transforms)?;
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

    let embed_report = if audio {
        match &embedding_key {
            Some(key) => KeyedAudioSpatialLsb::new(*key).embed_packet(
                &mut media.data,
                &packet_bytes,
                &config,
            )?,
            None => AudioSpatialLsb.embed_packet(&mut media.data, &packet_bytes, &config)?,
        }
    } else {
        match &embedding_key {
            Some(key) => {
                KeyedSpatialLsb::new(*key).embed_packet(&mut media.data, &packet_bytes, &config)?
            }
            None => SpatialLsb.embed_packet(&mut media.data, &packet_bytes, &config)?,
        }
    };
    media_io::write_output(output, &media, stego_type)?;
    if options.verify_write {
        verify_written_carrier(
            output,
            stego_type,
            audio,
            &config,
            embedding_key,
            &packet_bytes,
            &limits,
        )?;
    }

    let result = GenericEncodeResult {
        protocol: "1.0-alpha",
        packet_id: encode_hex(&packet_id),
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
        kdf,
    };
    print_encode_result(&result, format)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
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
    if format == "json" {
        crate::envelope::activate_json_mode("decode");
    }
    validate_format(format)?;
    preflight_payload_output(Path::new(input), Path::new(output), force)?;
    let RecoveredPacket {
        report,
        payload,
        kdf,
        signer_public_key,
        signer_trusted,
    } = recover_packet(input, stego_type, bits, input_format, options)?;

    let encrypted = report.packet.locator.flags & steganographer_core::packet::FLAG_ENCRYPTED != 0;
    let error_corrected =
        report.packet.locator.flags & steganographer_core::packet::FLAG_ERROR_CORRECTED != 0;
    let compressed =
        report.packet.locator.flags & steganographer_core::packet::FLAG_COMPRESSED != 0;
    let signed =
        report.packet.locator.flags & steganographer_core::packet::FLAG_PAYLOAD_SIGNED != 0;
    let keyed = report.packet.locator.flags & steganographer_core::packet::FLAG_KEYED_LOCATOR != 0;

    media_io::atomic_write(Path::new(output), &payload, force, false)?;
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
        packet_id: encode_hex(&report.packet.envelope.packet_id),
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
        signer_public_key,
        signer_trusted,
        keyed,
        mime_type: report.packet.envelope.mime_type,
        filename: report.packet.envelope.filename,
        ots: ots_info,
        kdf,
    };
    print_decode_result(&result, format)?;
    Ok(())
}

/// Extract through the same media, placement, transform, and trust path as decode.
pub fn run_extract(
    input: &Path,
    output: &Path,
    bits: Option<u8>,
    force: bool,
    format: &str,
    options: ExtractOptions,
) -> anyhow::Result<()> {
    if format == "json" {
        crate::envelope::activate_json_mode("extract");
    }
    validate_format(format)?;
    let output_str = output
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("output path is not valid UTF-8"))?;
    validate_extract_output_name(output_str)?;
    let input_str = input
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("input path is not valid UTF-8"))?;
    preflight_payload_output(input, output, force)?;
    let decode_options = GenericDecodeOptions {
        decrypt: options.encryption_key.is_some() || options.encryption_key_file.is_some(),
        decryption_key: options.encryption_key,
        decryption_key_file: options.encryption_key_file,
        embedding_key: options.embedding_key,
        embedding_key_file: options.embedding_key_file,
        password: options.password,
        password_file: options.password_file,
        decode_limits: options.decode_limits,
        trusted_signer: options.trusted_signer,
        revoked_list: options.revoked_list,
    };
    let bits = bits.map_or_else(|| "auto".to_owned(), |value| value.to_string());
    let recovered = recover_packet(
        input_str,
        &options.stego_type,
        &bits,
        options.input_format.as_deref(),
        &decode_options,
    )?;
    let digest = blake3::hash(&recovered.payload);
    let kind = payload_kind_name(recovered.report.packet.envelope.payload_kind);
    media_io::atomic_write(output, &recovered.payload, force, false)?;
    if format == "json" {
        crate::envelope::print(&crate::envelope::success(
            "extract",
            serde_json::json!({
                "payload_bytes": recovered.payload.len(),
                "payload_kind": kind,
                "output": output_str,
                "blake3_digest": digest.to_string(),
                "kdf": recovered.kdf,
                "signer_public_key": recovered.signer_public_key,
                "signer_trusted": recovered.signer_trusted,
            }),
        ));
    } else {
        println!(
            "Extracted payload: {} bytes (kind: {})",
            recovered.payload.len(),
            kind
        );
        println!("Saved to: {}", output_str);
        print_kdf_line(&recovered.kdf);
        print_signer_line(
            recovered.signer_public_key.as_deref(),
            recovered.signer_trusted,
        );
        println!("BLAKE3 digest: {}", digest);
    }
    Ok(())
}

fn preflight_payload_output(input: &Path, output: &Path, force: bool) -> anyhow::Result<()> {
    if input == output
        || matches!(
            (std::fs::canonicalize(input), std::fs::canonicalize(output)),
            (Ok(input), Ok(output)) if input == output
        )
    {
        anyhow::bail!("payload output must differ from the carrier input");
    }
    media_io::preflight_output(output, force)
}

struct RecoveredPacket {
    report: ExtractReport,
    payload: Vec<u8>,
    kdf: Option<KdfInfo>,
    signer_public_key: Option<String>,
    signer_trusted: bool,
}

fn recover_packet(
    input: &str,
    stego_type: &str,
    bits: &str,
    input_format: Option<&str>,
    options: &GenericDecodeOptions,
) -> anyhow::Result<RecoveredPacket> {
    validate_kernel(stego_type)?;
    let password = resolve_password(&options.password, &options.password_file)?;
    if password.is_some()
        && (options.decryption_key.is_some() || options.decryption_key_file.is_some())
    {
        anyhow::bail!(
            "--password/--password-file and --decryption-key/--decryption-key-file are mutually exclusive"
        );
    }
    let decrypt_key = resolve_decryption_key(options)?;
    let embedding_key = resolve_embedding_key(options)?;
    let trusted_signer = options
        .trusted_signer
        .as_deref()
        .map(decode_hex_array::<32>)
        .transpose()?;
    let revocations = crate::key_policy::load_revocations(options.revoked_list.as_deref())?;
    if trusted_signer
        .as_ref()
        .is_some_and(|key| revocations.is_revoked(key))
    {
        return Err(RevokedKey.into());
    }
    let candidates = bits_candidates(bits)?;
    let selected_format = input_format
        .map(str::to_owned)
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));
    let media = media_io::read_input(input, &selected_format, stego_type)?;
    validate_media_kernel(&media, stego_type)?;
    let audio = is_audio_kernel(stego_type);
    let mut extraction_error = None;
    let mut payload_error = None;
    for candidate in candidates {
        let config = EmbeddingConfig::new(candidate)?;
        // Supplying a key still permits a sequential packet, as in decode's
        // original behavior. Only genuine recognition failures mean absence.
        for keyed in [true, false] {
            let extraction = if keyed {
                let Some(key) = embedding_key else { continue };
                if audio {
                    KeyedAudioSpatialLsb::new(key).extract_packet(
                        &media.data,
                        &config,
                        &options.decode_limits,
                    )
                } else {
                    KeyedSpatialLsb::new(key).extract_packet(
                        &media.data,
                        &config,
                        &options.decode_limits,
                    )
                }
            } else if audio {
                AudioSpatialLsb.extract_packet(&media.data, &config, &options.decode_limits)
            } else {
                SpatialLsb.extract_packet(&media.data, &config, &options.decode_limits)
            };
            match extraction {
                Ok(report) => match reverse_packet(
                    report,
                    decrypt_key.as_ref(),
                    password.as_deref(),
                    trusted_signer.as_ref(),
                    &revocations,
                ) {
                    Ok(recovered) => return Ok(recovered),
                    Err(error) => {
                        // A fully parsed packet's authentication failure takes
                        // precedence over noise at other candidate strengths.
                        if payload_error.is_none() {
                            payload_error = Some(error);
                        }
                    }
                },
                Err(error) => {
                    let absent = matches!(error, CarrierError::NoPacket)
                        || (!keyed
                            && matches!(error, CarrierError::Packet(PacketError::InvalidMagic)))
                        || (!keyed
                            && matches!(
                                error,
                                CarrierError::InsufficientCapacity { needed_bits, .. }
                                    if needed_bits == steganographer_core::packet::LOCATOR_SIZE * 8
                            ));
                    if !absent && extraction_error.is_none() {
                        let message =
                            format!("corrupt generic packet candidate at {candidate} LSB(s)");
                        let resource_or_unsupported = matches!(
                            error,
                            CarrierError::Packet(
                                PacketError::LimitExceeded { .. }
                                    | PacketError::NestingDepthExceeded { .. }
                                    | PacketError::UnsupportedVersion { .. }
                                    | PacketError::UnknownCriticalField { .. }
                            )
                        );
                        let error = anyhow::Error::new(error);
                        extraction_error = Some(if resource_or_unsupported {
                            error.context(message)
                        } else {
                            error.context(crate::envelope::AuthenticationError(message))
                        });
                    }
                }
            }
        }
    }
    if let Some(error) = payload_error.or(extraction_error) {
        return Err(error);
    }
    Err(anyhow::Error::new(CarrierError::NoPacket)
        .context("no valid generic packet found with requested LSB strengths"))
}

fn reverse_packet(
    report: ExtractReport,
    decrypt_key: Option<&EncryptionKey>,
    password: Option<&[u8]>,
    trusted_signer: Option<&[u8; 32]>,
    revocations: &RevocationList,
) -> anyhow::Result<RecoveredPacket> {
    let context = TransformContext {
        packet_id: &report.packet.envelope.packet_id,
        payload_kind: report.packet.envelope.payload_kind as u16,
        original_len: report.packet.envelope.original_len,
    };
    let payload = transforms::reverse_with_password(
        &report.packet.body,
        &context,
        decrypt_key,
        password,
        &report.packet.envelope.transforms,
        report.packet.envelope.original_len,
    )?;
    if !report.packet.envelope.content_digest.verify(&payload) {
        return Err(transforms::TransformError::DigestMismatch.into());
    }
    // Core reversal has validated the descriptor layout and signature. Read
    // the public key from those actual params, never from a label or flag.
    let signer = report
        .packet
        .envelope
        .transforms
        .iter()
        .find(|transform| transform.algorithm == transforms::TRANSFORM_PAYLOAD_SIGN_ED25519);
    let signer_bytes = signer.map(|transform| {
        <&[u8; 32]>::try_from(&transform.parameters[..32])
            .expect("core reversal validated the signature descriptor")
    });
    if signer_bytes.is_some_and(|key| revocations.is_revoked(key)) {
        return Err(RevokedKey.into());
    }
    if let Some(expected) = trusted_signer {
        if signer_bytes != Some(expected) {
            return Err(
                anyhow::Error::new(transforms::TransformError::SignatureInvalid)
                    .context("packet is unsigned or does not match --trusted-signer"),
            );
        }
    }
    let signer_public_key = signer_bytes.map(|key| encode_hex(key));
    let signer_trusted = trusted_signer.is_some() && signer_public_key.is_some();
    let kdf = kdf_report(&report.packet.envelope.transforms)?;
    Ok(RecoveredPacket {
        report,
        payload,
        kdf,
        signer_public_key,
        signer_trusted,
    })
}

/// The final path component of an extract target must be a safe file name;
/// the caller supplies the directory.
fn validate_extract_output_name(output: &str) -> anyhow::Result<()> {
    let name = Path::new(output)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("output path has no safe file name component"))?;
    if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
        anyhow::bail!("output file name must be a safe file name without path components");
    }
    Ok(())
}

/// `--format` is a closed set: anything else is a usage error, never a
/// silent fallthrough to plain output. Shared by the packet and legacy
/// encode surfaces.
pub(crate) fn validate_format(format: &str) -> anyhow::Result<()> {
    match format {
        "plain" | "json" => Ok(()),
        other => anyhow::bail!("--format must be 'plain' or 'json', got '{other}'"),
    }
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

fn validate_kernel(stego_type: &str) -> anyhow::Result<()> {
    match stego_type {
        "lsb_video" | "lsb_audio" => Ok(()),
        other => anyhow::bail!(
            "generic packet alpha supports --stego-type lsb_video or lsb_audio, got '{other}'"
        ),
    }
}

fn is_audio_kernel(stego_type: &str) -> bool {
    stego_type == "lsb_audio"
}

fn validate_media_kernel(media: &media_io::MediaInput, stego_type: &str) -> anyhow::Result<()> {
    if media.is_audio() != is_audio_kernel(stego_type) {
        anyhow::bail!("--stego-type {stego_type} is incompatible with the input media");
    }
    Ok(())
}

/// Post-write verification (`FMT-005`): re-read the written carrier and confirm
/// the same extractor recovers byte-identical packet bytes. This catches any
/// writer that silently alters the carrier's LSBs.
fn verify_written_carrier(
    output: &str,
    stego_type: &str,
    audio: bool,
    config: &EmbeddingConfig,
    embedding_key: Option<[u8; 32]>,
    packet_bytes: &[u8],
    limits: &DecodeLimits,
) -> anyhow::Result<()> {
    let format = media_io::detect_format(output, stego_type);
    let media = media_io::read_input(output, &format, stego_type)?;
    let report = if audio {
        match embedding_key {
            Some(key) => {
                KeyedAudioSpatialLsb::new(key).extract_packet(&media.data, config, limits)?
            }
            None => AudioSpatialLsb.extract_packet(&media.data, config, limits)?,
        }
    } else {
        match embedding_key {
            Some(key) => KeyedSpatialLsb::new(key).extract_packet(&media.data, config, limits)?,
            None => SpatialLsb.extract_packet(&media.data, config, limits)?,
        }
    };
    let reencoded = report
        .packet
        .encode(limits)
        .context("post-write verification re-encode failed")?;
    if reencoded != packet_bytes {
        anyhow::bail!(
            "post-write verification failed: re-read packet ({} bytes) differs from embedded packet ({} bytes)",
            reencoded.len(),
            packet_bytes.len()
        );
    }
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
    crate::key_policy::load_signing_key(Path::new(path)).map(Some)
}

fn resolve_encryption_key(
    options: &GenericEncodeOptions,
    format: &str,
) -> anyhow::Result<Option<EncryptionKey>> {
    if !options.encrypt && options.encryption_key.is_none() && options.encryption_key_file.is_none()
    {
        return Ok(None);
    }
    let key = match (&options.encryption_key_file, &options.encryption_key) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--encryption-key and --encryption-key-file are mutually exclusive");
        }
        (Some(path), None) => {
            let hex_str = std::fs::read_to_string(path)?;
            EncryptionKey::from_hex(hex_str.trim())?
        }
        (None, Some(hex_str)) => EncryptionKey::from_hex(hex_str)?,
        (None, None) => {
            if format == "json" {
                anyhow::bail!(
                    "JSON encryption requires --encryption-key, --encryption-key-file, or a password; a generated secret would be lost"
                );
            }
            let key = EncryptionKey::generate();
            println!(
                "Generated random encryption key (hex, save it to decrypt later): {}",
                key.expose_hex()
            );
            key
        }
    };
    Ok(Some(key))
}

/// Resolve the password-path credentials shared by encode, decode, and
/// extract (PKT-007). `--password` and `--password-file` are mutually
/// exclusive; the file variant strips one trailing newline.
fn resolve_password(
    password: &Option<String>,
    password_file: &Option<String>,
) -> anyhow::Result<Option<Vec<u8>>> {
    match (password, password_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--password and --password-file are mutually exclusive")
        }
        (Some(password), None) => Ok(Some(password.as_bytes().to_vec())),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("Cannot read password file '{path}'"))?;
            Ok(Some(
                text.trim_end_matches(['\r', '\n']).as_bytes().to_vec(),
            ))
        }
        (None, None) => Ok(None),
    }
}

/// Extract the PKT-007 KDF descriptor report from a transform list, if any.
pub(crate) fn kdf_report(transforms: &[TransformDescriptor]) -> anyhow::Result<Option<KdfInfo>> {
    for transform in transforms {
        if transform.algorithm == TRANSFORM_KDF_ARGON2ID {
            let params = parse_kdf_argon2id_params(&transform.parameters)?;
            return Ok(Some(KdfInfo {
                algorithm: "argon2id",
                memory_kib: params.memory_kib,
                iterations: params.iterations,
                lanes: params.lanes,
            }));
        }
    }
    Ok(None)
}

/// Plain-text rendering shared by the encode/decode/extract reports.
fn print_kdf_line(kdf: &Option<KdfInfo>) {
    if let Some(kdf) = kdf {
        println!(
            "KDF: argon2id (m={}, t={}, p={})",
            kdf.memory_kib, kdf.iterations, kdf.lanes
        );
    }
}
fn resolve_decryption_key(options: &GenericDecodeOptions) -> anyhow::Result<Option<EncryptionKey>> {
    match (&options.decryption_key_file, &options.decryption_key) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--decryption-key and --decryption-key-file are mutually exclusive")
        }
        (Some(path), None) => {
            let key = std::fs::read_to_string(path)?;
            Ok(Some(EncryptionKey::from_hex(key.trim())?))
        }
        (None, Some(key)) => Ok(Some(EncryptionKey::from_hex(key)?)),
        (None, None)
            if options.decrypt && options.password.is_none() && options.password_file.is_none() =>
        {
            anyhow::bail!("--decrypt requires a decryption key or --password/--password-file")
        }
        (None, None) => Ok(None),
    }
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

fn print_encode_result(result: &GenericEncodeResult, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        crate::envelope::activate_json_mode("encode");
        crate::envelope::print(&crate::envelope::success(
            "encode",
            serde_json::to_value(result)?,
        ));
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
        print_kdf_line(&result.kdf);
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
        crate::envelope::activate_json_mode("decode");
        crate::envelope::print(&crate::envelope::success(
            "decode",
            serde_json::to_value(result)?,
        ));
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
        print_kdf_line(&result.kdf);
        print_signer_line(result.signer_public_key.as_deref(), result.signer_trusted);
        println!(
            "Placement: {}",
            if result.keyed { "keyed" } else { "sequential" }
        );
        println!("Decoded payload: {}", result.output);
    }
    Ok(())
}

fn print_signer_line(public_key: Option<&str>, trusted: bool) {
    if let Some(public_key) = public_key {
        println!(
            "Signer: {} ({})",
            public_key,
            if trusted {
                "trusted identity"
            } else {
                "signature valid; identity not pinned"
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    /// A small mono S16 PCM WAV carrier: 4096 samples × 1 LSB ≈ 512 bytes of
    /// packet capacity, comfortably above the password packet size.
    fn wav_carrier(path: &Path) {
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 8000,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut writer = hound::WavWriter::create(path, spec).unwrap();
        for i in 0..4096u32 {
            writer.write_sample(((i % 97) as i16) - 48).unwrap();
        }
        writer.finalize().unwrap();
    }

    fn encode_options(password: Option<String>) -> GenericEncodeOptions {
        GenericEncodeOptions {
            payload_file: None,
            payload_text: Some("secret packet payload".to_string()),
            mime_type: None,
            filename: None,
            input_format: None,
            raw_width: None,
            raw_height: None,
            decode_limits: DecodeLimits::default(),
            encrypt: false,
            encryption_key: None,
            encryption_key_file: None,
            ecc: false,
            ecc_parity: 0,
            compress: false,
            signing_key: None,
            embedding_key: None,
            embedding_key_file: None,
            verify_write: false,
            password,
            password_file: None,
        }
    }

    fn decode_options(password: Option<String>) -> GenericDecodeOptions {
        GenericDecodeOptions {
            decrypt: false,
            decryption_key: None,
            decryption_key_file: None,
            embedding_key: None,
            embedding_key_file: None,
            password,
            password_file: None,
            decode_limits: DecodeLimits::default(),
            trusted_signer: None,
            revoked_list: None,
        }
    }

    #[test]
    fn password_encode_decode_roundtrip() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("carrier.wav");
        let stego = dir.path().join("stego.wav");
        let payload_out = dir.path().join("payload.bin");
        wav_carrier(&input);

        encode(
            input.to_str().unwrap(),
            stego.to_str().unwrap(),
            "lsb_audio",
            1,
            "plain",
            &encode_options(Some("correct horse battery staple".to_string())),
        )
        .unwrap();
        decode(
            stego.to_str().unwrap(),
            payload_out.to_str().unwrap(),
            "lsb_audio",
            "1",
            "plain",
            None,
            true,
            &decode_options(Some("correct horse battery staple".to_string())),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&payload_out).unwrap(),
            b"secret packet payload"
        );
    }

    #[test]
    fn wrong_password_decode_fails_closed() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("carrier.wav");
        let stego = dir.path().join("stego.wav");
        let payload_out = dir.path().join("payload.bin");
        wav_carrier(&input);
        encode(
            input.to_str().unwrap(),
            stego.to_str().unwrap(),
            "lsb_audio",
            1,
            "plain",
            &encode_options(Some("correct horse battery staple".to_string())),
        )
        .unwrap();
        let error = decode(
            stego.to_str().unwrap(),
            payload_out.to_str().unwrap(),
            "lsb_audio",
            "1",
            "plain",
            None,
            true,
            &decode_options(Some("incorrect horse battery staple".to_string())),
        )
        .unwrap_err();
        assert!(error.to_string().contains("decryption failed"));
        assert!(!payload_out.exists());
    }

    #[test]
    fn password_and_encryption_key_are_mutually_exclusive() {
        let mut options = encode_options(Some("pw".to_string()));
        options.encryption_key = Some("00".repeat(32));
        let error =
            encode("/dev/null", "/dev/null2", "lsb_audio", 1, "plain", &options).unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn supplied_raw_key_implies_encryption() {
        let mut options = encode_options(None);
        options.encryption_key = Some("01".repeat(32));
        assert!(!options.encrypt);
        assert!(resolve_encryption_key(&options, "json").unwrap().is_some());
        options.encryption_key_file = Some("unused.key".to_string());
        assert!(resolve_encryption_key(&options, "json").is_err());
    }

    #[test]
    fn decrypt_accepts_password_sources_without_raw_key() {
        let mut options = decode_options(Some("password".to_string()));
        options.decrypt = true;
        assert!(resolve_decryption_key(&options).unwrap().is_none());
        options.password = None;
        options.password_file = Some("password.txt".to_string());
        assert!(resolve_decryption_key(&options).unwrap().is_none());
        options.password_file = None;
        assert!(resolve_decryption_key(&options).is_err());
    }

    #[test]
    fn json_rejects_discarding_generated_encryption_key() {
        let mut options = encode_options(None);
        options.encrypt = true;
        assert!(resolve_encryption_key(&options, "json").is_err());
    }

    #[test]
    fn password_file_resolution_strips_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pw.txt");
        std::fs::write(&path, b"carrier password\n").unwrap();
        let resolved = resolve_password(&None, &Some(path.to_str().unwrap().to_string())).unwrap();
        assert_eq!(resolved, Some(b"carrier password".to_vec()));
        assert!(resolve_password(&Some("a".into()), &Some("b".into())).is_err());
    }
}
