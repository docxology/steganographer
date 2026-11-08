//! `steganographer verify` subcommand — signature verification.
//!
//! Supports all stego types, payload encryption, error correction,
//! multi-frame spreading, and configurable hash algorithms.

use anyhow::Context;
use serde::Serialize;
use steganographer_core::crypto::{
    decode_hex_array, encode_hex, HashAlgorithm, SignaturePayload, Verifier,
};
use steganographer_core::dct_video::DctVideo;
use steganographer_core::encryption;
use steganographer_core::error_correction;
use steganographer_core::revocation::RevocationList;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

use crate::media_io;
use steganographer_core::carrier_binding;

// ─── Options & Results ──────────────────────────────────────────────

/// Options controlling the verify process.
#[derive(Clone)]
pub struct VerifyOptions {
    pub bits: VerifyBits,
    pub frame_index: u64,
    pub decrypt: bool,
    pub decryption_key: Option<String>,
    pub decryption_key_file: Option<String>,
    pub embedding_key_file: Option<String>,
    pub ecc: bool,
    pub ecc_parity: usize,
    pub spread: u32,
    pub hash_algorithm: Option<String>,
    pub input_format: Option<String>,
    pub raw_width: Option<u32>,
    pub raw_height: Option<u32>,
    /// Additional revoked identities as JSON hex keys. An omitted, absent
    /// `keys/revoked.json` is optional; known compromise policy always applies.
    pub revoked_list: Option<String>,
}

/// LSB extraction strength selected by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyBits {
    Auto,
    Exact(u8),
}

impl VerifyBits {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        if value.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let bits: u8 = value
            .parse()
            .map_err(|_| anyhow::anyhow!("--bits must be 'auto' or an integer from 1 to 4"))?;
        if !(1..=4).contains(&bits) {
            anyhow::bail!("--bits must be 'auto' or an integer from 1 to 4");
        }
        Ok(Self::Exact(bits))
    }

    fn candidates(self) -> &'static [u8] {
        const AUTO: &[u8] = &[1, 2, 3, 4];
        const ONE: &[u8] = &[1];
        const TWO: &[u8] = &[2];
        const THREE: &[u8] = &[3];
        const FOUR: &[u8] = &[4];
        match self {
            Self::Auto => AUTO,
            Self::Exact(1) => ONE,
            Self::Exact(2) => TWO,
            Self::Exact(3) => THREE,
            Self::Exact(4) => FOUR,
            Self::Exact(_) => unreachable!("VerifyBits::Exact is validated at construction"),
        }
    }
}

/// Stego types `verify` supports. Anything else is a usage error (exit 1)
/// rather than a silent `no_signature` result.
pub const VALID_STEGO_TYPES: &[&str] = &[
    "lsb_video",
    "lsb_audio",
    "spread_spectrum_video",
    "dct_video",
];

/// Reject unknown `--stego-type` values with a usage-class error.
pub fn validate_stego_type(value: &str) -> anyhow::Result<()> {
    if VALID_STEGO_TYPES.contains(&value) {
        Ok(())
    } else {
        anyhow::bail!(
            "unknown stego type '{}': expected one of {}",
            value,
            VALID_STEGO_TYPES.join(", ")
        )
    }
}

/// Strict hash-algorithm parsing: the accepted set mirrors
/// [`HashAlgorithm::parse`], but unknown names error out instead of
/// silently falling back to BLAKE3.
pub fn parse_hash_algorithm_strict(value: &str) -> anyhow::Result<HashAlgorithm> {
    match value.to_ascii_lowercase().as_str() {
        "blake3" => Ok(HashAlgorithm::Blake3),
        "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
        "sha3" | "sha-3" | "sha3-256" => Ok(HashAlgorithm::Sha3_256),
        _ => anyhow::bail!(
            "unsupported hash algorithm '{}': expected blake3, sha256, or sha3-256",
            value
        ),
    }
}

/// Machine-readable verification result (serializable to JSON).
#[derive(Debug, Serialize)]
pub struct VerifyResult {
    pub found: bool,
    pub stego_type: String,
    pub frame_index: Option<u64>,
    pub hash: Option<String>,
    pub signature_preview: Option<String>,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lsb_bits: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_corrected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    /// OpenTimestamps proof check; present only when OTS is configured in
    /// the config file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ots: Option<OtsInfo>,
}

/// OpenTimestamps proof check folded into the verify result. JSON v1: the
/// `verify --format json` document is emitted exactly once, with OTS info
/// inline instead of as a second JSON document on stdout.
#[derive(Debug, Serialize)]
pub struct OtsInfo {
    pub verified: bool,
    pub pending: bool,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    pub details: String,
}

// ─── Public entry points ────────────────────────────────────────────

/// Authenticate bytes decoded from the actual published carrier, without reporting
/// a second command result or applying local signer-revocation policy.
pub(crate) fn authenticate_written_output(
    input: &str,
    stego_type: &str,
    embedding_key: Option<&[u8; 32]>,
    opts: &VerifyOptions,
    hash_algo: HashAlgorithm,
    public_key: &str,
) -> anyhow::Result<()> {
    use steganographer_core::multi_frame::{reconstruct_payload_bytes, GenericPayloadShard};
    let bits = match opts.bits {
        VerifyBits::Exact(bits) => bits,
        VerifyBits::Auto => {
            anyhow::bail!("Post-write authentication requires exact embedding bits")
        }
    };
    let input_format = opts
        .input_format
        .clone()
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));
    let first_path = if opts.spread > 1 {
        format!("{}_001", input)
    } else {
        input.to_owned()
    };
    let first = media_io::read_input_with_dimensions(
        &first_path,
        &input_format,
        stego_type,
        opts.raw_width,
        opts.raw_height,
    )?;
    let bytes = if opts.spread > 1 {
        let total = u8::try_from(opts.spread)?;
        let mut shards = Vec::with_capacity(usize::from(total));
        let first_bytes = extract_raw_lsb_video(&first.data, bits)?
            .ok_or(steganographer_core::transforms::TransformError::SignatureInvalid)?;
        shards.push(GenericPayloadShard {
            frame_index: 0,
            shard_index: 0,
            total_shards: total,
            data: first_bytes,
        });
        for index in 1..total {
            let path = format!("{}_{:03}", input, index + 1);
            let media = media_io::read_input_with_dimensions(
                &path,
                &input_format,
                stego_type,
                opts.raw_width,
                opts.raw_height,
            )?;
            if media.width != first.width || media.height != first.height {
                anyhow::bail!("Published spread shard descriptors do not match");
            }
            let data = extract_raw_lsb_video(&media.data, bits)?
                .ok_or(steganographer_core::transforms::TransformError::SignatureInvalid)?;
            shards.push(GenericPayloadShard {
                frame_index: u64::from(index),
                shard_index: index,
                total_shards: total,
                data,
            });
        }
        reconstruct_payload_bytes(&shards)?
    } else {
        extract_payload(
            &first.data,
            first.width,
            first.height,
            stego_type,
            embedding_key,
            opts,
            &hash_algo,
            Some(public_key),
        )?
        .ok_or(steganographer_core::transforms::TransformError::SignatureInvalid)?
        .bytes
    };
    if !verify_extracted_bits(
        &first.data,
        &bytes,
        bits,
        first.width,
        first.height,
        bytes.len(),
        opts,
        &hash_algo,
        Some(public_key),
        stego_type,
    ) {
        return Err(steganographer_core::transforms::TransformError::SignatureInvalid.into());
    }
    Ok(())
}

/// Run verification with full options.
pub fn run_with_key(
    config_path: &str,
    input: &str,
    public_key_hex: Option<&str>,
    stego_type: &str,
    format: &str,
    embedding_key_hex: Option<&str>,
    opts: &VerifyOptions,
) -> anyhow::Result<String> {
    if format == "json" {
        crate::envelope::activate_json_mode("verify");
    }
    validate_stego_type(stego_type)?;
    crate::cmd_packet::validate_format(format)?;
    log::info!("Verifying: {}", input);
    log::info!("Stego type: {}", stego_type);
    log::info!(
        "Decrypt: {}, ECC: {}, Spread: {}",
        opts.decrypt,
        opts.ecc,
        opts.spread
    );

    let cfg = steganographer_core::config::Config::load_optional(config_path)?;

    let configured_payload = cfg
        .video
        .as_ref()
        .and_then(|video| video.pipeline.as_ref())
        .and_then(|pipeline| pipeline.payload.as_ref());
    let mut effective_opts = opts.clone();
    effective_opts.decrypt |=
        effective_opts.decryption_key.is_some() || effective_opts.decryption_key_file.is_some();
    if let Some(payload) = configured_payload {
        effective_opts.decrypt |= payload.encrypt_enabled();
        effective_opts.ecc |= payload
            .error_correction
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("reed_solomon"));
        if effective_opts.decryption_key_file.is_none() && effective_opts.decryption_key.is_none() {
            effective_opts.decryption_key_file = payload.encryption_key_file.clone();
            effective_opts.decryption_key = payload.encryption_key.clone();
        }
    }
    let opts = &effective_opts;
    if !matches!(stego_type, "lsb_audio" | "spread_spectrum_video")
        && (embedding_key_hex.is_some() || opts.embedding_key_file.is_some())
    {
        anyhow::bail!(
            "Legacy embedding keys are supported only for lsb_audio and spread_spectrum_video"
        );
    }
    if !matches!(stego_type, "lsb_video" | "lsb_audio")
        && matches!(opts.bits, VerifyBits::Exact(bits) if bits != 1)
    {
        anyhow::bail!("--bits applies only to LSB kernels");
    }
    if !(1..=8).contains(&opts.spread) {
        anyhow::bail!("--spread must be 1 (disabled) or 2-8");
    }
    if opts.spread > 1 && stego_type != "lsb_video" {
        anyhow::bail!("Legacy --spread supports only lsb_video");
    }
    if stego_type == "dct_video" && (opts.decrypt || opts.ecc) {
        anyhow::bail!(
            "dct_video supports only direct signed payloads; decryption and ECC are unsupported"
        );
    }
    if let Some(key) = public_key_hex {
        let bytes = parse_key_32(key, "Public key")?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
    }
    if opts.decrypt {
        resolve_decryption_key(opts)?;
    }
    let revocations = crate::key_policy::load_revocations(opts.revoked_list.as_deref())?;
    if opts.ecc && !(1..=16).contains(&opts.ecc_parity) {
        anyhow::bail!(
            "--ecc-parity must be in the range 1-16 when ECC is enabled, got {}",
            opts.ecc_parity
        );
    }
    let hash_algo = match opts
        .hash_algorithm
        .as_deref()
        .or(cfg.global.hash_algorithm.as_deref())
    {
        Some(value) => parse_hash_algorithm_strict(value)?,
        None => HashAlgorithm::Blake3,
    };

    let input_format = opts
        .input_format
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));

    // Spread groups have no unsuffixed file: bind the first actual shard.
    let first_input = if opts.spread > 1 {
        format!("{}_001", input)
    } else {
        input.to_string()
    };
    let media = media_io::read_input_with_dimensions(
        &first_input,
        &input_format,
        stego_type,
        opts.raw_width,
        opts.raw_height,
    )?;
    let data = &media.data;
    let (width, height) = (media.width, media.height);
    if media.is_audio() != (stego_type == "lsb_audio") {
        anyhow::bail!("Selected stego type is incompatible with the input media");
    }
    log::info!("Read {} decoded bytes from {}", data.len(), input);

    let embedding_key = resolve_embedding_key(embedding_key_hex, opts, &cfg, stego_type)?;

    // Multi-frame: read all files and reconstruct
    if opts.spread > 1 {
        return verify_multi_frame(
            input,
            data,
            width,
            height,
            public_key_hex,
            stego_type,
            format,
            opts,
            &hash_algo,
            &cfg,
            &revocations,
        );
    }

    // Extract raw payload bytes from the media
    let extracted = extract_payload(
        data,
        width,
        height,
        stego_type,
        embedding_key.as_ref(),
        opts,
        &hash_algo,
        public_key_hex,
    )?;
    let (raw_data, detected_bits) = match extracted {
        Some(extracted) => (extracted.bytes, extracted.lsb_bits),
        None => {
            let result = VerifyResult {
                found: false,
                stego_type: stego_type.to_string(),
                frame_index: None,
                hash: None,
                signature_preview: None,
                status: "no_signature".to_string(),
                message: "No steganographic signature found in the file".to_string(),
                lsb_bits: None,
                encrypted: None,
                ecc_corrected: None,
                hash_algorithm: Some(hash_algo.name().to_string()),
                ots: None,
            };
            print_result(&result, format)?;
            return Ok("no_signature".to_string());
        }
    };

    let payload = decode_signature_payload(&raw_data, opts)?;
    finish_verification(
        payload,
        data,
        width,
        height,
        public_key_hex,
        stego_type,
        format,
        opts.decrypt,
        opts.ecc,
        detected_bits,
        raw_data.len(),
        &hash_algo,
        &cfg,
        &revocations,
    )
}

// ─── Verification finalization ──────────────────────────────────────

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
fn finish_verification(
    payload: SignaturePayload,
    data: &[u8],
    width: u32,
    height: u32,
    public_key_hex: Option<&str>,
    stego_type: &str,
    format: &str,
    was_encrypted: bool,
    was_ecc: bool,
    lsb_bits: Option<u8>,
    embedded_payload_len: usize,
    hash_algo: &HashAlgorithm,
    cfg: &steganographer_core::config::Config,
    revocations: &RevocationList,
) -> anyhow::Result<String> {
    let hash_hex = encode_hex(&payload.hash);
    let sig_preview = encode_hex(&payload.signature.to_bytes()[..16]);

    // Compute the canonical carrier bytes once — used for both signature
    // verification and the optional OTS proof check.
    let canonical = carrier_binding::canonicalize(
        data,
        stego_type,
        lsb_bits.unwrap_or(1),
        width,
        height,
        embedded_payload_len,
    )?;

    let (status, message) = if let Some(pk_hex) = public_key_hex {
        let pk_arr = parse_key_32(pk_hex, "Public key")?;
        let verifier = Verifier::with_hash_algorithm(
            ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)?,
            *hash_algo,
        );
        let is_valid = verifier.verify(&payload, &canonical, None);
        if is_valid {
            log::info!("Signature verification: VALID");
            // A valid signature from a revoked identity is a policy failure.
            if revocations.is_revoked(&pk_arr) {
                log::warn!("Signature is valid but the signing identity is revoked");
                (
                    "valid_revoked".to_string(),
                    "Signature is valid but the signing identity is REVOKED".to_string(),
                )
            } else {
                ("valid".to_string(), "Signature is valid".to_string())
            }
        } else {
            log::warn!("Signature verification: INVALID");
            ("invalid".to_string(), "Signature is INVALID".to_string())
        }
    } else {
        (
            "not_verified".to_string(),
            "No public key provided — signature not verified".to_string(),
        )
    };

    let mut result = VerifyResult {
        found: true,
        stego_type: stego_type.to_string(),
        frame_index: Some(payload.frame_index),
        hash: Some(hash_hex),
        signature_preview: Some(sig_preview),
        status,
        message,
        lsb_bits,
        encrypted: Some(was_encrypted),
        ecc_corrected: Some(was_ecc),
        hash_algorithm: Some(hash_algo.name().to_string()),
        ots: None,
    };

    // ─── Optional OpenTimestamps post-signature verification ──────────
    // If OTS is enabled in the config, attempt to find and verify a proof
    // for the SHA-256 of the signed carrier data. This is best-effort: if
    // no proof exists or the OTS server is unreachable, the signature
    // verification result above is not affected. The info is folded into
    // the single verify JSON document (or the plain-text block) instead of
    // being printed as a second JSON document.
    if cfg.ots_enabled() {
        let ots_cfg = cfg.ots_config();
        let client = steganographer_core::OTSClient::from_config(&ots_cfg)?;
        let digest = steganographer_core::OTSClient::compute_sha256_digest(&canonical);
        let digest_hex = encode_hex(&digest);
        let proof_path = client.proof_path_for(&digest_hex)?;
        if proof_path.exists() {
            log::info!("Found OTS proof at {}", proof_path.display());
            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(steganographer_core::OTSClient::load_proof(&proof_path)) {
                Ok(proof) => {
                    result.ots = match rt.block_on(client.verify(&proof, &digest)) {
                        Ok(vr) => Some(OtsInfo {
                            verified: vr.verified,
                            pending: vr.pending,
                            method: vr.method,
                            timestamp: vr.timestamp,
                            details: vr.details,
                        }),
                        Err(e) => {
                            log::warn!("OTS verify failed: {}", e);
                            Some(OtsInfo {
                                verified: false,
                                pending: false,
                                method: client.method().as_str().to_string(),
                                timestamp: None,
                                details: format!("verification failed: {e}"),
                            })
                        }
                    };
                }
                Err(e) => {
                    log::warn!("OTS proof load failed: {}", e);
                }
            }
        } else {
            log::debug!("No OTS proof found for digest {}", digest_hex);
        }
    }

    print_result(&result, format)?;
    Ok(result.status)
}

// ─── Extraction ─────────────────────────────────────────────────────

struct ExtractedPayload {
    bytes: Vec<u8>,
    lsb_bits: Option<u8>,
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
/// Extract raw payload bytes from media.
///
/// Auto mode selects only candidates passing ECC, requested AEAD decryption,
/// strict payload parsing, and signature verification when a public key is supplied.
fn extract_payload(
    data: &[u8],
    width: u32,
    height: u32,
    stego_type: &str,
    embedding_key: Option<&[u8; 32]>,
    opts: &VerifyOptions,
    hash_algo: &HashAlgorithm,
    public_key_hex: Option<&str>,
) -> anyhow::Result<Option<ExtractedPayload>> {
    match stego_type {
        "lsb_video" => {
            let mut fallback = None;
            let mut verified: Option<ExtractedPayload> = None;
            let mut parsed_candidates = 0usize;
            let mut saw_candidate = false;
            for &bits in opts.bits.candidates() {
                if let Some(bytes) = extract_raw_lsb_video(data, bits)? {
                    saw_candidate = true;
                    let extracted = ExtractedPayload {
                        bytes,
                        lsb_bits: Some(bits),
                    };
                    if opts.bits != VerifyBits::Auto {
                        return Ok(Some(extracted));
                    }
                    // Prefer the candidate whose signature actually validates
                    // against the public key, since only the bits value used at
                    // encode time canonicalizes to the signed carrier.
                    if verify_extracted_bits(
                        data,
                        &extracted.bytes,
                        bits,
                        width,
                        height,
                        extracted.bytes.len(),
                        opts,
                        hash_algo,
                        public_key_hex,
                        "lsb_video",
                    ) {
                        verified = Some(extracted);
                        break;
                    }
                    if decode_signature_payload(&extracted.bytes, opts).is_ok() {
                        parsed_candidates += 1;
                        fallback.get_or_insert(extracted);
                    }
                }
            }
            select_candidate(verified, fallback, parsed_candidates, saw_candidate)
        }
        "lsb_audio" => {
            let key = embedding_key.ok_or_else(|| {
                anyhow::anyhow!(
                    "Audio verification requires an embedding key from --embedding-key, \
                         --embedding-key-file, or configuration"
                )
            })?;
            let (pcm_chunks, _remainder) = data.as_chunks::<2>();
            let samples: Vec<i16> = pcm_chunks.iter().map(|c| i16::from_le_bytes(*c)).collect();
            let mut fallback = None;
            let mut verified: Option<ExtractedPayload> = None;
            let mut parsed_candidates = 0usize;
            let mut saw_candidate = false;
            for &bits in opts.bits.candidates() {
                if let Some(bytes) = extract_raw_lsb_audio(&samples, bits, key, opts.frame_index)? {
                    saw_candidate = true;
                    let extracted = ExtractedPayload {
                        bytes,
                        lsb_bits: Some(bits),
                    };
                    if opts.bits != VerifyBits::Auto {
                        return Ok(Some(extracted));
                    }
                    if verify_extracted_bits(
                        data,
                        &extracted.bytes,
                        bits,
                        width,
                        height,
                        extracted.bytes.len(),
                        opts,
                        hash_algo,
                        public_key_hex,
                        "lsb_audio",
                    ) {
                        verified = Some(extracted);
                        break;
                    }
                    if decode_signature_payload(&extracted.bytes, opts).is_ok() {
                        parsed_candidates += 1;
                        fallback.get_or_insert(extracted);
                    }
                }
            }
            select_candidate(verified, fallback, parsed_candidates, saw_candidate)
        }
        "spread_spectrum_video" => {
            let key = embedding_key.ok_or_else(|| {
                anyhow::anyhow!(
                    "Spread-spectrum verification requires an embedding key from \
                     --embedding-key, --embedding-key-file, or configuration"
                )
            })?;
            Ok(
                extract_raw_ss_video(data, key)?.map(|bytes| ExtractedPayload {
                    bytes,
                    lsb_bits: None,
                }),
            )
        }
        "dct_video" => {
            let mut owned = data.to_vec();
            let frame = VideoFrame {
                width,
                height,
                stride: width
                    .checked_mul(3)
                    .ok_or_else(|| anyhow::anyhow!("Image stride overflow"))?,
                format: VideoFormat::Rgb8,
                data: &mut owned,
                frame_index: 0,
            };
            let dct = DctVideo::default();
            Ok(dct.extract(&frame)?.map(|payload| ExtractedPayload {
                bytes: payload.to_bytes().to_vec(),
                lsb_bits: None,
            }))
        }
        _ => Ok(None),
    }
}

fn select_candidate(
    verified: Option<ExtractedPayload>,
    fallback: Option<ExtractedPayload>,
    parsed_candidates: usize,
    saw_candidate: bool,
) -> anyhow::Result<Option<ExtractedPayload>> {
    if verified.is_some() {
        return Ok(verified);
    }
    // Only a unique, fully parsed failure candidate can be reported. Random
    // magic matches and ambiguous parses are never promoted to payload evidence.
    if parsed_candidates > 1 || (saw_candidate && fallback.is_none()) {
        return Err(steganographer_core::transforms::TransformError::SignatureInvalid.into());
    }
    Ok(fallback)
}

fn parse_key_32(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    decode_hex_array(value).with_context(|| format!("Invalid {label}"))
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
/// Perform the *full* signature verification for a candidate extraction, using
/// `bits` as the LSB strength for carrier canonicalization.
///
/// The public key, when present, lets us disambiguate which LSB strength was
/// actually used at encode time: only the correct `bits` canonicalizes the
/// carrier to the bytes that were signed, so `verifier.verify` succeeds for
/// exactly one candidate. Auto-mode extraction relies on this to report the
/// right `lsb_bits` instead of the first strength that merely yielded a
/// magic-matching buffer.
fn verify_extracted_bits(
    data: &[u8],
    raw_data: &[u8],
    bits: u8,
    width: u32,
    height: u32,
    embedded_len: usize,
    opts: &VerifyOptions,
    hash_algo: &HashAlgorithm,
    public_key_hex: Option<&str>,
    stego_type: &str,
) -> bool {
    let payload = match decode_signature_payload(raw_data, opts) {
        Ok(payload) => payload,
        Err(_) => return false,
    };
    let canonical =
        match carrier_binding::canonicalize(data, stego_type, bits, width, height, embedded_len) {
            Ok(c) => c,
            Err(_) => return false,
        };
    match public_key_hex {
        Some(pk_hex) => {
            let pk_arr = match decode_hex_array::<32>(pk_hex) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            let verifier = match ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) {
                Ok(k) => Verifier::with_hash_algorithm(k, *hash_algo),
                Err(_) => return false,
            };
            verifier.verify(&payload, &canonical, None)
        }
        None => true,
    }
}

fn decode_signature_payload(
    raw_data: &[u8],
    opts: &VerifyOptions,
) -> anyhow::Result<SignaturePayload> {
    use steganographer_core::transforms::TransformError;
    let corrected = apply_ecc_transform(raw_data, opts)
        .map_err(|error| TransformError::ErrorCorrectionFailed(error.to_string()))?;
    let plaintext = if opts.decrypt {
        let key = resolve_decryption_key(opts)?;
        encryption::decrypt_legacy(&key, &corrected, None)
            .map_err(|error| TransformError::DecryptionFailed(error.to_string()))?
    } else {
        corrected
    };
    let bytes: &[u8; SignaturePayload::SERIALIZED_SIZE] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| TransformError::SignatureInvalid)?;
    SignaturePayload::from_bytes(bytes).map_err(|_| TransformError::SignatureInvalid.into())
}

fn apply_ecc_transform(raw_data: &[u8], opts: &VerifyOptions) -> anyhow::Result<Vec<u8>> {
    if !opts.ecc {
        return Ok(raw_data.to_vec());
    }
    if raw_data.len() <= opts.ecc_parity {
        anyhow::bail!(
            "ECC payload is too short: {} bytes with {} parity symbols",
            raw_data.len(),
            opts.ecc_parity
        );
    }
    let data_len = raw_data.len() - opts.ecc_parity;
    let decoded = error_correction::decode(raw_data, data_len, opts.ecc_parity)?;
    log::info!("RS decoded: {} -> {} bytes", raw_data.len(), decoded.len());
    Ok(decoded)
}

/// Extract raw bytes from video LSB (length-prefixed).
fn extract_raw_lsb_video(data: &[u8], bits: u8) -> anyhow::Result<Option<Vec<u8>>> {
    let min_bytes = 32usize.div_ceil(bits as usize);
    if data.len() < min_bytes {
        return Ok(None);
    }

    // Read all LSBs
    let all_bits: Vec<u8> = data
        .iter()
        .flat_map(|byte| (0..bits).rev().map(move |i| (byte >> i) & 1))
        .collect();
    if all_bits.len() < 32 {
        return Ok(None);
    }

    // Read 32-bit length prefix
    let mut len = 0u32;
    for &bit in &all_bits[..32] {
        len = (len << 1) | bit as u32;
    }
    if len == 0 || len > 800_000 || !len.is_multiple_of(8) {
        return Ok(None); // sanity check
    }
    let len = len / 8;

    let total_bits = 32 + len as usize * 8;
    if all_bits.len() < total_bits {
        return Ok(None);
    }

    // Reconstruct payload bytes
    let payload_bits = &all_bits[32..total_bits];
    let mut result = vec![0u8; len as usize];
    for (i, byte) in result.iter_mut().enumerate() {
        for j in 0..8 {
            *byte |= payload_bits[i * 8 + j] << (7 - j);
        }
    }
    Ok(Some(result))
}

/// Extract raw bytes from audio LSB (length-prefixed, keyed).
fn extract_raw_lsb_audio(
    samples: &[i16],
    bits: u8,
    key: &[u8; 32],
    frame_index: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    if samples.len() < 32usize.div_ceil(bits as usize) {
        return Ok(None);
    }
    // Generate permutation
    let mut seed = [0u8; 32];
    let frame_bytes = frame_index.to_le_bytes();
    for (i, byte) in key.iter().enumerate() {
        seed[i] = byte ^ frame_bytes[i % 8];
    }
    let indices = steganographer_core::placement::KeyedPermutation::try_new(
        samples.len(),
        seed,
        b"legacy-audio-v4",
    )?;

    // Read 32 bits for length prefix
    let len_bits_needed = 32usize.div_ceil(bits as usize);
    if indices.len() < len_bits_needed {
        return Ok(None);
    }

    let mut all_bits = Vec::new();
    let mut bit_count = 0;
    for logical in 0..len_bits_needed {
        let idx = indices.permute(logical);
        if bit_count >= 32 {
            break;
        }
        for shift in (0..bits).rev() {
            if bit_count >= 32 {
                break;
            }
            all_bits.push(((samples[idx] >> shift) & 1) as u8);
            bit_count += 1;
        }
    }

    let mut len = 0u32;
    for &bit in &all_bits[..32] {
        len = (len << 1) | bit as u32;
    }
    if len == 0 || len > 800_000 || !len.is_multiple_of(8) {
        return Ok(None);
    }
    let len = len / 8;

    // Read full payload
    let total_bits = 32 + len as usize * 8;
    all_bits.clear();
    bit_count = 0;
    for logical in 0..total_bits.div_ceil(bits as usize).min(indices.len()) {
        let idx = indices.permute(logical);
        if bit_count >= total_bits {
            break;
        }
        for shift in (0..bits).rev() {
            if bit_count >= total_bits {
                break;
            }
            all_bits.push(((samples[idx] >> shift) & 1) as u8);
            bit_count += 1;
        }
    }

    if all_bits.len() < total_bits {
        return Ok(None);
    }

    let payload_bits = &all_bits[32..total_bits];
    let mut result = vec![0u8; len as usize];
    for (i, byte) in result.iter_mut().enumerate() {
        for j in 0..8 {
            *byte |= payload_bits[i * 8 + j] << (7 - j);
        }
    }
    Ok(Some(result))
}

/// Spread-spectrum spread factor (bytes per payload bit). Must match the
/// core default used by [`steganographer_core::spread_spectrum::SpreadSpectrumVideo::with_key`],
/// which is also the embed path's factor in `cmd_encode`.
const SS_SPREAD_FACTOR: usize = 64;

/// Extract raw bytes from spread-spectrum video.
///
/// Delegates per-bit extraction to the core host-canceling
/// differential-pair detector
/// ([`steganographer_core::spread_spectrum::SpreadSpectrumVideo::extract_bit`]),
/// constructed via `with_key` so the spread factor matches the embed path in
/// `cmd_encode` (the core default, 64 bytes per bit) by construction.
fn extract_raw_ss_video(data: &[u8], key: &[u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
    let ss = steganographer_core::spread_spectrum::SpreadSpectrumVideo::with_key(*key);
    let spread = SS_SPREAD_FACTOR;
    // Read 32-bit length prefix
    let mut len = 0u32;
    for bit_pos in 0..32 {
        let start = bit_pos * spread;
        if start + spread > data.len() {
            return Ok(None);
        }
        let bit = ss.extract_bit(data, start, bit_pos, 0)?;
        len = (len << 1) | bit as u32;
    }
    if len == 0 || len > 100_000 {
        return Ok(None);
    }

    let total_bits = 32 + len as usize * 8;
    let needed = total_bits * spread;
    if needed > data.len() {
        return Ok(None);
    }

    let mut result = vec![0u8; len as usize];
    for (byte_idx, slot) in result.iter_mut().enumerate() {
        for bit_in_byte in 0..8 {
            let payload_bit = 32 + byte_idx * 8 + bit_in_byte;
            let start = payload_bit * spread;
            let bit = ss.extract_bit(data, start, payload_bit, 0)?;
            *slot |= bit << bit_in_byte;
        }
    }
    Ok(Some(result))
}
// ─── Multi-frame verification ───────────────────────────────────────

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
fn verify_multi_frame(
    input: &str,
    data: &[u8],
    width: u32,
    height: u32,
    public_key_hex: Option<&str>,
    stego_type: &str,
    format: &str,
    opts: &VerifyOptions,
    hash_algo: &HashAlgorithm,
    cfg: &steganographer_core::config::Config,
    revocations: &RevocationList,
) -> anyhow::Result<String> {
    use steganographer_core::multi_frame::{reconstruct_payload_bytes, GenericPayloadShard};
    let n = u8::try_from(opts.spread)?;
    let input_format = opts
        .input_format
        .clone()
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));
    let mut media_shards = Vec::with_capacity(usize::from(n));
    for index in 0..n {
        let path = format!("{}_{:03}", input, index + 1);
        media_shards.push(media_io::read_input_with_dimensions(
            &path,
            &input_format,
            stego_type,
            opts.raw_width,
            opts.raw_height,
        )?);
    }
    let mut fallback = None;
    for &bits in opts.bits.candidates() {
        let mut shards = Vec::with_capacity(usize::from(n));
        for (index, media) in media_shards.iter().enumerate() {
            if media.width != width || media.height != height || media.is_audio() {
                anyhow::bail!("Spread shard media descriptors do not match");
            }
            match extract_raw_lsb_video(&media.data, bits)? {
                Some(bytes) => shards.push(GenericPayloadShard {
                    frame_index: index as u64,
                    shard_index: index as u8,
                    total_shards: n,
                    data: bytes,
                }),
                None => break,
            }
        }
        if shards.len() != usize::from(n) {
            continue;
        }
        let payload_bytes = match reconstruct_payload_bytes(&shards) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        if verify_extracted_bits(
            data,
            &payload_bytes,
            bits,
            width,
            height,
            payload_bytes.len(),
            opts,
            hash_algo,
            public_key_hex,
            stego_type,
        ) {
            let payload = decode_signature_payload(&payload_bytes, opts)?;
            return finish_verification(
                payload,
                data,
                width,
                height,
                public_key_hex,
                stego_type,
                format,
                opts.decrypt,
                opts.ecc,
                Some(bits),
                payload_bytes.len(),
                hash_algo,
                cfg,
                revocations,
            );
        }
        fallback.get_or_insert((payload_bytes, bits));
    }
    if let Some((bytes, bits)) = fallback {
        let payload = decode_signature_payload(&bytes, opts)?;
        return finish_verification(
            payload,
            data,
            width,
            height,
            public_key_hex,
            stego_type,
            format,
            opts.decrypt,
            opts.ecc,
            Some(bits),
            bytes.len(),
            hash_algo,
            cfg,
            revocations,
        );
    }
    Err(steganographer_core::transforms::TransformError::SignatureInvalid.into())
}

// ─── Key resolution ─────────────────────────────────────────────────

fn resolve_embedding_key(
    inline_key: Option<&str>,
    opts: &VerifyOptions,
    cfg: &steganographer_core::config::Config,
    stego_type: &str,
) -> anyhow::Result<Option<[u8; 32]>> {
    if let Some(path) = opts.embedding_key_file.as_deref() {
        let value = std::fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!("Cannot read embedding key file '{}': {}", path, error)
        })?;
        return parse_key_32(value.trim(), "Embedding key").map(Some);
    }
    if let Some(value) = inline_key {
        return parse_key_32(value, "Embedding key").map(Some);
    }

    let carrier_config = match stego_type {
        "lsb_audio" => cfg
            .audio
            .as_ref()
            .and_then(|audio| audio.stego.lsb_signature.as_ref()),
        "spread_spectrum_video" => cfg
            .video
            .as_ref()
            .and_then(|video| video.stego.lsb_signature.as_ref()),
        _ => None,
    };
    if let Some(path) = carrier_config.and_then(|config| config.key_file.as_deref()) {
        return steganographer_core::config::resolve_key(None, Some(path)).map(Some);
    }
    if let Some(path) = cfg.global.key_file.as_deref() {
        return steganographer_core::config::resolve_key(None, Some(path)).map(Some);
    }
    if let Some(value) = carrier_config.and_then(|config| config.key.as_deref()) {
        return parse_key_32(value, "Embedding key").map(Some);
    }
    Ok(None)
}

fn resolve_decryption_key(opts: &VerifyOptions) -> anyhow::Result<encryption::EncryptionKey> {
    if let Some(ref path) = opts.decryption_key_file {
        let hex_str = std::fs::read_to_string(path)?.trim().to_string();
        encryption::EncryptionKey::from_hex(&hex_str)
    } else if let Some(ref hex_str) = opts.decryption_key {
        encryption::EncryptionKey::from_hex(hex_str)
    } else {
        anyhow::bail!(
            "Decryption enabled but no key provided (--decryption-key or --decryption-key-file)"
        )
    }
}

// ─── Output ─────────────────────────────────────────────────────────

fn print_result(result: &VerifyResult, format: &str) -> anyhow::Result<()> {
    match format {
        "json" => {
            let value = serde_json::to_value(result)?;
            match result.status.as_str() {
                "invalid" | "valid_revoked" => {
                    crate::envelope::print(&crate::envelope::error_with_result(
                        "verify",
                        crate::envelope::VERIFICATION_FAILED,
                        &result.message,
                        Some(value),
                    ));
                }
                "no_signature" => {
                    crate::envelope::print(&crate::envelope::error_with_result(
                        "verify",
                        crate::envelope::PACKET_NOT_FOUND,
                        &result.message,
                        Some(value),
                    ));
                }
                _ => crate::envelope::print(&crate::envelope::success("verify", value)),
            }
        }
        _ => print_plain(result),
    }
    Ok(())
}

fn print_plain(result: &VerifyResult) {
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let green = if is_tty { "\x1b[32m" } else { "" };
    let red = if is_tty { "\x1b[31m" } else { "" };
    let yellow = if is_tty { "\x1b[33m" } else { "" };
    let cyan = if is_tty { "\x1b[36m" } else { "" };
    let bold = if is_tty { "\x1b[1m" } else { "" };
    let reset = if is_tty { "\x1b[0m" } else { "" };

    if result.found {
        let label = match result.stego_type.as_str() {
            "lsb_audio" => "=== Audio Signature Found ===",
            "spread_spectrum_video" => "=== Spread-Spectrum Signature Found ===",
            "dct_video" => "=== DCT Signature Found ===",
            _ => "=== Signature Found ===",
        };
        println!("{bold}{cyan}{}{reset}", label);
        if let Some(idx) = result.frame_index {
            println!("  Frame index: {}", idx);
        }
        if let Some(ref hash) = result.hash {
            println!("  Hash:        {}", hash);
        }
        if let Some(ref sig) = result.signature_preview {
            println!("  Signature:   {}...", sig);
        }
        if let Some(ref algo) = result.hash_algorithm {
            println!("  Hash algo:   {}", algo);
        }
        if let Some(bits) = result.lsb_bits {
            println!("  LSB bits:    {}", bits);
        }
        if result.encrypted == Some(true) {
            println!("  Encrypted:   yes (ChaCha20-Poly1305)");
        }
        if result.ecc_corrected == Some(true) {
            println!("  ECC:         Reed-Solomon applied");
        }
        match result.status.as_str() {
            "valid" => println!("  Status:      {green}{bold}\u{2713} VALID{reset}"),
            "invalid" => println!("  Status:      {red}{bold}\u{2717} INVALID{reset}"),
            "not_verified" => {
                println!(
                    "  Status:      {yellow}\u{26a0} No public key provided (signature not verified){reset}"
                );
                println!("  Tip:         Pass --public-key <hex> to verify the signature");
            }
            "extracted" => {
                println!(
                    "  Status:      {yellow}\u{26a0} Payload extracted but not verified{reset}"
                );
            }
            _ => {}
        }
        if let Some(ots) = &result.ots {
            let status_str = if ots.verified {
                "\u{2713} VERIFIED"
            } else {
                "\u{2717} NOT VERIFIED"
            };
            println!("  OTS:         {}", status_str);
            if let Some(ts) = ots.timestamp {
                println!("  OTS time:    {} (Unix)", ts);
            }
            if !ots.verified {
                println!("  OTS detail:  {}", ots.details);
            }
        }
    } else {
        println!("{yellow}{}{reset}", result.message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_verify_options() -> VerifyOptions {
        VerifyOptions {
            bits: VerifyBits::Auto,
            frame_index: 0,
            decrypt: false,
            decryption_key: None,
            decryption_key_file: None,
            embedding_key_file: None,
            ecc: false,
            ecc_parity: 4,
            spread: 1,
            hash_algorithm: None,
            input_format: None,
            raw_width: None,
            raw_height: None,
            revoked_list: None,
        }
    }

    #[test]
    fn encrypted_ecc_auto_bits_and_descriptor_spread_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        std::fs::write(&config, "[global]\n").unwrap();
        let input = directory.path().join("cover.png");
        image::RgbImage::from_pixel(64, 64, image::Rgb([128; 3]))
            .save(&input)
            .unwrap();
        let signer = steganographer_core::crypto::Signer::generate();
        let signing_key = directory.path().join("signing.key");
        std::fs::write(&signing_key, encode_hex(&signer.signing_key_bytes())).unwrap();
        let revoked = directory.path().join("revoked.json");
        std::fs::write(&revoked, "[]").unwrap();
        let public_key = encode_hex(&signer.verifying_key().to_bytes());
        let encryption_key = "ab".repeat(32);
        for spread in [1, 2] {
            let output = directory.path().join(format!("encoded-{spread}.png"));
            let options = crate::cmd_encode::EncodeOptions {
                encrypt: true,
                encryption_key: Some(encryption_key.clone()),
                encryption_key_file: None,
                embedding_key: None,
                embedding_key_file: None,
                ecc: true,
                ecc_parity: 4,
                spread,
                hash_algorithm: None,
                signing_key: Some(signing_key.to_str().unwrap().to_owned()),
                input_format: None,
                raw_width: None,
                raw_height: None,
                quiet_report: true,
            };
            crate::cmd_encode::run(
                config.to_str().unwrap(),
                input.to_str().unwrap(),
                output.to_str().unwrap(),
                "lsb_video",
                2,
                "json",
                &options,
            )
            .unwrap();
            let mut verify_options = plain_verify_options();
            verify_options.decrypt = true;
            verify_options.decryption_key = Some(encryption_key.clone());
            verify_options.ecc = true;
            verify_options.spread = spread;
            verify_options.revoked_list = Some(revoked.to_str().unwrap().to_owned());
            assert_eq!(
                run_with_key(
                    config.to_str().unwrap(),
                    output.to_str().unwrap(),
                    Some(&public_key),
                    "lsb_video",
                    "json",
                    None,
                    &verify_options
                )
                .unwrap(),
                "valid"
            );
        }
    }

    #[test]
    fn keyed_audio_extracts_core_recording_at_requested_frame_index() {
        use steganographer_core::{AudioBuffer, AudioStegoModule};
        let key = [7; 32];
        let mut samples = vec![128i16; 4096];
        let original: Vec<u8> = samples
            .iter()
            .flat_map(|sample| sample.to_le_bytes())
            .collect();
        let canonical = carrier_binding::canonicalize(
            &original,
            "lsb_audio",
            2,
            4096,
            1,
            SignaturePayload::SERIALIZED_SIZE,
        )
        .unwrap();
        let signer = steganographer_core::crypto::Signer::generate();
        let payload = signer.sign_frame(77, &canonical, None);
        let mut kernel = steganographer_core::lsb_audio::LsbAudio::try_new(2, key).unwrap();
        kernel
            .embed(
                &mut AudioBuffer {
                    samples: &mut samples,
                    channels: 1,
                    sample_rate: 44100,
                    frame_index: 77,
                },
                Some(&payload),
            )
            .unwrap();
        let data: Vec<u8> = samples
            .iter()
            .flat_map(|sample| sample.to_le_bytes())
            .collect();
        let extracted = extract_raw_lsb_audio(&samples, 2, &key, 77)
            .unwrap()
            .unwrap();
        let mut options = plain_verify_options();
        options.frame_index = 77;
        let public_key = encode_hex(&signer.verifying_key().to_bytes());
        assert!(verify_extracted_bits(
            &data,
            &extracted,
            2,
            4096,
            1,
            extracted.len(),
            &options,
            &HashAlgorithm::Blake3,
            Some(&public_key),
            "lsb_audio"
        ));
    }

    #[test]
    fn key_sets_preflight_and_malformed_revocations_preserve_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let prefix = directory.path().join("signer");
        std::fs::write(prefix.with_extension("pub"), "existing-public-key").unwrap();
        assert!(crate::cmd_encode::keygen(prefix.to_str().unwrap(), "plain").is_err());
        assert!(!prefix.with_extension("key").exists());
        assert_eq!(
            std::fs::read_to_string(prefix.with_extension("pub")).unwrap(),
            "existing-public-key"
        );
        let derived = directory.path().join("derived");
        std::fs::create_dir(&derived).unwrap();
        std::fs::write(derived.join("encryption.key"), "existing-secret").unwrap();
        assert!(crate::cmd_encode::derive_keys(
            &"ab".repeat(32),
            derived.to_str().unwrap(),
            "plain"
        )
        .is_err());
        assert!(!derived.join("signing.key").exists());
        assert_eq!(
            std::fs::read_to_string(derived.join("encryption.key")).unwrap(),
            "existing-secret"
        );
        let revoked = directory.path().join("revoked.json");
        std::fs::write(&revoked, "not-json").unwrap();
        assert!(crate::cmd_encode::revoke_key(
            &"ab".repeat(32),
            revoked.to_str().unwrap(),
            "plain"
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(revoked).unwrap(), "not-json");
    }

    #[test]
    fn verify_bits_parse_accepts_auto_and_one_to_four() {
        assert!(matches!(VerifyBits::parse("auto"), Ok(VerifyBits::Auto)));
        assert!(matches!(VerifyBits::parse("AUTO"), Ok(VerifyBits::Auto)));
        assert!(
            matches!(VerifyBits::parse("1"), Ok(VerifyBits::Exact(1))),
            "'1' must parse to Exact(1)"
        );
        assert!(
            matches!(VerifyBits::parse("4"), Ok(VerifyBits::Exact(4))),
            "'4' must parse to Exact(4)"
        );
    }

    #[test]
    fn verify_bits_parse_rejects_out_of_range_and_garbage() {
        assert!(VerifyBits::parse("0").is_err());
        assert!(VerifyBits::parse("5").is_err());
        assert!(VerifyBits::parse("two").is_err());
        assert!(VerifyBits::parse("").is_err());
    }

    #[test]
    fn validate_stego_type_accepts_supported_types() {
        for value in VALID_STEGO_TYPES {
            assert!(
                validate_stego_type(value).is_ok(),
                "{value} should be valid"
            );
        }
    }

    #[test]
    fn validate_stego_type_rejects_unknown_values() {
        assert!(validate_stego_type("foobar").is_err());
        assert!(validate_stego_type("LSB_VIDEO").is_err());
        assert!(validate_stego_type("").is_err());
    }

    #[test]
    fn parse_hash_algorithm_strict_accepts_documented_names() {
        assert!(matches!(
            parse_hash_algorithm_strict("blake3"),
            Ok(HashAlgorithm::Blake3)
        ));
        assert!(matches!(
            parse_hash_algorithm_strict("SHA-256"),
            Ok(HashAlgorithm::Sha256)
        ));
        assert!(matches!(
            parse_hash_algorithm_strict("sha3-256"),
            Ok(HashAlgorithm::Sha3_256)
        ));
    }

    #[test]
    fn parse_hash_algorithm_strict_rejects_unknown_names() {
        assert!(parse_hash_algorithm_strict("md5").is_err());
        assert!(parse_hash_algorithm_strict("").is_err());
    }

    #[test]
    fn ss_extraction_roundtrips_core_host_canceling_embed() {
        // Length-prefixed payload: 32-bit length MSB-first, then payload bits
        // LSB-first within each byte (the legacy spread-spectrum wire format:
        // matches embed_raw_spread_spectrum_video + extract_raw_ss_video).
        let payload: Vec<u8> = (0..16u8).collect();
        let mut bits: Vec<u8> = Vec::new();
        let len = payload.len() as u32;
        for i in (0..32).rev() {
            bits.push(((len >> i) & 1) as u8);
        }
        for byte in &payload {
            for j in 0..8 {
                bits.push((byte >> j) & 1);
            }
        }

        let key = [7u8; 32];
        let mut data = vec![128u8; bits.len() * SS_SPREAD_FACTOR];
        let ss = steganographer_core::spread_spectrum::SpreadSpectrumVideo::with_key(key);
        for (bit_pos, &bit) in bits.iter().enumerate() {
            let start = bit_pos * SS_SPREAD_FACTOR;
            ss.embed_bit(&mut data, start, bit, bit_pos, 0).unwrap();
        }

        let extracted = extract_raw_ss_video(&data, &key)
            .unwrap()
            .expect("payload should be extractable");
        assert_eq!(extracted, payload);
    }
}
