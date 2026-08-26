//! `steganographer verify` subcommand — signature verification.
//!
//! Supports all stego types, payload encryption, error correction,
//! multi-frame spreading, and configurable hash algorithms.

use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use steganographer_core::crypto::{HashAlgorithm, SignaturePayload, Verifier};
use steganographer_core::dct_video::DctVideo;
use steganographer_core::encryption;
use steganographer_core::error_correction;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

use crate::carrier_binding;
use crate::media_io;

// ─── Options & Results ──────────────────────────────────────────────

/// Options controlling the verify process.
#[derive(Clone)]
pub struct VerifyOptions {
    pub bits: VerifyBits,
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
}

// ─── Public entry points ────────────────────────────────────────────

#[allow(dead_code)]
pub fn run(
    config_path: &str,
    input: &str,
    public_key_hex: Option<&str>,
    stego_type: &str,
    format: &str,
) -> anyhow::Result<()> {
    let opts = VerifyOptions {
        bits: VerifyBits::Auto,
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
    };
    run_with_key(
        config_path,
        input,
        public_key_hex,
        stego_type,
        format,
        None,
        &opts,
    )
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
) -> anyhow::Result<()> {
    log::info!("Verifying: {}", input);
    log::info!("Stego type: {}", stego_type);
    log::info!(
        "Decrypt: {}, ECC: {}, Spread: {}",
        opts.decrypt,
        opts.ecc,
        opts.spread
    );

    let cfg = steganographer_core::config::Config::from_file(config_path).unwrap_or_else(|e| {
        log::warn!("Could not load config ({}), using defaults", e);
        steganographer_core::config::Config {
            global: steganographer_core::config::GlobalConfig {
                log_level: Some("info".to_string()),
                hash_algorithm: None,
                key_file: None,
            },
            video: None,
            audio: None,
            ots: None,
        }
    });

    let configured_payload = cfg
        .video
        .as_ref()
        .and_then(|video| video.pipeline.as_ref())
        .and_then(|pipeline| pipeline.payload.as_ref());
    let mut effective_opts = opts.clone();
    if let Some(payload) = configured_payload {
        effective_opts.decrypt |= payload.encrypt_enabled();
        effective_opts.ecc |= payload
            .error_correction
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("reed_solomon"));
        if effective_opts.spread == 1 {
            effective_opts.spread = payload.spread_count();
        }
        if effective_opts.decryption_key_file.is_none() && effective_opts.decryption_key.is_none() {
            effective_opts.decryption_key_file = payload.encryption_key_file.clone();
            effective_opts.decryption_key = payload.encryption_key.clone();
        }
    }
    let opts = &effective_opts;
    if opts.ecc && !(1..=16).contains(&opts.ecc_parity) {
        anyhow::bail!(
            "--ecc-parity must be in the range 1-16 when ECC is enabled, got {}",
            opts.ecc_parity
        );
    }

    let hash_algo = opts
        .hash_algorithm
        .as_deref()
        .or(cfg.global.hash_algorithm.as_deref())
        .map(HashAlgorithm::parse)
        .unwrap_or(HashAlgorithm::Blake3);

    let input_format = opts
        .input_format
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));

    // Read input
    let media = media_io::read_input_with_dimensions(
        input,
        &input_format,
        stego_type,
        opts.raw_width,
        opts.raw_height,
    )?;
    let data = &media.data;
    let (width, height) = (media.width, media.height);
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
            };
            print_result(&result, format)?;
            return Ok(());
        }
    };

    let payload_data = apply_ecc_transform(&raw_data, opts)?;

    // Check if the payload data looks like a valid SignaturePayload
    if payload_data.len() >= SignaturePayload::SERIALIZED_SIZE {
        let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
        let len = arr.len();
        arr.copy_from_slice(&payload_data[..len]);

        if SignaturePayload::has_valid_magic(&arr) {
            // Direct SignaturePayload
            let payload = SignaturePayload::from_bytes(&arr)?;
            return finish_verification(
                payload,
                data,
                width,
                height,
                public_key_hex,
                stego_type,
                format,
                false,
                opts.ecc,
                detected_bits,
                raw_data.len(),
                &hash_algo,
                &cfg,
            );
        }
    }

    // Try decryption if enabled
    if opts.decrypt {
        let dec_key = resolve_decryption_key(opts)?;
        let decrypted = encryption::decrypt(&dec_key, 0, &payload_data, None)?;
        log::info!(
            "Decrypted payload: {} -> {} bytes",
            payload_data.len(),
            decrypted.len()
        );

        if decrypted.len() >= SignaturePayload::SERIALIZED_SIZE {
            let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
            let len = arr.len();
            arr.copy_from_slice(&decrypted[..len]);
            if SignaturePayload::has_valid_magic(&arr) {
                let payload = SignaturePayload::from_bytes(&arr)?;
                return finish_verification(
                    payload,
                    data,
                    width,
                    height,
                    public_key_hex,
                    stego_type,
                    format,
                    true,
                    opts.ecc,
                    detected_bits,
                    raw_data.len(),
                    &hash_algo,
                    &cfg,
                );
            }
        }
    }

    // If we got raw bytes but can't parse them, report what we found
    let result = VerifyResult {
        found: true,
        stego_type: stego_type.to_string(),
        frame_index: None,
        hash: Some(hex_encode(&payload_data[..payload_data.len().min(32)])),
        signature_preview: None,
        status: "extracted".to_string(),
        message: format!("Extracted {} bytes of payload data", payload_data.len()),
        lsb_bits: detected_bits,
        encrypted: Some(opts.decrypt),
        ecc_corrected: Some(opts.ecc),
        hash_algorithm: Some(hash_algo.name().to_string()),
    };
    print_result(&result, format)?;
    Ok(())
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
) -> anyhow::Result<()> {
    let hash_hex = hex_encode(&payload.hash);
    let sig_preview = hex_encode(&payload.signature.to_bytes()[..16]);

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
        let pk_bytes = hex_decode(pk_hex)?;
        if pk_bytes.len() != 32 {
            anyhow::bail!("Public key must be 32 bytes (64 hex chars)");
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let verifier = Verifier::with_hash_algorithm(
            ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)?,
            *hash_algo,
        );
        let is_valid = verifier.verify(&payload, &canonical, None);
        if is_valid {
            log::info!("Signature verification: VALID");
            // Check if this key has been revoked
            let revoked_warning = check_revoked_key(pk_hex);
            if let Some(ref warning) = revoked_warning {
                log::warn!("{}", warning);
                (
                    "valid_revoked".to_string(),
                    format!("Signature is valid but key has been REVOKED: {}", warning),
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

    let result = VerifyResult {
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
    };
    print_result(&result, format)?;

    // ─── Optional OpenTimestamps post-signature verification ──────────
    // If OTS is enabled in the config, attempt to find and verify a proof
    // for the SHA-256 of the signed carrier data. This is best-effort: if
    // no proof exists or the OTS server is unreachable, the signature
    // verification result above is not affected.
    if cfg.ots_enabled() {
        let ots_cfg = cfg.ots_config();
        let client = steganographer_core::OTSClient::from_config(&ots_cfg);
        let digest = steganographer_core::OTSClient::compute_sha256_digest(&canonical);
        let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let proof_path = client.proof_path_for(&digest_hex);
        if proof_path.exists() {
            log::info!("Found OTS proof at {}", proof_path.display());
            match steganographer_core::OTSClient::load_proof(&proof_path) {
                Ok(proof) => {
                    let rt = tokio::runtime::Runtime::new()?;
                    match rt.block_on(client.verify(&proof)) {
                        Ok(vr) => {
                            if format == "json" {
                                println!(
                                    "{}",
                                    serde_json::json!({
                                        "ots": {
                                            "verified": vr.verified,
                                            "method": vr.method,
                                            "timestamp": vr.timestamp,
                                            "details": vr.details,
                                        }
                                    })
                                );
                            } else {
                                let status_str = if vr.verified {
                                    "\u{2713} VERIFIED"
                                } else {
                                    "\u{2717} NOT VERIFIED"
                                };
                                println!("  OTS:         {}", status_str);
                                if let Some(ts) = vr.timestamp {
                                    println!("  OTS time:    {} (Unix)", ts);
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("OTS verify failed: {}", e);
                            if format != "json" {
                                println!("  OTS:         verification failed ({})", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("OTS proof load failed: {}", e);
                }
            }
        } else {
            log::debug!("No OTS proof found for digest {}", digest_hex);
            if format != "json" {
                println!(
                    "  OTS:         no proof found (stamping was not active or proof file missing)"
                );
            }
        }
    }

    Ok(())
}

// ─── Extraction ─────────────────────────────────────────────────────

struct ExtractedPayload {
    bytes: Vec<u8>,
    lsb_bits: Option<u8>,
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
/// Extract raw payload bytes from media.
///
/// `public_key_hex` and `hash_algo` are threaded through only so auto-mode
/// LSB extraction can *verify* each candidate strength against the real public
/// key and pick the bits value that genuinely validates, instead of the first
/// strength whose bytes merely parse. Without a key, candidates are matched by
/// magic only (the historical behaviour).
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
            for &bits in opts.bits.candidates() {
                if let Some(bytes) = extract_raw_lsb_video(data, bits)? {
                    let extracted = ExtractedPayload {
                        bytes,
                        lsb_bits: Some(bits),
                    };
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
                    fallback.get_or_insert(extracted);
                }
            }
            Ok(verified.or(fallback))
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
            for &bits in opts.bits.candidates() {
                if let Some(bytes) = extract_raw_lsb_audio(&samples, bits, key)? {
                    let extracted = ExtractedPayload {
                        bytes,
                        lsb_bits: Some(bits),
                    };
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
                    fallback.get_or_insert(extracted);
                }
            }
            Ok(verified.or(fallback))
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

fn parse_key_32(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex_decode(value)?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "{} must be exactly 32 bytes (64 hex chars), got {} bytes",
            label,
            bytes.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
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
    let payload_data = match apply_ecc_transform(raw_data, opts) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if payload_data.len() < SignaturePayload::SERIALIZED_SIZE {
        return false;
    }
    let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
    arr.copy_from_slice(&payload_data[..SignaturePayload::SERIALIZED_SIZE]);
    if !SignaturePayload::has_valid_magic(&arr) {
        return false;
    }
    let payload = match SignaturePayload::from_bytes(&arr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let canonical =
        match carrier_binding::canonicalize(data, stego_type, bits, width, height, embedded_len) {
            Ok(c) => c,
            Err(_) => return false,
        };
    match public_key_hex {
        Some(pk_hex) => {
            let pk_bytes = match hex_decode(pk_hex) {
                Ok(b) => b,
                Err(_) => return false,
            };
            if pk_bytes.len() != 32 {
                return false;
            }
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes);
            let verifier = match ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) {
                Ok(k) => Verifier::with_hash_algorithm(k, *hash_algo),
                Err(_) => return false,
            };
            verifier.verify(&payload, &canonical, None)
        }
        None => true,
    }
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
    if len == 0 || len > 100_000 {
        return Ok(None); // sanity check
    }

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
) -> anyhow::Result<Option<Vec<u8>>> {
    // Generate permutation
    let mut seed = [0u8; 32];
    let frame_bytes = 0u64.to_le_bytes();
    for (i, byte) in key.iter().enumerate() {
        seed[i] = byte ^ frame_bytes[i % 8];
    }
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let mut indices: Vec<usize> = (0..samples.len()).collect();
    indices.shuffle(&mut rng);

    // Read 32 bits for length prefix
    let len_bits_needed = 32usize.div_ceil(bits as usize);
    if indices.len() < len_bits_needed {
        return Ok(None);
    }

    let mut all_bits = Vec::new();
    let mut bit_count = 0;
    for &idx in &indices {
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
    if len == 0 || len > 100_000 {
        return Ok(None);
    }

    // Read full payload
    let total_bits = 32 + len as usize * 8;
    all_bits.clear();
    bit_count = 0;
    for &idx in &indices {
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

/// Extract raw bytes from spread-spectrum video.
fn extract_raw_ss_video(data: &[u8], key: &[u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
    let spread = 64;
    // Read 32-bit length prefix
    let mut len = 0u32;
    for bit_pos in 0..32 {
        let start = bit_pos * spread;
        if start + spread > data.len() {
            return Ok(None);
        }
        let bit = extract_ss_bit(data, start, bit_pos, 0, key);
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
            let bit = extract_ss_bit(data, start, payload_bit, 0, key);
            *slot |= bit << bit_in_byte;
        }
    }
    Ok(Some(result))
}

fn extract_ss_bit(
    data: &[u8],
    start: usize,
    bit_pos: usize,
    frame_index: u64,
    key: &[u8; 32],
) -> u8 {
    let spread = 64;
    let mut seed = [0u8; 32];
    let fb = frame_index.to_le_bytes();
    let bb = (bit_pos as u64).to_le_bytes();
    for i in 0..32 {
        seed[i] = key[i] ^ fb[i % 8] ^ bb[i % 8];
    }
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let pn: Vec<i32> = (0..spread)
        .map(|_| if rng.gen::<bool>() { 1 } else { -1 })
        .collect();

    let correlation: i64 = (start..start + spread)
        .zip(pn.iter())
        .map(|(idx, pn_val)| (data[idx] as i64 - 128) * *pn_val as i64)
        .sum();

    if correlation > 0 {
        1
    } else {
        0
    }
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
) -> anyhow::Result<()> {
    let n = opts.spread as usize;
    log::info!("Multi-frame verify: reading {} shards", n);

    for &bits in opts.bits.candidates() {
        let mut shards: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            let shard_path = format!("{}_{:03}", input, i + 1);
            let shard_data = std::fs::read(&shard_path)
                .map_err(|e| anyhow::anyhow!("Failed to read shard {}: {}", i + 1, e))?;
            match extract_raw_lsb_video(&shard_data, bits)? {
                Some(shard) => shards.push(shard),
                None => {
                    shards.clear();
                    break;
                }
            }
        }
        if shards.len() != n {
            continue;
        }

        let mut payload_bytes = vec![0u8; shards[0].len()];
        for shard in &shards {
            for j in 0..payload_bytes.len().min(shard.len()) {
                payload_bytes[j] ^= shard[j];
            }
        }

        let payload_data = apply_ecc_transform(&payload_bytes, opts)?;
        let (payload_data, was_encrypted) = if opts.decrypt {
            let key = resolve_decryption_key(opts)?;
            (encryption::decrypt(&key, 0, &payload_data, None)?, true)
        } else {
            (payload_data, false)
        };

        if payload_data.len() >= SignaturePayload::SERIALIZED_SIZE {
            let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
            let len = arr.len();
            arr.copy_from_slice(&payload_data[..len]);
            if SignaturePayload::has_valid_magic(&arr) {
                let payload = SignaturePayload::from_bytes(&arr)?;
                return finish_verification(
                    payload,
                    data,
                    width,
                    height,
                    public_key_hex,
                    stego_type,
                    format,
                    was_encrypted,
                    opts.ecc,
                    Some(bits),
                    payload_bytes.len(),
                    hash_algo,
                    cfg,
                );
            }
        }
    }

    let result = VerifyResult {
        found: false,
        stego_type: stego_type.to_string(),
        frame_index: None,
        hash: None,
        signature_preview: None,
        status: "no_signature".to_string(),
        message: "Reconstructed payload is not a valid signature".to_string(),
        lsb_bits: None,
        encrypted: None,
        ecc_corrected: None,
        hash_algorithm: Some(hash_algo.name().to_string()),
    };
    print_result(&result, format)?;
    Ok(())
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
            let json = serde_json::to_string_pretty(result)?;
            println!("{}", json);
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
    } else {
        println!("{yellow}{}{reset}", result.message);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Check if a public key has been revoked by looking it up in keys/revoked.json.
/// Returns Some(warning_message) if the key is revoked, None otherwise.
fn check_revoked_key(public_key_hex: &str) -> Option<String> {
    let revoked_path = std::path::Path::new("keys/revoked.json");
    if !revoked_path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(revoked_path).ok()?;
    let revoked: Vec<String> = serde_json::from_str(&content).ok()?;
    let key_lower = public_key_hex.to_lowercase();
    if revoked.iter().any(|k| k.to_lowercase() == key_lower) {
        Some(format!(
            "Public key {} is in the revoked-keys list (keys/revoked.json)",
            public_key_hex
        ))
    } else {
        None
    }
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("Hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))
        })
        .collect()
}
