//! `steganographer encode` subcommand — offline file-to-file encoding.
//! `steganographer keygen` — generate a new signing key pair.
//! `steganographer info` — report steganographic capacity of a file.
//! `steganographer analyze` — steganalysis (chi-squared test).
//! `steganographer derive` — derive keys from a master secret.

use rand::RngCore;
use serde::Serialize;
use steganographer_core::crypto::{
    decode_hex, decode_hex_array, encode_hex, HashAlgorithm, SignaturePayload, Signer,
};
use steganographer_core::encryption::{self, EncryptionKey};
use steganographer_core::error_correction;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::steganalysis;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};
use steganographer_core::{
    AudioSpatialLsb, CarrierEmbedder, EmbeddingConfig, KeyedAudioSpatialLsb, KeyedSpatialLsb,
    SpatialLsb,
};

use crate::envelope;
use crate::media_io;
use steganographer_core::carrier_binding;

// ─── Options & Results ──────────────────────────────────────────────

/// Options controlling the encode process.
#[derive(Clone)]
pub struct EncodeOptions {
    pub encrypt: bool,
    pub encryption_key: Option<String>,
    pub encryption_key_file: Option<String>,
    pub embedding_key: Option<String>,
    pub embedding_key_file: Option<String>,
    pub ecc: bool,
    pub ecc_parity: usize,
    pub spread: u32,
    pub hash_algorithm: Option<String>,
    pub signing_key: Option<String>,
    pub input_format: Option<String>,
    pub raw_width: Option<u32>,
    pub raw_height: Option<u32>,
    /// Suppress the per-file stdout report (used by `--dir` batch mode in
    /// JSON, where the batch emits exactly one envelope).
    pub quiet_report: bool,
}

/// Machine-readable encode result (serializable to JSON).
#[derive(Debug, Serialize)]
pub struct EncodeResult {
    pub stego_type: String,
    pub input: String,
    pub output: String,
    pub bytes_written: usize,
    pub public_key: String,
    pub hash: String,
    pub signature_preview: String,
    pub bits: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing)]
    pub encryption_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_correction: Option<bool>,
    #[serde(skip_serializing)]
    pub embedding_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spread: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

/// Machine-readable capacity info result.
#[derive(Debug, Serialize)]
pub struct CapacityResult {
    pub file: String,
    pub file_size: usize,
    pub stego_type: String,
    pub bits: u8,
    pub payload_size: usize,
    pub total_capacity_bytes: usize,
    pub max_payloads: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_max_packet_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_usable_units: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_keyed: Option<bool>,
}

/// Machine-readable analysis result.
#[derive(Debug, Serialize)]
pub struct AnalysisResult {
    pub file: String,
    pub analysis_type: String,
    pub detected: bool,
    pub available: bool,
    pub confidence: f64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chi_squared: Option<DetectorResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_pairs: Option<DetectorResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rs_analysis: Option<DetectorResult>,
}

#[derive(Debug, Serialize)]
pub struct DetectorResult {
    pub detected: bool,
    pub available: bool,
    pub confidence: f64,
    pub message: String,
}

impl From<steganalysis::DetectionResult> for DetectorResult {
    fn from(value: steganalysis::DetectionResult) -> Self {
        Self {
            available: value.available,
            detected: value.detected,
            confidence: value.confidence,
            message: value.message,
        }
    }
}

/// Generate a new Ed25519 key pair and save to files.
///
/// In JSON mode the report is the `steganographer.cli/v1` envelope; the
/// private key material is never serialized (plain mode hands the raw hex
/// to the user on the terminal instead).
pub fn keygen(output_path: &str, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("keygen");
    }
    crate::cmd_packet::validate_format(format)?;
    let signer = Signer::generate();
    let private_key_path = format!("{}.key", output_path);
    let public_key_path = format!("{}.pub", output_path);
    let private_hex = encode_hex(&signer.signing_key_bytes());
    let public_hex = encode_hex(&signer.verifying_key().to_bytes());
    for path in [&private_key_path, &public_key_path] {
        media_io::preflight_output(std::path::Path::new(path), false)?;
    }
    media_io::atomic_write(
        std::path::Path::new(&private_key_path),
        private_hex.as_bytes(),
        false,
        true,
    )?;
    media_io::atomic_write(
        std::path::Path::new(&public_key_path),
        public_hex.as_bytes(),
        false,
        false,
    )?;

    log::info!("Private key written to: {} (0600)", private_key_path);
    log::info!("Public key written to:  {}", public_key_path);
    if format == "json" {
        envelope::activate_json_mode("keygen");
        envelope::print(&envelope::success(
            "keygen",
            serde_json::json!({
                "private_key_path": private_key_path,
                "public_key_path": public_key_path,
                "public_key": public_hex,
            }),
        ));
    } else {
        println!("Key pair generated:");
        println!("  Private key: {} (0600)", private_key_path);
        println!("  Public key:  {}", public_key_path);
        println!("  Public key (hex): {}", public_hex);
    }
    Ok(())
}

// ─── Derive Keys ────────────────────────────────────────────────────

/// Derive signing, encryption, and embedding keys from a master secret using
/// the high-entropy BLAKE3 KDF.
///
/// JSON mode emits the `steganographer.cli/v1` envelope with the written
/// file paths; key material itself is never serialized.
pub fn derive_keys(master_secret_hex: &str, output_dir: &str, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("derive");
    }
    crate::cmd_packet::validate_format(format)?;
    let master = decode_hex(master_secret_hex)?;
    if master.is_empty() {
        anyhow::bail!("Master secret cannot be empty");
    }

    // Derive keys via the library's KDF module (single source of truth for
    // context strings — previously these were hand-copied here, which risked
    // silent desync if kdf.rs's contexts changed)
    let keys = steganographer_core::kdf::derive_all(&master);
    let key_files = write_derived_keys(&keys, output_dir, format == "json")?;
    if format == "json" {
        envelope::print(&envelope::success(
            "derive",
            serde_json::json!({
                "output_dir": output_dir,
                "key_files": key_files,
            }),
        ));
    }
    Ok(())
}

/// Derive signing, encryption, and embedding keys from a human-chosen password
/// using Argon2id, then write them to files.
///
/// `salt_hex` must be a hex-encoded salt of at least
/// [`steganographer_core::password::MIN_SALT_LEN`] bytes. When `None`, a fresh
/// random salt is generated and printed so the caller can persist it for
/// reproducible derivation.
pub fn derive_keys_from_password(
    password: &[u8],
    salt_hex: Option<&str>,
    params: &steganographer_core::Argon2Params,
    output_dir: &str,
    format: &str,
) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("derive");
    }
    crate::cmd_packet::validate_format(format)?;
    let salt = match salt_hex {
        Some(hex) => decode_hex(hex)?,
        None => {
            let salt = steganographer_core::password::generate_salt();
            let salt_hex = encode_hex(&salt);
            // The salt is public information, but JSON stdout must stay a
            // single pure payload — the hint moves to stderr there.
            if format == "json" {
                eprintln!("Generated salt (hex, save it to re-derive these keys): {salt_hex}");
            } else {
                println!("Generated salt (hex, save it to re-derive these keys): {salt_hex}");
            }
            salt.to_vec()
        }
    };

    let keys = steganographer_core::password::derive_all_from_password(password, &salt, params)
        .map_err(|e| anyhow::anyhow!("Password key derivation failed: {e}"))?;
    let key_files = write_derived_keys(&keys, output_dir, format == "json")?;
    if format == "json" {
        envelope::activate_json_mode("derive");
        envelope::print(&envelope::success(
            "derive",
            serde_json::json!({
                "output_dir": output_dir,
                "key_files": key_files,
                "salt": encode_hex(&salt),
            }),
        ));
    }
    Ok(())
}

/// Write a derived key set to `output_dir` as hex files with 0600
/// permissions, returning the written file paths. When `json_mode`, no
/// per-key stdout report is emitted (the envelope carries the paths; raw
/// key material is never serialized).
fn write_derived_keys(
    keys: &steganographer_core::DerivedKeys,
    output_dir: &str,
    json_mode: bool,
) -> anyhow::Result<Vec<String>> {
    std::fs::create_dir_all(output_dir)?;

    let signing_pub = {
        let sk = ed25519_dalek::SigningKey::from_bytes(&keys.signing_key);
        sk.verifying_key().to_bytes()
    };

    let paths: [(String, Vec<u8>, &str); 4] = [
        (
            format!("{}/signing.key", output_dir),
            keys.signing_key.to_vec(),
            "Signing key (Ed25519 private)",
        ),
        (
            format!("{}/signing.pub", output_dir),
            signing_pub.to_vec(),
            "Signing public key",
        ),
        (
            format!("{}/encryption.key", output_dir),
            keys.encryption_key.to_vec(),
            "Encryption key (ChaCha20-Poly1305)",
        ),
        (
            format!("{}/embedding.key", output_dir),
            keys.embedding_key.to_vec(),
            "Embedding key (LSB PRNG)",
        ),
    ];

    for (path, _, _) in &paths {
        media_io::preflight_output(std::path::Path::new(path), false)?;
    }
    let mut written: Vec<String> = Vec::new();
    for (path, key_bytes, desc) in &paths {
        let hex_str = encode_hex(key_bytes);
        media_io::atomic_write(std::path::Path::new(path), hex_str.as_bytes(), false, true)?;
        if !json_mode {
            println!("  {}: {} (0600) — {}", path, hex_str, desc);
        }
        written.push(path.clone());
    }

    if !json_mode {
        println!("\nKeys derived and written to {}", output_dir);
    }
    Ok(written)
}

// ─── Run (main encode entry point) ──────────────────────────────────

/// Run offline encoding with full options.
pub fn run(
    config_path: &str,
    input: &str,
    output: &str,
    stego_type: &str,
    bits: u8,
    format: &str,
    opts: &EncodeOptions,
) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("encode");
    }
    crate::cmd_verify::validate_stego_type(stego_type)?;
    if matches!(stego_type, "lsb_video" | "lsb_audio") && !(1..=4).contains(&bits) {
        anyhow::bail!("LSB bits must be in the range 1-4, got {}", bits);
    }
    crate::cmd_packet::validate_format(format)?;

    let cfg = steganographer_core::config::Config::load_optional(config_path)?;

    // CLI values take precedence, while values left at their neutral defaults
    // inherit the offline payload configuration. This keeps file and live
    // surfaces aligned without changing legacy defaults.
    let configured_payload = cfg
        .video
        .as_ref()
        .and_then(|video| video.pipeline.as_ref())
        .and_then(|pipeline| pipeline.payload.as_ref());
    let mut effective_opts = opts.clone();
    effective_opts.encrypt |=
        effective_opts.encryption_key.is_some() || effective_opts.encryption_key_file.is_some();
    if let Some(payload) = configured_payload {
        effective_opts.encrypt |= payload.encrypt_enabled();
        effective_opts.ecc |= payload
            .error_correction
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("reed_solomon"));
        if effective_opts.encryption_key_file.is_none() && effective_opts.encryption_key.is_none() {
            effective_opts.encryption_key_file = payload.encryption_key_file.clone();
            effective_opts.encryption_key = payload.encryption_key.clone();
        }
    }
    let opts = &effective_opts;

    if !(1..=8).contains(&opts.spread) {
        anyhow::bail!("--spread must be 1 (disabled) or 2-8");
    }
    if opts.spread > 1 && stego_type != "lsb_video" {
        anyhow::bail!("Legacy --spread supports only lsb_video");
    }
    if format == "json"
        && opts.encrypt
        && opts.encryption_key.is_none()
        && opts.encryption_key_file.is_none()
    {
        anyhow::bail!("JSON encryption requires --encryption-key or --encryption-key-file; generated secrets cannot be recovered from JSON");
    }
    if !matches!(stego_type, "lsb_audio" | "spread_spectrum_video")
        && (opts.embedding_key.is_some() || opts.embedding_key_file.is_some())
    {
        anyhow::bail!(
            "Legacy embedding keys are supported only for lsb_audio and spread_spectrum_video"
        );
    }
    if !matches!(stego_type, "lsb_video" | "lsb_audio") && bits != 1 {
        anyhow::bail!("--bits applies only to LSB kernels");
    }
    if stego_type == "dct_video" && (opts.encrypt || opts.ecc || opts.spread > 1) {
        anyhow::bail!(
            "dct_video currently supports the signed payload directly; \
             --encrypt, --ecc, and --spread require the generic packet pipeline"
        );
    }
    if opts.ecc && !(1..=16).contains(&opts.ecc_parity) {
        anyhow::bail!(
            "--ecc-parity must be in the range 1-16 when ECC is enabled, got {}",
            opts.ecc_parity
        );
    }

    log::info!("Encoding: {} -> {}", input, output);
    log::info!("Stego type: {}, bits: {}", stego_type, bits);
    log::info!(
        "Encrypt: {}, ECC: {} (parity={}), Spread: {}",
        opts.encrypt,
        opts.ecc,
        opts.ecc_parity,
        opts.spread
    );

    // Resolve hash algorithm (strict: unknown names are rejected rather than
    // silently mapped onto BLAKE3).
    let hash_algo = match opts
        .hash_algorithm
        .as_deref()
        .or(cfg.global.hash_algorithm.as_deref())
    {
        Some(value) => parse_hash_algorithm_strict(value)?,
        None => HashAlgorithm::Blake3,
    };
    log::info!("Hash algorithm: {}", hash_algo.name());

    // Resolve or generate signer
    let mut signer = match &opts.signing_key {
        Some(path) => {
            let key = crate::key_policy::load_signing_key(std::path::Path::new(path))?;
            log::info!("Loaded signing key from {}", path);
            Signer::with_hash_algorithm(key, hash_algo)
        }
        None => {
            let s = Signer::with_hash_algorithm(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                hash_algo,
            );
            log::info!("Generated new signing key");
            s
        }
    };
    signer.set_hash_algorithm(hash_algo);
    let pub_hex = encode_hex(&signer.verifying_key().to_bytes());

    // Resolve encryption key if encryption is enabled
    let enc_key = if opts.encrypt {
        let key = if let Some(ref path) = opts.encryption_key_file {
            let hex_str = std::fs::read_to_string(path)?.trim().to_string();
            EncryptionKey::from_hex(&hex_str)?
        } else if let Some(ref hex_str) = opts.encryption_key {
            EncryptionKey::from_hex(hex_str)?
        } else {
            let k = EncryptionKey::generate();
            log::info!("Generated random encryption key");
            k
        };
        Some(key)
    } else {
        None
    };

    // Read input data (with format detection)
    let input_format = opts
        .input_format
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| media_io::detect_format(input, stego_type));
    log::info!("Input format: {}", input_format);

    let mut media = media_io::read_input_with_dimensions(
        input,
        &input_format,
        stego_type,
        opts.raw_width,
        opts.raw_height,
    )?;
    let (width, height) = (media.width, media.height);
    log::info!(
        "Read {} decoded bytes from {} ({}x{})",
        media.data.len(),
        input,
        width,
        height
    );

    if media.is_audio() != (stego_type == "lsb_audio") {
        anyhow::bail!("Selected stego type is incompatible with the input media");
    }
    if opts.spread == 1 {
        media_io::validate_media_output(output, &media, stego_type)?;
    } else {
        for index in 1..=opts.spread {
            media_io::validate_media_output(
                &format!("{}_{:03}", output, index),
                &media,
                stego_type,
            )?;
        }
    }
    let transformed_payload_len = SignaturePayload::SERIALIZED_SIZE
        + if opts.encrypt {
            encryption::LEGACY_ENCRYPTION_OVERHEAD
        } else {
            0
        }
        + if opts.ecc { opts.ecc_parity } else { 0 };
    let sign_data = carrier_binding::canonicalize(
        &media.data,
        stego_type,
        bits,
        width,
        height,
        transformed_payload_len,
    )?;

    // Sign the frame
    let payload = signer.sign_frame(0, &sign_data, None);
    log::info!("Signed frame 0: hash={}", encode_hex(&payload.hash[..8]));

    // Apply encryption if enabled
    let (embed_data, enc_key_hex) = if let Some(ref ek) = enc_key {
        let payload_bytes = payload.to_bytes();
        let encrypted = encryption::encrypt_legacy(ek, &payload_bytes, None)?;
        log::info!(
            "Encrypted payload: {} -> {} bytes",
            payload_bytes.len(),
            encrypted.len()
        );
        (encrypted, Some(ek.expose_hex()))
    } else {
        (payload.to_bytes().to_vec(), None)
    };

    // Apply error correction if enabled
    let embed_data = if opts.ecc {
        let encoded = error_correction::encode(&embed_data, opts.ecc_parity)?;
        log::info!(
            "RS encoded: {} -> {} bytes ({} parity)",
            embed_data.len(),
            encoded.len(),
            opts.ecc_parity
        );
        encoded
    } else {
        embed_data
    };
    if embed_data.len() != transformed_payload_len {
        anyhow::bail!("Transformed payload length does not match the canonical carrier binding");
    }

    let embedding_key = if matches!(stego_type, "lsb_audio" | "spread_spectrum_video") {
        let resolved = resolve_embedding_key(opts, &cfg, stego_type)?;
        if format == "json" && resolved.is_none() {
            anyhow::bail!("JSON encoding requires a supplied embedding key; generated secrets cannot be recovered from JSON");
        }
        Some(resolved.unwrap_or_else(generate_random_key))
    } else {
        None
    };

    // Apply multi-frame spreading if enabled
    if opts.spread > 1 {
        return encode_multi_frame(
            input,
            output,
            &media,
            &embed_data,
            stego_type,
            bits,
            format,
            opts,
            &pub_hex,
            &payload,
            enc_key_hex,
            hash_algo,
        );
    }

    // Embed the (possibly encrypted + ECC'd) data into the media
    let stego_result = embed_payload(
        &mut media.data,
        width,
        height,
        &embed_data,
        stego_type,
        bits,
        embedding_key.as_ref(),
    )?;
    // Write output (with format)
    media_io::write_output(output, &media, stego_type)?;
    authenticate_written_output(
        output,
        stego_type,
        bits,
        opts,
        &pub_hex,
        embedding_key.as_ref(),
        enc_key_hex.as_deref(),
        hash_algo,
    )?;
    let bytes_written = std::fs::metadata(output)?.len() as usize;
    log::info!("Wrote {} encoded bytes to {}", bytes_written, output);
    let result = EncodeResult {
        stego_type: stego_type.to_string(),
        input: input.to_string(),
        output: output.to_string(),
        bytes_written,
        public_key: pub_hex.clone(),
        hash: encode_hex(&payload.hash),
        signature_preview: encode_hex(&payload.signature.to_bytes()[..16]),
        bits,
        encrypted: Some(opts.encrypt),
        encryption_key_hex: enc_key_hex,
        error_correction: Some(opts.ecc),
        embedding_key_hex: stego_result.embedding_key_hex,
        spread: if opts.spread > 1 {
            Some(opts.spread)
        } else {
            None
        },
        hash_algorithm: Some(hash_algo.name().to_string()),
    };

    if !opts.quiet_report {
        match format {
            "json" => envelope::print(&envelope::success("encode", serde_json::to_value(&result)?)),
            _ => {
                println!("Public key (for verification): {}", pub_hex);
                if let Some(ek) = &result.encryption_key_hex {
                    println!("Encryption key: {}", ek);
                }
                if let Some(ak) = &result.embedding_key_hex {
                    println!("Embedding key (for extraction): {}", ak);
                }
                if let Some(ha) = &result.hash_algorithm {
                    println!("Hash algorithm: {}", ha);
                }
                if result.encrypted == Some(true) {
                    println!("Payload: encrypted (ChaCha20-Poly1305)");
                }
                if result.error_correction == Some(true) {
                    println!(
                        "Error correction: Reed-Solomon (parity={})",
                        opts.ecc_parity
                    );
                }
                println!("Encoded file written to: {}", output);
            }
        }
    }

    // ─── Optional OpenTimestamps post-embed stamping ──────────────────
    // Timestamp the SHA-256 commitment of the actual canonical signed carrier.
    // Calendar submission may remain pending until a Bitcoin attestation exists.
    if cfg.ots_enabled() {
        let ots_cfg = cfg.ots_config();
        log::info!(
            "OTS stamping enabled (method={}, interval={}s)",
            ots_cfg.method,
            ots_cfg.interval_secs
        );
        let client = steganographer_core::OTSClient::from_config(&ots_cfg)?;
        if client.can_stamp() {
            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(client.stamp_data(&sign_data)) {
                Ok(proof) => {
                    let digest = steganographer_core::OTSClient::compute_sha256_digest(&sign_data);
                    let digest_hex = encode_hex(&digest);
                    match rt.block_on(client.save_proof(&proof, &digest_hex)) {
                        Ok(path) => {
                            log::info!("OTS proof saved to {}", path.display());
                            if format != "json" {
                                println!("OTS proof: {} ({} bytes)", path.display(), proof.len());
                            }
                        }
                        Err(e) => log::warn!("OTS proof save failed: {}", e),
                    }
                }
                Err(e) => {
                    log::warn!("OTS stamping failed (continuing without proof): {}", e);
                    if format != "json" {
                        println!("OTS: stamping failed ({}). Encoded file is valid without timestamp proof.", e);
                    }
                }
            }
        } else {
            log::debug!("OTS: rate-limited (interval not elapsed), skipping stamp");
        }
    }

    Ok(())
}

/// Strict hash-algorithm parsing: the accepted set mirrors
/// [`HashAlgorithm::parse`], but unknown names error out instead of
/// silently falling back to BLAKE3.
fn parse_hash_algorithm_strict(value: &str) -> anyhow::Result<HashAlgorithm> {
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

// ─── Embedding ──────────────────────────────────────────────────────

fn resolve_embedding_key(
    opts: &EncodeOptions,
    cfg: &steganographer_core::config::Config,
    stego_type: &str,
) -> anyhow::Result<Option<[u8; 32]>> {
    if let Some(path) = opts.embedding_key_file.as_deref() {
        return steganographer_core::config::resolve_key(None, Some(path)).map(Some);
    }
    if let Some(key) = opts.embedding_key.as_deref() {
        return steganographer_core::config::resolve_key(Some(key), None).map(Some);
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
    if let Some(key) = carrier_config.and_then(|config| config.key.as_deref()) {
        return steganographer_core::config::resolve_key(Some(key), None).map(Some);
    }
    Ok(None)
}

struct StegoResult {
    embedding_key_hex: Option<String>,
}

/// Embed raw payload bytes into media data using the specified stego type.
fn embed_payload(
    data: &mut [u8],
    width: u32,
    height: u32,
    payload_bytes: &[u8],
    stego_type: &str,
    bits: u8,
    embedding_key: Option<&[u8; 32]>,
) -> anyhow::Result<StegoResult> {
    match stego_type {
        "lsb_video" => {
            embed_raw_lsb_video(data, payload_bytes, bits)?;
            Ok(StegoResult {
                embedding_key_hex: None,
            })
        }
        "lsb_audio" => {
            let audio_key = embedding_key
                .ok_or_else(|| anyhow::anyhow!("Missing resolved audio embedding key"))?;
            let key_hex = encode_hex(audio_key);
            let (pcm_chunks, _remainder) = data.as_chunks::<2>();
            let mut samples: Vec<i16> = pcm_chunks.iter().map(|c| i16::from_le_bytes(*c)).collect();
            embed_raw_lsb_audio(&mut samples, payload_bytes, bits, audio_key)?;
            // Write samples back to data
            for (i, s) in samples.iter().enumerate() {
                let offset = i * 2;
                if offset + 1 < data.len() {
                    data[offset..offset + 2].copy_from_slice(&s.to_le_bytes());
                }
            }
            Ok(StegoResult {
                embedding_key_hex: Some(key_hex),
            })
        }
        "spread_spectrum_video" => {
            let ss_key = *embedding_key
                .ok_or_else(|| anyhow::anyhow!("Missing resolved spread-spectrum embedding key"))?;
            let key_hex = encode_hex(&ss_key);
            let ss = steganographer_core::spread_spectrum::SpreadSpectrumVideo::with_key(ss_key);
            let mut frame = VideoFrame {
                width,
                height,
                stride: width * 3,
                format: VideoFormat::Rgb8,
                data,
                frame_index: 0,
            };
            embed_raw_spread_spectrum_video(&mut frame, payload_bytes, &ss)?;
            Ok(StegoResult {
                embedding_key_hex: Some(key_hex),
            })
        }
        "dct_video" => {
            let payload_array: [u8; SignaturePayload::SERIALIZED_SIZE] =
                payload_bytes.try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "dct_video requires a direct {}-byte SignaturePayload, got {} bytes",
                        SignaturePayload::SERIALIZED_SIZE,
                        payload_bytes.len()
                    )
                })?;
            let payload = SignaturePayload::from_bytes(&payload_array)?;
            let mut dct = steganographer_core::dct_video::DctVideo::default();
            let mut frame = VideoFrame {
                width,
                height,
                stride: width
                    .checked_mul(3)
                    .ok_or_else(|| anyhow::anyhow!("Image stride overflow"))?,
                format: VideoFormat::Rgb8,
                data,
                frame_index: 0,
            };
            dct.embed(&mut frame, Some(&payload))?;
            Ok(StegoResult {
                embedding_key_hex: None,
            })
        }
        _ => anyhow::bail!("Unsupported stego type: {}", stego_type),
    }
}

/// Embed raw bytes into video LSB with a 32-bit bit-length prefix.
fn embed_raw_lsb_video(data: &mut [u8], payload: &[u8], bits: u8) -> anyhow::Result<()> {
    let len = u32::try_from(
        payload
            .len()
            .checked_mul(8)
            .ok_or_else(|| anyhow::anyhow!("Video payload length overflow"))?,
    )?;
    let len_bits: Vec<u8> = (0..32).rev().map(|i| ((len >> i) & 1) as u8).collect();
    let payload_bits: Vec<u8> = payload
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect();
    let all_bits: Vec<u8> = len_bits
        .iter()
        .chain(payload_bits.iter())
        .copied()
        .collect();

    let capacity = data.len() * bits as usize;
    if all_bits.len() > capacity {
        anyhow::bail!(
            "Not enough LSB capacity: need {} bits, have {} ({} bytes x {} bits)",
            all_bits.len(),
            capacity,
            data.len(),
            bits
        );
    }

    let mask = !((1u8 << bits) - 1);
    let mut bit_idx = 0usize;
    for byte in data.iter_mut() {
        if bit_idx >= all_bits.len() {
            break;
        }
        let mut new_lsb: u8 = 0;
        for shift in (0..bits).rev() {
            if bit_idx < all_bits.len() {
                new_lsb |= all_bits[bit_idx] << shift;
                bit_idx += 1;
            }
        }
        *byte = (*byte & mask) | new_lsb;
    }
    Ok(())
}

/// Embed raw bytes into audio LSB with a 32-bit bit-length prefix.
fn embed_raw_lsb_audio(
    samples: &mut [i16],
    payload: &[u8],
    bits: u8,
    key: &[u8; 32],
) -> anyhow::Result<()> {
    let len = u32::try_from(
        payload
            .len()
            .checked_mul(8)
            .ok_or_else(|| anyhow::anyhow!("Audio payload length overflow"))?,
    )?;
    let len_bits: Vec<u8> = (0..32).rev().map(|i| ((len >> i) & 1) as u8).collect();
    let payload_bits: Vec<u8> = payload
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect();
    let all_bits: Vec<u8> = len_bits
        .iter()
        .chain(payload_bits.iter())
        .copied()
        .collect();

    // Generate permutation
    let mut seed = [0u8; 32];
    let frame_bytes = 0u64.to_le_bytes();
    for (i, byte) in key.iter().enumerate() {
        seed[i] = byte ^ frame_bytes[i % 8];
    }
    let indices = steganographer_core::placement::KeyedPermutation::try_new(
        samples.len(),
        seed,
        b"legacy-audio-v4",
    )?;

    let capacity = indices.len() * bits as usize;
    if all_bits.len() > capacity {
        anyhow::bail!(
            "Not enough audio LSB capacity: need {} bits, have {}",
            all_bits.len(),
            capacity
        );
    }

    let mask = !((1i16 << bits) - 1);
    let mut bit_idx = 0usize;
    for logical in 0..all_bits.len().div_ceil(bits as usize) {
        let idx = indices.permute(logical);
        if bit_idx >= all_bits.len() {
            break;
        }
        let sample = &mut samples[idx];
        let mut new_lsb: i16 = 0;
        for shift in (0..bits).rev() {
            if bit_idx < all_bits.len() {
                new_lsb |= (all_bits[bit_idx] as i16) << shift;
                bit_idx += 1;
            }
        }
        *sample = (*sample & mask) | new_lsb;
    }
    Ok(())
}

/// Default spread factor of
/// [`steganographer_core::spread_spectrum::SpreadSpectrumVideo::with_key`],
/// the constructor this embed path uses. The core type does not expose a
/// spread-factor getter, so the capacity guard mirrors the documented
/// default here; encode and extraction both construct via `with_key`, so
/// the two sides stay in lockstep.
const SS_DEFAULT_SPREAD: usize = 64;

/// Embed raw bytes into spread-spectrum video (direct bit embedding).
///
/// Every bit is delegated to the core host-canceling differential-pair
/// embedder ([`steganographer_core::spread_spectrum::SpreadSpectrumVideo::embed_bit`]);
/// the CLI carries no PN/correlation math of its own, so encode and
/// extraction stay in lockstep by construction.
fn embed_raw_spread_spectrum_video(
    frame: &mut VideoFrame,
    payload: &[u8],
    ss: &steganographer_core::spread_spectrum::SpreadSpectrumVideo,
) -> anyhow::Result<()> {
    let total_bits = 32 + payload.len() * 8;
    let needed = total_bits * SS_DEFAULT_SPREAD;
    if needed > frame.data.len() {
        anyhow::bail!(
            "Not enough capacity for spread-spectrum: need {} bytes, have {}",
            needed,
            frame.data.len()
        );
    }

    // Embed length prefix
    let len = payload.len() as u32;
    for bit_pos in 0..32 {
        let bit = ((len >> (31 - bit_pos)) & 1) as u8;
        let start = bit_pos * SS_DEFAULT_SPREAD;
        ss.embed_bit(frame.data, start, bit, bit_pos, frame.frame_index)?;
    }
    // Embed payload bits
    for (byte_idx, byte) in payload.iter().enumerate() {
        for bit_in_byte in 0..8 {
            let bit = (byte >> bit_in_byte) & 1;
            let payload_bit = 32 + byte_idx * 8 + bit_in_byte;
            let start = payload_bit * SS_DEFAULT_SPREAD;
            ss.embed_bit(frame.data, start, bit, payload_bit, frame.frame_index)?;
        }
    }
    Ok(())
}

// ─── Multi-frame spreading ──────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn authenticate_written_output(
    output: &str,
    stego_type: &str,
    bits: u8,
    options: &EncodeOptions,
    public_key: &str,
    embedding_key: Option<&[u8; 32]>,
    encryption_key: Option<&str>,
    hash_algorithm: HashAlgorithm,
) -> anyhow::Result<()> {
    let verify_options = crate::cmd_verify::VerifyOptions {
        bits: crate::cmd_verify::VerifyBits::Exact(bits),
        frame_index: 0,
        decrypt: options.encrypt,
        decryption_key: encryption_key.map(str::to_owned),
        decryption_key_file: None,
        embedding_key_file: None,
        ecc: options.ecc,
        ecc_parity: options.ecc_parity,
        spread: options.spread,
        hash_algorithm: None,
        input_format: options.input_format.clone(),
        raw_width: options.raw_width,
        raw_height: options.raw_height,
        revoked_list: None,
    };
    crate::cmd_verify::authenticate_written_output(
        output,
        stego_type,
        embedding_key,
        &verify_options,
        hash_algorithm,
        public_key,
    )
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
/// Encode with multi-frame spreading.
fn encode_multi_frame(
    input: &str,
    output: &str,
    media: &media_io::MediaInput,
    embed_data: &[u8],
    stego_type: &str,
    bits: u8,
    format: &str,
    opts: &EncodeOptions,
    pub_hex: &str,
    payload: &SignaturePayload,
    enc_key_hex: Option<String>,
    hash_algo: HashAlgorithm,
) -> anyhow::Result<()> {
    let n = u8::try_from(opts.spread)?;
    let shards = steganographer_core::multi_frame::split_payload_bytes(embed_data, n, 0)?;
    let mut bytes_written = 0;
    for (i, shard) in shards.iter().enumerate() {
        let out_path = format!("{}_{:03}", output, i + 1);
        let mut frame_media = media_io::MediaInput {
            data: media.data.clone(),
            width: media.width,
            height: media.height,
            encoded_len: media.encoded_len,
            kind: media.kind,
        };
        embed_raw_lsb_video(&mut frame_media.data, &shard.data, bits)?;
        media_io::write_output(&out_path, &frame_media, stego_type)?;
        bytes_written += std::fs::metadata(&out_path)?.len() as usize;
    }
    authenticate_written_output(
        output,
        stego_type,
        bits,
        opts,
        pub_hex,
        None,
        enc_key_hex.as_deref(),
        hash_algo,
    )?;

    let result = EncodeResult {
        stego_type: stego_type.to_string(),
        input: input.to_string(),
        output: output.to_string(),
        bytes_written,
        public_key: pub_hex.to_string(),
        hash: encode_hex(&payload.hash),
        signature_preview: encode_hex(&payload.signature.to_bytes()[..16]),
        bits,
        encrypted: Some(opts.encrypt),
        encryption_key_hex: enc_key_hex,
        error_correction: Some(opts.ecc),
        embedding_key_hex: None,
        spread: Some(opts.spread),
        hash_algorithm: Some(hash_algo.name().to_string()),
    };

    if !opts.quiet_report {
        match format {
            "json" => envelope::print(&envelope::success("encode", serde_json::to_value(&result)?)),
            _ => {
                println!("Public key: {}", pub_hex);
                if let Some(key) = &result.encryption_key_hex {
                    println!("Encryption key: {}", key);
                }
                println!("Spread across {} frames", n);
                println!("Shards written to {}_001..{}_{:03}", output, output, n);
            }
        }
    }
    Ok(())
}

// ─── Info / Capacity ────────────────────────────────────────────────

/// Report steganographic capacity of a file.
pub fn info(
    input: &str,
    stego_type: &str,
    bits: u8,
    format: &str,
    raw_width: Option<u32>,
    raw_height: Option<u32>,
    embedding_key: Option<&str>,
) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("info");
    }
    crate::cmd_packet::validate_format(format)?;
    if matches!(stego_type, "lsb_video" | "lsb_audio") && !(1..=4).contains(&bits) {
        anyhow::bail!("LSB bits must be in the range 1-4, got {}", bits);
    }
    let input_format = media_io::detect_format(input, stego_type);
    let media = media_io::read_input_with_dimensions(
        input,
        &input_format,
        stego_type,
        raw_width,
        raw_height,
    )?;
    let payload_size = steganographer_core::crypto::SignaturePayload::SERIALIZED_SIZE;
    let (total_capacity_bytes, max_payloads) = match stego_type {
        "lsb_video" | "lsb_audio" => {
            let capacity_bits = media.lsb_units(stego_type) * bits as usize;
            let total_bits = 32 + payload_size * 8;
            let capacity_bytes = capacity_bits.saturating_sub(32) / 8;
            let max = capacity_bits.checked_div(total_bits).unwrap_or(0);
            (capacity_bytes, max)
        }
        "spread_spectrum_video" => {
            let spread = 64;
            let capacity_bits = media.data.len() / spread;
            let capacity_bytes = capacity_bits.saturating_sub(32) / 8;
            let max = capacity_bits / (32 + payload_size * 8);
            (capacity_bytes, max)
        }
        "dct_video" => {
            let blocks = media.dct_blocks();
            let max = blocks / (payload_size * 8);
            (blocks / 8, max)
        }
        _ => anyhow::bail!("Unsupported stego type: {}", stego_type),
    };

    // Exact generic-packet capacity uses the same descriptor/slot math as the
    // encode/decode kernels (FMT-001 / SUR-004). Only spatial-LSB kernels are
    // reported; frequency-domain kernels keep `None`.
    let (generic_max_packet_bytes, generic_usable_units, generic_keyed) =
        match (stego_type, embedding_key) {
            ("lsb_video" | "lsb_audio", key) => {
                let config = EmbeddingConfig::new(bits)?;
                let descriptor = media.carrier_descriptor();
                let report = match (key, media.is_audio()) {
                    (Some(hex), true) => {
                        let parsed = steganographer_core::config::resolve_key(Some(hex), None)?;
                        KeyedAudioSpatialLsb::new(parsed).capacity(&descriptor, &config)?
                    }
                    (Some(hex), false) => {
                        let parsed = steganographer_core::config::resolve_key(Some(hex), None)?;
                        KeyedSpatialLsb::new(parsed).capacity(&descriptor, &config)?
                    }
                    (None, true) => AudioSpatialLsb.capacity(&descriptor, &config)?,
                    (None, false) => SpatialLsb.capacity(&descriptor, &config)?,
                };
                (
                    Some(report.max_packet_bytes),
                    Some(report.usable_units),
                    Some(key.is_some()),
                )
            }
            _ => (None, None, None),
        };

    let result = CapacityResult {
        file: input.to_string(),
        file_size: media.encoded_len,
        stego_type: stego_type.to_string(),
        bits,
        payload_size,
        total_capacity_bytes,
        max_payloads,
        generic_max_packet_bytes,
        generic_usable_units,
        generic_keyed,
    };

    match format {
        "json" => envelope::print(&envelope::success("info", serde_json::to_value(&result)?)),
        _ => {
            println!("File: {}", result.file);
            println!("File size: {} bytes", result.file_size);
            println!("Stego type: {}", result.stego_type);
            println!("Bits per sample/pixel: {}", result.bits);
            println!("Payload size: {} bytes", result.payload_size);
            println!("Total capacity: {} bytes", result.total_capacity_bytes);
            println!("Max payloads: {}", result.max_payloads);
            if let (Some(bytes), Some(units), Some(keyed)) = (
                result.generic_max_packet_bytes,
                result.generic_usable_units,
                result.generic_keyed,
            ) {
                println!(
                    "Generic packet capacity: {} bytes ({} usable units, {})",
                    bytes,
                    units,
                    if keyed { "keyed" } else { "sequential" }
                );
            }
        }
    }
    Ok(())
}

// ─── Analyze / Steganalysis ─────────────────────────────────────────

/// Revoke a signing key by adding its public key to a revoked-keys list.
///
/// The revoked-keys file is a JSON array of hex-encoded public keys.
/// The `verify` command can check this list and warn if a signature
/// was made with a revoked key. JSON mode emits the
/// `steganographer.cli/v1` envelope.
pub fn revoke_key(public_key_hex: &str, output_path: &str, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("revoke");
    }
    crate::cmd_packet::validate_format(format)?;
    let key_bytes = decode_hex_array::<32>(public_key_hex)?;

    // Missing lists start empty; malformed or unreadable evidence is preserved.
    let path = std::path::Path::new(output_path);
    // The companion inode is stable across registry replacements. Hold its
    // advisory lock over the complete read/merge/atomic-publish transaction.
    // Never remove this file: unlinking would split concurrent lock owners.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut lock_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("revocation output requires a filename"))?
        .to_os_string();
    lock_name.push(".lock");
    let mut lock_options = std::fs::OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let registry_lock = lock_options.open(parent.join(lock_name))?;
    registry_lock.lock()?;
    let mut revoked: steganographer_core::revocation::RevocationList =
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content)?,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(path).is_err() =>
            {
                Default::default()
            }
            Err(error) => return Err(error.into()),
        };

    // Add an explicit registry entry, including an already built-in compromise.
    if !revoked.insert(key_bytes) {
        if format == "json" {
            envelope::activate_json_mode("revoke");
            envelope::print(&envelope::success(
                "revoke",
                serde_json::json!({
                    "public_key": public_key_hex,
                    "output_path": output_path,
                    "already_revoked": true,
                    "total_keys": revoked.len(),
                }),
            ));
        } else {
            println!("Key already revoked: {}", public_key_hex);
        }
        return Ok(());
    }

    // Write back
    let json = serde_json::to_string_pretty(&revoked)?;
    media_io::atomic_write(path, json.as_bytes(), true, false)?;

    if format == "json" {
        envelope::activate_json_mode("revoke");
        envelope::print(&envelope::success(
            "revoke",
            serde_json::json!({
                "public_key": public_key_hex,
                "output_path": output_path,
                "already_revoked": false,
                "total_keys": revoked.len(),
            }),
        ));
    } else {
        println!("Key revoked: {}", public_key_hex);
        println!(
            "Revoked-keys list: {} ({} keys total)",
            output_path,
            revoked.len()
        );
    }
    Ok(())
}

pub fn analyze(input: &str, analysis_type: &str, format: &str) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("analyze");
    }
    crate::cmd_packet::validate_format(format)?;
    let data = std::fs::read(input)?;
    log::info!(
        "Analyzing {} ({} bytes) with {}",
        input,
        data.len(),
        analysis_type
    );

    let result = match analysis_type {
        "chi_squared" => {
            let detector = steganalysis::chi_squared_detect(&data);
            AnalysisResult {
                file: input.to_string(),
                analysis_type: analysis_type.to_string(),
                detected: detector.detected,
                available: detector.available,
                confidence: detector.confidence,
                message: detector.message.clone(),
                chi_squared: Some(detector.into()),
                sample_pairs: None,
                rs_analysis: None,
            }
        }
        "sample_pairs" | "spa" => {
            let detector = steganalysis::sample_pair_detect(&data);
            AnalysisResult {
                file: input.to_string(),
                analysis_type: "sample_pairs".to_string(),
                detected: detector.detected,
                available: detector.available,
                confidence: detector.confidence,
                message: detector.message.clone(),
                chi_squared: None,
                sample_pairs: Some(detector.into()),
                rs_analysis: None,
            }
        }
        "rs" | "rs_analysis" => {
            let detector = steganalysis::rs_analyze(&data);
            AnalysisResult {
                file: input.to_string(),
                analysis_type: "rs_analysis".to_string(),
                detected: detector.detected,
                available: detector.available,
                confidence: detector.confidence,
                message: detector.message.clone(),
                chi_squared: None,
                sample_pairs: None,
                rs_analysis: Some(detector.into()),
            }
        }
        "combined" => {
            let combined = steganalysis::analyze_combined(&data);
            AnalysisResult {
                file: input.to_string(),
                analysis_type: analysis_type.to_string(),
                detected: combined.detected,
                available: combined.chi_squared.available
                    || combined.sample_pairs.available
                    || combined.rs_analysis.available,
                confidence: combined.confidence,
                message: combined.message,
                chi_squared: Some(combined.chi_squared.into()),
                sample_pairs: Some(combined.sample_pairs.into()),
                rs_analysis: Some(combined.rs_analysis.into()),
            }
        }
        _ => {
            anyhow::bail!(
                "Unknown analysis type '{}'; expected combined, chi_squared, sample_pairs, or rs",
                analysis_type
            );
        }
    };
    let inconclusive = !result.available;

    match format {
        "json" if inconclusive => envelope::print(&envelope::partial(
            "analyze",
            serde_json::to_value(&result)?,
            vec![result.message.clone()],
        )),
        "json" => envelope::print(&envelope::success(
            "analyze",
            serde_json::to_value(&result)?,
        )),
        _ => {
            println!("File: {}", result.file);
            println!("Analysis: {}", result.analysis_type);
            println!(
                "Detected: {}",
                if inconclusive {
                    "inconclusive"
                } else if result.detected {
                    "yes"
                } else {
                    "no"
                }
            );
            println!("Statistical score: {:.1}%", result.confidence * 100.0);
            println!("{}", result.message);
            for (name, detector) in [
                ("Chi-squared", result.chi_squared.as_ref()),
                ("Sample pairs", result.sample_pairs.as_ref()),
                ("RS analysis", result.rs_analysis.as_ref()),
            ] {
                if let Some(detector) = detector {
                    println!(
                        "  {}: {} ({:.1}%) — {}",
                        name,
                        if !detector.available {
                            "unavailable"
                        } else if detector.detected {
                            "detected"
                        } else {
                            "not detected"
                        },
                        detector.confidence * 100.0,
                        detector.message
                    );
                }
            }
        }
    }
    if inconclusive {
        return Err(anyhow::Error::new(envelope::InconclusiveError));
    }
    Ok(())
}

// ─── Utility ────────────────────────────────────────────────────────

/// Generate a random 32-byte key using the OS RNG.
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Batch process a directory of files.
///
/// Encodes or verifies all files in the given directory.
pub fn batch_process(
    config_path: &str,
    input_dir: &str,
    output_dir: &str,
    stego_type: &str,
    bits: u8,
    format: &str,
    opts: &EncodeOptions,
) -> anyhow::Result<()> {
    if format == "json" {
        envelope::activate_json_mode("encode");
    }
    log::info!("Batch processing: {} -> {}", input_dir, output_dir);
    std::fs::create_dir_all(output_dir)?;

    let mut success_count = 0u32;
    let mut error_count = 0u32;

    let entries = std::fs::read_dir(input_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let input_path = path.to_string_lossy().to_string();
        let output_path = format!(
            "{}/{}",
            output_dir,
            path.file_name().unwrap_or_default().to_string_lossy()
        );

        log::info!("Processing: {}", input_path);
        // In JSON batch mode each file encodes silently; the batch emits
        // exactly one envelope on stdout.
        let mut file_opts = opts.clone();
        file_opts.quiet_report = format == "json";
        match run(
            config_path,
            &input_path,
            &output_path,
            stego_type,
            bits,
            format,
            &file_opts,
        ) {
            Ok(_) => {
                success_count += 1;
                log::info!("✓ {}", input_path);
            }
            Err(e) => {
                error_count += 1;
                log::error!("✗ {}: {}", input_path, e);
            }
        }
    }

    if format == "json" {
        envelope::activate_json_mode("encode");
        let result = serde_json::json!({
            "input_dir": input_dir,
            "output_dir": output_dir,
            "succeeded": success_count,
            "failed": error_count,
        });
        if error_count > 0 {
            envelope::print(&envelope::partial("encode", result, Vec::new()));
        } else {
            envelope::print(&envelope::success("encode", result));
        }
    } else {
        println!(
            "Batch complete: {} succeeded, {} failed",
            success_count, error_count
        );
    }
    if error_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // internal CLI orchestration entry
/// Encode a multi-frame raw video file.
///
/// Reads a raw RGB file containing multiple frames (each frame = width × height × 3 bytes),
/// signs each frame, embeds a signature in each, and writes the output.
#[allow(dead_code)]
pub fn encode_multi_frame_file(
    _config_path: &str,
    input: &str,
    output: &str,
    width: u32,
    height: u32,
    frame_count: u32,
    bits: u8,
    format: &str,
    opts: &EncodeOptions,
) -> anyhow::Result<()> {
    log::info!(
        "Multi-frame encode: {} ({}x{}x{} frames) -> {}",
        input,
        width,
        height,
        frame_count,
        output
    );

    let frame_size = (width * height * 3) as usize;
    let data = std::fs::read(input)?;
    let expected_size = frame_size * frame_count as usize;
    if data.len() < expected_size {
        anyhow::bail!(
            "Input file too small: expected {} bytes ({} frames × {} bytes), got {}",
            expected_size,
            frame_count,
            frame_size,
            data.len()
        );
    }

    let hash_algo = match opts.hash_algorithm.as_deref() {
        Some(value) => parse_hash_algorithm_strict(value)?,
        None => HashAlgorithm::Blake3,
    };

    let signer = match &opts.signing_key {
        Some(path) => {
            let key = crate::key_policy::load_signing_key(std::path::Path::new(path))?;
            Signer::with_hash_algorithm(key, hash_algo)
        }
        None => Signer::with_hash_algorithm(
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            hash_algo,
        ),
    };
    let pub_hex = encode_hex(&signer.verifying_key().to_bytes());

    let mut output_data = Vec::with_capacity(expected_size);

    for frame_idx in 0..frame_count as u64 {
        let start = frame_idx as usize * frame_size;
        let end = start + frame_size;
        let mut frame_data = data[start..end].to_vec();

        let payload = signer.sign_frame(frame_idx, &frame_data, None);

        let mut lsb = LsbVideo::try_new(bits)?;
        let mut frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut frame_data,
            frame_index: frame_idx,
        };
        lsb.embed(&mut frame, Some(&payload))?;

        output_data.extend_from_slice(&frame_data);

        if (frame_idx + 1) % 30 == 0 {
            log::info!("Encoded frame {}/{}", frame_idx + 1, frame_count);
        }
    }

    media_io::atomic_write(std::path::Path::new(output), &output_data, false, false)?;
    log::info!(
        "Wrote {} bytes ({} frames) to {}",
        output_data.len(),
        frame_count,
        output
    );

    match format {
        "json" => {
            let result = EncodeResult {
                stego_type: "lsb_video_multi".to_string(),
                input: input.to_string(),
                output: output.to_string(),
                bytes_written: output_data.len(),
                public_key: pub_hex,
                hash: String::new(),
                signature_preview: String::new(),
                bits,
                encrypted: None,
                encryption_key_hex: None,
                error_correction: None,
                embedding_key_hex: None,
                spread: None,
                hash_algorithm: Some(hash_algo.name().to_string()),
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => {
            println!("Public key: {}", pub_hex);
            println!("Encoded {} frames to {}", frame_count, output);
        }
    }

    Ok(())
}
