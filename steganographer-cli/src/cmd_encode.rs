//! `steganographer encode` subcommand — offline file-to-file encoding.
//! `steganographer keygen` — generate a new signing key pair.
//! `steganographer info` — report steganographic capacity of a file.
//! `steganographer analyze` — steganalysis (chi-squared test).
//! `steganographer derive` — derive keys from a master secret.

use rand::seq::SliceRandom;
use rand::{Rng, RngCore, SeedableRng};
use serde::Serialize;
use steganographer_core::crypto::{HashAlgorithm, SignaturePayload, Signer};
use steganographer_core::encryption::{self, EncryptionKey};
use steganographer_core::error_correction;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::steganalysis;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};
use steganographer_core::{
    AudioSpatialLsb, CarrierEmbedder, EmbeddingConfig, KeyedAudioSpatialLsb, KeyedSpatialLsb,
    SpatialLsb,
};

use crate::carrier_binding;
use crate::media_io;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_correction: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    pub confidence: f64,
    pub message: String,
}

impl From<steganalysis::DetectionResult> for DetectorResult {
    fn from(value: steganalysis::DetectionResult) -> Self {
        Self {
            detected: value.detected,
            confidence: value.confidence,
            message: value.message,
        }
    }
}

// ─── Keygen ─────────────────────────────────────────────────────────

/// Generate a new Ed25519 key pair and save to files.
pub fn keygen(output_path: &str) -> anyhow::Result<()> {
    let signer = Signer::generate();
    let private_key_path = format!("{}.key", output_path);
    let public_key_path = format!("{}.pub", output_path);
    let private_hex = hex_encode(&signer.signing_key_bytes());
    let public_hex = hex_encode(&signer.verifying_key().to_bytes());

    std::fs::write(&private_key_path, &private_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&private_key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&private_key_path, perms)?;
    }
    std::fs::write(&public_key_path, &public_hex)?;

    log::info!("Private key written to: {} (0600)", private_key_path);
    log::info!("Public key written to:  {}", public_key_path);
    println!("Key pair generated:");
    println!("  Private key: {} (0600)", private_key_path);
    println!("  Public key:  {}", public_key_path);
    println!("  Public key (hex): {}", public_hex);
    Ok(())
}

// ─── Derive Keys ────────────────────────────────────────────────────

/// Derive signing, encryption, and embedding keys from a master secret using
/// the high-entropy BLAKE3 KDF.
pub fn derive_keys(master_secret_hex: &str, output_dir: &str) -> anyhow::Result<()> {
    let master = hex_decode(master_secret_hex)?;
    if master.is_empty() {
        anyhow::bail!("Master secret cannot be empty");
    }

    // Derive keys via the library's KDF module (single source of truth for
    // context strings — previously these were hand-copied here, which risked
    // silent desync if kdf.rs's contexts changed)
    let keys = steganographer_core::kdf::derive_all(&master);
    write_derived_keys(&keys, output_dir)
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
) -> anyhow::Result<()> {
    let salt = match salt_hex {
        Some(hex) => hex_decode(hex)?,
        None => {
            let salt = steganographer_core::password::generate_salt();
            println!(
                "Generated salt (hex, save it to re-derive these keys): {}",
                hex_encode(&salt)
            );
            salt.to_vec()
        }
    };

    let keys = steganographer_core::password::derive_all_from_password(password, &salt, params)
        .map_err(|e| anyhow::anyhow!("Password key derivation failed: {e}"))?;
    write_derived_keys(&keys, output_dir)
}

/// Write a derived key set to `output_dir` as hex files with 0600 permissions.
fn write_derived_keys(
    keys: &steganographer_core::DerivedKeys,
    output_dir: &str,
) -> anyhow::Result<()> {
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

    for (path, key_bytes, desc) in &paths {
        let hex_str = hex_encode(key_bytes);
        std::fs::write(path, &hex_str)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        println!("  {}: {} (0600) — {}", path, hex_str, desc);
    }

    println!("\nKeys derived and written to {}", output_dir);
    Ok(())
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
    if matches!(stego_type, "lsb_video" | "lsb_audio") && !(1..=4).contains(&bits) {
        anyhow::bail!("LSB bits must be in the range 1-4, got {}", bits);
    }

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

    // CLI values take precedence, while values left at their neutral defaults
    // inherit the offline payload configuration. This keeps file and live
    // surfaces aligned without changing legacy defaults.
    let configured_payload = cfg
        .video
        .as_ref()
        .and_then(|video| video.pipeline.as_ref())
        .and_then(|pipeline| pipeline.payload.as_ref());
    let mut effective_opts = opts.clone();
    if let Some(payload) = configured_payload {
        effective_opts.encrypt |= payload.encrypt_enabled();
        effective_opts.ecc |= payload
            .error_correction
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("reed_solomon"));
        if effective_opts.spread == 1 {
            effective_opts.spread = payload.spread_count();
        }
        if effective_opts.encryption_key_file.is_none() && effective_opts.encryption_key.is_none() {
            effective_opts.encryption_key_file = payload.encryption_key_file.clone();
            effective_opts.encryption_key = payload.encryption_key.clone();
        }
    }
    let opts = &effective_opts;

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

    // Resolve hash algorithm
    let hash_algo = opts
        .hash_algorithm
        .as_deref()
        .or(cfg.global.hash_algorithm.as_deref())
        .map(HashAlgorithm::parse)
        .unwrap_or(HashAlgorithm::Blake3);
    log::info!("Hash algorithm: {}", hash_algo.name());

    // Resolve or generate signer
    let mut signer = match &opts.signing_key {
        Some(path) => {
            let key_hex = std::fs::read_to_string(path)?.trim().to_string();
            let key_bytes = hex_decode(&key_hex)?;
            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "Signing key must be 32 bytes (64 hex chars), got {}",
                    key_bytes.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            log::info!("Loaded signing key from {}", path);
            Signer::from_bytes_with_algo(&arr, hash_algo)
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
    let pub_hex = hex_encode(&signer.verifying_key().to_bytes());

    // Resolve encryption key if encryption is enabled
    let enc_key = if opts.encrypt {
        let key = if let Some(ref path) = opts.encryption_key_file {
            let hex_str = std::fs::read_to_string(path)?.trim().to_string();
            EncryptionKey::from_hex(&hex_str)?
        } else if let Some(ref hex_str) = opts.encryption_key {
            EncryptionKey::from_hex(hex_str)?
        } else {
            let k = EncryptionKey::generate();
            log::info!("Generated random encryption key: {}", k.to_hex());
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

    let transformed_payload_len = SignaturePayload::SERIALIZED_SIZE
        + if opts.encrypt { 4 + 16 } else { 0 }
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
    log::info!("Signed frame 0: hash={}", hex_encode(&payload.hash[..8]));

    // Apply encryption if enabled
    let (embed_data, enc_key_hex) = if let Some(ref ek) = enc_key {
        let payload_bytes = payload.to_bytes();
        let encrypted = encryption::encrypt(ek, 0, &payload_bytes, None)?;
        log::info!(
            "Encrypted payload: {} -> {} bytes",
            payload_bytes.len(),
            encrypted.len()
        );
        (encrypted, Some(ek.to_hex()))
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

    let embedding_key = if matches!(stego_type, "lsb_audio" | "spread_spectrum_video") {
        Some(
            resolve_embedding_key(opts, &cfg, stego_type)?.unwrap_or_else(|| {
                let key = generate_random_key();
                log::info!("Generated random embedding key");
                key
            }),
        )
    } else {
        None
    };

    // Apply multi-frame spreading if enabled
    if opts.spread > 1 {
        return encode_multi_frame(
            output,
            &media.data,
            &embed_data,
            stego_type,
            bits,
            format,
            opts,
            &pub_hex,
            &payload,
            enc_key_hex,
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
    let bytes_written = std::fs::metadata(output)?.len() as usize;
    log::info!("Wrote {} encoded bytes to {}", bytes_written, output);

    let result = EncodeResult {
        stego_type: stego_type.to_string(),
        input: input.to_string(),
        output: output.to_string(),
        bytes_written,
        public_key: pub_hex.clone(),
        hash: hex_encode(&payload.hash),
        signature_preview: hex_encode(&payload.signature.to_bytes()[..16]),
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

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&result)?),
        _ => {
            println!("Public key (for verification): {}", pub_hex);
            if let Some(ref ek) = result.encryption_key_hex {
                println!("Encryption key: {}", ek);
            }
            if let Some(ref ak) = result.embedding_key_hex {
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

    // ─── Optional OpenTimestamps post-embed stamping ──────────────────
    // If OTS is enabled in the config, stamp the BLAKE3 hash of the signed
    // carrier data (the same data that was signed above). This is a
    // best-effort, non-blocking operation: if the OTS server is unreachable,
    // the encode still succeeds — the proof is simply absent.
    if cfg.ots_enabled() {
        let ots_cfg = cfg.ots_config();
        log::info!(
            "OTS stamping enabled (method={}, interval={}s)",
            ots_cfg.method,
            ots_cfg.interval_secs
        );
        let client = steganographer_core::OTSClient::from_config(&ots_cfg);
        if client.can_stamp() {
            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(client.stamp_data(&sign_data)) {
                Ok(proof) => {
                    let digest = steganographer_core::OTSClient::compute_sha256_digest(&sign_data);
                    let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                    match client.save_proof(&proof, &digest_hex) {
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
            let key_hex = hex_encode(audio_key);
            let mut samples: Vec<i16> = data
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();
            embed_raw_lsb_audio(&mut samples, payload_bytes, bits, &audio_key)?;
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
            let key_hex = hex_encode(&ss_key);
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

/// Embed raw bytes into video LSB with a 32-bit length prefix.
fn embed_raw_lsb_video(data: &mut [u8], payload: &[u8], bits: u8) -> anyhow::Result<()> {
    let len = payload.len() as u32;
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

/// Embed raw bytes into audio LSB with a 32-bit length prefix.
fn embed_raw_lsb_audio(
    samples: &mut [i16],
    payload: &[u8],
    bits: u8,
    key: &[u8; 32],
) -> anyhow::Result<()> {
    let len = payload.len() as u32;
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
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let mut indices: Vec<usize> = (0..samples.len()).collect();
    indices.shuffle(&mut rng);

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
    for &idx in &indices {
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

/// Embed raw bytes into spread-spectrum video (direct bit embedding).
fn embed_raw_spread_spectrum_video(
    frame: &mut VideoFrame,
    payload: &[u8],
    ss: &steganographer_core::spread_spectrum::SpreadSpectrumVideo,
) -> anyhow::Result<()> {
    let total_bits = 32 + payload.len() * 8;
    let spread = 64; // default
    let needed = total_bits * spread;
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
        let start = bit_pos * spread;
        embed_ss_bit(frame.data, start, bit, bit_pos, frame.frame_index, ss);
    }
    // Embed payload bits
    for (byte_idx, byte) in payload.iter().enumerate() {
        for bit_in_byte in 0..8 {
            let bit = (byte >> bit_in_byte) & 1;
            let payload_bit = 32 + byte_idx * 8 + bit_in_byte;
            let start = payload_bit * spread;
            embed_ss_bit(frame.data, start, bit, payload_bit, frame.frame_index, ss);
        }
    }
    Ok(())
}

fn embed_ss_bit(
    data: &mut [u8],
    start: usize,
    bit: u8,
    bit_pos: usize,
    frame_index: u64,
    ss: &steganographer_core::spread_spectrum::SpreadSpectrumVideo,
) {
    let spread = 64usize;
    let amplitude = 3i32;
    if start + spread > data.len() {
        return;
    }
    // Seed PN sequence using the secret key — matches the extraction side
    // (cmd_verify.rs:extract_ss_bit) and the library (spread_spectrum.rs:pn_sequence).
    // Previously this was `fb ^ bb` only (no key), making embedding fully public
    // and breaking the round-trip with verify.
    let key = ss.key();
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
    let sign = if bit == 1 { 1 } else { -1 };
    for i in 0..spread {
        let val = data[start + i] as i32 + pn[i] * amplitude * sign;
        data[start + i] = val.clamp(0, 255) as u8;
    }
}

// ─── Multi-frame spreading ──────────────────────────────────────────

/// Encode with multi-frame spreading.
fn encode_multi_frame(
    output: &str,
    data: &[u8],
    embed_data: &[u8],
    stego_type: &str,
    bits: u8,
    format: &str,
    opts: &EncodeOptions,
    pub_hex: &str,
    payload: &SignaturePayload,
    enc_key_hex: Option<String>,
) -> anyhow::Result<()> {
    let n = opts.spread as u8;
    log::info!("Multi-frame spreading: {} shards", n);

    let shards = split_raw_shards(embed_data, n)?;

    for (i, shard) in shards.iter().enumerate() {
        let out_path = if opts.spread == 1 {
            output.to_string()
        } else {
            format!("{}_{:03}", output, i + 1)
        };

        let mut frame_data = data.to_vec();
        embed_raw_lsb_video(&mut frame_data, shard, bits)?;
        std::fs::write(&out_path, &frame_data)?;
        log::info!("Shard {} written to {}", i + 1, out_path);
    }

    let result = EncodeResult {
        stego_type: stego_type.to_string(),
        input: output.to_string(),
        output: output.to_string(),
        bytes_written: data.len() * n as usize,
        public_key: pub_hex.to_string(),
        hash: hex_encode(&payload.hash),
        signature_preview: hex_encode(&payload.signature.to_bytes()[..16]),
        bits,
        encrypted: Some(opts.encrypt),
        encryption_key_hex: enc_key_hex,
        error_correction: Some(opts.ecc),
        embedding_key_hex: None,
        spread: Some(opts.spread),
        hash_algorithm: opts.hash_algorithm.clone(),
    };

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&result)?),
        _ => {
            println!("Public key: {}", pub_hex);
            println!("Spread across {} frames", n);
            println!("Shards written to {}_001..{}_{:03}", output, output, n);
        }
    }
    Ok(())
}

/// Split raw data into n shards using XOR sharing.
fn split_raw_shards(data: &[u8], n: u8) -> anyhow::Result<Vec<Vec<u8>>> {
    if n < 2 {
        return Ok(vec![data.to_vec()]);
    }
    let n = n as usize;
    let mut all_masks: Vec<Vec<u8>> = (0..n - 1)
        .map(|_| {
            let mut m = vec![0u8; data.len()];
            rand::rngs::OsRng.fill_bytes(&mut m);
            m
        })
        .collect();

    let mut shard0 = vec![0u8; data.len()];
    let mut all_xor = vec![0u8; data.len()];
    for mask in &all_masks {
        for j in 0..data.len() {
            all_xor[j] ^= mask[j];
        }
    }
    for j in 0..data.len() {
        shard0[j] = data[j] ^ all_xor[j];
    }

    let mut shards = vec![shard0];
    for mask in all_masks.drain(..) {
        shards.push(mask);
    }
    Ok(shards)
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
            let max = if total_bits > 0 {
                capacity_bits / total_bits
            } else {
                0
            };
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
        "json" => println!("{}", serde_json::to_string_pretty(&result)?),
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
/// was made with a revoked key.
pub fn revoke_key(public_key_hex: &str, output_path: &str) -> anyhow::Result<()> {
    // Validate the public key format
    let key_bytes = hex_decode(public_key_hex)?;
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Public key must be 32 bytes (64 hex chars), got {} bytes",
            key_bytes.len()
        );
    }

    // Read existing revoked keys (or start fresh)
    let mut revoked: Vec<String> = if std::path::Path::new(output_path).exists() {
        let content = std::fs::read_to_string(output_path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Check if already revoked
    let key_lower = public_key_hex.to_lowercase();
    if revoked.iter().any(|k| k.to_lowercase() == key_lower) {
        println!("Key already revoked: {}", public_key_hex);
        return Ok(());
    }

    // Add to revoked list
    revoked.push(public_key_hex.to_string());

    // Write back
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&revoked)?;
    std::fs::write(output_path, json)?;

    println!("Key revoked: {}", public_key_hex);
    println!(
        "Revoked-keys list: {} ({} keys total)",
        output_path,
        revoked.len()
    );
    Ok(())
}

pub fn analyze(input: &str, analysis_type: &str, format: &str) -> anyhow::Result<()> {
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

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&result)?),
        _ => {
            println!("File: {}", result.file);
            println!("Analysis: {}", result.analysis_type);
            println!("Detected: {}", if result.detected { "yes" } else { "no" });
            println!("Confidence: {:.1}%", result.confidence * 100.0);
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
                        if detector.detected {
                            "detected"
                        } else {
                            "clear"
                        },
                        detector.confidence * 100.0,
                        detector.message
                    );
                }
            }
        }
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
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
        match run(
            config_path,
            &input_path,
            &output_path,
            stego_type,
            bits,
            format,
            opts,
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

    println!(
        "Batch complete: {} succeeded, {} failed",
        success_count, error_count
    );
    if error_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

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

    let hash_algo = opts
        .hash_algorithm
        .as_deref()
        .map(HashAlgorithm::parse)
        .unwrap_or(HashAlgorithm::Blake3);

    let signer = match &opts.signing_key {
        Some(path) => {
            let key_hex = std::fs::read_to_string(path)?.trim().to_string();
            let key_bytes = hex_decode(&key_hex)?;
            if key_bytes.len() != 32 {
                anyhow::bail!("Signing key must be 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            Signer::from_bytes_with_algo(&arr, hash_algo)
        }
        None => Signer::with_hash_algorithm(
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            hash_algo,
        ),
    };
    let pub_hex = hex_encode(&signer.verifying_key().to_bytes());

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

    std::fs::write(output, &output_data)?;
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
