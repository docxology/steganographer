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
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};
use steganographer_core::lsb_video::LsbVideo;

// ─── Options & Results ──────────────────────────────────────────────

/// Options controlling the encode process.
pub struct EncodeOptions {
    pub encrypt: bool,
    pub encryption_key: Option<String>,
    pub encryption_key_file: Option<String>,
    pub ecc: bool,
    pub ecc_parity: usize,
    pub spread: u32,
    pub hash_algorithm: Option<String>,
    pub signing_key: Option<String>,
    pub input_format: Option<String>,
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
    pub audio_key_hex: Option<String>,
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
}

/// Machine-readable analysis result.
#[derive(Debug, Serialize)]
pub struct AnalysisResult {
    pub file: String,
    pub analysis_type: String,
    pub chi_squared: f64,
    pub detected: bool,
    pub message: String,
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

/// Derive signing, encryption, and embedding keys from a master secret using HKDF.
pub fn derive_keys(master_secret_hex: &str, output_dir: &str) -> anyhow::Result<()> {
    let master = hex_decode(master_secret_hex)?;
    if master.is_empty() {
        anyhow::bail!("Master secret cannot be empty");
    }

    // Derive keys via the library's KDF module (single source of truth for
    // context strings — previously these were hand-copied here, which risked
    // silent desync if kdf.rs's contexts changed)
    let keys = steganographer_core::kdf::derive_all(&master);

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

    println!("\nKeys derived from master secret and written to {}", output_dir);
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
    log::info!("Encoding: {} -> {}", input, output);
    log::info!("Stego type: {}, bits: {}", stego_type, bits);
    log::info!(
        "Encrypt: {}, ECC: {} (parity={}), Spread: {}",
        opts.encrypt,
        opts.ecc,
        opts.ecc_parity,
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
        }
    });

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
        .unwrap_or_else(|| detect_format(input, stego_type));
    log::info!("Input format: {}", input_format);

    let (mut data, width, height) = read_input(input, &input_format, stego_type)?;
    log::info!("Read {} bytes from {} ({}x{})", data.len(), input, width, height);

    // Prepare the data to sign (the original raw pixel/sample data)
    let sign_data = data.clone();

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

    // Apply multi-frame spreading if enabled
    if opts.spread > 1 {
        return encode_multi_frame(
            output, &data, width, height, &embed_data, stego_type, bits, format, opts, &pub_hex,
            &payload, enc_key_hex,
        );
    }

    // Embed the (possibly encrypted + ECC'd) data into the media
    let stego_result = embed_payload(&mut data, width, height, &embed_data, stego_type, bits, opts)?;

    // Write output (with format)
    write_output(output, &data, &input_format, width, height)?;
    log::info!("Wrote {} bytes to {}", data.len(), output);

    let result = EncodeResult {
        stego_type: stego_type.to_string(),
        input: input.to_string(),
        output: output.to_string(),
        bytes_written: data.len(),
        public_key: pub_hex.clone(),
        hash: hex_encode(&payload.hash),
        signature_preview: hex_encode(&payload.signature.to_bytes()[..16]),
        bits,
        encrypted: Some(opts.encrypt),
        encryption_key_hex: enc_key_hex,
        error_correction: Some(opts.ecc),
        audio_key_hex: stego_result.audio_key_hex,
        spread: if opts.spread > 1 { Some(opts.spread) } else { None },
        hash_algorithm: Some(hash_algo.name().to_string()),
    };

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&result)?),
        _ => {
            println!("Public key (for verification): {}", pub_hex);
            if let Some(ref ek) = result.encryption_key_hex {
                println!("Encryption key: {}", ek);
            }
            if let Some(ref ak) = result.audio_key_hex {
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
    Ok(())
}

// ─── Embedding ──────────────────────────────────────────────────────

struct StegoResult {
    audio_key_hex: Option<String>,
}

/// Embed raw payload bytes into media data using the specified stego type.
fn embed_payload(
    data: &mut [u8],
    width: u32,
    height: u32,
    payload_bytes: &[u8],
    stego_type: &str,
    bits: u8,
    opts: &EncodeOptions,
) -> anyhow::Result<StegoResult> {
    match stego_type {
        "lsb_video" => {
            embed_raw_lsb_video(data, payload_bytes, bits)?;
            Ok(StegoResult { audio_key_hex: None })
        }
        "lsb_audio" => {
            let audio_key = generate_random_key();
            let key_hex = hex_encode(&audio_key);
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
                audio_key_hex: Some(key_hex),
            })
        }
        "spread_spectrum_video" => {
            let ss_key = generate_random_key();
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
                audio_key_hex: Some(key_hex),
            })
        }
        "dct_video" => {
            // DCT embedding for raw-byte payloads is not yet implemented.
            // The core library's DctVideo works with SignaturePayload (structured),
            // but the CLI raw-byte path uses a length-prefixed format that
            // doesn't map cleanly to the block-based DCT embedding.
            // Previously this silently fell back to LSB, which was misleading.
            anyhow::bail!(
                "dct_video CLI stego type is not yet implemented for raw-byte payloads. \
                 Use 'lsb_video' or 'spread_spectrum_video' instead, or use the \
                 GStreamer pipeline which supports DCT via the core library."
            );
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
    let all_bits: Vec<u8> = len_bits.iter().chain(payload_bits.iter()).copied().collect();

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
    let all_bits: Vec<u8> = len_bits.iter().chain(payload_bits.iter()).copied().collect();

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

/// Embed raw bytes into DCT video.
fn embed_raw_dct_video(
    frame: &mut VideoFrame,
    payload: &[u8],
    _dct: &mut steganographer_core::dct_video::DctVideo,
) -> anyhow::Result<()> {
    let total_bits = 32 + payload.len() * 8;
    let (blocks_x, blocks_y) = (frame.width as usize / 8, frame.height as usize / 8);
    let total_blocks = blocks_x * blocks_y;
    if total_blocks < total_bits {
        anyhow::bail!(
            "Not enough DCT blocks: need {}, have {}",
            total_bits,
            total_blocks
        );
    }

    // Use the same DCT embedding logic but with raw bits
    // Length prefix
    let len = payload.len() as u32;
    for bit_pos in 0..32 {
        let bit = ((len >> (31 - bit_pos)) & 1) as u8;
        embed_dct_bit(frame, bit_pos, bit, blocks_x);
    }
    for (byte_idx, byte) in payload.iter().enumerate() {
        for bit_in_byte in 0..8 {
            let bit = (byte >> bit_in_byte) & 1;
            let payload_bit = 32 + byte_idx * 8 + bit_in_byte;
            embed_dct_bit(frame, payload_bit, bit, blocks_x);
        }
    }
    Ok(())
}

fn embed_dct_bit(frame: &mut VideoFrame, payload_bit: usize, bit: u8, blocks_x: usize) {
    // Simplified direct DCT embedding for raw bytes.
    // Falls back to LSB for raw byte case.
    let block_y = payload_bit / blocks_x;
    let block_x = payload_bit % blocks_x;
    let pixel_offset = block_y * 8 * frame.stride as usize + block_x * 8 * 3;
    if pixel_offset < frame.data.len() {
        frame.data[pixel_offset] = (frame.data[pixel_offset] & 0xFE) | bit;
    }
}

// ─── Multi-frame spreading ──────────────────────────────────────────

/// Encode with multi-frame spreading.
fn encode_multi_frame(
    output: &str,
    data: &[u8],
    width: u32,
    height: u32,
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
        write_output(&out_path, &frame_data, "raw_rgb", width, height)?;
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
        audio_key_hex: None,
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
pub fn info(input: &str, stego_type: &str, bits: u8, format: &str) -> anyhow::Result<()> {
    let data = std::fs::read(input)?;
    let payload_size = steganographer_core::crypto::SignaturePayload::SERIALIZED_SIZE;
    let (total_capacity_bytes, max_payloads) = match stego_type {
        "lsb_video" => {
            let capacity_bits = data.len() * bits as usize;
            let total_bits = 32 + payload_size * 8;
            let capacity_bytes = capacity_bits / 8;
            let max = if total_bits > 0 {
                capacity_bits / total_bits
            } else {
                0
            };
            (capacity_bytes, max)
        }
        "lsb_audio" => {
            let sample_count = data.len() / 2;
            let capacity_bits = sample_count * bits as usize;
            let payload_bits = payload_size * 8 + 32;
            let capacity_bytes = capacity_bits / 8;
            let max = if payload_bits > 0 {
                capacity_bits / payload_bits
            } else {
                0
            };
            (capacity_bytes, max)
        }
        "spread_spectrum_video" => {
            let spread = 64;
            let capacity_bytes = data.len() / spread;
            let max = capacity_bytes / payload_size;
            (capacity_bytes, max)
        }
        "dct_video" => {
            let blocks = (data.len() / 3) / 64;
            let max = blocks / (payload_size * 8);
            (blocks, max)
        }
        _ => anyhow::bail!("Unsupported stego type: {}", stego_type),
    };

    let result = CapacityResult {
        file: input.to_string(),
        file_size: data.len(),
        stego_type: stego_type.to_string(),
        bits,
        payload_size,
        total_capacity_bytes,
        max_payloads,
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
        }
    }
    Ok(())
}

// ─── Analyze / Steganalysis ─────────────────────────────────────────

/// Analyze a file for steganographic artifacts using chi-squared test.
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
    println!("Revoked-keys list: {} ({} keys total)", output_path, revoked.len());
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

    let (chi_sq, detected, message) = match analysis_type {
        "chi_squared" => {
            // Chi-squared test on LSB pairs
            let mut pair_counts = [0u64; 128];
            for &byte in &data {
                let v = (byte >> 1) as usize;
                if v < 128 {
                    pair_counts[v] += 1;
                }
            }

            let mut chi_sq = 0.0f64;
            let total = data.len() as f64;
            for i in 0..128 {
                let expected = total / 128.0;
                if expected > 0.0 {
                    let diff = pair_counts[i] as f64 - expected;
                    chi_sq += diff * diff / expected;
                }
            }

            let detected = chi_sq > 200.0;
            let msg = if detected {
                "LSB distribution is non-uniform — possible steganographic embedding detected"
            } else {
                "LSB distribution appears natural — no steganographic embedding detected"
            };
            (chi_sq, detected, msg)
        }
        _ => {
            anyhow::bail!("Unknown analysis type: {}", analysis_type);
        }
    };

    let result = AnalysisResult {
        file: input.to_string(),
        analysis_type: analysis_type.to_string(),
        chi_squared: chi_sq,
        detected,
        message: message.to_string(),
    };

    match &*format {
        "json" => println!("{}", serde_json::to_string_pretty(&result)?),
        _ => {
            println!("File: {}", result.file);
            println!("Analysis: {}", result.analysis_type);
            println!("Chi-squared: {:.2}", result.chi_squared);
            println!(
                "Detected: {}",
                if result.detected { "yes" } else { "no" }
            );
            println!("{}", result.message);
        }
    }
    Ok(())
}

// ─── Format I/O ─────────────────────────────────────────────────────

fn detect_format(path: &str, stego_type: &str) -> String {
    let lower = path.to_lowercase();
    if lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image".to_string()
    } else if lower.ends_with(".wav") {
        "wav".to_string()
    } else if stego_type.contains("audio") {
        "raw_s16le".to_string()
    } else {
        "raw_rgb".to_string()
    }
}

fn read_input(path: &str, format: &str, stego_type: &str) -> anyhow::Result<(Vec<u8>, u32, u32)> {
    match &*format {
        "image" | "png" | "jpg" | "jpeg" => {
            let img =
                image::open(path).map_err(|e| anyhow::anyhow!("Failed to open image: {}", e))?;
            let rgb = img.to_rgb8();
            let (w, h) = (rgb.width(), rgb.height());
            Ok((rgb.into_raw(), w, h))
        }
        "wav" => {
            let reader = hound::WavReader::open(path)?;
            let spec = reader.spec();
            let samples: Vec<i16> = if spec.sample_format == hound::SampleFormat::Int {
                reader.into_samples::<i16>().filter_map(|s| s.ok()).collect()
            } else {
                anyhow::bail!("Only integer PCM WAV files are supported");
            };
            let data: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
            Ok((data, samples.len() as u32, 1))
        }
        _ => {
            let data = std::fs::read(path)?;
            let data_len = data.len();
            if stego_type.contains("audio") {
                Ok((data, data_len as u32 / 2, 1))
            } else {
                let pixel_count = data_len / 3;
                let side = (pixel_count as f64).sqrt() as u32;
                Ok((data, side, side))
            }
        }
    }
}

fn write_output(
    path: &str,
    data: &[u8],
    format: &str,
    width: u32,
    height: u32,
) -> anyhow::Result<()> {
    match format {
        "image" | "png" => {
            let img = image::RgbImage::from_raw(width, height, data.to_vec())
                .ok_or_else(|| anyhow::anyhow!("Failed to create image from raw data"))?;
            img.save(path)
                .map_err(|e| anyhow::anyhow!("Failed to write image: {}", e))?;
        }
        "wav" => {
            let spec = hound::WavSpec {
                channels: 1,
                sample_rate: 44100,
                bits_per_sample: 16,
                sample_format: hound::SampleFormat::Int,
            };
            let mut writer = hound::WavWriter::create(path, spec)?;
            let samples: Vec<i16> = data
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();
            for s in &samples {
                writer.write_sample(*s)?;
            }
            writer.finalize()?;
        }
        _ => {
            std::fs::write(path, data)?;
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
        let output_path = format!("{}/{}", output_dir, path.file_name().unwrap_or_default().to_string_lossy());

        log::info!("Processing: {}", input_path);
        match run(config_path, &input_path, &output_path, stego_type, bits, format, opts) {
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

    println!("Batch complete: {} succeeded, {} failed", success_count, error_count);
    if error_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Encode a multi-frame raw video file.
///
/// Reads a raw RGB file containing multiple frames (each frame = width × height × 3 bytes),
/// signs each frame, embeds a signature in each, and writes the output.
pub fn encode_multi_frame_file(
    config_path: &str,
    input: &str,
    output: &str,
    width: u32,
    height: u32,
    frame_count: u32,
    bits: u8,
    format: &str,
    opts: &EncodeOptions,
) -> anyhow::Result<()> {
    log::info!("Multi-frame encode: {} ({}x{}x{} frames) -> {}", input, width, height, frame_count, output);

    let frame_size = (width * height * 3) as usize;
    let data = std::fs::read(input)?;
    let expected_size = frame_size * frame_count as usize;
    if data.len() < expected_size {
        anyhow::bail!("Input file too small: expected {} bytes ({} frames × {} bytes), got {}",
            expected_size, frame_count, frame_size, data.len());
    }

    let hash_algo = opts.hash_algorithm.as_deref()
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
            width, height, stride: width * 3,
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
    log::info!("Wrote {} bytes ({} frames) to {}", output_data.len(), frame_count, output);

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
                audio_key_hex: None,
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
