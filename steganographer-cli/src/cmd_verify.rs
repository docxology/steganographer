//! `steganographer verify` subcommand — signature verification.
//!
//! Supports all stego types, payload encryption, error correction,
//! multi-frame spreading, and configurable hash algorithms.

use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use steganographer_core::crypto::{HashAlgorithm, SignaturePayload, Verifier};
use steganographer_core::encryption;
use steganographer_core::error_correction;

// ─── Options & Results ──────────────────────────────────────────────

/// Options controlling the verify process.
pub struct VerifyOptions {
    pub decrypt: bool,
    pub decryption_key: Option<String>,
    pub decryption_key_file: Option<String>,
    pub ecc: bool,
    pub ecc_parity: usize,
    pub spread: u32,
    pub hash_algorithm: Option<String>,
    pub input_format: Option<String>,
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
        decrypt: false,
        decryption_key: None,
        decryption_key_file: None,
        ecc: false,
        ecc_parity: 4,
        spread: 1,
        hash_algorithm: None,
        input_format: None,
    };
    run_with_key(config_path, input, public_key_hex, stego_type, format, None, &opts)
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
        }
    });

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
        .unwrap_or_else(|| detect_format(input, stego_type));

    // Read input
    let (data, width, height) = read_input(input, &input_format, stego_type)?;
    log::info!("Read {} bytes from {}", data.len(), input);

    // Multi-frame: read all files and reconstruct
    if opts.spread > 1 {
        return verify_multi_frame(
            input, &data, width, height, public_key_hex, stego_type, format,
            embedding_key_hex, opts, &hash_algo,
        );
    }

    // Extract raw payload bytes from the media
    let extracted = extract_payload(&data, width, height, stego_type, embedding_key_hex, opts)?;
    let raw_data = match extracted {
        Some(bytes) => bytes,
        None => {
            let result = VerifyResult {
                found: false,
                stego_type: stego_type.to_string(),
                frame_index: None,
                hash: None,
                signature_preview: None,
                status: "no_signature".to_string(),
                message: "No steganographic signature found in the file".to_string(),
                encrypted: None,
                ecc_corrected: None,
                hash_algorithm: Some(hash_algo.name().to_string()),
            };
            print_result(&result, format)?;
            return Ok(());
        }
    };

    // Apply error correction if enabled
    let payload_data = if opts.ecc {
        let data_len = raw_data.len().saturating_sub(opts.ecc_parity);
        match error_correction::decode(&raw_data, data_len, opts.ecc_parity) {
            Ok(decoded) => {
                log::info!("RS decoded: {} -> {} bytes", raw_data.len(), decoded.len());
                decoded
            }
            Err(e) => {
                log::warn!("RS decode failed: {}, using raw data", e);
                raw_data[..data_len].to_vec()
            }
        }
    } else {
        raw_data
    };

    // Check if the payload data looks like a valid SignaturePayload
    if payload_data.len() >= SignaturePayload::SERIALIZED_SIZE {
        let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
        let len = arr.len();
        arr.copy_from_slice(&payload_data[..len]);

        if SignaturePayload::has_valid_magic(&arr) {
            // Direct SignaturePayload
            let payload = SignaturePayload::from_bytes(&arr)?;
            return finish_verification(
                payload, &data, public_key_hex, stego_type, format, false, false, &hash_algo,
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
                    payload, &data, public_key_hex, stego_type, format, true, opts.ecc, &hash_algo,
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
        encrypted: Some(opts.decrypt),
        ecc_corrected: Some(opts.ecc),
        hash_algorithm: Some(hash_algo.name().to_string()),
    };
    print_result(&result, format)?;
    Ok(())
}

// ─── Verification finalization ──────────────────────────────────────

fn finish_verification(
    payload: SignaturePayload,
    data: &[u8],
    public_key_hex: Option<&str>,
    stego_type: &str,
    format: &str,
    was_encrypted: bool,
    was_ecc: bool,
    hash_algo: &HashAlgorithm,
) -> anyhow::Result<()> {
    let hash_hex = hex_encode(&payload.hash);
    let sig_preview = hex_encode(&payload.signature.to_bytes()[..16]);

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
        let is_valid = verifier.verify(&payload, data, None);
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
        encrypted: Some(was_encrypted),
        ecc_corrected: Some(was_ecc),
        hash_algorithm: Some(hash_algo.name().to_string()),
    };
    print_result(&result, format)?;
    Ok(())
}

// ─── Extraction ─────────────────────────────────────────────────────

/// Extract raw payload bytes from media.
fn extract_payload(
    data: &[u8],
    width: u32,
    height: u32,
    stego_type: &str,
    embedding_key_hex: Option<&str>,
    opts: &VerifyOptions,
) -> anyhow::Result<Option<Vec<u8>>> {
    match stego_type {
        "lsb_video" => {
            let bits = 1u8; // verify always uses 1-bit
            extract_raw_lsb_video(data, bits)
        }
        "lsb_audio" => {
            let key_hex = embedding_key_hex.ok_or_else(|| {
                anyhow::anyhow!("Audio verification requires --embedding-key")
            })?;
            let key_bytes = hex_decode(key_hex)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            let samples: Vec<i16> = data
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();
            extract_raw_lsb_audio(&samples, 1, &arr)
        }
        "spread_spectrum_video" => {
            let key_hex = embedding_key_hex.ok_or_else(|| {
                anyhow::anyhow!("Spread-spectrum verification requires --embedding-key")
            })?;
            let key_bytes = hex_decode(key_hex)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            extract_raw_ss_video(data, &arr)
        }
        "dct_video" => {
            // DCT extraction of raw bytes is not yet implemented.
            // The core library's DctVideo works with SignaturePayload (structured),
            // not the length-prefixed raw-byte format used by the CLI.
            anyhow::bail!(
                "dct_video verification is not yet implemented for raw-byte payloads. \
                 Use 'lsb_video' or 'spread_spectrum_video' instead, or use the \
                 GStreamer pipeline which supports DCT via the core library."
            );
        }
        _ => Ok(None),
    }
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
    for byte_idx in 0..result.len() {
        for bit_in_byte in 0..8 {
            let payload_bit = 32 + byte_idx * 8 + bit_in_byte;
            let start = payload_bit * spread;
            let bit = extract_ss_bit(data, start, payload_bit, 0, key);
            result[byte_idx] |= bit << bit_in_byte;
        }
    }
    Ok(Some(result))
}

fn extract_ss_bit(data: &[u8], start: usize, bit_pos: usize, frame_index: u64, key: &[u8; 32]) -> u8 {
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

fn verify_multi_frame(
    input: &str,
    data: &[u8],
    width: u32,
    height: u32,
    public_key_hex: Option<&str>,
    stego_type: &str,
    format: &str,
    embedding_key_hex: Option<&str>,
    opts: &VerifyOptions,
    hash_algo: &HashAlgorithm,
) -> anyhow::Result<()> {
    let n = opts.spread as usize;
    log::info!("Multi-frame verify: reading {} shards", n);

    let mut shards: Vec<Vec<u8>> = Vec::new();
    for i in 0..n {
        let shard_path = format!("{}_{:03}", input, i + 1);
        let shard_data = std::fs::read(&shard_path)
            .map_err(|e| anyhow::anyhow!("Failed to read shard {}: {}", i + 1, e))?;
        let extracted = extract_raw_lsb_video(&shard_data, 1)?;
        if let Some(s) = extracted {
            shards.push(s);
        } else {
            anyhow::bail!("Failed to extract shard {}", i + 1);
        }
    }

    // XOR all shards to reconstruct
    let mut payload_bytes = vec![0u8; shards[0].len()];
    for shard in &shards {
        for j in 0..payload_bytes.len().min(shard.len()) {
            payload_bytes[j] ^= shard[j];
        }
    }

    // Try to parse as SignaturePayload
    if payload_bytes.len() >= SignaturePayload::SERIALIZED_SIZE {
        let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
        let len = arr.len();
        arr.copy_from_slice(&payload_bytes[..len]);
        if SignaturePayload::has_valid_magic(&arr) {
            let payload = SignaturePayload::from_bytes(&arr)?;
            return finish_verification(
                payload, data, public_key_hex, stego_type, format, opts.decrypt, opts.ecc, hash_algo,
            );
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
        encrypted: None,
        ecc_corrected: None,
        hash_algorithm: Some(hash_algo.name().to_string()),
    };
    print_result(&result, format)?;
    Ok(())
}

// ─── Key resolution ─────────────────────────────────────────────────

fn resolve_decryption_key(opts: &VerifyOptions) -> anyhow::Result<encryption::EncryptionKey> {
    if let Some(ref path) = opts.decryption_key_file {
        let hex_str = std::fs::read_to_string(path)?.trim().to_string();
        encryption::EncryptionKey::from_hex(&hex_str)
    } else if let Some(ref hex_str) = opts.decryption_key {
        encryption::EncryptionKey::from_hex(hex_str)
    } else {
        anyhow::bail!("Decryption enabled but no key provided (--decryption-key or --decryption-key-file)")
    }
}

// ─── Output ─────────────────────────────────────────────────────────

fn print_result(result: &VerifyResult, format: &str) -> anyhow::Result<()> {
    match &*format {
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
    if s.len() % 2 != 0 {
        anyhow::bail!("Hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))
        })
        .collect()
}
