//! `steganographer encode` subcommand — offline file-to-file encoding.
//! `steganographer keygen` — generate a new signing key pair.
//! `steganographer info` — report steganographic capacity of a file.

use serde::Serialize;
use steganographer_core::audio::AudioStegoModule;
use steganographer_core::crypto::Signer;
use steganographer_core::encryption::{self, EncryptionKey};
use steganographer_core::error_correction;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

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

/// Generate a new Ed25519 key pair and save to files.
pub fn keygen(output_path: &str) -> anyhow::Result<()> {
    let signer = Signer::generate();

    let private_key_path = format!("{}.key", output_path);
    let public_key_path = format!("{}.pub", output_path);

    let private_hex = hex_encode(&signer.signing_key_bytes());
    let public_hex = hex_encode(&signer.verifying_key().to_bytes());

    // Set restrictive permissions on private key
    std::fs::write(&private_key_path, &private_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&private_key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&private_key_path, perms)?;
    }

    std::fs::write(&public_key_path, &public_hex)?;

    log::info!("Private key written to: {} (permissions: 0600)", private_key_path);
    log::info!("Public key written to:  {}", public_key_path);
    println!("Key pair generated:");
    println!("  Private key: {} (0600)", private_key_path);
    println!("  Public key:  {}", public_key_path);
    println!("  Public key (hex): {}", public_hex);

    Ok(())
}

/// Run offline encoding: read raw pixel data, embed stego, write output.
///
/// Supports:
/// - `lsb_video` — LSB embedding in raw RGB data
/// - `lsb_audio` — LSB embedding in raw S16LE PCM data
/// - `spread_spectrum_video` — Spread-spectrum embedding (noise-resistant)
/// - `dct_video` — DCT-domain embedding (compression-resistant)
pub fn run(
    config_path: &str,
    input: &str,
    output: &str,
    stego_type: &str,
    bits: u8,
    format: &str,
) -> anyhow::Result<()> {
    log::info!("Encoding: {} -> {}", input, output);
    log::info!("Stego type: {}, bits: {}", stego_type, bits);

    let _cfg = steganographer_core::config::Config::from_file(config_path)
        .unwrap_or_else(|e| {
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

    let mut data = std::fs::read(input)?;
    log::info!("Read {} bytes from {}", data.len(), input);

    match stego_type {
        "lsb_video" => {
            let signer = Signer::generate();
            let pub_hex = hex_encode(&signer.verifying_key().to_bytes());
            log::info!("Signing key generated. Public key: {}", pub_hex);

            let pixel_count = data.len() / 3;
            let side = (pixel_count as f64).sqrt() as u32;
            let width = side;
            let height = side;
            let usable = (width * height * 3) as usize;

            if usable > data.len() {
                anyhow::bail!(
                    "Input file too small: need at least {} bytes for {}x{} RGB",
                    usable,
                    width,
                    height
                );
            }

            let payload = signer.sign_frame(0, &data[..usable], None);

            let mut lsb = LsbVideo::new(bits);
            let mut frame = VideoFrame {
                width,
                height,
                stride: width * 3,
                format: VideoFormat::Rgb8,
                data: &mut data[..usable],
                frame_index: 0,
            };

            lsb.embed(&mut frame, Some(&payload))?;
            log::info!("Embedded signature into frame");

            std::fs::write(output, &data)?;
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
                encrypted: None,
                encryption_key_hex: None,
                error_correction: None,
                audio_key_hex: None,
            };

            match format {
                "json" => println!("{}", serde_json::to_string_pretty(&result)?),
                _ => {
                    println!("Public key (for verification): {}", pub_hex);
                    println!("Encoded file written to: {}", output);
                }
            }
        }
        "lsb_audio" => {
            let signer = Signer::generate();
            let pub_hex = hex_encode(&signer.verifying_key().to_bytes());

            // Generate a random audio key instead of using hardcoded zero key
            let audio_key = generate_random_key();
            let audio_key_hex = hex_encode(&audio_key);
            log::info!("Generated audio embedding key: {}", audio_key_hex);

            let mut samples: Vec<i16> = data
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();

            let payload = signer.sign_frame(0, &data, None);

            let mut lsb = steganographer_core::lsb_audio::LsbAudio::new(bits, audio_key);
            let mut buf = steganographer_core::audio::AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };

            lsb.embed(&mut buf, Some(&payload))?;
            log::info!("Embedded signature into audio");

            let output_bytes: Vec<u8> = samples
                .iter()
                .flat_map(|s| s.to_le_bytes())
                .collect();
            std::fs::write(output, &output_bytes)?;

            let result = EncodeResult {
                stego_type: stego_type.to_string(),
                input: input.to_string(),
                output: output.to_string(),
                bytes_written: output_bytes.len(),
                public_key: pub_hex.clone(),
                hash: hex_encode(&payload.hash),
                signature_preview: hex_encode(&payload.signature.to_bytes()[..16]),
                bits,
                encrypted: None,
                encryption_key_hex: None,
                error_correction: None,
                audio_key_hex: Some(audio_key_hex),
            };

            match format {
                "json" => println!("{}", serde_json::to_string_pretty(&result)?),
                _ => {
                    println!("Public key (for verification): {}", pub_hex);
                    println!("Audio key (for extraction): {}", result.audio_key_hex.as_ref().unwrap());
                    println!("Encoded file written to: {}", output);
                }
            }
        }
        "spread_spectrum_video" => {
            let signer = Signer::generate();
            let pub_hex = hex_encode(&signer.verifying_key().to_bytes());
            let ss_key = generate_random_key();
            let ss_key_hex = hex_encode(&ss_key);

            let pixel_count = data.len() / 3;
            let side = (pixel_count as f64).sqrt() as u32;
            let usable = (side * side * 3) as usize;

            let payload = signer.sign_frame(0, &data[..usable], None);

            let mut ss = steganographer_core::spread_spectrum::SpreadSpectrumVideo::with_key(ss_key);
            let mut frame = VideoFrame {
                width: side,
                height: side,
                stride: side * 3,
                format: VideoFormat::Rgb8,
                data: &mut data[..usable],
                frame_index: 0,
            };

            ss.embed(&mut frame, Some(&payload))?;
            std::fs::write(output, &data)?;

            let result = EncodeResult {
                stego_type: stego_type.to_string(),
                input: input.to_string(),
                output: output.to_string(),
                bytes_written: data.len(),
                public_key: pub_hex.clone(),
                hash: hex_encode(&payload.hash),
                signature_preview: hex_encode(&payload.signature.to_bytes()[..16]),
                bits: 0,
                encrypted: None,
                encryption_key_hex: None,
                error_correction: None,
                audio_key_hex: Some(ss_key_hex),
            };

            match format {
                "json" => println!("{}", serde_json::to_string_pretty(&result)?),
                _ => {
                    println!("Public key (for verification): {}", pub_hex);
                    println!("Spread-spectrum key (for extraction): {}", result.audio_key_hex.as_ref().unwrap());
                    println!("Encoded file written to: {}", output);
                }
            }
        }
        "dct_video" => {
            let signer = Signer::generate();
            let pub_hex = hex_encode(&signer.verifying_key().to_bytes());

            let pixel_count = data.len() / 3;
            let side = (pixel_count as f64).sqrt() as u32;
            let usable = (side * side * 3) as usize;

            let payload = signer.sign_frame(0, &data[..usable], None);

            let mut dct = steganographer_core::dct_video::DctVideo::default();
            let mut frame = VideoFrame {
                width: side,
                height: side,
                stride: side * 3,
                format: VideoFormat::Rgb8,
                data: &mut data[..usable],
                frame_index: 0,
            };

            dct.embed(&mut frame, Some(&payload))?;
            std::fs::write(output, &data)?;

            let result = EncodeResult {
                stego_type: stego_type.to_string(),
                input: input.to_string(),
                output: output.to_string(),
                bytes_written: data.len(),
                public_key: pub_hex.clone(),
                hash: hex_encode(&payload.hash),
                signature_preview: hex_encode(&payload.signature.to_bytes()[..16]),
                bits: 0,
                encrypted: None,
                encryption_key_hex: None,
                error_correction: None,
                audio_key_hex: None,
            };

            match format {
                "json" => println!("{}", serde_json::to_string_pretty(&result)?),
                _ => {
                    println!("Public key (for verification): {}", pub_hex);
                    println!("Encoded file written to: {}", output);
                }
            }
        }
        _ => {
            anyhow::bail!("Unsupported stego type: {}. Supported: lsb_video, lsb_audio, spread_spectrum_video, dct_video", stego_type);
        }
    }

    Ok(())
}

/// Report steganographic capacity of a file.
pub fn info(input: &str, stego_type: &str, bits: u8, format: &str) -> anyhow::Result<()> {
    let data = std::fs::read(input)?;
    let payload_size = steganographer_core::crypto::SignaturePayload::SERIALIZED_SIZE;

    let (total_capacity_bytes, max_payloads) = match stego_type {
        "lsb_video" => {
            let capacity_bits = data.len() * bits as usize;
            let prefix_bits = 32;
            let payload_bits = payload_size * 8;
            let total_bits = prefix_bits + payload_bits;
            let capacity_bytes = data.len() * bits as usize / 8;
            let max = if total_bits > 0 { capacity_bits / total_bits } else { 0 };
            (capacity_bytes, max)
        }
        "lsb_audio" => {
            let sample_count = data.len() / 2;
            let capacity_bits = sample_count * bits as usize;
            let payload_bits = payload_size * 8 + 32;
            let capacity_bytes = capacity_bits / 8;
            let max = if payload_bits > 0 { capacity_bits / payload_bits } else { 0 };
            (capacity_bytes, max)
        }
        "spread_spectrum_video" => {
            let spread = 64; // default spread factor
            let capacity_bytes = data.len() / spread;
            let max = capacity_bytes / payload_size;
            (capacity_bytes, max)
        }
        "dct_video" => {
            let blocks = (data.len() / 3) / 64; // rough estimate
            let max = blocks / (payload_size * 8);
            (blocks, max)
        }
        _ => {
            anyhow::bail!("Unsupported stego type: {}", stego_type);
        }
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

/// Generate a random 32-byte key using the OS RNG.
fn generate_random_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
