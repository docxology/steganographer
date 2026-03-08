//! `steganographer encode` subcommand — offline file-to-file encoding.
//! `steganographer keygen` — generate a new signing key pair.

use serde::Serialize;
use steganographer_core::audio::AudioStegoModule;
use steganographer_core::crypto::Signer;
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
}

/// Generate a new Ed25519 key pair and save to files.
pub fn keygen(output_path: &str) -> anyhow::Result<()> {
    let signer = Signer::generate();

    let private_key_path = format!("{}.key", output_path);
    let public_key_path = format!("{}.pub", output_path);

    let private_hex = hex_encode(&signer.signing_key_bytes());
    let public_hex = hex_encode(&signer.verifying_key().to_bytes());

    std::fs::write(&private_key_path, &private_hex)?;
    std::fs::write(&public_key_path, &public_hex)?;

    log::info!("Private key written to: {}", private_key_path);
    log::info!("Public key written to:  {}", public_key_path);
    println!("Key pair generated:");
    println!("  Private key: {}", private_key_path);
    println!("  Public key:  {}", public_key_path);
    println!("  Public key (hex): {}", public_hex);

    Ok(())
}

/// Run offline encoding: read raw pixel data, embed stego, write output.
///
/// Currently supports raw RGB files. For production use, integrate with
/// GStreamer's file decoding/encoding pipeline.
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
                },
                video: None,
                audio: None,
            }
        });

    // Read input file
    let mut data = std::fs::read(input)?;
    log::info!("Read {} bytes from {}", data.len(), input);

    match stego_type {
        "lsb_video" => {
            let signer = Signer::generate();
            let pub_hex = hex_encode(&signer.verifying_key().to_bytes());
            log::info!("Signing key generated. Public key: {}", pub_hex);
            println!("Public key (for verification): {}", pub_hex);

            // Assume raw RGB data, compute dimensions from data size
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
            log::info!("Signing key generated. Public key: {}", pub_hex);
            println!("Public key (for verification): {}", pub_hex);

            // Assume raw S16LE PCM data
            let mut samples: Vec<i16> = data
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]))
                .collect();

            let key = [0u8; 32]; // default key for CLI
            let payload = signer.sign_frame(0, &data, None);

            let mut lsb = steganographer_core::lsb_audio::LsbAudio::new(bits, key);
            let mut buf = steganographer_core::audio::AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };

            lsb.embed(&mut buf, Some(&payload))?;
            log::info!("Embedded signature into audio");

            // Convert back to bytes
            let output_bytes: Vec<u8> = samples
                .iter()
                .flat_map(|s| s.to_le_bytes())
                .collect();
            std::fs::write(output, &output_bytes)?;
            log::info!("Wrote {} bytes to {}", output_bytes.len(), output);

            let result = EncodeResult {
                stego_type: stego_type.to_string(),
                input: input.to_string(),
                output: output.to_string(),
                bytes_written: output_bytes.len(),
                public_key: pub_hex.clone(),
                hash: hex_encode(&payload.hash),
                signature_preview: hex_encode(&payload.signature.to_bytes()[..16]),
                bits,
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
            anyhow::bail!("Unsupported stego type: {}", stego_type);
        }
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
