//! `steganographer verify` subcommand — signature verification.
//!
//! Supports `--format plain` (default) and `--format json` for machine-readable output.

use serde::Serialize;
use steganographer_core::audio::AudioStegoModule;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

/// Machine-readable verification result (serializable to JSON).
#[derive(Debug, Serialize)]
pub struct VerifyResult {
    /// Whether a steganographic payload was found
    pub found: bool,
    /// The steganography type used
    pub stego_type: String,
    /// Frame/buffer index from the extracted payload
    pub frame_index: Option<u64>,
    /// BLAKE3 hash (hex-encoded) from the extracted payload
    pub hash: Option<String>,
    /// First 16 bytes of the signature (hex-encoded)
    pub signature_preview: Option<String>,
    /// Verification status: "valid", "invalid", "not_verified", "no_signature"
    pub status: String,
    /// Human-readable status message
    pub message: String,
}

pub fn run(
    config_path: &str,
    input: &str,
    public_key_hex: Option<&str>,
    stego_type: &str,
    format: &str,
) -> anyhow::Result<()> {
    log::info!("Verifying: {}", input);
    log::info!("Stego type: {}", stego_type);
    log::info!("Output format: {}", format);

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

    let mut data = std::fs::read(input)?;
    log::info!("Read {} bytes from {}", data.len(), input);

    let result = match stego_type {
        "lsb_video" => verify_video(&mut data, public_key_hex, stego_type),
        "lsb_audio" => verify_audio(&mut data, public_key_hex, stego_type),
        _ => Err(anyhow::anyhow!("Unsupported stego type: {}", stego_type)),
    }?;

    // Output based on format
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&result)?;
            println!("{}", json);
        }
        _ => {
            // Plain text output (original format)
            print_plain(&result);
        }
    }

    Ok(())
}

fn verify_video(
    data: &mut [u8],
    public_key_hex: Option<&str>,
    stego_type: &str,
) -> anyhow::Result<VerifyResult> {
    let pixel_count = data.len() / 3;
    let side = (pixel_count as f64).sqrt() as u32;
    let width = side;
    let height = side;
    let usable = (width * height * 3) as usize;

    let lsb = LsbVideo::new(1);
    let frame = VideoFrame {
        width,
        height,
        stride: width * 3,
        format: VideoFormat::Rgb8,
        data: &mut data[..usable],
        frame_index: 0,
    };

    let extraction = lsb.extract(&frame)?;
    match extraction {
        Some(payload) => {
            let hash_hex = hex_encode(&payload.hash);
            let sig_preview = hex_encode(&payload.signature.to_bytes()[..16]);

            let (status, message) = if let Some(pk_hex) = public_key_hex {
                let pk_bytes = hex_decode(pk_hex)?;
                if pk_bytes.len() != 32 {
                    anyhow::bail!("Public key must be 32 bytes (64 hex chars)");
                }
                let mut pk_arr = [0u8; 32];
                pk_arr.copy_from_slice(&pk_bytes);
                let verifier =
                    steganographer_core::crypto::Verifier::from_bytes(&pk_arr)?;
                let is_valid =
                    verifier.verify(&payload, &data[..usable], None);

                if is_valid {
                    log::info!("Signature verification: VALID");
                    ("valid".to_string(), "Signature is valid".to_string())
                } else {
                    log::warn!("Signature verification: INVALID");
                    ("invalid".to_string(), "Signature is INVALID".to_string())
                }
            } else {
                ("not_verified".to_string(), "No public key provided — signature not verified".to_string())
            };

            Ok(VerifyResult {
                found: true,
                stego_type: stego_type.to_string(),
                frame_index: Some(payload.frame_index),
                hash: Some(hash_hex),
                signature_preview: Some(sig_preview),
                status,
                message,
            })
        }
        None => Ok(VerifyResult {
            found: false,
            stego_type: stego_type.to_string(),
            frame_index: None,
            hash: None,
            signature_preview: None,
            status: "no_signature".to_string(),
            message: "No steganographic signature found in the file".to_string(),
        }),
    }
}

fn verify_audio(
    data: &mut [u8],
    public_key_hex: Option<&str>,
    stego_type: &str,
) -> anyhow::Result<VerifyResult> {
    let mut samples: Vec<i16> = data
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    let key = [0u8; 32];
    let lsb = steganographer_core::lsb_audio::LsbAudio::new(1, key);
    let buf = steganographer_core::audio::AudioBuffer {
        channels: 1,
        sample_rate: 44100,
        samples: &mut samples,
        frame_index: 0,
    };

    let extraction = lsb.extract(&buf)?;
    match extraction {
        Some(payload) => {
            let hash_hex = hex_encode(&payload.hash);
            let sig_preview = hex_encode(&payload.signature.to_bytes()[..16]);

            let (status, message) = if let Some(pk_hex) = public_key_hex {
                let pk_bytes = hex_decode(pk_hex)?;
                let mut pk_arr = [0u8; 32];
                pk_arr.copy_from_slice(&pk_bytes);
                let verifier =
                    steganographer_core::crypto::Verifier::from_bytes(&pk_arr)?;
                let raw_bytes: Vec<u8> =
                    samples.iter().flat_map(|s| s.to_le_bytes()).collect();
                if verifier.verify(&payload, &raw_bytes, None) {
                    ("valid".to_string(), "Audio signature is valid".to_string())
                } else {
                    ("invalid".to_string(), "Audio signature is INVALID".to_string())
                }
            } else {
                ("not_verified".to_string(), "No public key provided".to_string())
            };

            Ok(VerifyResult {
                found: true,
                stego_type: stego_type.to_string(),
                frame_index: Some(payload.frame_index),
                hash: Some(hash_hex),
                signature_preview: Some(sig_preview),
                status,
                message,
            })
        }
        None => Ok(VerifyResult {
            found: false,
            stego_type: stego_type.to_string(),
            frame_index: None,
            hash: None,
            signature_preview: None,
            status: "no_signature".to_string(),
            message: "No steganographic signature found in the audio file".to_string(),
        }),
    }
}

fn print_plain(result: &VerifyResult) {
    // ANSI color codes (only if stdout is a terminal)
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let green = if is_tty { "\x1b[32m" } else { "" };
    let red = if is_tty { "\x1b[31m" } else { "" };
    let yellow = if is_tty { "\x1b[33m" } else { "" };
    let cyan = if is_tty { "\x1b[36m" } else { "" };
    let bold = if is_tty { "\x1b[1m" } else { "" };
    let reset = if is_tty { "\x1b[0m" } else { "" };

    if result.found {
        let label = if result.stego_type == "lsb_audio" {
            "=== Audio Signature Found ==="
        } else {
            "=== Signature Found ==="
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
        match result.status.as_str() {
            "valid" => println!("  Status:      {green}{bold}✓ VALID{reset}"),
            "invalid" => println!("  Status:      {red}{bold}✗ INVALID{reset}"),
            "not_verified" => {
                println!("  Status:      {yellow}⚠ No public key provided (signature not verified){reset}");
                println!("  Tip:         Pass --public-key <hex> to verify the signature");
            }
            _ => {}
        }
    } else {
        println!("{yellow}{}{reset}", result.message);
        log::info!("No signature found");
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
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
