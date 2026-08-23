//! `steganographer ots` subcommands — OpenTimestamps stamping and verification.
//!
//! `steganographer ots stamp <input> [--output-dir DIR] [--method bitcoin|ethereum]`
//!     Process the input file, build the BLAKE3 hash chain, SHA-256 the
//!     Merkle root, and stamp it with the OTS service. The `.ots` proof
//!     file is saved to the output directory.
//!
//! `steganographer ots verify <input> <proof-file>`
//!     Re-compute the BLAKE3 hash chain, re-derive the Merkle root, SHA-256
//!     it, and verify the provided `.ots` proof file against the OTS service.
//!
//! Both subcommands accept `--format json` for machine-readable output.

use serde::Serialize;
use steganographer_core::hash_chain::HashChain;
use steganographer_core::ots_client::{OTSClient, OTSError, OTSMethod, OTSVResult};
use steganographer_core::ots_config::OtsConfig;

/// Result of the `ots stamp` command (serializable to JSON).
#[derive(Debug, Serialize)]
pub struct OtsStampResult {
    pub input: String,
    pub method: String,
    pub digest_hex: String,
    pub merkle_root_hex: String,
    pub segment_index: usize,
    pub frame_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_path: Option<String>,
    pub proof_bytes: usize,
    pub status: String,
    pub message: String,
}

/// Result of the `ots verify` command (serializable to JSON).
#[derive(Debug, Serialize)]
pub struct OtsVerifyResult {
    pub input: String,
    pub proof_file: String,
    pub digest_hex: String,
    pub merkle_root_hex: String,
    pub verified: bool,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    pub details: String,
    pub status: String,
}

/// Run the `ots stamp` subcommand.
pub fn stamp(
    config_path: &str,
    input: &str,
    output_dir: Option<&str>,
    method: Option<&str>,
    force: bool,
    format: &str,
) -> anyhow::Result<()> {
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

    let ots_cfg = cfg.ots_config();
    let method_name = method.unwrap_or(&ots_cfg.method);
    let ots_method = OTSMethod::parse(method_name);

    // Build the OTS client, overriding the proof dir if the CLI provided one.
    let mut client_builder = OTSClient::from_config(&OtsConfig {
        enabled: true,
        method: method_name.to_string(),
        ..ots_cfg.clone()
    });
    if let Some(dir) = output_dir {
        client_builder = client_builder.with_proof_dir(std::path::PathBuf::from(dir));
    }
    let client = client_builder;

    log::info!("OTS stamp: input={}, method={}", input, ots_method);

    // Read the input file
    let data = std::fs::read(input)
        .map_err(|e| anyhow::anyhow!("Cannot read input file '{}': {}", input, e))?;

    // Build a BLAKE3 hash chain over fixed-size segments of the file.
    // We treat the file as a sequence of 4KB "frames" and build a Merkle
    // tree over each 16-frame segment (matching the streaming pipeline).
    let segment_size = steganographer_core::hash_chain::DEFAULT_SEGMENT_SIZE;
    let chunk_size = 4096;
    let mut chain = HashChain::with_segment_size(segment_size);
    for (frame_index, chunk) in (0_u64..).zip(data.chunks(chunk_size)) {
        chain.add_frame(frame_index, chunk);
    }
    let root = chain
        .build_root()
        .ok_or_else(|| anyhow::anyhow!("input file is empty — nothing to stamp"))?;

    let merkle_root_hex = hex_encode(&root.root_hash);
    log::info!(
        "Merkle root: {} ({} frames, segment {})",
        merkle_root_hex,
        root.segment.frame_count,
        root.segment.segment_index
    );

    // SHA-256 the BLAKE3 Merkle root (OTS protocol requires SHA-256)
    let digest = OTSClient::compute_sha256_digest(&root.root_hash);
    let digest_hex = hex_encode(&digest);
    log::info!("OTS digest (SHA-256 of Merkle root): {}", digest_hex);

    // Check if a proof already exists (unless --force)
    let proof_path = client.proof_path_for(&digest_hex);
    if proof_path.exists() && !force {
        let result = OtsStampResult {
            input: input.to_string(),
            method: ots_method.as_str().to_string(),
            digest_hex: digest_hex.clone(),
            merkle_root_hex,
            segment_index: root.segment.segment_index,
            frame_count: root.segment.frame_count,
            proof_path: Some(proof_path.display().to_string()),
            proof_bytes: std::fs::metadata(&proof_path)
                .map(|m| m.len() as usize)
                .unwrap_or(0),
            status: "exists".to_string(),
            message: format!(
                "Proof already exists at {}; use --force to re-stamp",
                proof_path.display()
            ),
        };
        print_stamp_result(&result, format)?;
        return Ok(());
    }

    // Stamp the digest
    let rt = tokio::runtime::Runtime::new()?;
    let proof_result = rt.block_on(client.stamp_digest(&digest));

    match proof_result {
        Ok(proof) => {
            let saved_path = client.save_proof(&proof, &digest_hex)?;
            let result = OtsStampResult {
                input: input.to_string(),
                method: ots_method.as_str().to_string(),
                digest_hex,
                merkle_root_hex,
                segment_index: root.segment.segment_index,
                frame_count: root.segment.frame_count,
                proof_path: Some(saved_path.display().to_string()),
                proof_bytes: proof.len(),
                status: "stamped".to_string(),
                message: format!("Proof saved to {}", saved_path.display()),
            };
            print_stamp_result(&result, format)?;
            Ok(())
        }
        Err(OTSError::Http(e)) => {
            log::warn!("OTS stamp failed (network): {}", e);
            let result = OtsStampResult {
                input: input.to_string(),
                method: ots_method.as_str().to_string(),
                digest_hex,
                merkle_root_hex,
                segment_index: root.segment.segment_index,
                frame_count: root.segment.frame_count,
                proof_path: None,
                proof_bytes: 0,
                status: "network_error".to_string(),
                message: format!("OTS stamping failed (network): {}", e),
            };
            print_stamp_result(&result, format)?;
            Ok(()) // graceful degradation — don't fail the pipeline
        }
        Err(OTSError::Network(e)) => {
            log::warn!("OTS stamp failed (network): {}", e);
            let result = OtsStampResult {
                input: input.to_string(),
                method: ots_method.as_str().to_string(),
                digest_hex,
                merkle_root_hex,
                segment_index: root.segment.segment_index,
                frame_count: root.segment.frame_count,
                proof_path: None,
                proof_bytes: 0,
                status: "network_error".to_string(),
                message: format!("OTS stamping failed (network): {}", e),
            };
            print_stamp_result(&result, format)?;
            Ok(())
        }
        Err(e) => {
            log::warn!("OTS stamp failed: {}", e);
            let result = OtsStampResult {
                input: input.to_string(),
                method: ots_method.as_str().to_string(),
                digest_hex,
                merkle_root_hex,
                segment_index: root.segment.segment_index,
                frame_count: root.segment.frame_count,
                proof_path: None,
                proof_bytes: 0,
                status: "error".to_string(),
                message: format!("OTS stamping failed: {}", e),
            };
            print_stamp_result(&result, format)?;
            Ok(()) // graceful degradation
        }
    }
}

/// Run the `ots verify` subcommand.
pub fn verify(
    config_path: &str,
    input: &str,
    proof_file: &str,
    format: &str,
) -> anyhow::Result<()> {
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

    let ots_cfg = cfg.ots_config();
    let client = OTSClient::from_config(&OtsConfig {
        enabled: true,
        ..ots_cfg.clone()
    });

    log::info!("OTS verify: input={}, proof={}", input, proof_file);

    // Read the input file and re-compute the Merkle root
    let data = std::fs::read(input)
        .map_err(|e| anyhow::anyhow!("Cannot read input file '{}': {}", input, e))?;

    let segment_size = steganographer_core::hash_chain::DEFAULT_SEGMENT_SIZE;
    let chunk_size = 4096;
    let mut chain = HashChain::with_segment_size(segment_size);
    for (frame_index, chunk) in (0_u64..).zip(data.chunks(chunk_size)) {
        chain.add_frame(frame_index, chunk);
    }
    let root = chain
        .build_root()
        .ok_or_else(|| anyhow::anyhow!("input file is empty — nothing to verify"))?;

    let merkle_root_hex = hex_encode(&root.root_hash);
    let digest = OTSClient::compute_sha256_digest(&root.root_hash);
    let digest_hex = hex_encode(&digest);

    // Load the proof file
    let proof = OTSClient::load_proof(std::path::Path::new(proof_file))
        .map_err(|e| anyhow::anyhow!("Cannot read proof file '{}': {}", proof_file, e))?;

    // Verify the proof
    let rt = tokio::runtime::Runtime::new()?;
    let verify_result: Result<OTSVResult, OTSError> = rt.block_on(client.verify(&proof));

    let result = match verify_result {
        Ok(vr) => OtsVerifyResult {
            input: input.to_string(),
            proof_file: proof_file.to_string(),
            digest_hex,
            merkle_root_hex,
            verified: vr.verified,
            method: vr.method,
            timestamp: vr.timestamp,
            details: vr.details,
            status: if vr.verified {
                "verified".to_string()
            } else {
                "not_verified".to_string()
            },
        },
        Err(OTSError::Http(e)) => {
            log::warn!("OTS verify failed (network): {}", e);
            OtsVerifyResult {
                input: input.to_string(),
                proof_file: proof_file.to_string(),
                digest_hex,
                merkle_root_hex,
                verified: false,
                method: client.method().as_str().to_string(),
                timestamp: None,
                details: format!("verification failed (network): {}", e),
                status: "network_error".to_string(),
            }
        }
        Err(OTSError::Network(e)) => {
            log::warn!("OTS verify failed (network): {}", e);
            OtsVerifyResult {
                input: input.to_string(),
                proof_file: proof_file.to_string(),
                digest_hex,
                merkle_root_hex,
                verified: false,
                method: client.method().as_str().to_string(),
                timestamp: None,
                details: format!("verification failed (network): {}", e),
                status: "network_error".to_string(),
            }
        }
        Err(e) => {
            log::warn!("OTS verify failed: {}", e);
            OtsVerifyResult {
                input: input.to_string(),
                proof_file: proof_file.to_string(),
                digest_hex,
                merkle_root_hex,
                verified: false,
                method: client.method().as_str().to_string(),
                timestamp: None,
                details: format!("verification failed: {}", e),
                status: "error".to_string(),
            }
        }
    };

    print_verify_result(&result, format)?;
    Ok(())
}

fn print_stamp_result(result: &OtsStampResult, format: &str) -> anyhow::Result<()> {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(result)?),
        _ => {
            println!("=== OpenTimestamps Stamp ===");
            println!("  Input:       {}", result.input);
            println!("  Method:      {}", result.method);
            println!("  Digest:      {}", result.digest_hex);
            println!("  Merkle root: {}", result.merkle_root_hex);
            println!(
                "  Segment:     {} ({} frames)",
                result.segment_index, result.frame_count
            );
            if let Some(ref path) = result.proof_path {
                println!("  Proof file:  {} ({} bytes)", path, result.proof_bytes);
            }
            println!("  Status:      {}", result.status);
            println!("  {}", result.message);
        }
    }
    Ok(())
}

fn print_verify_result(result: &OtsVerifyResult, format: &str) -> anyhow::Result<()> {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(result)?),
        _ => {
            let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
            let green = if is_tty { "\x1b[32m" } else { "" };
            let red = if is_tty { "\x1b[31m" } else { "" };
            let bold = if is_tty { "\x1b[1m" } else { "" };
            let reset = if is_tty { "\x1b[0m" } else { "" };

            println!("=== OpenTimestamps Verify ===");
            println!("  Input:       {}", result.input);
            println!("  Proof file:  {}", result.proof_file);
            println!("  Digest:      {}", result.digest_hex);
            println!("  Merkle root: {}", result.merkle_root_hex);
            println!("  Method:      {}", result.method);
            if let Some(ts) = result.timestamp {
                println!("  Timestamp:   {} (Unix)", ts);
            }
            if result.verified {
                println!("  Status:      {green}{bold}\u{2713} VERIFIED{reset}");
            } else {
                println!("  Status:      {red}{bold}\u{2717} NOT VERIFIED{reset}");
            }
            println!("  {}", result.details);
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
