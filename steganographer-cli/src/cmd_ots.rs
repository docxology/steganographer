//! Standard detached OpenTimestamps proofs for SHA256(file).
//! Pending receipts are explicitly inconclusive; operational failures propagate
//! to the CLI error envelope and nonzero exit status.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
use steganographer_core::{
    crypto::encode_hex,
    ots_client::{OTSClient, OTSMethod},
    ots_config::OtsConfig,
};

#[derive(Debug, Serialize)]
pub struct OtsStampResult {
    pub input: String,
    pub method: String,
    pub digest_hex: String,
    pub digest_scheme: &'static str,
    pub proof_path: String,
    pub proof_bytes: usize,
    pub verified: bool,
    pub pending: bool,
    pub status: String,
    pub message: String,
}
#[derive(Debug, Serialize)]
pub struct OtsVerifyResult {
    pub input: String,
    pub proof_file: String,
    pub digest_hex: String,
    pub digest_scheme: &'static str,
    pub verified: bool,
    pub pending: bool,
    pub method: String,
    pub timestamp: Option<u64>,
    pub details: String,
    pub status: String,
}
pub fn validate_method(method: &str) -> anyhow::Result<()> {
    OTSMethod::parse(method)?;
    Ok(())
}
fn file_digest(path: &str) -> anyhow::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "OTS input must be a regular file"
    );
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().into())
}
fn client(
    config_path: &str,
    output_dir: Option<&str>,
    method: Option<&str>,
) -> anyhow::Result<OTSClient> {
    let cfg = steganographer_core::config::Config::load_optional(config_path)?;
    let mut ots = OtsConfig {
        enabled: true,
        ..cfg.ots_config()
    };
    if let Some(method) = method {
        validate_method(method)?;
        ots.method = method.into();
    }
    if let Some(dir) = output_dir {
        ots.proof_dir = dir.into();
    }
    Ok(OTSClient::from_config(&ots)?)
}
pub fn stamp(
    config_path: &str,
    input: &str,
    output_dir: Option<&str>,
    method: Option<&str>,
    force: bool,
    format: &str,
) -> anyhow::Result<()> {
    if format == "json" {
        crate::envelope::activate_json_mode("ots stamp");
    }
    let client = client(config_path, output_dir, method)?;
    let digest = file_digest(input)?;
    let digest_hex = encode_hex(&digest);
    let path = client.proof_path_for(&digest_hex)?;
    let rt = tokio::runtime::Runtime::new()?;
    let (proof, path, cached) = rt.block_on(async {
        if !force {
            match tokio::fs::symlink_metadata(&path).await {
                Ok(_) => {
                    let proof = OTSClient::load_proof(&path).await?;
                    OTSClient::validate_proof(&proof, &digest)?;
                    return Ok::<_, steganographer_core::OTSError>((proof, path, true));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let proof = if force {
            client.stamp_digest_force(&digest).await?
        } else {
            client.stamp_digest(&digest).await?
        };
        let path = client.save_proof(&proof, &digest_hex).await?;
        Ok((proof, path, false))
    })?;
    let pending = OTSClient::validate_proof(&proof, &digest)?;
    let result = OtsStampResult {
        input: input.into(),
        method: "bitcoin".into(),
        digest_hex,
        digest_scheme: "sha256-file",
        proof_path: path.display().to_string(),
        proof_bytes: proof.len(),
        verified: false,
        pending,
        status: if cached {
            "exists"
        } else if pending {
            "pending"
        } else {
            "stamped"
        }
        .into(),
        message: "Standard detached calendar receipt; Bitcoin confirmation has not been verified"
            .into(),
    };
    if format == "json" {
        crate::envelope::print(&crate::envelope::success(
            "ots stamp",
            serde_json::to_value(&result)?,
        ));
    } else {
        println!(
            "OpenTimestamps: {}\nSHA256: {}\nProof: {}\n{}",
            result.status, result.digest_hex, result.proof_path, result.message
        );
    }
    Ok(())
}
/// If omitted, proof resolves to proof_dir/<SHA256(file)>.ots, matching stamp.
pub fn verify(
    config_path: &str,
    input: &str,
    proof_file: Option<&str>,
    format: &str,
) -> anyhow::Result<()> {
    if format == "json" {
        crate::envelope::activate_json_mode("ots verify");
    }
    let client = client(config_path, None, None)?;
    let digest = file_digest(input)?;
    let digest_hex = encode_hex(&digest);
    let default_path = client.proof_path_for(&digest_hex)?;
    let path = proof_file.map(Path::new).unwrap_or(&default_path);
    let rt = tokio::runtime::Runtime::new()?;
    let verification = rt.block_on(async {
        let proof = OTSClient::load_proof(path).await?;
        let upgraded = client.upgrade(&proof, &digest).await?;
        let result = client.verify_attestations(&upgraded, &digest).await?;
        if upgraded != proof {
            client.save_proof_to(&upgraded, path).await?;
        }
        Ok::<_, steganographer_core::OTSError>(result)
    })?;
    let result = OtsVerifyResult {
        input: input.into(),
        proof_file: path.display().to_string(),
        digest_hex,
        digest_scheme: "sha256-file",
        verified: verification.verified,
        pending: verification.pending,
        method: verification.method,
        timestamp: verification.timestamp,
        details: verification.details,
        status: if verification.verified {
            "verified"
        } else if verification.pending {
            "pending"
        } else {
            "unverified"
        }
        .into(),
    };
    if format == "json" {
        crate::envelope::print(&crate::envelope::success(
            "ots verify",
            serde_json::to_value(&result)?,
        ));
    } else {
        println!(
            "OpenTimestamps: {}\nSHA256: {}\n{}",
            result.status, result.digest_hex, result.details
        );
    }
    Ok(())
}
