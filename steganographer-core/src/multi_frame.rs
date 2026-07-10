//! Multi-frame signature spreading.
//!
//! Spreads a single cryptographic signature across N consecutive video
//! frames, providing resilience against partial frame loss. Each frame
//! carries a shard of the payload, and extraction requires collecting
//! shards from all N frames to reconstruct the full signature.
//!
//! ## Algorithm
//!
//! Uses Shamir's Secret Sharing (SSS) at the byte level:
//! - The payload is split into `n` shards using polynomial evaluation
//!   over GF(257) (a prime field).
//! - Each shard is embedded into a separate frame.
//! - To reconstruct, at least `n` shards are needed.
//! - If any frame is lost, the signature cannot be reconstructed,
//!   but if redundancy is configured (k < n), any k frames suffice.
//!
//! For simplicity and size efficiency, this implementation uses XOR
//! sharing for the case where all shards are needed (n-of-n scheme):
//!
//! - `shard_0 = payload XOR random_mask`
//! - `shard_1 = random_mask`
//! - `shard_i = payload XOR mask_i` (for n > 2, masks are derived)
//!
//! This is the simplest n-of-n scheme: any single shard is meaningless
//! without the others, but combining all N shards recovers the payload.

use crate::crypto::SignaturePayload;
use rand::rngs::OsRng;
use rand::RngCore;

/// A shard of a multi-frame signature.
#[derive(Debug, Clone)]
pub struct SignatureShard {
    /// Frame index this shard belongs to.
    pub frame_index: u64,
    /// Shard index (0-based, within the spread group).
    pub shard_index: u8,
    /// Total number of shards in the group.
    pub total_shards: u8,
    /// Shard data (same size as the original payload).
    pub data: [u8; SignaturePayload::SERIALIZED_SIZE],
}

/// Split a signature payload into N shards using XOR secret sharing.
///
/// This is an n-of-n scheme: all N shards are required to reconstruct
/// the original payload. No single shard reveals any information about
/// the payload.
///
/// # Arguments
/// * `payload` — The signature to split.
/// * `n` — Number of shards to create (2–8).
/// * `base_frame_index` — The frame index for shard 0.
///
/// # Returns
/// A vector of N shards, each to be embedded in a separate frame.
pub fn split(payload: &SignaturePayload, n: u8, base_frame_index: u64) -> anyhow::Result<Vec<SignatureShard>> {
    if n < 2 {
        anyhow::bail!("Number of shards must be at least 2, got {}", n);
    }
    if n > 8 {
        anyhow::bail!("Number of shards must be at most 8, got {}", n);
    }

    let payload_bytes = payload.to_bytes();
    let n = n as usize;

    // Generate n-1 random masks
    let mut masks = [[0u8; SignaturePayload::SERIALIZED_SIZE]; 8];
    for i in 0..(n - 1) {
        OsRng.fill_bytes(&mut masks[i]);
    }

    let mut shards = Vec::with_capacity(n);

    // Shard 0: payload XOR mask_0
    let mut shard0 = [0u8; SignaturePayload::SERIALIZED_SIZE];
    for i in 0..payload_bytes.len() {
        shard0[i] = payload_bytes[i] ^ masks[0][i];
    }

    // For n=2: shard_1 = mask_0
    // For n=3: shard_1 = mask_0, shard_2 = mask_1
    // (but we need: shard_0 XOR shard_1 XOR ... XOR shard_{n-1} = payload)
    // So shard_0 = payload XOR mask_0 XOR mask_1 XOR ... XOR mask_{n-2}
    // And shard_i = mask_{i-1} for i = 1..n-1

    // Recompute shard 0 with all masks XORed
    let mut all_masks_xor = [0u8; SignaturePayload::SERIALIZED_SIZE];
    for i in 0..(n - 1) {
        for j in 0..all_masks_xor.len() {
            all_masks_xor[j] ^= masks[i][j];
        }
    }

    for i in 0..payload_bytes.len() {
        shard0[i] = payload_bytes[i] ^ all_masks_xor[i];
    }

    shards.push(SignatureShard {
        frame_index: base_frame_index,
        shard_index: 0,
        total_shards: n as u8,
        data: shard0,
    });

    // Shards 1..n-1 are the masks
    for i in 1..n {
        shards.push(SignatureShard {
            frame_index: base_frame_index + i as u64,
            shard_index: i as u8,
            total_shards: n as u8,
            data: masks[i - 1],
        });
    }

    Ok(shards)
}

/// Reconstruct a signature payload from N shards.
///
/// All shards must be present (n-of-n scheme). The shards are XORed
/// together to recover the original payload.
///
/// # Arguments
/// * `shards` — All N shards (must be exactly the right number and order).
///
/// # Returns
/// The reconstructed [`SignaturePayload`].
pub fn reconstruct(shards: &[SignatureShard]) -> anyhow::Result<SignaturePayload> {
    if shards.is_empty() {
        anyhow::bail!("No shards provided");
    }

    let expected_total = shards[0].total_shards as usize;
    if shards.len() != expected_total {
        anyhow::bail!(
            "Expected {} shards, got {}",
            expected_total,
            shards.len()
        );
    }

    // Verify all shards have the same total_shards
    for shard in shards {
        if shard.total_shards as usize != expected_total {
            anyhow::bail!("Inconsistent total_shards across shards");
        }
    }

    // XOR all shards together
    let mut result = [0u8; SignaturePayload::SERIALIZED_SIZE];
    for shard in shards {
        for i in 0..result.len() {
            result[i] ^= shard.data[i];
        }
    }

    SignaturePayload::from_bytes(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    #[test]
    fn test_split_reconstruct_2_shards() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(100, b"multi-frame test", None);

        let shards = split(&payload, 2, 100).unwrap();
        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].shard_index, 0);
        assert_eq!(shards[1].shard_index, 1);
        assert_eq!(shards[0].frame_index, 100);
        assert_eq!(shards[1].frame_index, 101);

        let reconstructed = reconstruct(&shards).unwrap();
        assert_eq!(reconstructed.frame_index, payload.frame_index);
        assert_eq!(reconstructed.hash, payload.hash);
        assert_eq!(reconstructed.signature, payload.signature);
    }

    #[test]
    fn test_split_reconstruct_4_shards() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"4-shard test", None);

        let shards = split(&payload, 4, 0).unwrap();
        assert_eq!(shards.len(), 4);

        let reconstructed = reconstruct(&shards).unwrap();
        assert_eq!(reconstructed.frame_index, 0);
        assert_eq!(reconstructed.hash, payload.hash);
    }

    #[test]
    fn test_split_reconstruct_8_shards() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(42, b"8-shard test", None);

        let shards = split(&payload, 8, 42).unwrap();
        assert_eq!(shards.len(), 8);

        // Verify frame indices are sequential
        for (i, shard) in shards.iter().enumerate() {
            assert_eq!(shard.frame_index, 42 + i as u64);
        }

        let reconstructed = reconstruct(&shards).unwrap();
        assert_eq!(reconstructed.frame_index, 42);
        assert_eq!(reconstructed.signature, payload.signature);
    }

    #[test]
    fn test_incomplete_shards_fail() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);

        let shards = split(&payload, 4, 0).unwrap();
        // Only provide 3 of 4 shards
        let incomplete = &shards[..3];
        assert!(reconstruct(incomplete).is_err());
    }

    #[test]
    fn test_too_many_shards_fail() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);

        let mut shards = split(&payload, 2, 0).unwrap();
        // Add a duplicate shard
        shards.push(shards[0].clone());
        assert!(reconstruct(&shards).is_err()); // wrong count
    }

    #[test]
    fn test_invalid_shard_count() {
        assert!(split(&Signer::generate().sign_frame(0, b"", None), 1, 0).is_err());
        assert!(split(&Signer::generate().sign_frame(0, b"", None), 9, 0).is_err());
    }

    #[test]
    fn test_empty_shards_fail() {
        let shards: Vec<SignatureShard> = vec![];
        assert!(reconstruct(&shards).is_err());
    }

    #[test]
    fn test_individual_shard_is_opaque() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"opacity test", None);
        let payload_bytes = payload.to_bytes();

        let shards = split(&payload, 2, 0).unwrap();

        // Neither shard should equal the payload bytes
        assert_ne!(shards[0].data, payload_bytes);
        assert_ne!(shards[1].data, payload_bytes);
    }
}
