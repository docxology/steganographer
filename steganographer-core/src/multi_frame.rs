//! Multi-frame signature spreading.
//!
//! Spreads a single cryptographic signature across N consecutive video
//! frames, providing resilience against partial frame loss. Each frame
//! carries a shard of the payload, and extraction requires collecting
//! shards from all N frames to reconstruct the full signature.
//!
//! ## Algorithm
//!
//! Uses XOR secret sharing — an n-of-n threshold scheme (this is **not**
//! Shamir's Secret Sharing, which would allow `k < n` reconstruction):
//!
//! - `n-1` random masks are drawn from the OS CSPRNG.
//! - `shard_0 = payload XOR (mask_0 XOR ... XOR mask_{n-2})`.
//! - `shard_i = mask_{i-1}` for `i = 1..n-1`.
//! - XORing all N shards recovers the payload.
//!
//! Every mask is independent uniform randomness, so each shard is uniformly
//! random on its own and any proper subset reveals nothing about the payload.
//! There is **no** `k < n` threshold recovery: all shards are required, and a
//! lost frame means the signature cannot be reconstructed (the intended
//! fail-closed property for partial frame loss).

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

/// A generic shard of arbitrary payload bytes spread across multiple frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericPayloadShard {
    /// Frame index this shard belongs to.
    pub frame_index: u64,
    /// Shard index (0-based, within the spread group).
    pub shard_index: u8,
    /// Total number of shards in the group.
    pub total_shards: u8,
    /// Shard byte buffer (same size as the original data).
    pub data: Vec<u8>,
}

/// Split arbitrary payload bytes into N shards using XOR secret sharing.
pub fn split_payload_bytes(
    payload: &[u8],
    n: u8,
    base_frame_index: u64,
) -> anyhow::Result<Vec<GenericPayloadShard>> {
    if n < 2 {
        anyhow::bail!("Number of shards must be at least 2, got {}", n);
    }
    if n > 8 {
        anyhow::bail!("Number of shards must be at most 8, got {}", n);
    }
    if payload.is_empty() {
        anyhow::bail!("Cannot split an empty payload");
    }

    let len = payload.len();
    let n = n as usize;

    // Generate n-1 random masks of length `len`
    let mut masks = Vec::with_capacity(n - 1);
    for _ in 0..(n - 1) {
        let mut mask = vec![0u8; len];
        OsRng.fill_bytes(&mut mask);
        masks.push(mask);
    }

    // Shard 0 = payload XOR mask_0 XOR mask_1 ... XOR mask_{n-2}
    let mut shard0 = payload.to_vec();
    for mask in &masks {
        for (byte, m) in shard0.iter_mut().zip(mask.iter()) {
            *byte ^= m;
        }
    }

    let mut shards = Vec::with_capacity(n);
    shards.push(GenericPayloadShard {
        frame_index: base_frame_index,
        shard_index: 0,
        total_shards: n as u8,
        data: shard0,
    });

    for (i, mask) in masks.into_iter().enumerate() {
        shards.push(GenericPayloadShard {
            frame_index: base_frame_index + (i + 1) as u64,
            shard_index: (i + 1) as u8,
            total_shards: n as u8,
            data: mask,
        });
    }

    Ok(shards)
}

/// Reconstruct arbitrary payload bytes from N generic shards.
pub fn reconstruct_payload_bytes(shards: &[GenericPayloadShard]) -> anyhow::Result<Vec<u8>> {
    if shards.is_empty() {
        anyhow::bail!("No shards provided");
    }

    let expected_total = shards[0].total_shards as usize;
    if shards.len() != expected_total {
        anyhow::bail!("Expected {} shards, got {}", expected_total, shards.len());
    }
    if !(2..=8).contains(&expected_total) {
        anyhow::bail!("Invalid shard group size: {}", expected_total);
    }

    let expected_len = shards[0].data.len();
    if expected_len == 0 {
        anyhow::bail!("Shard data must not be empty");
    }

    let mut seen = [false; 8];
    for shard in shards {
        if shard.total_shards as usize != expected_total {
            anyhow::bail!("Inconsistent total_shards across shards");
        }
        if shard.data.len() != expected_len {
            anyhow::bail!("Inconsistent shard data lengths");
        }
        let idx = shard.shard_index as usize;
        if idx >= expected_total {
            anyhow::bail!(
                "Shard index {} out of range for group size {}",
                shard.shard_index,
                expected_total
            );
        }
        if seen[idx] {
            anyhow::bail!("Duplicate shard index {}", shard.shard_index);
        }
        seen[idx] = true;
    }

    let mut sorted: Vec<&GenericPayloadShard> = shards.iter().collect();
    sorted.sort_by_key(|shard| shard.shard_index);

    let mut result = vec![0u8; expected_len];
    for shard in sorted {
        for (r, s) in result.iter_mut().zip(shard.data.iter()) {
            *r ^= s;
        }
    }

    Ok(result)
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
pub fn split(
    payload: &SignaturePayload,
    n: u8,
    base_frame_index: u64,
) -> anyhow::Result<Vec<SignatureShard>> {
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
    for mask in masks.iter_mut().take(n - 1) {
        OsRng.fill_bytes(mask);
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
    for mask in masks.iter().take(n - 1) {
        for (acc, &byte) in all_masks_xor.iter_mut().zip(mask.iter()) {
            *acc ^= byte;
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
/// All shards must be present (n-of-n scheme). The shards are XORed together
/// to recover the original payload.
///
/// Reconstruction validates that the input is a complete, non-duplicated
/// n-of-n cover: every shard must agree on `total_shards` and carry a unique
/// in-range `shard_index`. This turns a duplicate/missing-shard bug into a
/// clear error instead of silently XORing to garbage (which would only fail
/// later on the payload magic check).
///
/// # Arguments
/// * `shards` — All N shards, in any order (canonical order is derived from
///   `shard_index`).
///
/// # Returns
/// The reconstructed [`SignaturePayload`].
pub fn reconstruct(shards: &[SignatureShard]) -> anyhow::Result<SignaturePayload> {
    if shards.is_empty() {
        anyhow::bail!("No shards provided");
    }

    let expected_total = shards[0].total_shards as usize;
    if shards.len() != expected_total {
        anyhow::bail!("Expected {} shards, got {}", expected_total, shards.len());
    }
    if !(2..=8).contains(&expected_total) {
        anyhow::bail!("Invalid shard group size: {}", expected_total);
    }

    // Every shard must agree on the group size and carry a unique, in-range
    // index. Since `shards.len() == expected_total`, uniqueness of indices in
    // `0..expected_total` also guarantees the set is a complete cover.
    let mut seen = [false; 8];
    for shard in shards {
        if shard.total_shards as usize != expected_total {
            anyhow::bail!("Inconsistent total_shards across shards");
        }
        let idx = shard.shard_index as usize;
        if idx >= expected_total {
            anyhow::bail!(
                "Shard index {} out of range for group size {}",
                shard.shard_index,
                expected_total
            );
        }
        if seen[idx] {
            anyhow::bail!("Duplicate shard index {}", shard.shard_index);
        }
        seen[idx] = true;
    }

    // XOR is commutative, but XOR in canonical shard order so the result is
    // deterministic regardless of the caller's ordering.
    let mut sorted: Vec<&SignatureShard> = shards.iter().collect();
    sorted.sort_by_key(|shard| shard.shard_index);

    let mut result = [0u8; SignaturePayload::SERIALIZED_SIZE];
    for shard in sorted {
        for (acc, &byte) in result.iter_mut().zip(shard.data.iter()) {
            *acc ^= byte;
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

    #[test]
    fn test_reconstruct_accepts_any_shard_order() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"order test", None);

        let mut shards = split(&payload, 4, 0).unwrap();
        shards.reverse();

        let reconstructed = reconstruct(&shards).unwrap();
        assert_eq!(reconstructed.frame_index, 0);
        assert_eq!(reconstructed.signature, payload.signature);
    }

    #[test]
    fn test_reconstruct_rejects_duplicate_shard_index() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"dup test", None);

        let mut shards = split(&payload, 2, 0).unwrap();
        // Replace shard 1 with a clone of shard 0: indices become [0, 0], a
        // non-cover. This must error, not silently XOR to zero.
        shards[1] = shards[0].clone();
        assert!(reconstruct(&shards).is_err());
    }

    #[test]
    fn test_reconstruct_rejects_out_of_range_shard_index() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"range test", None);

        let mut shards = split(&payload, 3, 0).unwrap();
        shards[1].shard_index = 9; // out of range for a 3-shard group
        assert!(reconstruct(&shards).is_err());
    }

    #[test]
    fn test_split_reconstruct_payload_bytes() {
        let payload = b"Hello, post-quantum and multi-frame generic packet data!";
        for n in [2, 3, 5, 8] {
            let shards = split_payload_bytes(payload, n, 50).unwrap();
            assert_eq!(shards.len(), n as usize);
            for (i, shard) in shards.iter().enumerate() {
                assert_eq!(shard.shard_index, i as u8);
                assert_eq!(shard.frame_index, 50 + i as u64);
                assert_eq!(shard.data.len(), payload.len());
            }
            let recovered = reconstruct_payload_bytes(&shards).unwrap();
            assert_eq!(recovered, payload);
        }
    }
}
