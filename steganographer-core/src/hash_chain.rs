//! Merkle tree / hash chain for streaming authentication.
//!
//! Builds a tamper-evident hash chain over video frames, where each frame's
//! hash covers the previous frame's hash. Frames are grouped into N-frame
//! segments and a Merkle root is computed over each segment.
//!
//! ## Overview
//!
//! - [`HashChain`] accumulates frame hashes sequentially.
//! - [`MerkleRoot`] captures the root hash plus segment metadata (frame range, count).
//! - [`HashChain::verify_chain`] recomputes the Merkle root from a set of frames
//!   and compares it to a known-good root.
//!
//! The chain uses BLAKE3 for all hashing.

use blake3::Hasher;

/// Number of frames per Merkle tree segment.
pub const DEFAULT_SEGMENT_SIZE: usize = 16;

/// A 32-byte hash (BLAKE3 digest).
pub type FrameHash = [u8; 32];

/// Metadata describing a Merkle tree segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMeta {
    /// Index of the first frame in the segment.
    pub start_frame: u64,
    /// Number of frames in the segment.
    pub frame_count: usize,
    /// 0-based segment index.
    pub segment_index: usize,
}

/// Merkle root for a segment of frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleRoot {
    /// The root hash of the Merkle tree.
    pub root_hash: FrameHash,
    /// Segment metadata.
    pub segment: SegmentMeta,
    /// Hash of the last frame in the segment (for chaining).
    pub last_frame_hash: FrameHash,
}

/// A tamper-evident hash chain that builds Merkle trees over N-frame segments.
///
/// Each frame's hash incorporates the previous frame's hash, creating an
/// unbreakable chain. When `segment_size` frames have been added, a Merkle
/// root is computed over the segment.
pub struct HashChain {
    /// Number of frames per segment.
    segment_size: usize,
    /// Collected frame hashes for the current segment.
    segment_hashes: Vec<FrameHash>,
    /// Frame indices in the current segment.
    segment_indices: Vec<u64>,
    /// Completed segment roots.
    completed_roots: Vec<MerkleRoot>,
    /// The previous frame's hash (for chaining). Zero for the first frame.
    prev_hash: FrameHash,
    /// Total frames added.
    total_frames: u64,
    /// Current segment index.
    segment_index: usize,
}

impl HashChain {
    /// Create a new hash chain with the default segment size (16 frames).
    pub fn new() -> Self {
        Self::with_segment_size(DEFAULT_SEGMENT_SIZE)
    }

    /// Create a new hash chain with a custom segment size.
    pub fn with_segment_size(segment_size: usize) -> Self {
        assert!(segment_size > 0, "segment_size must be > 0");
        Self {
            segment_size,
            segment_hashes: Vec::with_capacity(segment_size),
            segment_indices: Vec::with_capacity(segment_size),
            completed_roots: Vec::new(),
            prev_hash: [0u8; 32],
            total_frames: 0,
            segment_index: 0,
        }
    }

    /// Add a frame to the chain.
    ///
    /// Computes `BLAKE3(frame_index || prev_hash || data)` and stores it.
    /// When the segment is full, a Merkle root is automatically computed.
    ///
    /// Returns the computed frame hash.
    pub fn add_frame(&mut self, frame_index: u64, data: &[u8]) -> FrameHash {
        let mut hasher = Hasher::new();
        hasher.update(&frame_index.to_le_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(data);
        let hash = *hasher.finalize().as_bytes();

        self.segment_hashes.push(hash);
        self.segment_indices.push(frame_index);
        self.prev_hash = hash;
        self.total_frames += 1;

        // If segment is full, compute the Merkle root
        if self.segment_hashes.len() >= self.segment_size {
            self.finalize_segment();
        }

        hash
    }

    /// Finalize the current segment, computing its Merkle root.
    fn finalize_segment(&mut self) {
        if self.segment_hashes.is_empty() {
            return;
        }

        let start_frame = *self.segment_indices.first().unwrap_or(&0);
        let frame_count = self.segment_hashes.len();
        let last_frame_hash = *self.segment_hashes.last().unwrap_or(&[0u8; 32]);

        let root_hash = compute_merkle_root(&self.segment_hashes);

        let root = MerkleRoot {
            root_hash,
            segment: SegmentMeta {
                start_frame,
                frame_count,
                segment_index: self.segment_index,
            },
            last_frame_hash,
        };

        self.completed_roots.push(root);
        self.segment_hashes.clear();
        self.segment_indices.clear();
        self.segment_index += 1;
    }

    /// Build and return the Merkle root for the current (possibly partial) segment.
    ///
    /// This does NOT clear the segment — it computes a root over whatever
    /// frames have been added since the last completed segment. If the segment
    /// is full, it returns the already-computed root.
    pub fn build_root(&mut self) -> Option<MerkleRoot> {
        if !self.segment_hashes.is_empty() {
            self.finalize_segment();
        }
        self.completed_roots.last().cloned()
    }

    /// Get all completed segment roots.
    pub fn completed_segments(&self) -> &[MerkleRoot] {
        &self.completed_roots
    }

    /// Get the total number of frames added.
    pub fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// Get the current segment size.
    pub fn segment_size(&self) -> usize {
        self.segment_size
    }

    /// Verify a chain of frames against a known Merkle root.
    ///
    /// Recomputes the hash chain and Merkle tree from the given frames
    /// and compares the root hash to the provided root.
    ///
    /// # Arguments
    /// * `frames` — Slice of `(frame_index, data)` tuples.
    /// * `root` — The expected Merkle root.
    ///
    /// Returns `true` if the recomputed root matches.
    pub fn verify_chain(frames: &[(u64, &[u8])], root: &MerkleRoot) -> bool {
        if frames.is_empty() {
            return false;
        }

        let mut prev_hash: FrameHash = [0u8; 32];
        let mut segment_hashes: Vec<FrameHash> = Vec::new();

        for &(frame_index, data) in frames {
            let mut hasher = Hasher::new();
            hasher.update(&frame_index.to_le_bytes());
            hasher.update(&prev_hash);
            hasher.update(data);
            let hash = *hasher.finalize().as_bytes();
            segment_hashes.push(hash);
            prev_hash = hash;
        }

        // Check frame count matches
        if segment_hashes.len() != root.segment.frame_count {
            return false;
        }

        // Check last frame hash (chain continuity)
        if segment_hashes.last() != Some(&root.last_frame_hash) {
            return false;
        }

        // Recompute Merkle root
        let computed_root = compute_merkle_root(&segment_hashes);
        computed_root == root.root_hash
    }
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a Merkle root over a list of leaf hashes.
///
/// - If there's one leaf, it is the root.
/// - If the number of leaves is odd, the last leaf is duplicated.
/// - Pairs are hashed: `BLAKE3(left || right)`.
/// - This repeats until a single root remains.
pub fn compute_merkle_root(leaves: &[FrameHash]) -> FrameHash {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut level: Vec<FrameHash> = leaves.to_vec();

    while level.len() > 1 {
        // Duplicate last element if odd
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }

        let mut next_level: Vec<FrameHash> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut hasher = Hasher::new();
            hasher.update(&pair[0]);
            hasher.update(&pair[1]);
            next_level.push(*hasher.finalize().as_bytes());
        }
        level = next_level;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_new_chain_is_empty() {
        let chain = HashChain::new();
        assert_eq!(chain.total_frames(), 0);
        assert_eq!(chain.segment_size(), DEFAULT_SEGMENT_SIZE);
        assert!(chain.completed_segments().is_empty());
    }

    #[test]
    fn test_add_frame_returns_hash() {
        let mut chain = HashChain::new();
        let data = dummy_data(100);
        let hash = chain.add_frame(0, &data);

        // Hash should be non-zero (BLAKE3 of non-empty data)
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(chain.total_frames(), 1);
    }

    #[test]
    fn test_chain_linkage() {
        // Each frame hash should depend on the previous frame's hash
        let mut chain = HashChain::new();
        let data0 = dummy_data(50);
        let data1 = dummy_data(60);

        let hash0 = chain.add_frame(0, &data0);
        let hash1 = chain.add_frame(1, &data1);

        // Recompute hash0 independently
        let mut h0 = Hasher::new();
        h0.update(&0u64.to_le_bytes());
        h0.update(&[0u8; 32]); // prev_hash is zero for first frame
        h0.update(&data0);
        assert_eq!(*h0.finalize().as_bytes(), hash0);

        // Recompute hash1 independently
        let mut h1 = Hasher::new();
        h1.update(&1u64.to_le_bytes());
        h1.update(&hash0); // prev_hash is hash0
        h1.update(&data1);
        assert_eq!(*h1.finalize().as_bytes(), hash1);
    }

    #[test]
    fn test_build_root_partial_segment() {
        let mut chain = HashChain::with_segment_size(8);
        chain.add_frame(0, &dummy_data(10));
        chain.add_frame(1, &dummy_data(20));
        chain.add_frame(2, &dummy_data(30));

        let root = chain.build_root().expect("should have a root");
        assert_eq!(root.segment.frame_count, 3);
        assert_eq!(root.segment.start_frame, 0);
        assert_eq!(root.segment.segment_index, 0);
    }

    #[test]
    fn test_full_segment_auto_finalizes() {
        let mut chain = HashChain::with_segment_size(4);
        chain.add_frame(0, &dummy_data(10));
        chain.add_frame(1, &dummy_data(20));
        chain.add_frame(2, &dummy_data(30));
        chain.add_frame(3, &dummy_data(40));

        // After 4 frames (segment_size), the segment should auto-finalize
        assert_eq!(chain.completed_segments().len(), 1);
        let root = &chain.completed_segments()[0];
        assert_eq!(root.segment.frame_count, 4);
    }

    #[test]
    fn test_verify_chain_valid() {
        let mut chain = HashChain::with_segment_size(4);

        let frames: Vec<(u64, Vec<u8>)> = vec![
            (0, dummy_data(10)),
            (1, dummy_data(20)),
            (2, dummy_data(30)),
        ];
        for (idx, ref data) in &frames {
            chain.add_frame(*idx, data);
        }
        let root = chain.build_root().unwrap();

        // Verify with the same data
        let frame_refs: Vec<(u64, &[u8])> =
            frames.iter().map(|(i, d)| (*i, d.as_slice())).collect();
        assert!(HashChain::verify_chain(&frame_refs, &root));
    }

    #[test]
    fn test_verify_chain_tampered_data() {
        let mut chain = HashChain::with_segment_size(4);

        let frames: Vec<(u64, Vec<u8>)> = vec![
            (0, dummy_data(10)),
            (1, dummy_data(20)),
            (2, dummy_data(30)),
        ];
        for (idx, ref data) in &frames {
            chain.add_frame(*idx, data);
        }
        let root = chain.build_root().unwrap();

        // Tamper with one frame's data
        let mut tampered = frames.clone();
        tampered[1].1[0] ^= 0xFF;
        let frame_refs: Vec<(u64, &[u8])> =
            tampered.iter().map(|(i, d)| (*i, d.as_slice())).collect();
        assert!(!HashChain::verify_chain(&frame_refs, &root));
    }

    #[test]
    fn test_verify_chain_wrong_frame_count() {
        let mut chain = HashChain::with_segment_size(4);
        chain.add_frame(0, &dummy_data(10));
        chain.add_frame(1, &dummy_data(20));
        let root = chain.build_root().unwrap();

        // Only provide 1 frame but root expects 2
        let frames: Vec<(u64, Vec<u8>)> = vec![(0, dummy_data(10))];
        let frame_refs: Vec<(u64, &[u8])> =
            frames.iter().map(|(i, d)| (*i, d.as_slice())).collect();
        assert!(!HashChain::verify_chain(&frame_refs, &root));
    }

    #[test]
    fn test_verify_chain_empty() {
        let root = MerkleRoot {
            root_hash: [0u8; 32],
            segment: SegmentMeta {
                start_frame: 0,
                frame_count: 0,
                segment_index: 0,
            },
            last_frame_hash: [0u8; 32],
        };
        let empty: Vec<(u64, &[u8])> = vec![];
        assert!(!HashChain::verify_chain(&empty, &root));
    }

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaf = [0xAB; 32];
        let root = compute_merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let left = [0x01; 32];
        let right = [0x02; 32];
        let root = compute_merkle_root(&[left, right]);

        let mut hasher = Hasher::new();
        hasher.update(&left);
        hasher.update(&right);
        let expected = *hasher.finalize().as_bytes();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_odd_leaves_duplicates_last() {
        let leaves = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
        let root = compute_merkle_root(&leaves);

        // With 3 leaves, the last is duplicated: pairs are (01,02), (03,03)
        let mut h1 = Hasher::new();
        h1.update(&[0x01; 32]);
        h1.update(&[0x02; 32]);
        let mid1 = *h1.finalize().as_bytes();

        let mut h2 = Hasher::new();
        h2.update(&[0x03; 32]);
        h2.update(&[0x03; 32]);
        let mid2 = *h2.finalize().as_bytes();

        let mut h3 = Hasher::new();
        h3.update(&mid1);
        h3.update(&mid2);
        let expected = *h3.finalize().as_bytes();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_multiple_segments() {
        let mut chain = HashChain::with_segment_size(2);
        chain.add_frame(0, &dummy_data(10));
        chain.add_frame(1, &dummy_data(20));
        // Segment 0 complete (2 frames)
        assert_eq!(chain.completed_segments().len(), 1);

        chain.add_frame(2, &dummy_data(30));
        chain.add_frame(3, &dummy_data(40));
        // Segment 1 complete (2 frames)
        assert_eq!(chain.completed_segments().len(), 2);
        assert_eq!(chain.completed_segments()[1].segment.segment_index, 1);
        assert_eq!(chain.completed_segments()[1].segment.start_frame, 2);
    }

    #[test]
    fn test_chain_continuity_across_segments() {
        // The last_frame_hash of segment N should equal the hash of the
        // last frame in that segment, and that hash is used as prev_hash
        // for the first frame of segment N+1.
        let mut chain = HashChain::with_segment_size(2);
        let _h0 = chain.add_frame(0, &dummy_data(10));
        let h1 = chain.add_frame(1, &dummy_data(20));
        let root0 = chain.completed_segments()[0].clone();
        // last_frame_hash is the hash of the last frame (frame 1, not frame 0)
        assert_eq!(root0.last_frame_hash, h1);

        // Now add a frame to segment 1 — its hash should incorporate h1
        // (the previous frame's hash, which is the chain's current prev_hash)
        let h2 = chain.add_frame(2, &dummy_data(30));

        // Verify independently: h2 = BLAKE3(frame_index=2 || prev_hash=h1 || data)
        let mut hasher = Hasher::new();
        hasher.update(&2u64.to_le_bytes());
        hasher.update(&h1);
        hasher.update(&dummy_data(30));
        assert_eq!(*hasher.finalize().as_bytes(), h2);
    }
}
