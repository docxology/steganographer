//! Bounded-memory keyed placement schedules for generic packet carriers.
//!
//! A placement schedule maps a logical carrier position to a physical carrier
//! position under a 32-byte placement key, so packet bits are spread
//! deterministically across the carrier instead of landing at the front. The
//! schedule is a keyed permutation over `0..unit_count`: every physical slot is
//! hit exactly once, and a different key yields an effectively unrelated order.
//!
//! Memory is O(1) regardless of carrier size. The permutation is a balanced
//! Feistel network over the next power-of-two domain (rounded to an even bit
//! width so the halves are equal), with cycle walking into `[0, unit_count)`.
//! This is the `PLC-002` bounded-memory keyed schedule.

use blake3::Hasher;

/// Feistel rounds. Eight is conservative for a small-domain format-preserving
/// permutation while keeping per-slot lookups cheap.
const ROUNDS: u8 = 8;

/// A keyed permutation over `0..len`, derived from a 32-byte placement key and
/// a short domain label. The label keeps the same key from yielding identical
/// schedules for different purposes (locator vs body vs distinct carriers).
pub struct KeyedPermutation {
    key: [u8; 32],
    label: [u8; 16],
    len: u64,
    bits: u32,
}

impl KeyedPermutation {
    /// Build a keyed permutation over `0..len`.
    ///
    /// # Panics
    /// Panics if `len == 0`.
    pub fn new(len: usize, key: [u8; 32], label: &[u8]) -> Self {
        assert!(len > 0, "keyed permutation length must be positive");
        let len = len as u64;
        // Next power of two >= len, rounded up to an even bit width so the
        // Feistel halves are balanced. The domain is therefore < 4*len, which
        // keeps cycle-walk iterations bounded in expectation.
        let bits = ceil_log2(len).max(2);
        let bits = if bits.is_multiple_of(2) {
            bits
        } else {
            bits + 1
        };
        let mut padded_label = [0u8; 16];
        let take = label.len().min(16);
        padded_label[..take].copy_from_slice(&label[..take]);
        Self {
            key,
            label: padded_label,
            len,
            bits,
        }
    }

    /// Number of elements in the permutation.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Map logical index `i` to a distinct physical index in `0..len`.
    ///
    /// Every `i` in `0..len` maps to a unique value in `0..len` (a
    /// permutation), so iterating `i` covers the whole carrier exactly once.
    pub fn permute(&self, i: usize) -> usize {
        let mut y = i as u64;
        loop {
            y = feistel(y, self.bits, &self.key, &self.label);
            if y < self.len {
                return y as usize;
            }
        }
    }

    /// Map physical index `y` back to its logical index `i` in `0..len`.
    ///
    /// This is the exact inverse of [`permute`]: `inverse_permute(permute(i)) == i`.
    pub fn inverse_permute(&self, y: usize) -> usize {
        let mut x = y as u64;
        loop {
            x = feistel_inverse(x, self.bits, &self.key, &self.label);
            if x < self.len {
                return x as usize;
            }
        }
    }

    /// Generate the entire permutation schedule as a vector of physical indices.
    pub fn schedule(&self) -> Vec<usize> {
        (0..self.len()).map(|i| self.permute(i)).collect()
    }
}

fn ceil_log2(value: u64) -> u32 {
    if value <= 1 {
        return 1;
    }
    64 - (value - 1).leading_zeros()
}

fn feistel(x: u64, bits: u32, key: &[u8; 32], label: &[u8; 16]) -> u64 {
    let half = bits / 2;
    let mask = (1u64 << half) - 1;
    let domain_mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let mut left = (x >> half) & mask;
    let mut right = x & mask;
    for round in 0..ROUNDS {
        let f = round_fn(key, label, round, right) & mask;
        let next_left = right;
        let next_right = (left ^ f) & mask;
        left = next_left;
        right = next_right;
    }
    ((left << half) | right) & domain_mask
}

fn feistel_inverse(y: u64, bits: u32, key: &[u8; 32], label: &[u8; 16]) -> u64 {
    let half = bits / 2;
    let mask = (1u64 << half) - 1;
    let domain_mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let mut left = (y >> half) & mask;
    let mut right = y & mask;
    for round in (0..ROUNDS).rev() {
        let prev_right = left;
        let f = round_fn(key, label, round, prev_right) & mask;
        let prev_left = (right ^ f) & mask;
        left = prev_left;
        right = prev_right;
    }
    ((left << half) | right) & domain_mask
}

fn round_fn(key: &[u8; 32], label: &[u8; 16], round: u8, right: u64) -> u64 {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(label);
    hasher.update(&[round]);
    hasher.update(&right.to_le_bytes());
    let output = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&output.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn permutes_all_positions_exactly_once() {
        for len in 1..=300usize {
            let perm = KeyedPermutation::new(len, key(7), b"placement");
            let mut seen = vec![false; len];
            for i in 0..len {
                let p = perm.permute(i);
                assert!(p < len, "permute({i}) = {p} out of range for len {len}");
                assert!(!seen[p], "duplicate position {p} for len {len}");
                seen[p] = true;
            }
            assert!(
                seen.iter().all(|&hit| hit),
                "not full coverage for len {len}"
            );
        }
    }

    #[test]
    fn deterministic_for_same_key_and_label() {
        let a = KeyedPermutation::new(128, key(9), b"body");
        let b = KeyedPermutation::new(128, key(9), b"body");
        for i in 0..128 {
            assert_eq!(a.permute(i), b.permute(i));
        }
    }

    #[test]
    fn different_key_or_label_yields_different_order() {
        let base = KeyedPermutation::new(256, key(1), b"body");
        let other_key = KeyedPermutation::new(256, key(2), b"body");
        let other_label = KeyedPermutation::new(256, key(1), b"locator");
        let mut key_diff = 0;
        let mut label_diff = 0;
        for i in 0..256 {
            if base.permute(i) != other_key.permute(i) {
                key_diff += 1;
            }
            if base.permute(i) != other_label.permute(i) {
                label_diff += 1;
            }
        }
        assert!(key_diff > 200, "only {key_diff} positions differed by key");
        assert!(
            label_diff > 200,
            "only {label_diff} positions differed by label"
        );
    }

    #[test]
    fn zero_key_is_still_a_valid_permutation() {
        let perm = KeyedPermutation::new(64, [0u8; 32], b"body");
        let mut seen = [false; 64];
        for i in 0..64 {
            let p = perm.permute(i);
            assert!(!seen[p]);
            seen[p] = true;
        }
        assert!(seen.iter().all(|&hit| hit));
    }

    #[test]
    fn inverse_permutation_roundtrip() {
        for len in [1, 2, 7, 16, 63, 100, 256, 500] {
            let perm = KeyedPermutation::new(len, key(42), b"inverse-test");
            for i in 0..len {
                let physical = perm.permute(i);
                let logical = perm.inverse_permute(physical);
                assert_eq!(
                    logical, i,
                    "inverse_permute(permute({i})) = {logical} != {i} (len={len})"
                );
            }
            let sched = perm.schedule();
            assert_eq!(sched.len(), len);
        }
    }
}
