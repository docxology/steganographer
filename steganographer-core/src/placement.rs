//! Bounded-memory keyed placement schedules for generic packet carriers.
//!
//! A placement schedule maps a logical carrier position to a physical carrier
//! position under a 32-byte placement key, so packet bits are spread
//! deterministically across the carrier instead of landing at the front. The
//! schedule is a keyed permutation over `0..unit_count`: every physical slot is
//! hit exactly once, and a different key yields an effectively unrelated order.
//!
//! Memory is O(1) regardless of carrier size. Two schedule families live here:
//!
//! * [`KeyedPermutation`] — a balanced Feistel network over the next
//!   power-of-two domain (rounded to an even bit width so the halves are
//!   equal), with cycle walking into `[0, len)`. This is the `PLC-002`
//!   bounded-memory keyed schedule.
//! * [`InterleavedSchedule`] — a coprime-stride slot mapping
//!   `physical = (logical * stride + phase) mod len`, with the stride kept
//!   coprime to `len` and both constants derived from the placement key. This
//!   is the `PLC-001` even-spread interleaved schedule; it is likewise
//!   O(1)-memory per slot lookup.

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

/// Registry identifier for the `PLC-001` interleaved placement schedule. The
/// carrier envelope's `placement.algorithm` field carries this value when the
/// packet body is spread with [`InterleavedSchedule`].
pub const PLACEMENT_INTERLEAVED: u16 = 3;

/// Even-spread keyed placement schedule: `physical = (logical * stride +
/// phase) mod len` where `stride` is coprime to `len`, so iterating the
/// logical positions covers every physical slot exactly once.
///
/// Both constants are derived from a 32-byte placement key and a domain label
/// via BLAKE3, so a different key (or label) yields an unrelated schedule. A
/// coprime stride makes the mapping an affine permutation over `Z/len`, which
/// is what gives full coverage with no duplicates while keeping per-slot work
/// and memory O(1) — no permutation vector is ever built.
pub struct InterleavedSchedule {
    len: usize,
    stride: u64,
    phase: u64,
}

impl InterleavedSchedule {
    /// Build an even-spread schedule over `0..len`.
    ///
    /// `len == 0` is accepted and yields a degenerate identity schedule so the
    /// constructor is total; [`slot`](Self::slot) short-circuits in that case.
    pub fn new(len: usize, key: [u8; 32], label: &[u8]) -> Self {
        if len == 0 {
            return Self {
                len: 0,
                stride: 1,
                phase: 0,
            };
        }
        let domain = len as u64;
        // Candidate stride in 1..len; advance until it is coprime with the
        // domain. The scan always terminates because 1 is coprime with every
        // length, and the average number of steps is small (phi(n)/n).
        let raw_stride = derive_u64(&key, label, b"interleaved-stride");
        let mut stride = if domain == 1 {
            1
        } else {
            1 + raw_stride % (domain - 1)
        };
        while gcd(stride, domain) != 1 {
            stride = if stride + 1 == domain { 1 } else { stride + 1 };
        }
        let raw_phase = derive_u64(&key, label, b"interleaved-phase");
        let phase = if domain == 1 { 0 } else { raw_phase % domain };
        Self { len, stride, phase }
    }

    /// Number of elements in the schedule.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Map logical index `i` to its physical slot in `0..len`.
    ///
    /// Iterating `i` over `0..len` visits every physical slot exactly once.
    pub fn slot(&self, logical: usize) -> usize {
        if self.len == 0 {
            return 0;
        }
        // 128-bit arithmetic keeps the affine product overflow-free for any
        // usize-sized domain.
        let x = (logical as u128 * self.stride as u128 + self.phase as u128) % self.len as u128;
        x as usize
    }
}

/// Derive one 64-bit schedule constant from the placement key, domain label,
/// and a fixed context suffix. The label is length-prefixed so distinct
/// `(label, context)` pairs never hash identically.
fn derive_u64(key: &[u8; 32], label: &[u8], context: &[u8]) -> u64 {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(context);
    let output = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&output.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
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

    #[test]
    fn interleaved_covers_all_positions_exactly_once() {
        for len in 1..=300usize {
            let schedule = InterleavedSchedule::new(len, key(7), b"ka-body");
            let mut seen = vec![false; len];
            for i in 0..len {
                let slot = schedule.slot(i);
                assert!(slot < len, "slot({i}) = {slot} out of range for len {len}");
                assert!(!seen[slot], "duplicate slot {slot} for len {len}");
                seen[slot] = true;
            }
            assert!(
                seen.iter().all(|&hit| hit),
                "not full coverage for len {len}"
            );
        }
    }

    #[test]
    fn interleaved_known_answer_deterministic() {
        // Pinned vectors computed independently against the BLAKE3 keyed
        // derivation `len8le(label) || label || context` (stride then phase).
        // slot(0) == phase and slot(1) == (stride + phase) mod len, so each
        // pair pins both derived constants for the fixed key/label/length.
        let cases: &[(u8, usize, usize, usize)] = &[
            // (key byte, len, expected slot(0), expected slot(1))
            (0x37, 101, 41, 72),
            (0x37, 64, 25, 38),
            (0x37, 3, 1, 2),
            (0x00, 64, 37, 46),
            (0x00, 101, 31, 33),
            (0x5a, 300, 164, 67),
            (0x5a, 64, 44, (44 + 47) % 64),
        ];
        for &(seed, len, expected_first, expected_second) in cases {
            let schedule = InterleavedSchedule::new(len, key(seed), b"ka-body");
            assert_eq!(
                schedule.slot(0),
                expected_first,
                "slot(0) mismatch for key {seed:#04x}, len {len}"
            );
            assert_eq!(
                schedule.slot(1),
                expected_second,
                "slot(1) mismatch for key {seed:#04x}, len {len}"
            );
            // Determinism: a fresh construction yields the same slots.
            let again = InterleavedSchedule::new(len, key(seed), b"ka-body");
            for i in 0..len {
                assert_eq!(schedule.slot(i), again.slot(i));
            }
        }
    }

    #[test]
    fn interleaved_spreads_with_key_and_label() {
        let base = InterleavedSchedule::new(256, key(1), b"ka-body");
        let other_key = InterleavedSchedule::new(256, key(2), b"ka-body");
        let other_label = InterleavedSchedule::new(256, key(1), b"locator");
        let mut key_diff = 0;
        let mut label_diff = 0;
        for i in 0..256 {
            if base.slot(i) != other_key.slot(i) {
                key_diff += 1;
            }
            if base.slot(i) != other_label.slot(i) {
                label_diff += 1;
            }
        }
        assert!(key_diff > 200, "only {key_diff} slots differed by key");
        assert!(
            label_diff > 200,
            "only {label_diff} slots differed by label"
        );
    }

    #[test]
    fn interleaved_zero_key_and_degenerate_lengths() {
        // The zero key must still produce a valid full-coverage schedule.
        let schedule = InterleavedSchedule::new(64, [0u8; 32], b"ka-body");
        let mut seen = [false; 64];
        for i in 0..64 {
            let slot = schedule.slot(i);
            assert!(!seen[slot]);
            seen[slot] = true;
        }
        assert!(seen.iter().all(|&hit| hit));

        // Degenerate domains stay total and never divide by zero.
        assert_eq!(InterleavedSchedule::new(0, key(3), b"ka-body").len(), 0);
        assert!(InterleavedSchedule::new(0, key(3), b"ka-body").is_empty());
        let unit = InterleavedSchedule::new(1, key(3), b"ka-body");
        assert_eq!(unit.len(), 1);
        assert_eq!(unit.slot(0), 0);
    }
}
