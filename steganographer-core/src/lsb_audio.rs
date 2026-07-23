//! LSB (Least Significant Bit) audio steganography with pseudo-random index selection.
//!
//! Embeds and extracts [`SignaturePayload`] data into/from audio sample buffers
//! using a keyed PRNG (ChaCha8 via `rand`) to generate a permutation of sample
//! indices. A 32-bit length prefix is embedded first so extract knows how many
//! bits to recover.

use crate::audio::{AudioBuffer, AudioStegoModule};
use crate::crypto::SignaturePayload;
use rand::seq::SliceRandom;
use rand::SeedableRng;

/// LSB-based audio steganography module with pseudo-random index selection.
pub struct LsbAudio {
    bits: u8,
    key: [u8; 32],
}

impl LsbAudio {
    /// Create a new LSB audio module.
    ///
    /// # Arguments
    /// * `bits` — Number of LSBs to use per sample (1–4).
    /// * `key` — 32-byte key for deterministic index permutation.
    ///
    /// # Panics
    /// Panics if `bits` is not in 1..=4. For fallible construction, use [`try_new`](Self::try_new).
    pub fn new(bits: u8, key: [u8; 32]) -> Self {
        assert!((1..=4).contains(&bits), "LSB bits must be 1–4");
        Self { bits, key }
    }

    /// Create a new LSB audio module, returning an error on invalid bits.
    ///
    /// Use this when `bits` comes from untrusted input (config, CLI args).
    pub fn try_new(bits: u8, key: [u8; 32]) -> anyhow::Result<Self> {
        if !(1..=4).contains(&bits) {
            anyhow::bail!("LSB bits must be 1–4, got {}", bits);
        }
        Ok(Self { bits, key })
    }

    /// Returns the current number of LSBs used per sample.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Generate a deterministic permutation of sample indices using the key and frame index.
    fn gen_indices(&self, len: usize, frame_index: u64) -> Vec<usize> {
        // Derive a per-frame seed from the key and frame index
        let mut seed = [0u8; 32];
        // Mix key with frame index
        let frame_bytes = frame_index.to_le_bytes();
        for (i, byte) in self.key.iter().enumerate() {
            seed[i] = byte ^ frame_bytes[i % 8];
        }
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let mut idx: Vec<usize> = (0..len).collect();
        idx.shuffle(&mut rng);
        idx
    }

    /// Serialize payload to a bit vector, prefixed by a 32-bit length (in bits).
    fn payload_to_bits(payload: &SignaturePayload) -> Vec<u8> {
        let raw_bytes = payload.to_bytes();
        let raw_bits: Vec<u8> = raw_bytes
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect();

        let len = raw_bits.len() as u32;
        let len_bits: Vec<u8> = (0..32).rev().map(|i| ((len >> i) & 1) as u8).collect();

        let mut result = len_bits;
        result.extend_from_slice(&raw_bits);
        result
    }

    /// Write bits into samples at the given permuted indices.
    fn write_bits(
        samples: &mut [i16],
        indices: &[usize],
        bits_data: &[u8],
        bits_per_sample: u8,
    ) -> anyhow::Result<()> {
        let total_bits = bits_data.len();
        let capacity = indices.len() * bits_per_sample as usize;
        if total_bits > capacity {
            anyhow::bail!(
                "Not enough LSB capacity: need {} bits, have {} ({} samples × {} bits)",
                total_bits,
                capacity,
                indices.len(),
                bits_per_sample
            );
        }

        let mask = !((1i16 << bits_per_sample) - 1);
        let mut bit_idx = 0usize;

        for &sample_idx in indices {
            if bit_idx >= total_bits {
                break;
            }
            let sample = &mut samples[sample_idx];
            let mut new_lsb: i16 = 0;
            for shift in (0..bits_per_sample).rev() {
                if bit_idx < total_bits {
                    new_lsb |= (bits_data[bit_idx] as i16) << shift;
                    bit_idx += 1;
                }
            }
            *sample = (*sample & mask) | new_lsb;
        }

        Ok(())
    }

    /// Read bits from samples at the given permuted indices.
    fn read_bits(
        samples: &[i16],
        indices: &[usize],
        total_bits: usize,
        bits_per_sample: u8,
    ) -> Vec<u8> {
        let mut result = Vec::with_capacity(total_bits);
        let mut bit_count = 0;

        for &sample_idx in indices {
            if bit_count >= total_bits {
                break;
            }
            let sample = samples[sample_idx];
            for shift in (0..bits_per_sample).rev() {
                if bit_count >= total_bits {
                    break;
                }
                result.push(((sample >> shift) & 1) as u8);
                bit_count += 1;
            }
        }

        result
    }
}

impl AudioStegoModule for LsbAudio {
    fn embed(
        &mut self,
        buf: &mut AudioBuffer,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let sig = match sig {
            Some(s) => s,
            None => return Ok(()),
        };

        let bits = Self::payload_to_bits(sig);
        let indices = self.gen_indices(buf.samples.len(), buf.frame_index);

        log::debug!(
            "LSB audio embed: {} bits into {} samples (frame {})",
            bits.len(),
            buf.samples.len(),
            buf.frame_index
        );

        Self::write_bits(buf.samples, &indices, &bits, self.bits)?;

        log::debug!("LSB audio embed complete");
        Ok(())
    }

    fn extract(&self, buf: &AudioBuffer) -> anyhow::Result<Option<SignaturePayload>> {
        let indices = self.gen_indices(buf.samples.len(), buf.frame_index);

        // First read 32 bits for the length prefix
        let len_bits_needed = 32usize.div_ceil(self.bits as usize);
        if indices.len() < len_bits_needed {
            return Ok(None);
        }

        let prefix_bits = Self::read_bits(buf.samples, &indices, 32, self.bits);
        if prefix_bits.len() < 32 {
            return Ok(None);
        }

        let mut payload_bit_count: u32 = 0;
        for &bit in &prefix_bits[..32] {
            payload_bit_count = (payload_bit_count << 1) | bit as u32;
        }

        let expected = SignaturePayload::SERIALIZED_SIZE * 8;
        if payload_bit_count as usize != expected {
            log::trace!(
                "LSB audio: length prefix {} != expected payload bits {}",
                payload_bit_count,
                expected
            );
            return Ok(None);
        }

        let total_bits = 32 + payload_bit_count as usize;
        let all_bits = Self::read_bits(buf.samples, &indices, total_bits, self.bits);

        if all_bits.len() < total_bits {
            return Ok(None);
        }

        // Reconstruct payload bytes
        let payload_bits = &all_bits[32..total_bits];
        let mut payload_bytes = [0u8; SignaturePayload::SERIALIZED_SIZE];
        for (i, byte) in payload_bytes.iter_mut().enumerate() {
            let offset = i * 8;
            for j in 0..8 {
                *byte = (*byte << 1) | payload_bits[offset + j];
            }
        }

        SignaturePayload::from_bytes(&payload_bytes).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    fn make_test_buffer(samples: &mut [i16]) -> AudioBuffer<'_> {
        AudioBuffer {
            channels: 1,
            sample_rate: 44100,
            samples,
            frame_index: 0,
        }
    }

    #[test]
    fn test_embed_extract_roundtrip() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(77, b"audio test data", None);

        let mut samples = vec![1000i16; 8192]; // plenty of capacity
        let key = test_key();
        let mut lsb = LsbAudio::new(1, key);

        {
            let mut buf = make_test_buffer(&mut samples);
            lsb.embed(&mut buf, Some(&payload)).unwrap();
        }

        {
            let buf = AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };
            let extracted = lsb.extract(&buf).unwrap();
            assert!(extracted.is_some(), "Should extract a payload");
            let extracted = extracted.unwrap();
            assert_eq!(extracted.frame_index, payload.frame_index);
            assert_eq!(extracted.hash, payload.hash);
            assert_eq!(extracted.signature, payload.signature);
        }
    }

    #[test]
    fn test_embed_extract_2bit() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(55, b"2-bit test", None);

        let mut samples = vec![500i16; 8192];
        let key = test_key();
        let mut lsb = LsbAudio::new(2, key);

        {
            let mut buf = make_test_buffer(&mut samples);
            lsb.embed(&mut buf, Some(&payload)).unwrap();
        }

        {
            let buf = AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };
            let extracted = lsb.extract(&buf).unwrap();
            assert!(extracted.is_some());
            assert_eq!(extracted.unwrap().frame_index, 55);
        }
    }

    #[test]
    fn test_capacity_error() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);

        let mut samples = vec![0i16; 10]; // way too small
        let key = test_key();
        let mut lsb = LsbAudio::new(1, key);
        let mut buf = make_test_buffer(&mut samples);
        let result = lsb.embed(&mut buf, Some(&payload));
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_empty_buffer() {
        let key = test_key();
        let lsb = LsbAudio::new(1, key);
        let mut samples = vec![0i16; 8192];
        let buf = AudioBuffer {
            channels: 1,
            sample_rate: 44100,
            samples: &mut samples,
            frame_index: 0,
        };
        let result = lsb.extract(&buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_none_sig_is_noop() {
        let mut samples = vec![42i16; 1024];
        let original = samples.clone();
        let key = test_key();
        let mut lsb = LsbAudio::new(1, key);
        let mut buf = make_test_buffer(&mut samples);
        lsb.embed(&mut buf, None).unwrap();
        assert_eq!(samples, original);
    }

    #[test]
    fn test_different_frame_index_different_permutation() {
        let key = test_key();
        let lsb = LsbAudio::new(1, key);
        let idx0 = lsb.gen_indices(100, 0);
        let idx1 = lsb.gen_indices(100, 1);
        // The permutations should differ
        assert_ne!(idx0, idx1);
    }

    #[test]
    fn test_same_frame_index_same_permutation() {
        let key = test_key();
        let lsb = LsbAudio::new(1, key);
        let idx_a = lsb.gen_indices(100, 42);
        let idx_b = lsb.gen_indices(100, 42);
        assert_eq!(idx_a, idx_b);
    }
}
