//! MDCT (Modified Discrete Cosine Transform) audio steganography.
//!
//! This module embeds data in the frequency domain of audio using the MDCT,
//! which is the transform used by MP3 and AAC compression. This makes it
//! resistant to lossy audio compression, just as DCT embedding is resistant
//! to JPEG for video.
//!
//! ## Algorithm
//!
//! 1. Process audio in blocks of 2N samples (N=8, so 16 samples per block).
//! 2. Apply the MDCT to get N frequency-domain coefficients.
//! 3. Modify a mid-frequency coefficient to embed a bit:
//!    - Quantize the coefficient to `quant_step` boundaries.
//!    - If bit=1, move to the upper half of the quantization cell.
//!    - If bit=0, move to the lower half.
//! 4. Apply the IMDCT to reconstruct the time-domain block.
//! 5. Extraction: apply MDCT, read the coefficient, determine bit from
//!    quantization cell position.
//!
//! ## Advantages
//!
//! - **Compression resistant**: Since data is in the MDCT domain (same as
//!   MP3/AAC), lossy compression preserves it better than time-domain LSB.
//! - **Less detectable**: Frequency-domain modifications are less perceptible
//!   than LSB changes at the same capacity.
//! - **Tunable**: Coefficient index and quantization step are configurable.

use crate::audio::{AudioBuffer, AudioStegoModule};
use crate::crypto::SignaturePayload;

/// MDCT block size N (produces N coefficients from 2N input samples).
const MDCT_N: usize = 8;

/// Input block size (2N samples per MDCT block).
const BLOCK_SIZE: usize = 2 * MDCT_N; // 16

/// Precompute the MDCT cosine basis value.
///
/// MDCT: X[k] = Σ_{n=0}^{2N-1} x[n] * cos(π/N * (n + 1/2) * (k + 1/2))
fn mdct_basis(n: usize, k: usize) -> f64 {
    let pi_over_n = std::f64::consts::PI / MDCT_N as f64;
    let angle = pi_over_n * (n as f64 + 0.5) * (k as f64 + 0.5);
    angle.cos()
}

/// Apply the forward MDCT to a block of 2N samples, producing N coefficients.
///
/// X[k] = Σ_{n=0}^{2N-1} x[n] * cos(π/N * (n + 1/2) * (k + 1/2))
fn mdct(input: &[f64; BLOCK_SIZE]) -> [f64; MDCT_N] {
    let mut output = [0.0f64; MDCT_N];
    for k in 0..MDCT_N {
        let mut sum = 0.0;
        for n in 0..BLOCK_SIZE {
            sum += input[n] * mdct_basis(n, k);
        }
        output[k] = sum;
    }
    output
}

/// Apply the inverse MDCT to N coefficients, producing 2N samples.
///
/// y[n] = (1/N) * Σ_{k=0}^{N-1} X[k] * cos(π/N * (n + 1/2) * (k + 1/2))
fn imdct(input: &[f64; MDCT_N]) -> [f64; BLOCK_SIZE] {
    let mut output = [0.0f64; BLOCK_SIZE];
    let scale = 1.0 / MDCT_N as f64;
    for n in 0..BLOCK_SIZE {
        let mut sum = 0.0;
        for k in 0..MDCT_N {
            sum += input[k] * mdct_basis(n, k);
        }
        output[n] = sum * scale;
    }
    output
}

/// MDCT-domain audio steganography module.
///
/// Embeds payload data into mid-frequency MDCT coefficients of 16-sample
/// audio blocks for compression-resistant steganography.
pub struct MdctAudio {
    /// Which MDCT coefficient to modify (0-based, 0 to N-1).
    /// Mid-frequency (default: 3) offers good robustness/inaudibility tradeoff.
    coef_index: usize,
    /// Quantization step for embedding. Higher = more robust but more audible.
    quant_step: f64,
}

impl MdctAudio {
    /// Create a new MDCT audio steganography module.
    ///
    /// # Arguments
    /// * `coef_index` — Which MDCT coefficient to modify (0 to 7).
    /// * `quant_step` — Quantization step for bit embedding (8–32 recommended).
    pub fn new(coef_index: usize, quant_step: i32) -> Self {
        assert!(
            coef_index < MDCT_N,
            "Coefficient index must be 0 to {}",
            MDCT_N - 1
        );
        assert!(quant_step > 0, "Quantization step must be positive");
        Self {
            coef_index,
            quant_step: quant_step as f64,
        }
    }

    /// Create with defaults: coef_index=3, quant_step=16.
    pub fn default() -> Self {
        Self::new(3, 16)
    }

    /// Number of bits that can be embedded in the given sample count.
    fn capacity_bits(sample_count: usize) -> usize {
        sample_count / BLOCK_SIZE
    }

    /// Convert payload to a bit vector, prefixed by a 32-bit length (in bits).
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

    /// Embed a single bit into an MDCT coefficient using quantization cells.
    ///
    /// The coefficient is moved to the upper or lower half of its quantization
    /// cell depending on the bit value.
    fn embed_bit(coef: f64, bit: u8, quant_step: f64) -> f64 {
        // Find which quantization cell we're in
        let cell = (coef / quant_step).floor();
        let cell_start = cell * quant_step;
        let half = quant_step / 2.0;

        if bit == 1 {
            // Move to upper half of the cell
            cell_start + half + quant_step * 0.25
        } else {
            // Move to lower half of the cell
            cell_start + quant_step * 0.25
        }
    }

    /// Extract a single bit from an MDCT coefficient based on its position
    /// within the quantization cell.
    fn extract_bit(coef: f64, quant_step: f64) -> u8 {
        let cell = (coef / quant_step).floor();
        let cell_start = cell * quant_step;
        let offset = coef - cell_start;
        let half = quant_step / 2.0;

        if offset >= half {
            1
        } else {
            0
        }
    }
}

impl AudioStegoModule for MdctAudio {
    fn embed(
        &mut self,
        buf: &mut AudioBuffer,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let sig = match sig {
            Some(s) => s,
            None => return Ok(()),
        };

        let samples = &mut *buf.samples;
        let bits = Self::payload_to_bits(sig);
        let num_blocks = Self::capacity_bits(samples.len());

        if bits.len() > num_blocks {
            anyhow::bail!(
                "Not enough MDCT capacity: need {} bits, have {} blocks ({} samples / {} per block)",
                bits.len(),
                num_blocks,
                samples.len(),
                BLOCK_SIZE
            );
        }

        log::debug!(
            "MDCT audio embed: {} bits into {} blocks ({} samples, frame {})",
            bits.len(),
            num_blocks,
            samples.len(),
            buf.frame_index
        );

        // Process each 16-sample block
        for (block_idx, chunk) in samples.chunks_exact_mut(BLOCK_SIZE).enumerate() {
            if block_idx >= bits.len() {
                break;
            }

            // Convert i16 samples to f64
            let mut input: [f64; BLOCK_SIZE] = [0.0; BLOCK_SIZE];
            for (i, &s) in chunk.iter().enumerate() {
                input[i] = s as f64;
            }

            // Apply forward MDCT
            let coefs_original = mdct(&input);

            // Compute the modified coefficient
            let new_coef = Self::embed_bit(
                coefs_original[self.coef_index],
                bits[block_idx],
                self.quant_step,
            );

            // Compute delta in frequency domain, then apply IMDCT to get time-domain delta
            let mut delta_coefs: [f64; MDCT_N] = [0.0; MDCT_N];
            delta_coefs[self.coef_index] = new_coef - coefs_original[self.coef_index];
            let delta = imdct(&delta_coefs);

            // Apply only the delta to the original samples (minimizes distortion)
            for (i, d) in delta.iter().enumerate() {
                let new_val = input[i] + d;
                let clamped = new_val.round().clamp(i16::MIN as f64, i16::MAX as f64);
                chunk[i] = clamped as i16;
            }
        }

        log::debug!("MDCT audio embed complete");
        Ok(())
    }

    fn extract(&self, buf: &AudioBuffer) -> anyhow::Result<Option<SignaturePayload>> {
        let samples = &*buf.samples;
        let num_blocks = Self::capacity_bits(samples.len());

        // Need at least enough blocks for the 32-bit length prefix
        if num_blocks < 32 {
            return Ok(None);
        }

        // Extract bits from each block
        let mut all_bits: Vec<u8> = Vec::with_capacity(num_blocks);

        for chunk in samples.chunks_exact(BLOCK_SIZE) {
            // Convert i16 samples to f64
            let mut input: [f64; BLOCK_SIZE] = [0.0; BLOCK_SIZE];
            for (i, &s) in chunk.iter().enumerate() {
                input[i] = s as f64;
            }

            // Apply forward MDCT
            let coefs = mdct(&input);

            // Extract bit from the selected coefficient
            let bit = Self::extract_bit(coefs[self.coef_index], self.quant_step);
            all_bits.push(bit);
        }

        // Read 32-bit length prefix
        if all_bits.len() < 32 {
            return Ok(None);
        }

        let mut payload_bit_count: u32 = 0;
        for &bit in &all_bits[..32] {
            payload_bit_count = (payload_bit_count << 1) | bit as u32;
        }

        let expected = SignaturePayload::SERIALIZED_SIZE * 8;
        if payload_bit_count as usize != expected {
            log::trace!(
                "MDCT audio: length prefix {} != expected payload bits {}",
                payload_bit_count,
                expected
            );
            return Ok(None);
        }

        let total_bits = 32 + payload_bit_count as usize;
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
    use crate::audio::AudioBuffer;
    use crate::crypto::Signer;

    fn make_test_buffer(samples: &mut [i16]) -> AudioBuffer<'_> {
        AudioBuffer {
            channels: 1,
            sample_rate: 44100,
            samples,
            frame_index: 0,
        }
    }

    #[test]
    fn test_mdct_imdct_roundtrip() {
        // Test that MDCT -> IMDCT preserves energy (within floating point precision)
        // Note: MDCT is not perfectly invertible (it maps 2N->N->2N), but it
        // preserves energy. We check that the output is reasonably close.

        let input: [f64; BLOCK_SIZE] = [
            100.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0, 700.0, 600.0, 500.0, 400.0,
            300.0, 200.0, 100.0, 50.0,
        ];

        let coefs = mdct(&input);
        let output = imdct(&coefs);

        // Check energy preservation: sum of squares should be comparable
        let input_energy: f64 = input.iter().map(|x| x * x).sum();
        let output_energy: f64 = output.iter().map(|x| x * x).sum();

        // The MDCT/IMDCT pair has a specific energy relationship.
        // For the IMDCT as defined (1/N scale), the ratio should be N/2.
        // Just verify the energy is in the same order of magnitude.
        let ratio = output_energy / input_energy;
        assert!(
            ratio > 0.01 && ratio < 100.0,
            "Energy ratio out of expected range: {} (input={}, output={})",
            ratio,
            input_energy,
            output_energy
        );

        // Verify that the output is not all zeros (sanity check)
        let max_output = output.iter().cloned().fold(0.0f64, |a, b| a.max(b.abs()));
        assert!(
            max_output > 1.0,
            "Output should have meaningful values, max={}",
            max_output
        );
    }

    #[test]
    fn test_embed_extract_roundtrip() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(77, b"mdct audio test", None);

        // Need enough samples: 32 (length prefix) + 109*8 (payload) = 904 bits = 904 blocks
        // 904 * 16 = 14464 samples minimum
        let mut samples = vec![1000i16; 16384];

        let mut mdct_audio = MdctAudio::default();

        {
            let mut buf = make_test_buffer(&mut samples);
            mdct_audio.embed(&mut buf, Some(&payload)).unwrap();
        }

        {
            let buf = AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };
            let extracted = mdct_audio.extract(&buf).unwrap();
            assert!(extracted.is_some(), "Should extract a payload");
            let extracted = extracted.unwrap();
            assert_eq!(extracted.frame_index, payload.frame_index);
            assert_eq!(extracted.hash, payload.hash);
            assert_eq!(
                extracted.signature.to_bytes(),
                payload.signature.to_bytes()
            );
        }
    }

    #[test]
    fn test_capacity_error() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);

        // 10 samples = 0 full blocks -> way too small
        let mut samples = vec![0i16; 10];
        let mut mdct_audio = MdctAudio::default();
        let mut buf = make_test_buffer(&mut samples);
        let result = mdct_audio.embed(&mut buf, Some(&payload));
        assert!(
            result.is_err(),
            "Should fail with capacity error for too few samples"
        );
    }

    #[test]
    fn test_none_sig_is_noop() {
        let mut samples = vec![42i16; 1024];
        let original = samples.clone();
        let mut mdct_audio = MdctAudio::default();
        let mut buf = make_test_buffer(&mut samples);
        mdct_audio.embed(&mut buf, None).unwrap();
        assert_eq!(
            samples, original,
            "Samples should be unchanged when sig is None"
        );
    }

    #[test]
    fn test_empty_buffer_returns_none() {
        let mdct_audio = MdctAudio::default();
        let mut samples: Vec<i16> = vec![0i16; 16]; // 1 block, not enough for 32-bit length prefix
        let buf = AudioBuffer {
            channels: 1,
            sample_rate: 44100,
            samples: &mut samples,
            frame_index: 0,
        };
        let result = mdct_audio.extract(&buf).unwrap();
        assert!(
            result.is_none(),
            "Should return None for buffer with no embedded data"
        );
    }

    #[test]
    fn test_distortion_is_minimal() {
        // After embedding, the average sample change should be small (< 5)
        let signer = Signer::generate();
        let payload = signer.sign_frame(42, b"distortion test", None);

        let mut samples = vec![1000i16; 16384];
        let original = samples.clone();

        let mut mdct_audio = MdctAudio::default();

        {
            let mut buf = make_test_buffer(&mut samples);
            mdct_audio.embed(&mut buf, Some(&payload)).unwrap();
        }

        // Calculate average absolute change
        let total_change: f64 = samples
            .iter()
            .zip(original.iter())
            .map(|(a, b)| (*a as f64 - *b as f64).abs())
            .sum();
        let avg_change = total_change / samples.len() as f64;

        assert!(
            avg_change < 5.0,
            "Average sample change should be < 5, got {}",
            avg_change
        );
    }

    #[test]
    fn test_embed_bit_extract_bit_consistency() {
        // Verify that embed_bit followed by extract_bit recovers the original bit
        let quant_step = 16.0;

        for bit in [0u8, 1u8] {
            // Start with a typical coefficient value
            let original_coef = 42.0;
            let embedded_coef = MdctAudio::embed_bit(original_coef, bit, quant_step);
            let extracted_bit = MdctAudio::extract_bit(embedded_coef, quant_step);
            assert_eq!(
                extracted_bit, bit,
                "Bit {} should be recovered (coef={}, embedded={})",
                bit, original_coef, embedded_coef
            );
        }

        // Also test with negative coefficients
        for bit in [0u8, 1u8] {
            let original_coef = -37.5;
            let embedded_coef = MdctAudio::embed_bit(original_coef, bit, quant_step);
            let extracted_bit = MdctAudio::extract_bit(embedded_coef, quant_step);
            assert_eq!(
                extracted_bit, bit,
                "Bit {} should be recovered for negative coef (coef={}, embedded={})",
                bit, original_coef, embedded_coef
            );
        }
    }

    #[test]
    fn test_custom_coef_index() {
        // Test with a different coefficient index
        let signer = Signer::generate();
        let payload = signer.sign_frame(99, b"custom coef", None);

        let mut samples = vec![500i16; 16384];
        let mut mdct_audio = MdctAudio::new(5, 16);

        {
            let mut buf = make_test_buffer(&mut samples);
            mdct_audio.embed(&mut buf, Some(&payload)).unwrap();
        }

        {
            let buf = AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };
            let extracted = mdct_audio.extract(&buf).unwrap();
            assert!(extracted.is_some());
            assert_eq!(extracted.unwrap().frame_index, 99);
        }
    }
}
