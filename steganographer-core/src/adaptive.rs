//! Content-adaptive steganography.
//!
//! Embeds signature payloads in high-texture regions of video frames where
//! modifications are less detectable by statistical steganalysis. Uses local
//! variance as a distortion metric to select embedding locations.
//!
//! ## Overview
//!
//! - [`AdaptiveLsbVideo`] implements [`VideoStegoModule`].
//! - For each frame, local variance is computed over a sliding window.
//! - Pixels with variance ≥ `threshold` are selected as embedding candidates.
//! - Candidates are sorted by variance (highest first) and LSB-embedded.
//!
//! This makes detection harder because changes are concentrated in noisy
//! regions where statistical anomalies are harder to spot.

use crate::crypto::SignaturePayload;
use crate::video::{VideoFrame, VideoStegoModule};

/// Window size for local variance computation (window is `WINDOW x WINDOW`).
const WINDOW: usize = 3;

/// Header bits: 32-bit length prefix (same as LsbVideo).
const HEADER_BITS: usize = 32;

/// Adaptive LSB video steganography module.
///
/// Embeds data in high-variance regions of video frames to reduce
/// detectability by statistical steganalysis.
pub struct AdaptiveLsbVideo {
    /// Minimum local variance required for a pixel to be an embedding candidate.
    threshold: u32,
    /// Number of LSBs to use per byte (1–4).
    bits: u8,
}

impl AdaptiveLsbVideo {
    /// Create a new adaptive LSB video module.
    ///
    /// # Arguments
    /// * `threshold` — Minimum local variance for embedding eligibility.
    /// * `bits` — Number of LSBs per byte (1–4).
    pub fn new(threshold: u32, bits: u8) -> Self {
        assert!((1..=4).contains(&bits), "bits must be 1–4");
        Self { threshold, bits }
    }

    /// Get the configured threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Get the configured bits.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Compute local variance for each pixel position in the frame.
    ///
    /// Returns a vector of `(byte_offset, variance)` for all pixel byte
    /// positions, where variance is computed over a `WINDOW x WINDOW`
    /// neighborhood of pixel indices.
    ///
    /// The low `bits_per_byte` LSBs of each byte are masked out before
    /// computing variance, so the variance map is stable across
    /// embed/extract (embedding only modifies those LSBs).
    fn compute_variance_map(frame: &VideoFrame, bits_per_byte: u8) -> Vec<(usize, u32)> {
        let bpp = frame.format.bytes_per_pixel().unwrap_or(1) as usize;
        let w = frame.width as usize;
        let h = frame.height as usize;
        let stride = frame.stride as usize;
        let data = &frame.data;
        let half = WINDOW / 2;
        let mask = !((1u8 << bits_per_byte) - 1);

        let mut result: Vec<(usize, u32)> = Vec::with_capacity(w * h * bpp);

        for y in 0..h {
            for x in 0..w {
                // Gather pixel values in the window (upper bits only)
                let mut values: Vec<u8> = Vec::with_capacity(WINDOW * WINDOW);
                let y_start = y.saturating_sub(half);
                let y_end = (y + half + 1).min(h);
                let x_start = x.saturating_sub(half);
                let x_end = (x + half + 1).min(w);

                for wy in y_start..y_end {
                    for wx in x_start..x_end {
                        let pixel_offset = wy * stride + wx * bpp;
                        if pixel_offset < data.len() {
                            values.push(data[pixel_offset] & mask);
                        }
                    }
                }

                let variance = compute_variance(&values);

                // Emit an entry for each byte of this pixel
                let base_offset = y * stride + x * bpp;
                for b in 0..bpp {
                    let off = base_offset + b;
                    if off < data.len() {
                        result.push((off, variance));
                    }
                }
            }
        }

        result
    }

    /// Select embedding positions sorted by variance (highest first),
    /// filtering out positions below the threshold.
    fn select_positions(&self, frame: &VideoFrame) -> Vec<usize> {
        let mut variance_map = Self::compute_variance_map(frame, self.bits);

        // Filter by threshold
        variance_map.retain(|(_, v)| *v >= self.threshold);

        // Sort by variance descending (highest variance = least detectable)
        variance_map.sort_by(|a, b| b.1.cmp(&a.1));

        // Extract positions
        variance_map.into_iter().map(|(pos, _)| pos).collect()
    }

    /// Convert a byte slice to a bit vector (MSB first per byte).
    fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect()
    }

    /// Convert a bit vector back to bytes (MSB first per byte).
    fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(bits.len().div_ceil(8));
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for &bit in chunk {
                byte = (byte << 1) | (bit & 1);
            }
            // Pad remaining bits with zeros
            let pad = 8 - chunk.len();
            byte <<= pad;
            result.push(byte);
        }
        result
    }
}

impl VideoStegoModule for AdaptiveLsbVideo {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let payload_bytes = match sig {
            Some(s) => s.to_bytes().to_vec(),
            None => return Ok(()), // No payload to embed
        };

        let payload_bits = Self::bytes_to_bits(&payload_bytes);
        let total_bits = HEADER_BITS + payload_bits.len();

        // Select positions based on variance
        let positions = self.select_positions(frame);

        if positions.len() < total_bits {
            anyhow::bail!(
                "Insufficient high-variance positions: need {} bits, found {} positions (threshold={})",
                total_bits,
                positions.len(),
                self.threshold
            );
        }

        // Build the bit stream: 32-bit length prefix + payload bits
        let len_bits = Self::bytes_to_bits(&(payload_bits.len() as u32).to_le_bytes());
        let mut all_bits = len_bits;
        all_bits.extend_from_slice(&payload_bits);

        // Embed using all `bits_per_byte` LSBs — each position holds one bit-value
        // (0 or 1 for 1-bit mode, 0-3 for 2-bit mode, etc.)
        // But since positions are byte-level, we embed one bit per position for
        // 1-bit mode, and for multi-bit, we pack bits differently.
        // For simplicity and correctness, we embed 1 logical bit per position
        // using the low `bits_per_byte` bits as the value.
        // To support multi-bit: we need fewer positions (total_bits / bits_per_byte).
        let positions_needed = total_bits.div_ceil(self.bits as usize);
        if positions.len() < positions_needed {
            anyhow::bail!(
                "Insufficient positions for {}-bit embedding: need {}, found {}",
                self.bits,
                positions_needed,
                positions.len()
            );
        }

        // Pack bits into groups of `bits_per_byte`
        let packed_values: Vec<u8> = all_bits
            .chunks(self.bits as usize)
            .map(|chunk| {
                let mut val = 0u8;
                for &b in chunk {
                    val = (val << 1) | (b & 1);
                }
                // Left-pad if chunk is short
                let pad = (self.bits as usize).saturating_sub(chunk.len());
                val <<= pad;
                val
            })
            .collect();

        // Use only the first `positions_needed` positions
        let embed_positions: Vec<usize> = positions.into_iter().take(positions_needed).collect();

        // Write
        let mask = (1u8 << self.bits) - 1;
        for (i, &val) in packed_values.iter().enumerate() {
            let pos = embed_positions[i];
            if pos < frame.data.len() {
                frame.data[pos] = (frame.data[pos] & !mask) | (val & mask);
            }
        }

        Ok(())
    }

    fn extract(&self, frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        let positions = self.select_positions(frame);

        let min_header_positions = HEADER_BITS.div_ceil(self.bits as usize);
        if positions.len() < min_header_positions {
            return Ok(None);
        }

        let mask = (1u8 << self.bits) - 1;

        // Read header (32 bits = 4 bytes)
        let header_positions_needed = HEADER_BITS.div_ceil(self.bits as usize);
        let mut header_vals: Vec<u8> = Vec::with_capacity(header_positions_needed);
        for i in 0..header_positions_needed {
            let pos = positions[i];
            if pos < frame.data.len() {
                header_vals.push(frame.data[pos] & mask);
            } else {
                return Ok(None);
            }
        }

        // Unpack header values back to bits
        let mut header_bits: Vec<u8> = Vec::with_capacity(HEADER_BITS);
        for val in &header_vals {
            for i in (0..self.bits as usize).rev() {
                header_bits.push((val >> i) & 1);
            }
        }
        header_bits.truncate(HEADER_BITS);

        let header_bytes = Self::bits_to_bytes(&header_bits);
        if header_bytes.len() < 4 {
            return Ok(None);
        }
        let payload_bit_count = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]) as usize;

        let expected = SignaturePayload::SERIALIZED_SIZE * 8;
        if payload_bit_count != expected {
            log::trace!(
                "Adaptive LSB: length prefix {} != expected {}",
                payload_bit_count,
                expected
            );
            return Ok(None);
        }

        // Read payload
        let total_bits = HEADER_BITS + payload_bit_count;
        let total_positions_needed = total_bits.div_ceil(self.bits as usize);
        if positions.len() < total_positions_needed {
            return Ok(None);
        }

        let mut all_vals: Vec<u8> = Vec::with_capacity(total_positions_needed);
        for i in 0..total_positions_needed {
            let pos = positions[i];
            if pos < frame.data.len() {
                all_vals.push(frame.data[pos] & mask);
            } else {
                return Ok(None);
            }
        }

        // Unpack all values to bits
        let mut all_bits: Vec<u8> = Vec::with_capacity(total_positions_needed * 4);
        for val in &all_vals {
            for i in (0..self.bits as usize).rev() {
                all_bits.push((val >> i) & 1);
            }
        }
        all_bits.truncate(total_bits);

        // Extract payload bits (skip header)
        let payload_bits = &all_bits[HEADER_BITS..];
        let payload_bytes = Self::bits_to_bytes(payload_bits);

        if payload_bytes.len() < SignaturePayload::SERIALIZED_SIZE {
            return Ok(None);
        }

        let mut buf = [0u8; SignaturePayload::SERIALIZED_SIZE];
        buf.copy_from_slice(&payload_bytes[..SignaturePayload::SERIALIZED_SIZE]);

        match SignaturePayload::from_bytes(&buf) {
            Ok(sig) => Ok(Some(sig)),
            Err(_) => Ok(None),
        }
    }
}

/// Compute the variance of a slice of u8 values.
fn compute_variance(values: &[u8]) -> u32 {
    if values.len() < 2 {
        return 0;
    }
    let n = values.len() as u64;
    let sum: u64 = values.iter().map(|&v| v as u64).sum();
    let mean = sum / n;
    let sq_sum: u64 = values
        .iter()
        .map(|&v| {
            let d = (v as i64 - mean as i64).unsigned_abs();
            d * d
        })
        .sum();
    (sq_sum / n) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::video::VideoFormat;

    /// Create a test frame with a gradient pattern (high variance at edges).
    fn make_frame(width: u32, height: u32, _frame_index: u64) -> (Vec<u8>, VideoFormat) {
        let bpp = 3; // RGB8
        let stride = width as usize * bpp;
        let mut data = vec![0u8; stride * height as usize];

        // Create a pattern with both smooth and high-variance regions
        for y in 0..height as usize {
            for x in 0..width as usize {
                let offset = y * stride + x * bpp;
                // Checkerboard pattern in the left half (high variance)
                // Smooth gradient in the right half (low variance)
                if x < width as usize / 2 {
                    let val = if (x + y) % 2 == 0 { 200 } else { 10 };
                    data[offset] = val;
                    data[offset + 1] = val;
                    data[offset + 2] = val;
                } else {
                    let val = (x * 2) as u8;
                    data[offset] = val;
                    data[offset + 1] = val;
                    data[offset + 2] = val;
                }
            }
        }
        (data, VideoFormat::Rgb8)
    }

    /// Create a signature payload for testing.
    fn make_payload(frame_index: u64) -> SignaturePayload {
        let signer = Signer::generate();
        let frame_data = vec![0x42u8; 100];
        signer.sign_frame(frame_index, &frame_data, None)
    }

    #[test]
    fn test_new_validates_bits() {
        let mod1 = AdaptiveLsbVideo::new(10, 1);
        assert_eq!(mod1.bits(), 1);
        assert_eq!(mod1.threshold(), 10);

        let mod4 = AdaptiveLsbVideo::new(50, 4);
        assert_eq!(mod4.bits(), 4);
    }

    #[test]
    #[should_panic(expected = "bits must be 1–4")]
    fn test_new_rejects_zero_bits() {
        let _ = AdaptiveLsbVideo::new(10, 0);
    }

    #[test]
    #[should_panic(expected = "bits must be 1–4")]
    fn test_new_rejects_too_many_bits() {
        let _ = AdaptiveLsbVideo::new(10, 5);
    }

    #[test]
    fn test_compute_variance_empty() {
        assert_eq!(compute_variance(&[]), 0);
    }

    #[test]
    fn test_compute_variance_single() {
        assert_eq!(compute_variance(&[100]), 0);
    }

    #[test]
    fn test_compute_variance_uniform() {
        assert_eq!(compute_variance(&[50, 50, 50, 50]), 0);
    }

    #[test]
    fn test_compute_variance_high() {
        let v = compute_variance(&[0, 255, 0, 255]);
        assert!(v > 10000, "high variance should be large, got {}", v);
    }

    #[test]
    fn test_embed_extract_roundtrip() {
        let (data, format) = make_frame(64, 64, 0);
        let mut frame = VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format,
            data: &mut data.clone(),
            frame_index: 0,
        };

        let mut module = AdaptiveLsbVideo::new(0, 1); // threshold=0 to embed everywhere
        let payload = make_payload(0);

        module.embed(&mut frame, Some(&payload)).unwrap();
        let extracted = module.extract(&frame).unwrap();

        assert!(extracted.is_some());
        let ext = extracted.unwrap();
        assert_eq!(ext.frame_index, payload.frame_index);
        assert_eq!(ext.hash, payload.hash);
    }

    #[test]
    fn test_embed_extract_multi_bit() {
        let (data, format) = make_frame(64, 64, 1);
        let mut frame = VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format,
            data: &mut data.clone(),
            frame_index: 1,
        };

        let mut module = AdaptiveLsbVideo::new(0, 2);
        let payload = make_payload(1);

        module.embed(&mut frame, Some(&payload)).unwrap();
        let extracted = module.extract(&frame).unwrap();

        assert!(extracted.is_some());
        let ext = extracted.unwrap();
        assert_eq!(ext.frame_index, payload.frame_index);
        assert_eq!(ext.hash, payload.hash);
    }

    #[test]
    fn test_embed_extract_4bit() {
        let (data, format) = make_frame(64, 64, 2);
        let mut frame = VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format,
            data: &mut data.clone(),
            frame_index: 2,
        };

        let mut module = AdaptiveLsbVideo::new(0, 4);
        let payload = make_payload(2);

        module.embed(&mut frame, Some(&payload)).unwrap();
        let extracted = module.extract(&frame).unwrap();

        assert!(extracted.is_some());
        let ext = extracted.unwrap();
        assert_eq!(ext.frame_index, payload.frame_index);
    }

    #[test]
    fn test_no_payload_embed_is_noop() {
        let (data, format) = make_frame(32, 32, 0);
        let original = data.clone();
        let mut frame = VideoFrame {
            width: 32,
            height: 32,
            stride: 32 * 3,
            format,
            data: &mut data.clone(),
            frame_index: 0,
        };

        let mut module = AdaptiveLsbVideo::new(0, 1);
        module.embed(&mut frame, None).unwrap();

        assert_eq!(frame.data, original.as_slice());
    }

    #[test]
    fn test_high_threshold_blocks_embedding() {
        // With a very high threshold, there won't be enough positions
        let (data, format) = make_frame(8, 8, 0);
        let mut frame = VideoFrame {
            width: 8,
            height: 8,
            stride: 8 * 3,
            format,
            data: &mut data.clone(),
            frame_index: 0,
        };

        let mut module = AdaptiveLsbVideo::new(u32::MAX, 1); // impossible threshold
        let payload = make_payload(0);

        let result = module.embed(&mut frame, Some(&payload));
        assert!(result.is_err(), "should fail with insufficient positions");
    }

    #[test]
    fn test_extract_from_clean_frame_returns_none() {
        let (data, format) = make_frame(32, 32, 0);
        let frame = VideoFrame {
            width: 32,
            height: 32,
            stride: 32 * 3,
            format,
            data: &mut data.clone(),
            frame_index: 0,
        };

        let module = AdaptiveLsbVideo::new(0, 1);
        let result = module.extract(&frame).unwrap();
        assert!(result.is_none(), "clean frame should yield no payload");
    }

    #[test]
    fn test_threshold_filters_low_variance() {
        // With threshold=0, all positions are candidates.
        // With threshold=high, only checkerboard region positions qualify.
        let (mut data, format) = make_frame(32, 32, 0);
        let frame = VideoFrame {
            width: 32,
            height: 32,
            stride: 32 * 3,
            format,
            data: &mut data,
            frame_index: 0,
        };

        let mod_low = AdaptiveLsbVideo::new(0, 1);
        let mod_high = AdaptiveLsbVideo::new(5000, 1);

        let pos_low = mod_low.select_positions(&frame);
        let pos_high = mod_high.select_positions(&frame);

        assert!(
            pos_low.len() > pos_high.len(),
            "low threshold should have more positions"
        );
    }

    #[test]
    fn test_bytes_to_bits_roundtrip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let bits = AdaptiveLsbVideo::bytes_to_bits(&original);
        let recovered = AdaptiveLsbVideo::bits_to_bytes(&bits);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_variance_map_correctness() {
        // Create a simple 3x3 frame with a known pattern
        let bpp = 3;
        let w = 3;
        let h = 3;
        let stride = w * bpp;
        let mut data: Vec<u8> = vec![
            // Row 0: 0, 255, 0
            0, 0, 0, 255, 255, 255, 0, 0, 0, // Row 1: 255, 0, 255
            255, 255, 255, 0, 0, 0, 255, 255, 255, // Row 2: 0, 255, 0
            0, 0, 0, 255, 255, 255, 0, 0, 0,
        ];

        let frame = VideoFrame {
            width: w as u32,
            height: h as u32,
            stride: stride as u32,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };

        let variances = AdaptiveLsbVideo::compute_variance_map(&frame, 1);
        // Should have w*h*bpp = 27 entries
        assert_eq!(variances.len(), w * h * bpp);

        // Center pixel should have high variance (checkerboard)
        let center_offset = 1 * stride + 1 * bpp; // pixel (1,1)
        let center_var = variances
            .iter()
            .find(|(off, _)| *off == center_offset)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        assert!(center_var > 0, "center pixel should have non-zero variance");
    }
}
