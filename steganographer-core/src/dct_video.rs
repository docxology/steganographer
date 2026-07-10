//! DCT-domain steganography for compression-resistant embedding.
//!
//! This module implements a Discrete Cosine Transform (DCT) based
//! steganography technique where payload bits are embedded into the
//! mid-frequency DCT coefficients of 8×8 pixel blocks. This is the
//! same domain used by JPEG compression, making the embedding
//! significantly more resistant to JPEG re-encoding than LSB methods.
//!
//! ## Algorithm
//!
//! 1. Divide the frame into 8×8 blocks.
//! 2. Apply a 2D DCT to each block (using f64 for precision).
//! 3. For each payload bit, modify a mid-frequency coefficient:
//!    - Round the coefficient to the nearest `quant_step` boundary.
//!    - If bit=1, move to the upper half of the cell; if bit=0, the lower half.
//! 4. Apply the inverse DCT to reconstruct the block.
//! 5. Extraction: apply DCT, read the coefficient, determine which half
//!    of the quantization cell it falls in.
//!
//! ## Advantages over LSB
//!
//! - **JPEG resistant**: Since data is in the DCT domain, JPEG
//!   compression preserves it better than spatial-domain LSB.
//! - **Less detectable**: DCT modifications are less visible than LSB
//!   changes at the same capacity.
//! - **Tunable**: The coefficient index and quantization step are
//!   configurable, trading off robustness vs. visibility.

use crate::crypto::SignaturePayload;
use crate::video::{VideoFormat, VideoFrame, VideoStegoModule};

/// Block size for DCT processing (8×8 as in JPEG).
const BLOCK_SIZE: usize = 8;

/// Precomputed DCT basis matrix: cos(pi * (2k+1) * n / 16) / sqrt(2) normalization.
/// Computed once at startup.
fn cos_basis(n: usize, k: usize) -> f64 {
    let factor = if n == 0 { 1.0 / 2.0_f64.sqrt() } else { 1.0 };
    factor * (std::f64::consts::PI * (2.0 * k as f64 + 1.0) * n as f64 / 16.0).cos()
}

/// DCT-domain steganography module.
///
/// Embeds payload data into mid-frequency DCT coefficients of 8×8 pixel
/// blocks for compression-resistant steganography.
pub struct DctVideo {
    /// Which coefficient to modify (zigzag index, 0-based, excluding DC).
    /// Recommended: 10–40 (mid-frequencies). Default: 20.
    coef_index: usize,
    /// Quantization step for embedding. Higher = more robust but more visible.
    /// Recommended: 8–32. Default: 16.
    quant_step: f64,
    /// Which color channel to use (0=R/B, 1=G, 2=B/R). Default: 1 (green, least visible).
    channel: usize,
}

impl DctVideo {
    /// Create a new DCT steganography module.
    ///
    /// # Arguments
    /// * `coef_index` — Zigzag position of the coefficient to modify (1–63, not DC).
    /// * `quant_step` — Quantization step for bit embedding (8–32 recommended).
    /// * `channel` — Color channel index (0, 1, or 2).
    pub fn new(coef_index: usize, quant_step: i32, channel: usize) -> Self {
        assert!(
            coef_index >= 1 && coef_index < 64,
            "Coefficient index must be 1–63"
        );
        assert!(quant_step > 0, "Quantization step must be positive");
        assert!(channel < 3, "Channel must be 0, 1, or 2");
        Self {
            coef_index,
            quant_step: quant_step as f64,
            channel,
        }
    }

    /// Create with defaults: coef_index=20, quant_step=16, channel=1 (green).
    pub fn default() -> Self {
        Self::new(20, 16, 1)
    }

    /// Get the number of 8×8 blocks available in a frame.
    fn block_count(width: u32, height: u32) -> (usize, usize) {
        (width as usize / BLOCK_SIZE, height as usize / BLOCK_SIZE)
    }

    /// Apply 2D DCT to an 8×8 block of pixel values.
    ///
    /// Returns 64 DCT coefficients as a flat array (row-major).
    fn dct_2d(block: &[u8; 64]) -> [f64; 64] {
        let mut centered = [0.0f64; 64];
        for i in 0..64 {
            centered[i] = block[i] as f64 - 128.0;
        }

        // 2D DCT = 1D DCT on rows, then 1D DCT on columns
        let mut temp = [0.0f64; 64];

        // Row transform
        for i in 0..8 {
            for n in 0..8 {
                let mut sum = 0.0;
                for k in 0..8 {
                    sum += centered[i * 8 + k] * cos_basis(n, k);
                }
                temp[i * 8 + n] = sum / 2.0;
            }
        }

        // Column transform
        let mut result = [0.0f64; 64];
        for j in 0..8 {
            for n in 0..8 {
                let mut sum = 0.0;
                for k in 0..8 {
                    sum += temp[k * 8 + j] * cos_basis(n, k);
                }
                result[n * 8 + j] = sum / 2.0;
            }
        }

        result
    }

    /// Apply 2D inverse DCT to 64 DCT coefficients.
    fn idct_2d(coeffs: &[f64; 64]) -> [u8; 64] {
        // Column inverse transform
        let mut temp = [0.0f64; 64];
        for j in 0..8 {
            for k in 0..8 {
                let mut sum = 0.0;
                for n in 0..8 {
                    sum += coeffs[n * 8 + j] * cos_basis(n, k);
                }
                temp[k * 8 + j] = sum / 2.0;
            }
        }

        // Row inverse transform
        let mut result = [0u8; 64];
        for i in 0..8 {
            for k in 0..8 {
                let mut sum = 0.0;
                for n in 0..8 {
                    sum += temp[i * 8 + n] * cos_basis(n, k);
                }
                let val = (sum / 2.0 + 128.0).round();
                result[i * 8 + k] = val.clamp(0.0, 255.0) as u8;
            }
        }

        result
    }

    /// Map a linear index to zigzag scan position.
    fn zigzag_to_linear(idx: usize) -> usize {
        const ZIGZAG: [usize; 64] = [
            0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34,
            27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37,
            44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
        ];
        ZIGZAG[idx]
    }
}

impl VideoStegoModule for DctVideo {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let sig = match sig {
            Some(s) => s,
            None => return Ok(()),
        };

        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3,
            VideoFormat::Bgra8 => 4,
            VideoFormat::Yuv420 => {
                anyhow::bail!("DCT steganography does not support YUV420 planar format");
            }
        };

        let (blocks_x, blocks_y) = Self::block_count(frame.width, frame.height);
        let total_blocks = blocks_x * blocks_y;
        let payload_bytes = sig.to_bytes();
        let total_bits = payload_bytes.len() * 8;

        if total_blocks < total_bits {
            anyhow::bail!(
                "Not enough 8x8 blocks for DCT embedding: need {} blocks ({} bits), have {} ({}x{} blocks)",
                total_bits,
                total_bits,
                total_blocks,
                blocks_x,
                blocks_y
            );
        }

        let stride = frame.stride as usize;
        let data = &mut frame.data;
        let coef_linear = Self::zigzag_to_linear(self.coef_index);

        for (bit_idx, byte) in payload_bytes.iter().enumerate() {
            for bit_in_byte in 0..8 {
                let bit = (byte >> bit_in_byte) & 1;
                let payload_bit = bit_idx * 8 + bit_in_byte;

                let block_x = (payload_bit % blocks_x) * BLOCK_SIZE;
                let block_y = (payload_bit / blocks_x) * BLOCK_SIZE;

                // Extract 8×8 block from the chosen channel
                let mut block = [0u8; 64];
                for i in 0..8 {
                    for j in 0..8 {
                        let offset = (block_y + i) * stride + (block_x + j) * bpp + self.channel;
                        if offset < data.len() {
                            block[i * 8 + j] = data[offset];
                        }
                    }
                }

                // Forward DCT
                let mut coeffs = Self::dct_2d(&block);

                // Embed bit into the chosen coefficient
                let coef = &mut coeffs[coef_linear];
                let quant = self.quant_step;
                // Move coefficient to quantization grid
                let cell = (*coef / quant).floor();
                if bit == 1 {
                    *coef = cell * quant + quant * 0.75; // upper part of cell
                } else {
                    *coef = cell * quant + quant * 0.25; // lower part of cell
                }

                // Inverse DCT
                let restored = Self::idct_2d(&coeffs);

                // Write back
                for i in 0..8 {
                    for j in 0..8 {
                        let offset = (block_y + i) * stride + (block_x + j) * bpp + self.channel;
                        if offset < data.len() {
                            data[offset] = restored[i * 8 + j];
                        }
                    }
                }
            }
        }

        log::debug!(
            "DCT embed: {} bits into {} blocks, coef[{}], q={} (frame {})",
            total_bits,
            total_blocks,
            self.coef_index,
            self.quant_step,
            frame.frame_index
        );

        Ok(())
    }

    fn extract(&self, frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3,
            VideoFormat::Bgra8 => 4,
            VideoFormat::Yuv420 => return Ok(None),
        };

        let (blocks_x, blocks_y) = Self::block_count(frame.width, frame.height);
        let total_blocks = blocks_x * blocks_y;
        let total_bits = SignaturePayload::SERIALIZED_SIZE * 8;

        if total_blocks < total_bits {
            return Ok(None);
        }

        let stride = frame.stride as usize;
        let data = &frame.data;
        let coef_linear = Self::zigzag_to_linear(self.coef_index);

        let mut payload_bytes = [0u8; SignaturePayload::SERIALIZED_SIZE];

        for bit_idx in 0..payload_bytes.len() {
            for bit_in_byte in 0..8 {
                let payload_bit = bit_idx * 8 + bit_in_byte;

                let block_x = (payload_bit % blocks_x) * BLOCK_SIZE;
                let block_y = (payload_bit / blocks_x) * BLOCK_SIZE;

                // Extract block
                let mut block = [0u8; 64];
                for i in 0..8 {
                    for j in 0..8 {
                        let offset = (block_y + i) * stride + (block_x + j) * bpp + self.channel;
                        if offset < data.len() {
                            block[i * 8 + j] = data[offset];
                        }
                    }
                }

                // Forward DCT
                let coeffs = Self::dct_2d(&block);

                // Extract bit from coefficient
                let coef = coeffs[coef_linear];
                let quant = self.quant_step;
                let cell_pos = (coef / quant).rem_euclid(1.0);

                if cell_pos >= 0.5 {
                    payload_bytes[bit_idx] |= 1 << bit_in_byte;
                }
            }
        }

        if !SignaturePayload::has_valid_magic(&payload_bytes) {
            return Ok(None);
        }

        SignaturePayload::from_bytes(&payload_bytes).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn make_frame(data: &mut [u8], width: u32, height: u32) -> VideoFrame<'_> {
        VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data,
            frame_index: 0,
        }
    }

    #[test]
    fn test_dct_roundtrip() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"dct test", None);

        // Need enough blocks: 109 bytes * 8 bits = 872 bits = 872 blocks
        // 872 blocks = ~30x30 blocks = 240x240 pixels
        let mut data = vec![128u8; 320 * 320 * 3];
        let mut dct = DctVideo::new(20, 16, 1);

        {
            let mut frame = make_frame(&mut data, 320, 320);
            dct.embed(&mut frame, Some(&payload)).unwrap();
        }

        {
            let frame = make_frame(&mut data, 320, 320);
            let extracted = dct.extract(&frame).unwrap();
            assert!(extracted.is_some(), "Should extract DCT payload");
            let extracted = extracted.unwrap();
            assert_eq!(extracted.frame_index, 0);
            assert_eq!(extracted.hash, payload.hash);
            assert_eq!(extracted.signature, payload.signature);
        }
    }

    #[test]
    fn test_dct_capacity_error() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);

        // Too small (8x8 = 1 block, need 872)
        let mut data = vec![128u8; 8 * 8 * 3];
        let mut dct = DctVideo::default();
        let mut frame = make_frame(&mut data, 8, 8);
        assert!(dct.embed(&mut frame, Some(&payload)).is_err());
    }

    #[test]
    fn test_dct_empty_frame_returns_none() {
        let dct = DctVideo::default();
        let mut data = vec![128u8; 320 * 320 * 3];
        let frame = make_frame(&mut data, 320, 320);
        let result = dct.extract(&frame).unwrap();
        assert!(result.is_none(), "Empty frame should return None");
    }

    #[test]
    fn test_dct_none_sig_noop() {
        let mut data = vec![128u8; 320 * 320 * 3];
        let original = data.clone();
        let mut dct = DctVideo::default();
        let mut frame = make_frame(&mut data, 320, 320);
        dct.embed(&mut frame, None).unwrap();
        assert_eq!(data, original, "None sig should not modify frame");
    }

    #[test]
    fn test_dct_bgra_format() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"bgra dct", None);

        let mut data = vec![128u8; 320 * 320 * 4];
        let mut dct = DctVideo::new(20, 16, 1);

        {
            let mut frame = VideoFrame {
                width: 320,
                height: 320,
                stride: 320 * 4,
                format: VideoFormat::Bgra8,
                data: &mut data,
                frame_index: 0,
            };
            dct.embed(&mut frame, Some(&payload)).unwrap();
        }

        {
            let frame = VideoFrame {
                width: 320,
                height: 320,
                stride: 320 * 4,
                format: VideoFormat::Bgra8,
                data: &mut data,
                frame_index: 0,
            };
            let extracted = dct.extract(&frame).unwrap();
            assert!(extracted.is_some());
        }
    }

    #[test]
    fn test_dct_visual_distortion_is_minimal() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"distortion test", None);

        let mut data = vec![128u8; 320 * 320 * 3];
        let original = data.clone();
        let mut dct = DctVideo::new(20, 8, 1);

        {
            let mut frame = make_frame(&mut data, 320, 320);
            dct.embed(&mut frame, Some(&payload)).unwrap();
        }

        // Check that the average pixel change is small
        let total_diff: u64 = data
            .iter()
            .zip(original.iter())
            .map(|(a, b)| (*a as i32 - *b as i32).unsigned_abs() as u64)
            .sum();
        let avg_diff = total_diff as f64 / data.len() as f64;
        assert!(
            avg_diff < 5.0,
            "Average pixel distortion should be small, got {}",
            avg_diff
        );
    }
}
