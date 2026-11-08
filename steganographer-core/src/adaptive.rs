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
//! - Only the payload-sized best prefix is retained, highest variance first.
//!
//! This makes detection harder because changes are concentrated in noisy
//! regions where statistical anomalies are harder to spot.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::crypto::SignaturePayload;
use crate::video::{VideoFormat, VideoFrame, VideoStegoModule};

/// Window size for local variance computation (window is `WINDOW x WINDOW`).
const WINDOW: usize = 3;

/// Header bits: 32-bit length prefix (same as LsbVideo).
const HEADER_BITS: usize = 32;
const PAYLOAD_BITS: usize = SignaturePayload::SERIALIZED_SIZE * 8;
const TOTAL_BITS: usize = HEADER_BITS + PAYLOAD_BITS;
const STREAM_BYTES: usize = TOTAL_BITS / 8;

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
    ///
    /// # Panics
    /// Panics if `bits` is not in 1..=4. For fallible construction, use
    /// [`try_new`](Self::try_new).
    pub fn new(threshold: u32, bits: u8) -> Self {
        Self::try_new(threshold, bits).expect("bits must be 1–4")
    }

    /// Create a new adaptive LSB video module, returning an error on
    /// invalid bits.
    ///
    /// Use this when `bits` comes from untrusted input (config, CLI args).
    pub fn try_new(threshold: u32, bits: u8) -> anyhow::Result<Self> {
        if !(1..=4).contains(&bits) {
            anyhow::bail!("bits must be 1–4, got {}", bits);
        }
        Ok(Self { threshold, bits })
    }

    /// Get the configured threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Get the configured bits.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Visit candidates in original row/pixel/channel order. Masking low bits
    /// keeps variance stable across embedding and extraction.
    fn visit_variances(frame: &VideoFrame, bits_per_byte: u8, mut visit: impl FnMut(usize, u32)) {
        let bpp = frame.format.bytes_per_pixel().unwrap_or(1);
        let w = frame.width as usize;
        let h = frame.height as usize;
        let stride = frame.stride as usize;
        let data = &frame.data;
        let half = WINDOW / 2;
        let mask = !((1u8 << bits_per_byte) - 1);

        for y in 0..h {
            for x in 0..w {
                // Gather pixel values in the window (upper bits only)
                let mut values = [0u8; WINDOW * WINDOW];
                let mut count = 0;
                let y_start = y.saturating_sub(half);
                let y_end = (y + half + 1).min(h);
                let x_start = x.saturating_sub(half);
                let x_end = (x + half + 1).min(w);

                for wy in y_start..y_end {
                    for wx in x_start..x_end {
                        let pixel_offset = wy * stride + wx * bpp;
                        if pixel_offset < data.len() {
                            values[count] = data[pixel_offset] & mask;
                            count += 1;
                        }
                    }
                }

                let variance = compute_variance(&values[..count]);

                // Emit an entry for each embeddable byte of this pixel.
                let base_offset = y * stride + x * bpp;
                // Alpha and row padding are not embedding candidates.
                for b in 0..bpp {
                    if frame.format == VideoFormat::Bgra8 && b + 1 == bpp {
                        continue;
                    }
                    let off = base_offset + b;
                    if off < data.len() {
                        visit(off, variance);
                    }
                }
            }
        }
    }

    /// Retain only the fixed framing-sized best prefix. The heap's maximum
    /// is the worst retained candidate: lowest variance, then latest offset.
    /// Offsets increase in scan order, preserving the old stable-sort ties.
    fn select_positions(&self, frame: &VideoFrame) -> Vec<usize> {
        let needed = TOTAL_BITS.div_ceil(self.bits as usize);
        let mut best = BinaryHeap::with_capacity(needed);
        Self::visit_variances(frame, self.bits, |offset, variance| {
            if variance < self.threshold {
                return;
            }
            let candidate = (Reverse(variance), offset);
            if best.len() < needed {
                best.push(candidate);
            } else if best.peek().is_some_and(|worst| candidate < *worst) {
                *best.peek_mut().expect("full candidate heap") = candidate;
            }
        });
        best.into_sorted_vec()
            .into_iter()
            .map(|(_, offset)| offset)
            .collect()
    }
}

impl VideoStegoModule for AdaptiveLsbVideo {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let payload = match sig {
            Some(sig) => sig.to_bytes(),
            None => return Ok(()),
        };
        frame.validate_packed_layout()?;
        let positions = self.select_positions(frame);
        let needed = TOTAL_BITS.div_ceil(self.bits as usize);
        if positions.len() < needed {
            anyhow::bail!(
                "Insufficient positions for {}-bit embedding: need {}, found {}",
                self.bits,
                needed,
                positions.len()
            );
        }

        let mut stream = [0u8; STREAM_BYTES];
        stream[..HEADER_BITS / 8].copy_from_slice(&(PAYLOAD_BITS as u32).to_le_bytes());
        stream[HEADER_BITS / 8..].copy_from_slice(&payload);
        let mask = (1u8 << self.bits) - 1;
        for (unit, &position) in positions.iter().enumerate() {
            let mut value = 0u8;
            for bit in 0..self.bits as usize {
                let index = unit * self.bits as usize + bit;
                value <<= 1;
                if index < TOTAL_BITS {
                    value |= (stream[index / 8] >> (7 - index % 8)) & 1;
                }
            }
            frame.data[position] = (frame.data[position] & !mask) | value;
        }
        Ok(())
    }

    fn extract(&self, frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        frame.validate_packed_layout()?;
        let positions = self.select_positions(frame);

        let header_positions = HEADER_BITS.div_ceil(self.bits as usize);
        if positions.len() < header_positions {
            return Ok(None);
        }
        let read_bit = |index: usize| {
            let unit = index / self.bits as usize;
            let shift = self.bits as usize - 1 - index % self.bits as usize;
            (frame.data[positions[unit]] >> shift) & 1
        };
        let mut header = [0u8; HEADER_BITS / 8];
        for index in 0..HEADER_BITS {
            header[index / 8] |= read_bit(index) << (7 - index % 8);
        }
        if u32::from_le_bytes(header) != PAYLOAD_BITS as u32 {
            return Ok(None);
        }
        if positions.len() < TOTAL_BITS.div_ceil(self.bits as usize) {
            return Ok(None);
        }
        let mut payload = [0u8; SignaturePayload::SERIALIZED_SIZE];
        for index in 0..PAYLOAD_BITS {
            payload[index / 8] |= read_bit(HEADER_BITS + index) << (7 - index % 8);
        }
        Ok(SignaturePayload::from_bytes(&payload).ok())
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
    #[test]
    fn multibit_minimum_pixels_and_one_pixel_short() {
        let payload = make_payload(5);
        for bits in 1..=4 {
            let needed = (32 + SignaturePayload::SERIALIZED_SIZE * 8).div_ceil(bits as usize);
            let width = needed.div_ceil(3) as u32;
            let mut data = vec![0x80; width as usize * 3];
            let mut frame = VideoFrame {
                width,
                height: 1,
                stride: width * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            let mut kernel = AdaptiveLsbVideo::new(0, bits);
            kernel.embed(&mut frame, Some(&payload)).unwrap();
            assert_eq!(
                kernel.extract(&frame).unwrap().unwrap().to_bytes(),
                payload.to_bytes()
            );
            let mut short = vec![0x80; (width as usize - 1) * 3];
            let before = short.clone();
            let mut frame = VideoFrame {
                width: width - 1,
                height: 1,
                stride: (width - 1) * 3,
                format: VideoFormat::Rgb8,
                data: &mut short,
                frame_index: 0,
            };
            assert!(kernel.embed(&mut frame, Some(&payload)).is_err());
            assert_eq!(short, before);
        }
    }

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
        let mod_high = AdaptiveLsbVideo::new(u32::MAX, 1);
        assert_eq!(mod_low.select_positions(&frame).len(), TOTAL_BITS);
        assert!(mod_high.select_positions(&frame).is_empty());
    }

    #[test]
    fn bounded_prefix_matches_stable_sort_and_legacy_carrier_bytes() {
        let payload = make_payload(7);
        for format in [VideoFormat::Rgb8, VideoFormat::Bgra8] {
            let bpp = format.bytes_per_pixel().unwrap();
            for bits in 1..=4 {
                for threshold in [0, 1000, u32::MAX] {
                    for flat in [false, true] {
                        let width = 37usize;
                        let height = 19usize;
                        let stride = width * bpp + 11;
                        let mut data = vec![0xA5; stride * height + 17];
                        for y in 0..height {
                            for x in 0..width {
                                for channel in 0..bpp {
                                    data[y * stride + x * bpp + channel] = if flat {
                                        0x80
                                    } else {
                                        ((x * 73 + y * 31 + channel * 47) % 256) as u8
                                    };
                                }
                            }
                        }
                        let before = data.clone();
                        let mut frame = VideoFrame {
                            width: width as u32,
                            height: height as u32,
                            stride: stride as u32,
                            format,
                            data: &mut data,
                            frame_index: 7,
                        };
                        let mut reference = Vec::new();
                        AdaptiveLsbVideo::visit_variances(&frame, bits, |offset, variance| {
                            if variance >= threshold {
                                reference.push((offset, variance));
                            }
                        });
                        // This is the previous full stable-sort selection.
                        reference.sort_by_key(|&(_, variance)| Reverse(variance));
                        let needed = TOTAL_BITS.div_ceil(bits as usize);
                        let expected: Vec<_> = reference
                            .iter()
                            .take(needed)
                            .map(|&(offset, _)| offset)
                            .collect();
                        let mut module = AdaptiveLsbVideo::new(threshold, bits);
                        assert_eq!(module.select_positions(&frame), expected);
                        if expected.len() < needed {
                            assert!(module.embed(&mut frame, Some(&payload)).is_err());
                            assert_eq!(frame.data, before);
                            continue;
                        }
                        let mut legacy = before.clone();
                        let mut bytes = (PAYLOAD_BITS as u32).to_le_bytes().to_vec();
                        bytes.extend_from_slice(&payload.to_bytes());
                        let wire_bits: Vec<_> = bytes
                            .iter()
                            .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
                            .collect();
                        for (chunk, &offset) in wire_bits.chunks(bits as usize).zip(&expected) {
                            let value = chunk.iter().fold(0, |value, bit| (value << 1) | bit)
                                << (bits as usize - chunk.len());
                            let mask = (1u8 << bits) - 1;
                            legacy[offset] = (legacy[offset] & !mask) | value;
                        }
                        module.embed(&mut frame, Some(&payload)).unwrap();
                        assert_eq!(frame.data, legacy);
                        assert_eq!(module.select_positions(&frame), expected);
                        assert_eq!(
                            module.extract(&frame).unwrap().unwrap().to_bytes(),
                            payload.to_bytes()
                        );
                        for y in 0..height {
                            assert_eq!(
                                &frame.data[y * stride + width * bpp..(y + 1) * stride],
                                &before[y * stride + width * bpp..(y + 1) * stride]
                            );
                            if format == VideoFormat::Bgra8 {
                                for x in 0..width {
                                    let alpha = y * stride + x * bpp + 3;
                                    assert_eq!(frame.data[alpha], before[alpha]);
                                }
                            }
                        }
                        assert_eq!(&frame.data[stride * height..], &before[stride * height..]);
                    }
                }
            }
        }
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

        let mut variances = Vec::new();
        AdaptiveLsbVideo::visit_variances(&frame, 1, |offset, variance| {
            variances.push((offset, variance));
        });
        // Should have w*h*bpp = 27 entries
        assert_eq!(variances.len(), w * h * bpp);

        // Center pixel should have high variance (checkerboard)
        let center_offset = stride + bpp; // pixel (1,1)
        let center_var = variances
            .iter()
            .find(|(off, _)| *off == center_offset)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        assert!(center_var > 0, "center pixel should have non-zero variance");
    }
    #[test]
    fn test_bgra8_alpha_bytes_untouched() {
        // FMT-002: BGRA8 alpha bytes must never be modified by embedding.
        let w = 64usize;
        let h = 64usize;
        let bpp = 4usize;
        let stride = w * bpp;
        let mut data = vec![0u8; stride * h];
        for y in 0..h {
            for x in 0..w {
                let off = y * stride + x * bpp;
                data[off] = ((x * 7 + y * 3) % 251) as u8;
                data[off + 1] = ((x * 11 + y) % 199) as u8;
                data[off + 2] = ((x + y * 5) % 173) as u8;
                data[off + 3] = ((x * 2 + y * 7) % 256) as u8; // alpha
            }
        }
        let alpha_before: Vec<u8> = data.iter().skip(3).step_by(4).copied().collect();

        let mut module = AdaptiveLsbVideo::try_new(0, 1).unwrap();
        let payload = make_payload(0);

        {
            let mut frame = VideoFrame {
                width: w as u32,
                height: h as u32,
                stride: stride as u32,
                format: VideoFormat::Bgra8,
                data: &mut data,
                frame_index: 0,
            };
            module.embed(&mut frame, Some(&payload)).unwrap();
        }

        let alpha_after: Vec<u8> = data.iter().skip(3).step_by(4).copied().collect();
        assert_eq!(alpha_before, alpha_after, "alpha bytes must be untouched");

        let frame = VideoFrame {
            width: w as u32,
            height: h as u32,
            stride: stride as u32,
            format: VideoFormat::Bgra8,
            data: &mut data,
            frame_index: 0,
        };
        let extracted = module.extract(&frame).unwrap();
        assert!(
            extracted.is_some(),
            "Bgra8 roundtrip should recover payload"
        );
        let ext = extracted.unwrap();
        assert_eq!(ext.frame_index, payload.frame_index);
        assert_eq!(ext.hash, payload.hash);
    }

    #[test]
    fn test_variance_map_excludes_bgra8_alpha() {
        let w = 4usize;
        let h = 2usize;
        let bpp = 4usize;
        let stride = w * bpp;
        let mut data = vec![7u8; stride * h];
        let frame = VideoFrame {
            width: w as u32,
            height: h as u32,
            stride: stride as u32,
            format: VideoFormat::Bgra8,
            data: &mut data,
            frame_index: 0,
        };
        let mut variances = Vec::new();
        AdaptiveLsbVideo::visit_variances(&frame, 1, |offset, variance| {
            variances.push((offset, variance));
        });
        // One entry per non-alpha byte: w * h * (bpp - 1).
        assert_eq!(variances.len(), w * h * (bpp - 1));
        // No alpha offset (byte index % 4 == 3) may appear.
        assert!(
            variances.iter().all(|(off, _)| off % 4 != 3),
            "alpha offsets must be excluded from candidates"
        );
    }

    #[test]
    fn test_try_new_rejects_invalid_bits() {
        assert!(AdaptiveLsbVideo::try_new(10, 0).is_err());
        assert!(AdaptiveLsbVideo::try_new(10, 5).is_err());
        assert!(AdaptiveLsbVideo::try_new(10, 1).is_ok());
        assert!(AdaptiveLsbVideo::try_new(10, 4).is_ok());
        // new() still works for valid input.
        assert_eq!(AdaptiveLsbVideo::new(10, 3).bits(), 3);
    }
}
