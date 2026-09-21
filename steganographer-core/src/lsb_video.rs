//! LSB (Least Significant Bit) video steganography.
//!
//! Embeds and extracts [`SignaturePayload`] data into/from video frame pixel bytes
//! using sequential LSB replacement. A 32-bit length prefix enables extraction
//! to know how many bits to read back.
//!
//! The number of LSBs used per byte is configurable (1–4).

use crate::crypto::SignaturePayload;
use crate::video::{VideoFormat, VideoFrame, VideoStegoModule};

/// LSB-based video steganography module.
pub struct LsbVideo {
    bits: u8,
}

impl LsbVideo {
    /// Create a new LSB video module.
    ///
    /// # Arguments
    /// * `bits` — Number of least-significant bits to use per pixel byte (1–4).
    ///
    /// # Panics
    /// Panics if `bits` is not in 1..=4. For fallible construction, use [`try_new`](Self::try_new).
    pub fn new(bits: u8) -> Self {
        assert!((1..=4).contains(&bits), "LSB bits must be 1–4");
        Self { bits }
    }

    /// Create a new LSB video module, returning an error on invalid bits.
    ///
    /// Use this when `bits` comes from untrusted input (config, CLI args).
    pub fn try_new(bits: u8) -> anyhow::Result<Self> {
        if !(1..=4).contains(&bits) {
            anyhow::bail!("LSB bits must be 1–4, got {}", bits);
        }
        Ok(Self { bits })
    }

    /// Serialize payload to a bit vector, prefixed by a 32-bit length (in bits).
    fn payload_to_bits(payload: &SignaturePayload) -> Vec<u8> {
        let raw_bytes = payload.to_bytes();
        let raw_bits: Vec<u8> = raw_bytes
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect();

        // Prepend 32-bit length prefix (number of payload bits)
        let len = raw_bits.len() as u32;
        let len_bits: Vec<u8> = (0..32).rev().map(|i| ((len >> i) & 1) as u8).collect();

        let mut result = len_bits;
        result.extend_from_slice(&raw_bits);
        result
    }

    /// Extract bits from pixel data, reading the 32-bit length prefix first.
    fn bits_to_payload(data: &[u8], bits_per_byte: u8) -> anyhow::Result<Option<SignaturePayload>> {
        // We need at least 32 bits for the length prefix
        let min_bytes_for_prefix = 32usize.div_ceil(bits_per_byte as usize);
        if data.len() < min_bytes_for_prefix {
            return Ok(None);
        }

        // Extract all LSBs
        let all_bits: Vec<u8> = data
            .iter()
            .flat_map(|byte| (0..bits_per_byte).rev().map(move |i| (byte >> i) & 1))
            .collect();

        if all_bits.len() < 32 {
            return Ok(None);
        }

        // Read 32-bit length prefix
        let mut payload_bit_count: u32 = 0;
        for &bit in &all_bits[..32] {
            payload_bit_count = (payload_bit_count << 1) | bit as u32;
        }

        let expected = SignaturePayload::SERIALIZED_SIZE * 8;
        if payload_bit_count as usize != expected {
            log::trace!(
                "LSB video: length prefix {} != expected payload bits {}",
                payload_bit_count,
                expected
            );
            return Ok(None);
        }

        let total_needed = 32 + payload_bit_count as usize;
        if all_bits.len() < total_needed {
            return Ok(None);
        }

        // Reconstruct payload bytes from bits
        let payload_bits = &all_bits[32..total_needed];
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

impl VideoStegoModule for LsbVideo {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let sig = match sig {
            Some(s) => s,
            None => return Ok(()),
        };

        let bits = Self::payload_to_bits(sig);
        let total_bits = bits.len();
        // FMT-002: the alpha channel of BGRA8 is never an embedding target.
        // Core `VideoFrame` data is packed (`stride == width * bpp`), so
        // alpha bytes are exactly every 4th byte; there is no row padding to
        // exclude. RGB8 (and other) carriers are unchanged.
        let alpha_last = frame.format == VideoFormat::Bgra8;
        let eligible_bytes = if alpha_last {
            frame.data.len() - frame.data.len() / 4
        } else {
            frame.data.len()
        };
        let capacity = eligible_bytes * self.bits as usize;

        if total_bits > capacity {
            anyhow::bail!(
                "Not enough LSB capacity in frame: need {} bits, have {} ({} eligible bytes × {} bits)",
                total_bits,
                capacity,
                eligible_bytes,
                self.bits
            );
        }

        log::debug!(
            "LSB video embed: {} bits into {} bytes (frame {})",
            total_bits,
            frame.data.len(),
            frame.frame_index
        );

        let mut bit_idx = 0usize;
        let mask = !((1u8 << self.bits) - 1); // e.g., bits=2 → mask = 0b11111100
        for (idx, byte) in frame.data.iter_mut().enumerate() {
            if bit_idx >= total_bits {
                break;
            }
            if alpha_last && idx % 4 == 3 {
                continue;
            }
            let mut new_lsb: u8 = 0;
            for shift in (0..self.bits).rev() {
                if bit_idx < total_bits {
                    new_lsb |= bits[bit_idx] << shift;
                    bit_idx += 1;
                }
            }
            *byte = (*byte & mask) | new_lsb;
        }

        log::debug!("LSB video embed complete: wrote {} bits", bit_idx);
        Ok(())
    }

    fn extract(&self, frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        log::debug!(
            "LSB video extract: reading from {} bytes (frame {})",
            frame.data.len(),
            frame.frame_index
        );
        // FMT-002: mirror the embed side — skip BGRA8 alpha bytes so the bit
        // stream stays aligned with what was written.
        if frame.format == VideoFormat::Bgra8 {
            let visible: Vec<u8> = frame
                .data
                .iter()
                .enumerate()
                .filter(|(idx, _)| idx % 4 != 3)
                .map(|(_, b)| *b)
                .collect();
            Self::bits_to_payload(&visible, self.bits)
        } else {
            Self::bits_to_payload(frame.data, self.bits)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::video::VideoFormat;

    fn make_test_frame(data: &mut [u8]) -> VideoFrame<'_> {
        VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format: VideoFormat::Rgb8,
            data,
            frame_index: 0,
        }
    }

    #[test]
    fn test_embed_extract_roundtrip() {
        let signer = Signer::generate();
        let video_data_original = vec![0u8; 64 * 64 * 3]; // RGB 64x64
        let payload = signer.sign_frame(42, &video_data_original, None);

        let mut frame_data = vec![128u8; 64 * 64 * 3]; // non-zero initial data
        let mut lsb = LsbVideo::new(1);

        {
            let mut frame = make_test_frame(&mut frame_data);
            lsb.embed(&mut frame, Some(&payload)).unwrap();
        }

        {
            let frame = VideoFrame {
                width: 64,
                height: 64,
                stride: 64 * 3,
                format: VideoFormat::Rgb8,
                data: &mut frame_data,
                frame_index: 0,
            };
            let extracted = lsb.extract(&frame).unwrap();
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
        let video_data = vec![0u8; 64 * 64 * 3];
        let payload = signer.sign_frame(99, &video_data, None);

        let mut frame_data = vec![200u8; 64 * 64 * 3];
        let mut lsb = LsbVideo::new(2);

        {
            let mut frame = make_test_frame(&mut frame_data);
            lsb.embed(&mut frame, Some(&payload)).unwrap();
        }

        {
            let frame = VideoFrame {
                width: 64,
                height: 64,
                stride: 64 * 3,
                format: VideoFormat::Rgb8,
                data: &mut frame_data,
                frame_index: 0,
            };
            let extracted = lsb.extract(&frame).unwrap();
            assert!(extracted.is_some());
            let extracted = extracted.unwrap();
            assert_eq!(extracted.frame_index, 99);
            assert_eq!(extracted.hash, payload.hash);
        }
    }

    #[test]
    fn test_capacity_error() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);

        // Frame too small to hold payload
        let mut frame_data = vec![0u8; 10];
        let mut lsb = LsbVideo::new(1);
        let mut frame = VideoFrame {
            width: 10,
            height: 1,
            stride: 10,
            format: VideoFormat::Rgb8,
            data: &mut frame_data,
            frame_index: 0,
        };
        let result = lsb.embed(&mut frame, Some(&payload));
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_empty_frame() {
        let lsb = LsbVideo::new(1);
        let mut data = vec![0u8; 64 * 64 * 3];
        let frame = VideoFrame {
            width: 64,
            height: 64,
            stride: 64 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let result = lsb.extract(&frame).unwrap();
        assert!(result.is_none(), "Empty frame should not yield a payload");
    }

    #[test]
    fn test_none_sig_is_noop() {
        let mut frame_data = vec![42u8; 1024];
        let original = frame_data.clone();
        let mut lsb = LsbVideo::new(1);
        let mut frame = make_test_frame(&mut frame_data);
        lsb.embed(&mut frame, None).unwrap();
        // Data should be unchanged (limited to the portion that the frame covers)
        assert_eq!(&frame_data[..1024], &original[..1024]);
    }
    #[test]
    fn test_bgra8_alpha_bytes_untouched() {
        // FMT-002: BGRA8 alpha bytes must never be modified by embedding,
        // and the bit stream must skip them on extraction too.
        let signer = Signer::generate();
        let payload = signer.sign_frame(5, b"bgra8 alpha test", None);

        let w = 64usize;
        let h = 64usize;
        let bpp = 4usize;
        let stride = w * bpp;
        let mut frame_data = vec![0u8; stride * h];
        for y in 0..h {
            for x in 0..w {
                let off = y * stride + x * bpp;
                frame_data[off] = ((x * 7 + y * 3) % 251) as u8;
                frame_data[off + 1] = ((x * 11 + y) % 199) as u8;
                frame_data[off + 2] = ((x + y * 5) % 173) as u8;
                frame_data[off + 3] = ((x * 2 + y * 7) % 256) as u8; // alpha
            }
        }
        let alpha_before: Vec<u8> = frame_data.iter().skip(3).step_by(4).copied().collect();

        let mut lsb = LsbVideo::new(1);
        {
            let mut frame = VideoFrame {
                width: w as u32,
                height: h as u32,
                stride: stride as u32,
                format: VideoFormat::Bgra8,
                data: &mut frame_data,
                frame_index: 0,
            };
            lsb.embed(&mut frame, Some(&payload)).unwrap();
        }

        let alpha_after: Vec<u8> = frame_data.iter().skip(3).step_by(4).copied().collect();
        assert_eq!(alpha_before, alpha_after, "alpha bytes must be untouched");

        let frame = VideoFrame {
            width: w as u32,
            height: h as u32,
            stride: stride as u32,
            format: VideoFormat::Bgra8,
            data: &mut frame_data,
            frame_index: 0,
        };
        let extracted = lsb.extract(&frame).unwrap();
        assert!(
            extracted.is_some(),
            "Bgra8 roundtrip should recover payload"
        );
        let ext = extracted.unwrap();
        assert_eq!(ext.frame_index, payload.frame_index);
        assert_eq!(ext.hash, payload.hash);
    }
}
