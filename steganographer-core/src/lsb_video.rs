//! LSB (Least Significant Bit) video steganography.
//!
//! Embeds and extracts [`SignaturePayload`] data into/from video frame pixel bytes
//! using sequential LSB replacement. A 32-bit length prefix enables extraction
//! to know how many bits to read back.
//!
//! The number of LSBs used per byte is configurable (1–4).

use crate::crypto::SignaturePayload;
use crate::video::{VideoFrame, VideoStegoModule};

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

    /// Fixed-size MSB-first stream: length prefix followed by the signature.
    fn payload_to_bits(
        payload: &SignaturePayload,
    ) -> [u8; 32 + SignaturePayload::SERIALIZED_SIZE * 8] {
        let bytes = payload.to_bytes();
        let mut result = [0; 32 + SignaturePayload::SERIALIZED_SIZE * 8];
        let length = (SignaturePayload::SERIALIZED_SIZE * 8) as u32;
        for (i, bit) in result[..32].iter_mut().enumerate() {
            *bit = ((length >> (31 - i)) & 1) as u8;
        }
        for (i, bit) in result[32..].iter_mut().enumerate() {
            *bit = (bytes[i / 8] >> (7 - i % 8)) & 1;
        }
        result
    }

    /// Map logical color bytes to rows, never padding or BGRA alpha.
    fn byte_offset(frame: &VideoFrame, logical: usize) -> usize {
        let row_units = frame.width as usize * 3;
        let row = logical / row_units;
        let column = logical % row_units;
        let bpp = frame
            .format
            .bytes_per_pixel()
            .expect("validated packed format");
        row * frame.stride as usize + (column / 3) * bpp + column % 3
    }

    fn read_bit(frame: &VideoFrame, bit: usize, bits: u8) -> u8 {
        let offset = Self::byte_offset(frame, bit / bits as usize);
        (frame.data[offset] >> (bits as usize - 1 - bit % bits as usize)) & 1
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

        frame.validate_packed_layout()?;
        let bits = Self::payload_to_bits(sig);
        let total_bits = bits.len();
        let eligible_bytes = (frame.width as usize)
            .checked_mul(frame.height as usize)
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or_else(|| anyhow::anyhow!("LSB video capacity overflow"))?;
        anyhow::ensure!(
            eligible_bytes >= total_bits.div_ceil(self.bits as usize),
            "Not enough LSB capacity in frame"
        );

        let mut bit_idx = 0usize;
        let mask = !((1u8 << self.bits) - 1); // e.g., bits=2 → mask = 0b11111100
        for logical in 0..total_bits.div_ceil(self.bits as usize) {
            let offset = Self::byte_offset(frame, logical);
            let byte = &mut frame.data[offset];
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
        frame.validate_packed_layout()?;
        let units = (frame.width as usize)
            .checked_mul(frame.height as usize)
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or_else(|| anyhow::anyhow!("LSB video capacity overflow"))?;
        if units < 32usize.div_ceil(self.bits as usize) {
            return Ok(None);
        }
        let mut length = 0u32;
        for bit in 0..32 {
            length = (length << 1) | Self::read_bit(frame, bit, self.bits) as u32;
        }
        let expected = SignaturePayload::SERIALIZED_SIZE * 8;
        if length as usize != expected || units < (32 + expected).div_ceil(self.bits as usize) {
            return Ok(None);
        }
        let mut payload = [0u8; SignaturePayload::SERIALIZED_SIZE];
        for bit in 0..expected {
            payload[bit / 8] = (payload[bit / 8] << 1) | Self::read_bit(frame, 32 + bit, self.bits);
        }
        SignaturePayload::from_bytes(&payload).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::video::VideoFormat;
    #[test]
    fn strided_rgb_and_bgra_survive_pixel_only_repacking() {
        let payload = Signer::generate().sign_frame(7, b"layout", None);
        for format in [VideoFormat::Rgb8, VideoFormat::Bgra8] {
            for bits in 1..=4 {
                let bpp = format.bytes_per_pixel().unwrap();
                let row = 16 * bpp;
                let stride = row + 5;
                let mut data = vec![0xa7; stride * 32];
                let mut kernel = LsbVideo::new(bits);
                let mut frame = VideoFrame {
                    width: 16,
                    height: 32,
                    stride: stride as u32,
                    format,
                    data: &mut data,
                    frame_index: 0,
                };
                kernel.embed(&mut frame, Some(&payload)).unwrap();
                let mut packed = Vec::new();
                for row_data in data.chunks_exact(stride) {
                    assert!(row_data[row..].iter().all(|byte| *byte == 0xa7));
                    if bpp == 4 {
                        assert!(row_data[..row]
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .all(|pixel| pixel[3] == 0xa7));
                    }
                    packed.extend_from_slice(&row_data[..row]);
                }
                let frame = VideoFrame {
                    width: 16,
                    height: 32,
                    stride: row as u32,
                    format,
                    data: &mut packed,
                    frame_index: 0,
                };
                assert_eq!(
                    kernel.extract(&frame).unwrap().unwrap().to_bytes(),
                    payload.to_bytes()
                );
            }
        }
    }

    #[test]
    fn invalid_layout_is_rejected_before_mutation() {
        let payload = Signer::generate().sign_frame(0, b"layout", None);
        let mut data = vec![0x55; 1536];
        let before = data.clone();
        let mut frame = VideoFrame {
            width: 16,
            height: 32,
            stride: 47,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        assert!(LsbVideo::new(1).embed(&mut frame, Some(&payload)).is_err());
        assert_eq!(data, before);
    }

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
