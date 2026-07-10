//! Fuzz targets for steganographer-core.
//!
//! Run with: cargo +nightly fuzz -p steganographer-core
//!
//! These fuzz targets verify that extraction never panics on arbitrary input,
//! which is critical for security — a malicious media file should never crash
//! the extraction pipeline.

use steganographer_core::crypto::SignaturePayload;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

#[cfg(fuzzing)]
mod fuzz {
    use super::*;

    /// Fuzz LSB video extraction with random byte inputs.
    /// The extractor should never panic, even with adversarial data.
    pub fn fuzz_lsb_video_extract(data: &[u8]) {
        if data.len() < 100 {
            return;
        }
        let bits = (data[0] % 4) + 1;
        let lsb = LsbVideo::new(bits);
        let frame = VideoFrame {
            width: data.len() as u32 / 3,
            height: 1,
            stride: data.len() as u32,
            format: VideoFormat::Rgb8,
            data: &mut data.to_vec(),
            frame_index: 0,
        };
        let _ = lsb.extract(&frame);
    }

    /// Fuzz SignaturePayload::from_bytes with arbitrary 109-byte inputs.
    pub fn fuzz_payload_from_bytes(data: &[u8]) {
        if data.len() != SignaturePayload::SERIALIZED_SIZE {
            return;
        }
        let mut arr = [0u8; SignaturePayload::SERIALIZED_SIZE];
        arr.copy_from_slice(data);
        let _ = SignaturePayload::from_bytes(&arr);
    }

    /// Fuzz the magic header check.
    pub fn fuzz_has_valid_magic(data: &[u8]) {
        let _ = SignaturePayload::has_valid_magic(data);
    }
}
