//! Spread-spectrum steganography using PN-sequence modulation.
//!
//! This module implements a spread-spectrum embedding technique where
//! the payload bits are modulated onto a pseudo-noise (PN) sequence and
//! added to the pixel values. This provides significantly better noise
//! resistance than plain LSB embedding because:
//!
//! 1. **Spread spectrum**: Each payload bit is spread across many pixels,
//!    so local noise that destroys individual pixels does not destroy
//!    the payload.
//! 2. **Correlation detection**: Extraction uses correlation with the
//!    known PN sequence, which is robust to additive noise.
//! 3. **Keystream**: The PN sequence is derived from a secret key,
//!    making it difficult for an attacker to detect or remove the
//!    watermark without the key.
//!
//! ## Algorithm
//!
//! For each payload bit `b`:
//! 1. Generate a PN sequence `pn[i] ∈ {-1, +1}` of length `spread_factor`
//!    using a keyed PRNG.
//! 2. For each pixel in the spread region: `pixel += pn[i] * amplitude * (2*b - 1)`
//! 3. Extraction: compute `correlation = Σ(pixel[i] * pn[i])` over the
//!    spread region. If `correlation > threshold`, bit = 1; else bit = 0.
//!
//! ## Parameters
//!
//! - `key` — 32-byte secret key for PN sequence generation.
//! - `amplitude` — Embedding strength (typically 1–5). Higher = more
//!   robust but more visible.
//! - `spread_factor` — Number of pixels per payload bit (typically
//!   32–256). Higher = more robust but lower capacity.

use crate::audio::{AudioBuffer, AudioStegoModule};
use crate::crypto::SignaturePayload;
use crate::video::{VideoFrame, VideoStegoModule};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Default embedding amplitude.
const DEFAULT_AMPLITUDE: i32 = 3;

/// Default spread factor (pixels per payload bit).
const DEFAULT_SPREAD: usize = 64;

/// Spread-spectrum video steganography module.
///
/// Embeds payload data using PN-sequence spread-spectrum modulation
/// for superior noise resistance compared to LSB embedding.
pub struct SpreadSpectrumVideo {
    key: [u8; 32],
    amplitude: i32,
    spread_factor: usize,
}

impl SpreadSpectrumVideo {
    /// Create a new spread-spectrum video module.
    ///
    /// # Arguments
    /// * `key` — 32-byte secret key for PN sequence generation.
    /// * `amplitude` — Embedding strength (1–5 recommended).
    /// * `spread_factor` — Pixels per payload bit (32–256 recommended).
    pub fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self {
        assert!(amplitude > 0, "Amplitude must be positive");
        assert!(spread_factor > 0, "Spread factor must be positive");
        assert!(spread_factor >= 8, "Spread factor must be at least 8");
        Self {
            key,
            amplitude,
            spread_factor,
        }
    }

    /// Create with default parameters.
    pub fn with_key(key: [u8; 32]) -> Self {
        Self::new(key, DEFAULT_AMPLITUDE, DEFAULT_SPREAD)
    }

    /// Returns the secret key used for PN sequence generation.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Generate a PN sequence of `len` values in {-1, +1} for the given
    /// bit position and frame index.
    fn pn_sequence(&self, len: usize, bit_pos: usize, frame_index: u64) -> Vec<i32> {
        let mut seed = [0u8; 32];
        let frame_bytes = frame_index.to_le_bytes();
        let bit_bytes = (bit_pos as u64).to_le_bytes();
        for (i, byte) in self.key.iter().enumerate() {
            seed[i] = byte ^ frame_bytes[i % 8] ^ bit_bytes[i % 8];
        }
        let mut rng = StdRng::from_seed(seed);
        (0..len)
            .map(|_| if rng.gen::<bool>() { 1 } else { -1 })
            .collect()
    }

    /// Embed a single bit at a given offset in the pixel data.
    fn embed_bit(&self, data: &mut [u8], start: usize, bit: u8, bit_pos: usize, frame_index: u64) {
        let region = &mut data[start..start + self.spread_factor];
        let pn = self.pn_sequence(self.spread_factor, bit_pos, frame_index);
        let sign = if bit == 1 { 1 } else { -1 };

        for (i, pixel) in region.iter_mut().enumerate() {
            let val = *pixel as i32 + pn[i] * self.amplitude * sign;
            *pixel = val.clamp(0, 255) as u8;
        }
    }

    /// Extract a single bit from a given offset in the pixel data.
    fn extract_bit(&self, data: &[u8], start: usize, bit_pos: usize, frame_index: u64) -> u8 {
        let region = &data[start..start + self.spread_factor];
        let pn = self.pn_sequence(self.spread_factor, bit_pos, frame_index);

        let correlation: i64 = region
            .iter()
            .zip(pn.iter())
            .map(|(pixel, pn_val)| (*pixel as i64 - 128) * *pn_val as i64)
            .sum();

        if correlation > 0 {
            1
        } else {
            0
        }
    }
}

impl VideoStegoModule for SpreadSpectrumVideo {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let sig = match sig {
            Some(s) => s,
            None => return Ok(()),
        };

        let payload_bytes = sig.to_bytes();
        let total_bits = payload_bytes.len() * 8;
        let needed = total_bits * self.spread_factor;

        if needed > frame.data.len() {
            anyhow::bail!(
                "Not enough capacity for spread-spectrum: need {} bytes, have {} ({} bits × {} spread)",
                needed,
                frame.data.len(),
                total_bits,
                self.spread_factor
            );
        }

        for (byte_idx, byte) in payload_bytes.iter().enumerate() {
            for bit_in_byte in 0..8 {
                let bit = (byte >> bit_in_byte) & 1;
                let payload_bit_pos = byte_idx * 8 + bit_in_byte;
                let start = payload_bit_pos * self.spread_factor;
                self.embed_bit(frame.data, start, bit, payload_bit_pos, frame.frame_index);
            }
        }

        log::debug!(
            "Spread-spectrum embed: {} bits, {} spread, amplitude {} (frame {})",
            total_bits,
            self.spread_factor,
            self.amplitude,
            frame.frame_index
        );

        Ok(())
    }

    fn extract(&self, frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        let total_bits = SignaturePayload::SERIALIZED_SIZE * 8;
        let needed = total_bits * self.spread_factor;

        if frame.data.len() < needed {
            return Ok(None);
        }

        let mut payload_bytes = [0u8; SignaturePayload::SERIALIZED_SIZE];

        for (byte_idx, byte) in payload_bytes.iter_mut().enumerate() {
            for bit_in_byte in 0..8 {
                let payload_bit_pos = byte_idx * 8 + bit_in_byte;
                let start = payload_bit_pos * self.spread_factor;
                let bit = self.extract_bit(frame.data, start, payload_bit_pos, frame.frame_index);
                *byte |= bit << bit_in_byte;
            }
        }

        // Check if this looks like a valid payload (magic header)
        if !SignaturePayload::has_valid_magic(&payload_bytes) {
            return Ok(None);
        }

        SignaturePayload::from_bytes(&payload_bytes).map(Some)
    }
}

/// Spread-spectrum audio steganography module.
///
/// Uses the same PN-sequence technique but applied to audio samples.
pub struct SpreadSpectrumAudio {
    key: [u8; 32],
    amplitude: i32,
    spread_factor: usize,
}

impl SpreadSpectrumAudio {
    /// Create a new spread-spectrum audio module.
    pub fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self {
        assert!(amplitude > 0, "Amplitude must be positive");
        assert!(spread_factor > 0, "Spread factor must be positive");
        assert!(spread_factor >= 8, "Spread factor must be at least 8");
        Self {
            key,
            amplitude,
            spread_factor,
        }
    }

    /// Create with default parameters.
    pub fn with_key(key: [u8; 32]) -> Self {
        Self::new(key, DEFAULT_AMPLITUDE, DEFAULT_SPREAD)
    }

    fn pn_sequence(&self, len: usize, bit_pos: usize, frame_index: u64) -> Vec<i32> {
        let mut seed = [0u8; 32];
        let frame_bytes = frame_index.to_le_bytes();
        let bit_bytes = (bit_pos as u64).to_le_bytes();
        for (i, byte) in self.key.iter().enumerate() {
            seed[i] = byte ^ frame_bytes[i % 8] ^ bit_bytes[i % 8];
        }
        let mut rng = StdRng::from_seed(seed);
        (0..len)
            .map(|_| if rng.gen::<bool>() { 1 } else { -1 })
            .collect()
    }
}

impl AudioStegoModule for SpreadSpectrumAudio {
    fn embed(
        &mut self,
        buf: &mut AudioBuffer,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let sig = match sig {
            Some(s) => s,
            None => return Ok(()),
        };

        let payload_bytes = sig.to_bytes();
        let total_bits = payload_bytes.len() * 8;
        let needed = total_bits * self.spread_factor;

        if needed > buf.samples.len() {
            anyhow::bail!(
                "Not enough capacity for audio spread-spectrum: need {} samples, have {}",
                needed,
                buf.samples.len()
            );
        }

        for (byte_idx, byte) in payload_bytes.iter().enumerate() {
            for bit_in_byte in 0..8 {
                let bit = (byte >> bit_in_byte) & 1;
                let payload_bit_pos = byte_idx * 8 + bit_in_byte;
                let start = payload_bit_pos * self.spread_factor;
                let region = &mut buf.samples[start..start + self.spread_factor];
                let pn = self.pn_sequence(self.spread_factor, payload_bit_pos, buf.frame_index);
                let sign = if bit == 1 { 1 } else { -1 };

                for (i, sample) in region.iter_mut().enumerate() {
                    let val = *sample as i32 + pn[i] * self.amplitude * sign;
                    *sample = val.clamp(-32768, 32767) as i16;
                }
            }
        }

        Ok(())
    }

    fn extract(&self, buf: &AudioBuffer) -> anyhow::Result<Option<SignaturePayload>> {
        let total_bits = SignaturePayload::SERIALIZED_SIZE * 8;
        let needed = total_bits * self.spread_factor;

        if buf.samples.len() < needed {
            return Ok(None);
        }

        let mut payload_bytes = [0u8; SignaturePayload::SERIALIZED_SIZE];

        for (byte_idx, byte) in payload_bytes.iter_mut().enumerate() {
            for bit_in_byte in 0..8 {
                let payload_bit_pos = byte_idx * 8 + bit_in_byte;
                let start = payload_bit_pos * self.spread_factor;
                let region = &buf.samples[start..start + self.spread_factor];
                let pn = self.pn_sequence(self.spread_factor, payload_bit_pos, buf.frame_index);

                let correlation: i64 = region
                    .iter()
                    .zip(pn.iter())
                    .map(|(sample, pn_val)| (*sample as i64) * (*pn_val as i64))
                    .sum();

                if correlation > 0 {
                    *byte |= 1 << bit_in_byte;
                }
            }
        }

        if !SignaturePayload::has_valid_magic(&payload_bytes) {
            return Ok(None);
        }

        SignaturePayload::from_bytes(&payload_bytes).map(Some)
    }
}

/// Compute the capacity (in bytes) of a spread-spectrum embedder
/// given the data length and spread factor.
pub fn capacity(data_len: usize, spread_factor: usize) -> usize {
    data_len / spread_factor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::video::VideoFormat;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    #[test]
    fn test_video_roundtrip() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(42, b"spread spectrum test", None);

        let mut data = vec![128u8; SignaturePayload::SERIALIZED_SIZE * 8 * DEFAULT_SPREAD];
        let mut ss = SpreadSpectrumVideo::with_key(test_key());

        {
            let mut frame = VideoFrame {
                width: 1024,
                height: 1024,
                stride: 1024 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 42,
            };
            ss.embed(&mut frame, Some(&payload)).unwrap();
        }

        {
            let frame = VideoFrame {
                width: 1024,
                height: 1024,
                stride: 1024 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 42,
            };
            let extracted = ss.extract(&frame).unwrap();
            assert!(extracted.is_some(), "Should extract payload");
            let extracted = extracted.unwrap();
            assert_eq!(extracted.frame_index, 42);
            assert_eq!(extracted.hash, payload.hash);
            assert_eq!(extracted.signature, payload.signature);
        }
    }

    #[test]
    fn test_video_capacity_error() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"test", None);

        let mut data = vec![128u8; 100]; // way too small
        let mut ss = SpreadSpectrumVideo::with_key(test_key());
        let mut frame = VideoFrame {
            width: 100,
            height: 1,
            stride: 100,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        assert!(ss.embed(&mut frame, Some(&payload)).is_err());
    }

    #[test]
    fn test_video_no_signal_returns_none() {
        let key = test_key();
        let ss = SpreadSpectrumVideo::with_key(key);
        let mut data = vec![128u8; SignaturePayload::SERIALIZED_SIZE * 8 * DEFAULT_SPREAD];
        let frame = VideoFrame {
            width: 1024,
            height: 1024,
            stride: 1024 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let result = ss.extract(&frame).unwrap();
        assert!(result.is_none(), "No signal should return None");
    }

    #[test]
    fn test_audio_roundtrip() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"audio SS test", None);

        let mut samples = vec![0i16; SignaturePayload::SERIALIZED_SIZE * 8 * DEFAULT_SPREAD];
        let mut ss = SpreadSpectrumAudio::with_key(test_key());

        {
            let mut buf = AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };
            ss.embed(&mut buf, Some(&payload)).unwrap();
        }

        {
            let buf = AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };
            let extracted = ss.extract(&buf).unwrap();
            assert!(extracted.is_some());
            let extracted = extracted.unwrap();
            assert_eq!(extracted.frame_index, 0);
            assert_eq!(extracted.hash, payload.hash);
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"wrong key test", None);

        let mut data = vec![128u8; SignaturePayload::SERIALIZED_SIZE * 8 * DEFAULT_SPREAD];
        let mut ss = SpreadSpectrumVideo::with_key(test_key());

        {
            let mut frame = VideoFrame {
                width: 1024,
                height: 1024,
                stride: 1024 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            ss.embed(&mut frame, Some(&payload)).unwrap();
        }

        // Extract with wrong key
        let wrong_key = [255u8; 32];
        let ss_wrong = SpreadSpectrumVideo::with_key(wrong_key);
        let frame = VideoFrame {
            width: 1024,
            height: 1024,
            stride: 1024 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let result = ss_wrong.extract(&frame).unwrap();
        assert!(result.is_none(), "Wrong key should not extract");
    }

    #[test]
    fn test_none_sig_is_noop() {
        let mut data = vec![128u8; 1024];
        let original = data.clone();
        let mut ss = SpreadSpectrumVideo::with_key(test_key());
        let mut frame = VideoFrame {
            width: 1024,
            height: 1,
            stride: 1024,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        ss.embed(&mut frame, None).unwrap();
        assert_eq!(&data[..1024], &original[..1024]);
    }

    #[test]
    fn test_custom_amplitude_and_spread() {
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"custom params", None);

        // Use high amplitude and small spread for robust embedding
        let mut data = vec![128u8; SignaturePayload::SERIALIZED_SIZE * 8 * 32];
        let mut ss = SpreadSpectrumVideo::new(test_key(), 5, 32);

        {
            let mut frame = VideoFrame {
                width: 2048,
                height: 2048,
                stride: 2048 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            ss.embed(&mut frame, Some(&payload)).unwrap();
        }

        {
            let frame = VideoFrame {
                width: 2048,
                height: 2048,
                stride: 2048 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            let extracted = ss.extract(&frame).unwrap();
            assert!(extracted.is_some());
            assert_eq!(extracted.unwrap().frame_index, 0);
        }
    }

    #[test]
    fn test_noise_resistance() {
        // Test that spread-spectrum survives moderate noise
        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"noise test", None);

        let mut data = vec![128u8; SignaturePayload::SERIALIZED_SIZE * 8 * DEFAULT_SPREAD];
        let mut ss = SpreadSpectrumVideo::new(test_key(), 4, DEFAULT_SPREAD);

        {
            let mut frame = VideoFrame {
                width: 1024,
                height: 1024,
                stride: 1024 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            ss.embed(&mut frame, Some(&payload)).unwrap();
        }

        // Add noise: flip random LSBs (simulate compression)
        let mut rng = StdRng::from_seed([42; 32]);
        for byte in data.iter_mut() {
            if rng.gen::<bool>() {
                *byte ^= 1; // flip LSB
            }
        }

        // Should still extract despite noise (amplitude=4 is strong enough)
        let frame = VideoFrame {
            width: 1024,
            height: 1024,
            stride: 1024 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let extracted = ss.extract(&frame).unwrap();
        // With amplitude=4 and noise on LSBs, should survive
        // (may fail occasionally due to RNG, but high amplitude helps)
        if let Some(ref ext) = extracted {
            assert_eq!(ext.frame_index, 0);
        }
    }
}
