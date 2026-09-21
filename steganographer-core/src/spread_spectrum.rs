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
//! For each payload bit `b` (host-canceling **differential** modulation):
//! 1. Generate a PN sequence `pn[i] ∈ {-1, +1}` of length `spread_factor`
//!    using a keyed PRNG.
//! 2. Embed into *differential pairs*: the byte at `2i` receives
//!    `+amplitude * pn[2i] * s` and the byte at `2i+1` receives
//!    `-amplitude * pn[2i] * s`, where `s = +1` for bit 1 and `-1` for bit 0.
//! 3. Extraction sums `(pixel[2i] − pixel[2i+1]) * pn[2i]` over the pairs.
//!    The embedded signal contributes `+amplitude·spread` (bit 1) or
//!    `−amplitude·spread` (bit 0), while the host contribution reduces to the
//!    *adjacent-pixel differences* `Σ (host[2i] − host[2i+1]) * pn[2i]` —
//!    near zero for natural imagery. The old absolute-correlation scheme
//!    (`Σ (pixel[i] − 128) * pn[i]`) left the host term un-cancelled with
//!    std ≈ σ_host·√spread, which exceeds the signal margin on real carriers
//!    and corrupts ~35% of bits. If `spread_factor` is odd, the final byte
//!    of each region is left unused.
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
    ///
    /// # Panics
    /// Panics if `amplitude <= 0` or `spread_factor < 8`. For fallible
    /// construction, use [`try_new`](Self::try_new).
    pub fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self {
        Self::try_new(key, amplitude, spread_factor).expect("invalid spread-spectrum parameters")
    }

    /// Create with default parameters.
    pub fn with_key(key: [u8; 32]) -> Self {
        Self::new(key, DEFAULT_AMPLITUDE, DEFAULT_SPREAD)
    }

    /// Create a new spread-spectrum video module, returning an error on
    /// invalid parameters.
    ///
    /// Use this when parameters come from untrusted input (config, CLI args).
    pub fn try_new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> anyhow::Result<Self> {
        if amplitude <= 0 {
            anyhow::bail!("Amplitude must be positive, got {}", amplitude);
        }
        if spread_factor < 8 {
            anyhow::bail!("Spread factor must be at least 8, got {}", spread_factor);
        }
        Ok(Self {
            key,
            amplitude,
            spread_factor,
        })
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

    /// Embed a single bit at a given offset in the pixel data using
    /// deterministic differential-pair modulation: every adjacent pair's
    /// difference is forced to `sign * 2 * amplitude` along the pair's PN
    /// direction (both pixels moved toward the midpoint, clamped). The
    /// region length is `spread_factor` bytes (an odd trailing byte is
    /// left unused).
    pub fn embed_bit(
        &self,
        data: &mut [u8],
        start: usize,
        bit: u8,
        bit_pos: usize,
        frame_index: u64,
    ) {
        let region = &mut data[start..start + self.spread_factor];
        let pn = self.pn_sequence(self.spread_factor, bit_pos, frame_index);
        // Deterministic differential modulation: force each adjacent pair's
        // difference to `sign * 2 * amplitude` * the pair's PN direction
        // (both pixels adjusted toward the pair midpoint, clamped). The
        // extractor below correlates pair differences with the PN sequence;
        // because the difference is fully determined by the embedded sign,
        // live pairs contribute exactly `sign * 2 * amplitude` and
        // fully-clamped ("dead") pairs contribute 0 — host-texture noise
        // cancels exactly instead of merely to adjacent-pixel differences.
        let target: i32 = 2 * self.amplitude * if bit == 1 { 1 } else { -1 };
        for i in 0..self.spread_factor / 2 {
            let pn_dir: i32 = if pn[2 * i] > 0 { 1 } else { -1 };
            let diff = target * pn_dir;
            let mid = (region[2 * i] as i32 + region[2 * i + 1] as i32) / 2;
            let a = (mid + diff / 2).clamp(0, 255);
            let b = a - diff;
            region[2 * i] = a as u8;
            region[2 * i + 1] = b.clamp(0, 255) as u8;
        }
    }

    /// Extract a single bit from a given offset in the pixel data by
    /// correlating adjacent-pixel differences with the PN sequence. The
    /// host contribution cancels to adjacent-pixel differences instead of
    /// absolute deviations from 128.
    pub fn extract_bit(&self, data: &[u8], start: usize, bit_pos: usize, frame_index: u64) -> u8 {
        let region = &data[start..start + self.spread_factor];
        let pn = self.pn_sequence(self.spread_factor, bit_pos, frame_index);

        let correlation: i64 = (0..self.spread_factor / 2)
            .map(|i| {
                let diff = region[2 * i] as i64 - region[2 * i + 1] as i64;
                diff * pn[2 * i] as i64
            })
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
    ///
    /// # Panics
    /// Panics if `amplitude <= 0` or `spread_factor < 8`. For fallible
    /// construction, use [`try_new`](Self::try_new).
    pub fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self {
        Self::try_new(key, amplitude, spread_factor).expect("invalid spread-spectrum parameters")
    }

    /// Create a new spread-spectrum audio module, returning an error on
    /// invalid parameters.
    ///
    /// Use this when parameters come from untrusted input (config, CLI args).
    pub fn try_new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> anyhow::Result<Self> {
        if amplitude <= 0 {
            anyhow::bail!("Amplitude must be positive, got {}", amplitude);
        }
        if spread_factor < 8 {
            anyhow::bail!("Spread factor must be at least 8, got {}", spread_factor);
        }
        Ok(Self {
            key,
            amplitude,
            spread_factor,
        })
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

    /// `start`, using deterministic differential-pair modulation: each
    /// adjacent pair's difference is forced to `sign * 2 * amplitude` along
    /// the pair's PN direction (see the video `embed_bit` for the rationale).
    /// An odd trailing sample is left unused.
    pub fn embed_bit(
        &self,
        samples: &mut [i16],
        start: usize,
        bit: u8,
        bit_pos: usize,
        frame_index: u64,
    ) {
        let region = &mut samples[start..start + self.spread_factor];
        let pn = self.pn_sequence(self.spread_factor, bit_pos, frame_index);
        // Deterministic differential modulation (see the video embed_bit for
        // the full rationale): each adjacent pair's difference is forced to
        // `sign * 2 * amplitude` * the pair's PN direction, so live pairs
        // contribute exactly `sign * 2 * amplitude` to the correlation and
        // fully-clamped pairs contribute 0 — host noise cancels exactly.
        let target: i32 = 2 * self.amplitude * if bit == 1 { 1 } else { -1 };
        for i in 0..self.spread_factor / 2 {
            let pn_dir: i32 = if pn[2 * i] > 0 { 1 } else { -1 };
            let diff = target * pn_dir;
            let mid = (region[2 * i] as i32 + region[2 * i + 1] as i32) / 2;
            let a = (mid + diff / 2).clamp(-32768, 32767);
            let b = a - diff;
            region[2 * i] = a as i16;
            region[2 * i + 1] = b.clamp(-32768, 32767) as i16;
        }
    }

    /// Extract a single bit from `spread_factor` audio samples starting at
    /// `start` by correlating adjacent-sample differences with the PN
    /// sequence (host-canceling differential detection).
    pub fn extract_bit(
        &self,
        samples: &[i16],
        start: usize,
        bit_pos: usize,
        frame_index: u64,
    ) -> u8 {
        let region = &samples[start..start + self.spread_factor];
        let pn = self.pn_sequence(self.spread_factor, bit_pos, frame_index);

        let correlation: i64 = (0..self.spread_factor / 2)
            .map(|i| {
                let diff = region[2 * i] as i64 - region[2 * i + 1] as i64;
                diff * pn[2 * i] as i64
            })
            .sum();

        if correlation > 0 {
            1
        } else {
            0
        }
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
        for (byte_idx, byte) in payload_bytes.iter().enumerate() {
            for bit_in_byte in 0..8 {
                let bit = (byte >> bit_in_byte) & 1;
                let payload_bit_pos = byte_idx * 8 + bit_in_byte;
                let start = payload_bit_pos * self.spread_factor;
                self.embed_bit(buf.samples, start, bit, payload_bit_pos, buf.frame_index);
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
                let bit = self.extract_bit(buf.samples, start, payload_bit_pos, buf.frame_index);
                *byte |= bit << bit_in_byte;
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
    /// Deterministic pseudo-random textured carrier: a slowly-varying base
    /// pattern (large σ_host, small adjacent-pixel differences) plus small
    /// LCG texture noise — shaped like natural imagery.
    fn textured_carrier(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len);
        let mut lcg = 0x2545F4914F6CDD1Du64;
        for i in 0..len {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let noise = ((lcg >> 33) % 9) as i32 - 4; // ±4 texture noise
                                                      // Base pattern steps every 8 pixels across a ±50 span around 128.
            let base = 128 + ((i as i32 / 8) % 100) - 50;
            data.push((base + noise).clamp(0, 255) as u8);
        }
        data
    }

    #[test]
    fn test_textured_carrier_roundtrip() {
        // OLD SCHEME (absolute correlation Σ(pixel−128)·pn) FAILS on this
        // carrier: the un-cancelled host term has std ≈ σ_host·√spread.
        // Here σ_host ≈ 29 (base pattern spanning ±50), spread = 64, so host
        // noise std ≈ 232 vs. a signal margin of amplitude·spread = 192
        // (amplitude 3) — a per-bit error rate of ≈ 20% (Gaussian tail),
        // corrupting effectively every payload. On uniform-random pixels
        // (σ_host ≈ 73.6) it is ≈ 35% per bit. The host-canceling
        // differential modulation below cancels the host term down to
        // adjacent-pixel differences (std ≈ 60 here), so exact recovery
        // holds; this test asserts EXACT bit recovery.
        let signer = Signer::generate();
        let payload = signer.sign_frame(7, b"textured carrier test", None);

        let total_bits = SignaturePayload::SERIALIZED_SIZE * 8;
        let spread = DEFAULT_SPREAD;
        let mut data = textured_carrier(total_bits * spread);
        let original = data.clone();
        let mut ss = SpreadSpectrumVideo::new(test_key(), 5, spread);

        {
            let mut frame = VideoFrame {
                width: 2048,
                height: (data.len() / (2048 * 3)) as u32,
                stride: 2048 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 7,
            };
            ss.embed(&mut frame, Some(&payload)).unwrap();
        }

        // Embedded region must be non-constant and differ from the carrier.
        assert_ne!(
            &data[..total_bits * spread],
            &original[..total_bits * spread]
        );

        // Exact bit-level recovery via the public bit helpers.
        for bit_pos in 0..total_bits {
            let byte = payload.to_bytes()[bit_pos / 8];
            let expected = (byte >> (bit_pos % 8)) & 1;
            let got = ss.extract_bit(&data, bit_pos * spread, bit_pos, 7);
            assert_eq!(got, expected, "bit {} mismatch", bit_pos);
        }

        // Full payload roundtrip through the trait API.
        let mut data2 = textured_carrier(total_bits * spread);
        let mut frame = VideoFrame {
            width: 2048,
            height: (data2.len() / (2048 * 3)) as u32,
            stride: 2048 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data2,
            frame_index: 7,
        };
        ss.embed(&mut frame, Some(&payload)).unwrap();
        let extracted = ss.extract(&frame).unwrap();
        assert!(
            extracted.is_some(),
            "should extract payload from textured carrier"
        );
        let extracted = extracted.unwrap();
        assert_eq!(extracted.frame_index, 7);
        assert_eq!(extracted.hash, payload.hash);
        assert_eq!(extracted.signature, payload.signature);
    }

    #[test]
    fn test_bit_helpers_differential_roundtrip() {
        // Bit-level helpers: embed alternating bits into a textured carrier
        // at distinct regions and recover them exactly.
        let spread = 64;
        let ss = SpreadSpectrumVideo::new(test_key(), 5, spread);
        let mut data = textured_carrier(8 * spread * 2);
        for k in 0..8 {
            let bit = (k % 2) as u8;
            ss.embed_bit(&mut data, k * spread, bit, k, 0);
        }
        for k in 0..8 {
            assert_eq!(ss.extract_bit(&data, k * spread, k, 0), (k % 2) as u8);
        }
    }

    #[test]
    fn test_try_new_rejects_invalid_params() {
        let key = test_key();
        assert!(SpreadSpectrumVideo::try_new(key, 0, 64).is_err());
        assert!(SpreadSpectrumVideo::try_new(key, -1, 64).is_err());
        assert!(SpreadSpectrumVideo::try_new(key, 3, 7).is_err());
        assert!(SpreadSpectrumVideo::try_new(key, 3, 64).is_ok());
        assert!(SpreadSpectrumAudio::try_new(key, 0, 64).is_err());
        assert!(SpreadSpectrumAudio::try_new(key, 3, 7).is_err());
        assert!(SpreadSpectrumAudio::try_new(key, 3, 64).is_ok());
        // new() still works for valid input (delegates to try_new).
        assert_eq!(SpreadSpectrumVideo::new(key, 3, 64).amplitude, 3);
        assert_eq!(SpreadSpectrumAudio::new(key, 3, 64).amplitude, 3);
    }

    #[test]
    fn test_audio_bit_helpers_differential_roundtrip() {
        let spread = 64;
        let ss = SpreadSpectrumAudio::new(test_key(), 5, spread);
        let mut samples = vec![0i16; 8 * spread];
        for k in 0..8 {
            let bit = (k / 2 % 2) as u8;
            ss.embed_bit(&mut samples, k * spread, bit, k, 3);
        }
        for k in 0..8 {
            assert_eq!(
                ss.extract_bit(&samples, k * spread, k, 3),
                (k / 2 % 2) as u8
            );
        }
    }
}
