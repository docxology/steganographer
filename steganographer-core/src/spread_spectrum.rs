//! Keyed residue-quantized spread-spectrum watermarking with bounded distortion.
//!
//! Each scalar is projected onto one of two interleaved integer lattices,
//! selected by the payload bit and a keyed PN chip. Majority detection reads
//! the lattice class, not the host's magnitude, so texture cannot overwhelm
//! the watermark. Projection stays within the configured amplitude even at
//! unsigned-video and signed-PCM extrema; it never averages neighboring values.
//! Noise/codec resilience is carrier-dependent, not guaranteed.
//!
//! Video uses green pixels only (RGB/BGRA, no alpha or row padding); audio
//! uses the first channel only. `spread_factor` counts these eligible units
//! per bit. Older additive/host-averaging artifacts must be re-embedded.
//! Raw bit helpers use scalar slices and the same integer detector.

use crate::audio::{AudioBuffer, AudioStegoModule};
use crate::crypto::SignaturePayload;
use crate::video::{VideoFrame, VideoStegoModule};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const DEFAULT_AMPLITUDE: i32 = 3;
const DEFAULT_SPREAD: usize = 64;
const PAYLOAD_BITS: usize = SignaturePayload::SERIALIZED_SIZE * 8;

fn validate(amplitude: i32, spread: usize, max_amplitude: i32) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=max_amplitude).contains(&amplitude),
        "amplitude must be 1..={max_amplitude}"
    );
    anyhow::ensure!(spread >= 8, "spread factor must be at least 8");
    anyhow::ensure!(
        spread.checked_mul(PAYLOAD_BITS).is_some(),
        "spread capacity overflow"
    );
    anyhow::ensure!(spread <= i64::MAX as usize, "spread correlation overflow");
    Ok(())
}

fn pn_rng(key: &[u8; 32], bit_pos: usize, frame_index: u64) -> StdRng {
    let mut seed = [0; 32];
    let frame = frame_index.to_le_bytes();
    let bit = (bit_pos as u64).to_le_bytes();
    for i in 0..32 {
        seed[i] = key[i] ^ frame[i % 8] ^ bit[i % 8];
    }
    StdRng::from_seed(seed)
}

fn region_end(start: usize, spread: usize, len: usize) -> anyhow::Result<usize> {
    let end = start
        .checked_add(spread)
        .ok_or_else(|| anyhow::anyhow!("spread region overflow"))?;
    anyhow::ensure!(end <= len, "insufficient spread-spectrum capacity");
    Ok(end)
}

fn decision(correlation: i64) -> u8 {
    u8::from(correlation > 0)
}

// Binary quantization lattices are `step` apart, with period `2 * step`.
// Choosing step <= (amplitude + 1) / 2 bounds even a one-sided projection
// at a carrier endpoint by period - 1 <= amplitude. Each supported integer
// domain contains a point of both classes, including at maximum amplitude.
// Centers lie within their decision bins. With the default amplitude 3,
// bins are two integers wide, so toggling the delivered byte's LSB preserves
// its chip class.
fn quantization_step(amplitude: i32) -> i32 {
    (amplitude + 1) / 2
}

fn project(value: i32, amplitude: i32, min: i32, max: i32, chip: u8) -> i32 {
    let step = quantization_step(amplitude);
    let period = 2 * step;
    let residue = i32::from(chip) * step + (step - 1) / 2;
    let lower = residue + (value - residue).div_euclid(period) * period;
    let upper = lower + period;
    if lower < min {
        upper
    } else if upper > max || value - lower <= upper - value {
        lower
    } else {
        upper
    }
}

fn correlation(
    key: &[u8; 32],
    spread: usize,
    amplitude: i32,
    bit_pos: usize,
    frame_index: u64,
    mut read: impl FnMut(usize) -> i32,
) -> i64 {
    let mut rng = pn_rng(key, bit_pos, frame_index);
    let step = quantization_step(amplitude);
    let mut sum = 0i64;
    for i in 0..spread {
        let pn = u8::from(rng.gen::<bool>());
        let chip = read(i).div_euclid(step).rem_euclid(2) as u8;
        sum += if chip ^ pn == 1 { 1 } else { -1 };
    }
    sum
}

fn write_chips(
    key: &[u8; 32],
    spread: usize,
    bit: u8,
    bit_pos: usize,
    frame: u64,
    mut write: impl FnMut(usize, u8),
) {
    let mut rng = pn_rng(key, bit_pos, frame);
    for i in 0..spread {
        write(i, bit ^ u8::from(rng.gen::<bool>()));
    }
}

/// Bounded residue-quantized spread-spectrum video watermark.
pub struct SpreadSpectrumVideo {
    key: [u8; 32],
    amplitude: i32,
    spread_factor: usize,
}

impl SpreadSpectrumVideo {
    /// Panics for invalid parameters; use `try_new` for untrusted parameters.
    pub fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self {
        Self::try_new(key, amplitude, spread_factor).expect("invalid spread-spectrum parameters")
    }
    pub fn with_key(key: [u8; 32]) -> Self {
        Self::new(key, DEFAULT_AMPLITUDE, DEFAULT_SPREAD)
    }
    pub fn try_new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> anyhow::Result<Self> {
        validate(amplitude, spread_factor, 255)?;
        Ok(Self {
            key,
            amplitude,
            spread_factor,
        })
    }
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Embed one bit in scalar bytes. Failure leaves the entire slice unchanged.
    pub fn embed_bit(
        &self,
        data: &mut [u8],
        start: usize,
        bit: u8,
        bit_pos: usize,
        frame_index: u64,
    ) -> anyhow::Result<()> {
        let end = region_end(start, self.spread_factor, data.len())?;
        anyhow::ensure!(bit <= 1, "expected a binary bit");
        let region = &mut data[start..end];
        write_chips(
            &self.key,
            self.spread_factor,
            bit,
            bit_pos,
            frame_index,
            |i, chip| region[i] = project(region[i] as i32, self.amplitude, 0, 255, chip) as u8,
        );
        Ok(())
    }
    /// Extract one bit from scalar bytes; invalid ranges return an error.
    pub fn extract_bit(
        &self,
        data: &[u8],
        start: usize,
        bit_pos: usize,
        frame_index: u64,
    ) -> anyhow::Result<u8> {
        let end = region_end(start, self.spread_factor, data.len())?;
        let region = &data[start..end];
        Ok(decision(correlation(
            &self.key,
            self.spread_factor,
            self.amplitude,
            bit_pos,
            frame_index,
            |i| region[i] as i32,
        )))
    }
}

impl VideoStegoModule for SpreadSpectrumVideo {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let Some(sig) = sig else { return Ok(()) };
        let bpp = frame.validate_packed_layout()?;
        let width = frame.width as usize;
        let units = width * frame.height as usize;
        let needed = PAYLOAD_BITS * self.spread_factor; // checked at construction
        anyhow::ensure!(
            units >= needed,
            "need {needed} green pixels for spread-spectrum"
        );
        let stride = frame.stride as usize;
        let offset = |unit: usize| (unit / width) * stride + (unit % width) * bpp + 1;
        let bytes = sig.to_bytes();
        // Capacity and layout are checked before the first carrier write.
        for pos in 0..PAYLOAD_BITS {
            let bit = (bytes[pos / 8] >> (pos % 8)) & 1;
            let start = pos * self.spread_factor;
            write_chips(
                &self.key,
                self.spread_factor,
                bit,
                pos,
                frame.frame_index,
                |i, chip| {
                    let at = offset(start + i);
                    frame.data[at] =
                        project(frame.data[at] as i32, self.amplitude, 0, 255, chip) as u8;
                },
            );
        }
        Ok(())
    }
    fn extract(&self, frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        let bpp = frame.validate_packed_layout()?;
        let width = frame.width as usize;
        if width * (frame.height as usize) < PAYLOAD_BITS * self.spread_factor {
            return Ok(None);
        }
        let mut bytes = [0; SignaturePayload::SERIALIZED_SIZE];
        for pos in 0..PAYLOAD_BITS {
            let start = pos * self.spread_factor;
            let score = correlation(
                &self.key,
                self.spread_factor,
                self.amplitude,
                pos,
                frame.frame_index,
                |i| {
                    let unit = start + i;
                    frame.data[(unit / width) * frame.stride as usize + (unit % width) * bpp + 1]
                        as i32
                },
            );
            bytes[pos / 8] |= decision(score) << (pos % 8);
        }
        if !SignaturePayload::has_valid_magic(&bytes) {
            return Ok(None);
        }
        SignaturePayload::from_bytes(&bytes).map(Some)
    }
}

/// Bounded residue-quantized watermark in the first PCM channel only.
pub struct SpreadSpectrumAudio {
    key: [u8; 32],
    amplitude: i32,
    spread_factor: usize,
}
impl SpreadSpectrumAudio {
    /// Panics for invalid parameters; use `try_new` for untrusted parameters.
    pub fn new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> Self {
        Self::try_new(key, amplitude, spread_factor).expect("invalid spread-spectrum parameters")
    }
    pub fn try_new(key: [u8; 32], amplitude: i32, spread_factor: usize) -> anyhow::Result<Self> {
        validate(amplitude, spread_factor, 32767)?;
        Ok(Self {
            key,
            amplitude,
            spread_factor,
        })
    }
    pub fn with_key(key: [u8; 32]) -> Self {
        Self::new(key, DEFAULT_AMPLITUDE, DEFAULT_SPREAD)
    }
    /// Embed one bit into scalar samples; failure never mutates the slice.
    pub fn embed_bit(
        &self,
        samples: &mut [i16],
        start: usize,
        bit: u8,
        bit_pos: usize,
        frame_index: u64,
    ) -> anyhow::Result<()> {
        let end = region_end(start, self.spread_factor, samples.len())?;
        anyhow::ensure!(bit <= 1, "expected a binary bit");
        let region = &mut samples[start..end];
        write_chips(
            &self.key,
            self.spread_factor,
            bit,
            bit_pos,
            frame_index,
            |i, chip| {
                region[i] = project(
                    region[i] as i32,
                    self.amplitude,
                    i16::MIN as i32,
                    i16::MAX as i32,
                    chip,
                ) as i16
            },
        );
        Ok(())
    }
    pub fn extract_bit(
        &self,
        samples: &[i16],
        start: usize,
        bit_pos: usize,
        frame_index: u64,
    ) -> anyhow::Result<u8> {
        let end = region_end(start, self.spread_factor, samples.len())?;
        let region = &samples[start..end];
        Ok(decision(correlation(
            &self.key,
            self.spread_factor,
            self.amplitude,
            bit_pos,
            frame_index,
            |i| region[i] as i32,
        )))
    }
}
fn audio_channels(buf: &AudioBuffer) -> anyhow::Result<usize> {
    buf.validate()?;
    Ok(buf.channels as usize)
}
impl AudioStegoModule for SpreadSpectrumAudio {
    fn embed(
        &mut self,
        buf: &mut AudioBuffer,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let Some(sig) = sig else { return Ok(()) };
        let channels = audio_channels(buf)?;
        let needed = PAYLOAD_BITS * self.spread_factor;
        anyhow::ensure!(
            buf.samples.len() / channels >= needed,
            "need {needed} audio frames for spread-spectrum"
        );
        let bytes = sig.to_bytes();
        for pos in 0..PAYLOAD_BITS {
            let bit = (bytes[pos / 8] >> (pos % 8)) & 1;
            let start = pos * self.spread_factor;
            write_chips(
                &self.key,
                self.spread_factor,
                bit,
                pos,
                buf.frame_index,
                |i, chip| {
                    let at = (start + i) * channels;
                    buf.samples[at] = project(
                        buf.samples[at] as i32,
                        self.amplitude,
                        i16::MIN as i32,
                        i16::MAX as i32,
                        chip,
                    ) as i16;
                },
            );
        }
        Ok(())
    }
    fn extract(&self, buf: &AudioBuffer) -> anyhow::Result<Option<SignaturePayload>> {
        let channels = audio_channels(buf)?;
        if buf.samples.len() / channels < PAYLOAD_BITS * self.spread_factor {
            return Ok(None);
        }
        let mut bytes = [0; SignaturePayload::SERIALIZED_SIZE];
        for pos in 0..PAYLOAD_BITS {
            let start = pos * self.spread_factor;
            let score = correlation(
                &self.key,
                self.spread_factor,
                self.amplitude,
                pos,
                buf.frame_index,
                |i| buf.samples[(start + i) * channels] as i32,
            );
            bytes[pos / 8] |= decision(score) << (pos % 8);
        }
        if !SignaturePayload::has_valid_magic(&bytes) {
            return Ok(None);
        }
        SignaturePayload::from_bytes(&bytes).map(Some)
    }
}

/// Complete payload bytes per eligible scalar unit count. Video counts green
/// pixels; audio counts PCM frames, not interleaved samples. Invalid spread
/// parameters have zero usable capacity.
pub fn capacity(eligible_units: usize, spread_factor: usize) -> usize {
    if validate(1, spread_factor, 255).is_err() {
        return 0;
    }
    eligible_units / spread_factor / 8
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bit_helpers_roundtrip_and_bound_distortion() {
        let video = SpreadSpectrumVideo::with_key([7; 32]);
        let audio = SpreadSpectrumAudio::with_key([7; 32]);
        for bit in 0..=1 {
            let mut pixels = [128; 64];
            video.embed_bit(&mut pixels, 0, bit, 4, 9).unwrap();
            assert_eq!(video.extract_bit(&pixels, 0, 4, 9).unwrap(), bit);
            assert!(pixels.iter().all(|&value| (value as i32 - 128).abs() <= 3));
            let mut samples = [30000; 64];
            audio.embed_bit(&mut samples, 0, bit, 4, 9).unwrap();
            assert_eq!(audio.extract_bit(&samples, 0, 4, 9).unwrap(), bit);
            assert!(samples
                .iter()
                .all(|&value| (value as i32 - 30000).abs() <= 3));
        }
    }
    #[test]
    fn adversarial_host_recovers_without_averaging() {
        let ss = SpreadSpectrumVideo::with_key([1; 32]);
        let mut pixels = [0; 64];
        let mut rng = pn_rng(&ss.key, 0, 0);
        for pair in 0..32 {
            let positive = rng.gen::<bool>();
            let _ = rng.gen::<bool>();
            pixels[2 * pair] = if positive { 255 } else { 0 };
            pixels[2 * pair + 1] = if positive { 0 } else { 255 };
        }
        let original = pixels;
        ss.embed_bit(&mut pixels, 0, 0, 0, 0).unwrap();
        assert_eq!(ss.extract_bit(&pixels, 0, 0, 0).unwrap(), 0);
        assert!(pixels
            .iter()
            .zip(original)
            .all(|(&after, before)| (i32::from(after) - i32::from(before)).abs() <= 3));
        let embedded = pixels;
        for (start, bit) in [(usize::MAX, 0), (1, 0), (0, 2)] {
            assert!(ss.embed_bit(&mut pixels, start, bit, 0, 0).is_err());
            assert_eq!(pixels, embedded);
        }
    }
    #[test]
    fn parameters_and_capacity_are_checked() {
        for spread in [0, 7, usize::MAX, 1usize << (usize::BITS - 3)] {
            assert!(SpreadSpectrumVideo::try_new([0; 32], 3, spread).is_err());
            assert!(SpreadSpectrumAudio::try_new([0; 32], 3, spread).is_err());
        }
        for amplitude in [i32::MIN, -1, 0, 256, i32::MAX] {
            assert!(SpreadSpectrumVideo::try_new([0; 32], amplitude, 64).is_err());
        }
        for amplitude in [i32::MIN, -1, 0, 32768, i32::MAX] {
            assert!(SpreadSpectrumAudio::try_new([0; 32], amplitude, 64).is_err());
        }
        assert_eq!(capacity(64, 64), 0);
        assert_eq!(capacity(55808, 64), 109);
        assert_eq!(capacity(55808, 0), 0);
    }
    #[test]
    fn late_adversarial_audio_region_recovers_without_destroying_contrast() {
        let payload = crate::crypto::Signer::from_bytes(&[8; 32]).sign_frame(0, b"atomic", None);
        let bytes = payload.to_bytes();
        let last = PAYLOAD_BITS - 1;
        let bit = (bytes[last / 8] >> (last % 8)) & 1;
        let mut ss = SpreadSpectrumAudio::with_key([1; 32]);
        let mut samples = vec![0i16; PAYLOAD_BITS * DEFAULT_SPREAD];
        let mut rng = pn_rng(&ss.key, last, 0);
        for pair in 0..DEFAULT_SPREAD / 2 {
            let pn = if rng.gen::<bool>() { 1 } else { -1 };
            let _ = rng.gen::<bool>();
            let value = 30000 * pn * if bit == 1 { -1 } else { 1 };
            samples[last * DEFAULT_SPREAD + 2 * pair] = value as i16;
            samples[last * DEFAULT_SPREAD + 2 * pair + 1] = -value as i16;
        }
        let original = samples.clone();
        let mut buf = AudioBuffer {
            channels: 1,
            sample_rate: 48000,
            samples: &mut samples,
            frame_index: 0,
        };
        ss.embed(&mut buf, Some(&payload)).unwrap();
        assert_eq!(
            ss.extract(&buf).unwrap().unwrap().to_bytes(),
            payload.to_bytes()
        );
        assert!(buf
            .samples
            .iter()
            .zip(original)
            .all(|(&after, before)| (i32::from(after) - i32::from(before)).abs() <= 3));
    }

    #[test]
    fn integer_projection_covers_full_domains_and_amplitude_limits() {
        for amplitude in 1..=255 {
            for value in 0..=255 {
                for chip in 0..=1 {
                    let projected = project(value, amplitude, 0, 255, chip);
                    assert!((0..=255).contains(&projected));
                    assert!((projected - value).abs() <= amplitude);
                    assert_eq!(
                        projected
                            .div_euclid(quantization_step(amplitude))
                            .rem_euclid(2),
                        i32::from(chip)
                    );
                }
            }
        }
        for amplitude in [1, 2, 3, 4, 255, 256, 32766, 32767] {
            for value in i16::MIN as i32..=i16::MAX as i32 {
                for chip in 0..=1 {
                    let projected =
                        project(value, amplitude, i16::MIN as i32, i16::MAX as i32, chip);
                    assert!((i16::MIN as i32..=i16::MAX as i32).contains(&projected));
                    assert!((projected - value).abs() <= amplitude);
                    assert_eq!(
                        projected
                            .div_euclid(quantization_step(amplitude))
                            .rem_euclid(2),
                        i32::from(chip)
                    );
                }
            }
        }
    }

    #[test]
    fn textured_carrier_roundtrip_preserves_bounded_distortion() {
        let payload = crate::crypto::Signer::from_bytes(&[8; 32]).sign_frame(
            7,
            b"textured carrier test",
            None,
        );
        let mut data = Vec::with_capacity(256 * 218 * 3);
        let mut lcg = 0x2545F4914F6CDD1Du64;
        for i in 0..256 * 218 * 3 {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let noise = ((lcg >> 33) % 9) as i32 - 4;
            let base = 128 + ((i / 8) % 100) - 50;
            data.push((base + noise).clamp(0, 255) as u8);
        }
        let original = data.clone();
        let mut frame = VideoFrame {
            width: 256,
            height: 218,
            stride: 256 * 3,
            format: crate::video::VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 7,
        };
        let mut ss = SpreadSpectrumVideo::new([1; 32], 5, 64);
        ss.embed(&mut frame, Some(&payload)).unwrap();
        assert_eq!(
            ss.extract(&frame).unwrap().unwrap().to_bytes(),
            payload.to_bytes()
        );
        assert_ne!(&*frame.data, original.as_slice());
        for (index, (&after, &before)) in frame.data.iter().zip(&original).enumerate() {
            if index % 3 == 1 {
                assert!((after as i32 - before as i32).abs() <= 5);
            } else {
                assert_eq!(after, before);
            }
        }
    }

    #[test]
    fn bounded_lsb_noise_roundtrip_is_exact() {
        let payload =
            crate::crypto::Signer::from_bytes(&[8; 32]).sign_frame(0, b"noise test", None);
        let mut data = vec![128; 256 * 218 * 3];
        let mut frame = VideoFrame {
            width: 256,
            height: 218,
            stride: 256 * 3,
            format: crate::video::VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let mut ss = SpreadSpectrumVideo::with_key([1; 32]);
        ss.embed(&mut frame, Some(&payload)).unwrap();
        let mut rng = StdRng::from_seed([42; 32]);
        for byte in frame.data.iter_mut() {
            if rng.gen::<bool>() {
                *byte ^= 1;
            }
        }
        assert_eq!(
            ss.extract(&frame).unwrap().unwrap().to_bytes(),
            payload.to_bytes()
        );
        assert!(SpreadSpectrumVideo::with_key([255; 32])
            .extract(&frame)
            .unwrap()
            .is_none());
    }
}
