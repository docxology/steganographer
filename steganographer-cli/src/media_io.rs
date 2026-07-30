//! Shared, format-aware media I/O for offline CLI commands.
//!
//! The steganography kernels operate on decoded RGB bytes or PCM samples. This
//! module keeps the encoded file size and source properties alongside those
//! bytes so capacity reporting and output writing use the same descriptor.

use std::path::Path;

/// Decoded media kind and the properties required to write it safely.
#[derive(Debug, Clone, Copy)]
pub enum MediaKind {
    /// Packed RGB8 image pixels.
    Rgb8Image,
    /// PCM S16 WAV with the original channel/rate specification.
    WavPcm16(hound::WavSpec),
    /// Headerless interleaved S16LE PCM.
    RawS16Le,
    /// Headerless packed RGB8 bytes.
    RawRgb8,
}

/// A decoded carrier plus its source descriptor.
#[derive(Debug)]
pub struct MediaInput {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub encoded_len: usize,
    pub kind: MediaKind,
}

impl MediaInput {
    /// Number of decoded RGB bytes or PCM samples eligible for spatial LSB.
    pub fn lsb_units(&self, stego_type: &str) -> usize {
        if stego_type.contains("audio") {
            self.data.len() / 2
        } else {
            self.data.len()
        }
    }

    /// Number of complete 8x8 image blocks.
    pub fn dct_blocks(&self) -> usize {
        (self.width as usize / 8) * (self.height as usize / 8)
    }
}

/// Infer the input representation from its extension and selected algorithm.
pub fn detect_format(path: &str, stego_type: &str) -> String {
    let lower = path.to_lowercase();
    if lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image".to_string()
    } else if lower.ends_with(".wav") {
        "wav".to_string()
    } else if stego_type.contains("audio") {
        "raw_s16le".to_string()
    } else {
        "raw_rgb".to_string()
    }
}

/// Decode supported input into the representation consumed by CLI kernels.
pub fn read_input(path: &str, format: &str, _stego_type: &str) -> anyhow::Result<MediaInput> {
    read_input_with_dimensions(path, format, _stego_type, None, None)
}

/// Decode supported input with optional explicit dimensions for headerless RGB.
pub fn read_input_with_dimensions(
    path: &str,
    format: &str,
    _stego_type: &str,
    raw_width: Option<u32>,
    raw_height: Option<u32>,
) -> anyhow::Result<MediaInput> {
    let encoded_len = std::fs::metadata(path)?.len() as usize;
    match format {
        "image" | "png" | "jpg" | "jpeg" => {
            let img =
                image::open(path).map_err(|e| anyhow::anyhow!("Failed to open image: {}", e))?;
            let rgb = img.to_rgb8();
            let (width, height) = (rgb.width(), rgb.height());
            Ok(MediaInput {
                data: rgb.into_raw(),
                width,
                height,
                encoded_len,
                kind: MediaKind::Rgb8Image,
            })
        }
        "wav" => {
            let reader = hound::WavReader::open(path)?;
            let spec = reader.spec();
            if spec.sample_format != hound::SampleFormat::Int || spec.bits_per_sample != 16 {
                anyhow::bail!(
                    "Only 16-bit integer PCM WAV files are supported (got {:?}, {} bits)",
                    spec.sample_format,
                    spec.bits_per_sample
                );
            }
            if spec.channels == 0 || spec.sample_rate == 0 {
                anyhow::bail!(
                    "Invalid WAV specification: channels={} sample_rate={}",
                    spec.channels,
                    spec.sample_rate
                );
            }
            let samples: Vec<i16> = reader.into_samples::<i16>().collect::<Result<_, _>>()?;
            let data = samples
                .iter()
                .flat_map(|sample| sample.to_le_bytes())
                .collect();
            let frame_count = samples.len() / spec.channels as usize;
            Ok(MediaInput {
                data,
                width: u32::try_from(frame_count).unwrap_or(u32::MAX),
                height: u32::from(spec.channels),
                encoded_len,
                kind: MediaKind::WavPcm16(spec),
            })
        }
        "raw_s16le" => {
            let data = std::fs::read(path)?;
            if !data.len().is_multiple_of(2) {
                anyhow::bail!(
                    "Raw S16LE input must contain an even number of bytes, got {}",
                    data.len()
                );
            }
            Ok(MediaInput {
                width: u32::try_from(data.len() / 2).unwrap_or(u32::MAX),
                height: 1,
                encoded_len,
                data,
                kind: MediaKind::RawS16Le,
            })
        }
        "raw_rgb" => {
            let data = std::fs::read(path)?;
            if !data.len().is_multiple_of(3) {
                anyhow::bail!(
                    "Raw RGB input must contain a multiple of 3 bytes, got {}",
                    data.len()
                );
            }
            let pixel_count = data.len() / 3;
            let (width, height) = match (raw_width, raw_height) {
                (Some(width), Some(height)) => {
                    let expected = (width as usize)
                        .checked_mul(height as usize)
                        .and_then(|pixels| pixels.checked_mul(3))
                        .ok_or_else(|| anyhow::anyhow!("Raw RGB dimensions overflow"))?;
                    if expected != data.len() {
                        anyhow::bail!(
                            "Raw RGB dimensions {}x{} require {} bytes, got {}",
                            width,
                            height,
                            expected,
                            data.len()
                        );
                    }
                    (width, height)
                }
                (None, None) => {
                    let side = (pixel_count as f64).sqrt() as usize;
                    if side.checked_mul(side) == Some(pixel_count) {
                        let side = u32::try_from(side)
                            .map_err(|_| anyhow::anyhow!("Raw RGB dimensions exceed u32"))?;
                        (side, side)
                    } else {
                        (
                            u32::try_from(pixel_count)
                                .map_err(|_| anyhow::anyhow!("Raw RGB pixel count exceeds u32"))?,
                            1,
                        )
                    }
                }
                _ => anyhow::bail!("Raw RGB dimensions require both --width and --height"),
            };
            Ok(MediaInput {
                data,
                width,
                height,
                encoded_len,
                kind: MediaKind::RawRgb8,
            })
        }
        other => anyhow::bail!(
            "Unsupported input format '{}'; expected raw_rgb, raw_s16le, png/image, or wav",
            other
        ),
    }
}

/// Write a decoded carrier while preserving source properties and rejecting
/// output encodings known to destroy the selected steganography domain.
pub fn write_output(path: &str, media: &MediaInput, stego_type: &str) -> anyhow::Result<()> {
    validate_output_compatibility(path, stego_type)?;

    match media.kind {
        MediaKind::Rgb8Image => {
            let expected = media.width as usize * media.height as usize * 3;
            if media.data.len() != expected {
                anyhow::bail!(
                    "Decoded RGB buffer length mismatch: expected {}, got {}",
                    expected,
                    media.data.len()
                );
            }
            let image = image::RgbImage::from_raw(media.width, media.height, media.data.clone())
                .ok_or_else(|| anyhow::anyhow!("Failed to create image from decoded RGB data"))?;
            image
                .save(path)
                .map_err(|e| anyhow::anyhow!("Failed to write image: {}", e))?;
        }
        MediaKind::WavPcm16(spec) => {
            let mut writer = hound::WavWriter::create(path, spec)?;
            for bytes in media.data.chunks_exact(2) {
                writer.write_sample(i16::from_le_bytes([bytes[0], bytes[1]]))?;
            }
            writer.finalize()?;
        }
        MediaKind::RawS16Le | MediaKind::RawRgb8 => {
            std::fs::write(path, &media.data)?;
        }
    }
    Ok(())
}

fn validate_output_compatibility(path: &str, stego_type: &str) -> anyhow::Result<()> {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if matches!(stego_type, "lsb_video") && matches!(extension.as_str(), "jpg" | "jpeg") {
        anyhow::bail!(
            "Refusing to write spatial LSB data to lossy JPEG output '{}': \
             JPEG re-encoding destroys pixel LSBs. Use PNG/raw output or dct_video.",
            path
        );
    }
    if matches!(stego_type, "lsb_audio")
        && matches!(extension.as_str(), "mp3" | "aac" | "ogg" | "opus" | "m4a")
    {
        anyhow::bail!(
            "Refusing to write PCM LSB data to lossy audio output '{}'; use WAV/raw PCM",
            path
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spatial_lsb_rejects_jpeg_output() {
        let media = MediaInput {
            data: vec![0; 3],
            width: 1,
            height: 1,
            encoded_len: 3,
            kind: MediaKind::Rgb8Image,
        };
        let error = write_output("output.jpg", &media, "lsb_video").unwrap_err();
        assert!(error.to_string().contains("lossy JPEG"));
    }

    #[test]
    fn decoded_capacity_uses_samples_for_audio() {
        let media = MediaInput {
            data: vec![0; 20],
            width: 10,
            height: 1,
            encoded_len: 64,
            kind: MediaKind::RawS16Le,
        };
        assert_eq!(media.lsb_units("lsb_audio"), 10);
        assert_eq!(media.lsb_units("lsb_video"), 20);
    }

    #[test]
    fn non_square_raw_rgb_is_not_guessed_as_a_square() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("frame.rgb");
        std::fs::write(&path, vec![0; 6 * 4 * 3]).unwrap();

        let inferred = read_input(path.to_str().unwrap(), "raw_rgb", "lsb_video").unwrap();
        assert_eq!((inferred.width, inferred.height), (24, 1));

        let explicit = read_input_with_dimensions(
            path.to_str().unwrap(),
            "raw_rgb",
            "dct_video",
            Some(6),
            Some(4),
        )
        .unwrap();
        assert_eq!((explicit.width, explicit.height), (6, 4));
    }

    #[test]
    fn raw_rgb_dimension_mismatch_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("frame.rgb");
        std::fs::write(&path, vec![0; 12]).unwrap();
        assert!(read_input_with_dimensions(
            path.to_str().unwrap(),
            "raw_rgb",
            "dct_video",
            Some(3),
            Some(3),
        )
        .is_err());
        assert!(read_input_with_dimensions(
            path.to_str().unwrap(),
            "raw_rgb",
            "dct_video",
            Some(2),
            None,
        )
        .is_err());
    }
}
