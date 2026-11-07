//! Shared, format-aware media I/O for offline CLI commands.
//!
//! The steganography kernels operate on decoded RGB bytes or PCM samples. This
//! module keeps the encoded file size and source properties alongside those
//! bytes so capacity reporting and output writing use the same descriptor.

use std::path::Path;

use steganographer_core::CarrierDescriptor;

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

    /// The shared carrier descriptor used by generic packet capacity math.
    /// Byte carriers (`Rgb8`/`ByteStream`) report one unit per byte; PCM S16LE
    /// carriers report one unit per interleaved sample.
    pub fn carrier_descriptor(&self) -> CarrierDescriptor {
        match self.kind {
            MediaKind::Rgb8Image | MediaKind::RawRgb8 => CarrierDescriptor::rgb8(self.data.len()),
            MediaKind::WavPcm16(_) | MediaKind::RawS16Le => {
                CarrierDescriptor::pcm_s16le(self.data.len() / 2)
            }
        }
    }

    /// Whether this carrier is PCM S16LE audio (2-byte units).
    pub fn is_audio(&self) -> bool {
        matches!(self.kind, MediaKind::WavPcm16(_) | MediaKind::RawS16Le)
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
pub fn read_input(path: &str, format: &str, stego_type: &str) -> anyhow::Result<MediaInput> {
    read_input_with_dimensions(path, format, stego_type, None, None)
}

/// Decode supported input with optional explicit dimensions for headerless RGB.
pub fn read_input_with_dimensions(
    path: &str,
    format: &str,
    stego_type: &str,
    raw_width: Option<u32>,
    raw_height: Option<u32>,
) -> anyhow::Result<MediaInput> {
    let encoded_len = std::fs::metadata(path)?.len() as usize;
    let media: anyhow::Result<MediaInput> = match format {
        "image" | "png" | "jpg" | "jpeg" => {
            let img = image::ImageReader::open(path)?
                .with_guessed_format()?
                .decode()
                .map_err(|e| anyhow::anyhow!("Failed to open image: {}", e))?;
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
    };
    let media = media?;
    if media.is_audio() != stego_type.contains("audio") {
        anyhow::bail!(
            "Carrier media does not match selected kernel '{}'",
            stego_type
        );
    }
    if !matches!(media.kind, MediaKind::RawRgb8) {
        match (raw_width, raw_height) {
            (None, None) => {}
            (Some(width), Some(height))
                if !media.is_audio() && (width, height) == (media.width, media.height) => {}
            _ => anyhow::bail!("Explicit dimensions must match the decoded RGB carrier"),
        }
    }
    Ok(media)
}

/// Refuse an existing destination unless replacement was explicitly requested.
/// `symlink_metadata` deliberately observes dangling links as existing outputs.
pub(crate) fn preflight_output(path: &Path, force: bool) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !force {
                anyhow::bail!(
                    "Output '{}' already exists; refusing to overwrite",
                    path.display()
                );
            }
            if metadata.is_dir() {
                anyhow::bail!("Output '{}' is a directory", path.display());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(crate) fn output_temp(path: &Path, force: bool) -> anyhow::Result<tempfile::NamedTempFile> {
    preflight_output(path, force)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // tempfile creates the file with mode 0600 before any bytes are written.
    Ok(tempfile::NamedTempFile::new_in(parent)?)
}

pub(crate) fn publish_output(
    file: tempfile::NamedTempFile,
    path: &Path,
    force: bool,
) -> anyhow::Result<()> {
    file.as_file().sync_all()?;
    if force {
        // Rename replaces the directory entry, never truncating a symlink target
        // or another name for a hard-linked input inode.
        file.persist(path).map_err(|error| error.error)?;
    } else {
        file.persist_noclobber(path).map_err(|error| error.error)?;
    }
    Ok(())
}

pub(crate) fn atomic_write(
    path: &Path,
    bytes: &[u8],
    force: bool,
    _secret: bool,
) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = output_temp(path, force)?;
    file.write_all(bytes)?;
    publish_output(file, path, force)
}

/// Validate the target representation before embedding or creating any output.
pub(crate) fn validate_media_output(
    path: &str,
    media: &MediaInput,
    _stego_type: &str,
) -> anyhow::Result<()> {
    let format_path = path
        .rsplit_once('_')
        .filter(|(_, suffix)| {
            matches!(
                *suffix,
                "001" | "002" | "003" | "004" | "005" | "006" | "007" | "008"
            )
        })
        .map_or(path, |(base, _)| base);
    let extension = Path::new(format_path)
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(extension.as_str(), "jpg" | "jpeg") {
        anyhow::bail!(
            "Refusing lossy JPEG output: signed carriers require exact pixels; use PNG/raw"
        );
    }
    let supported = match media.kind {
        MediaKind::Rgb8Image => extension == "png",
        MediaKind::WavPcm16(_) => extension == "wav",
        MediaKind::RawRgb8 => matches!(extension.as_str(), "" | "rgb" | "raw" | "bin"),
        MediaKind::RawS16Le => matches!(extension.as_str(), "" | "pcm" | "s16le" | "raw" | "bin"),
    };
    if !supported {
        anyhow::bail!("Output '{}' does not match the decoded input representation; format conversion is unsupported", path);
    }
    preflight_output(Path::new(path), false)
}

/// Encode to a private same-directory temporary file and publish without clobber.
pub fn write_output(path: &str, media: &MediaInput, stego_type: &str) -> anyhow::Result<()> {
    validate_media_output(path, media, stego_type)?;
    let destination = Path::new(path);
    let mut file = output_temp(destination, false)?;
    match media.kind {
        MediaKind::Rgb8Image => {
            let expected = (media.width as usize)
                .checked_mul(media.height as usize)
                .and_then(|pixels| pixels.checked_mul(3))
                .ok_or_else(|| anyhow::anyhow!("Decoded RGB dimensions overflow"))?;
            if media.data.len() != expected {
                anyhow::bail!(
                    "Decoded RGB buffer length mismatch: expected {}, got {}",
                    expected,
                    media.data.len()
                );
            }
            use image::ImageEncoder;
            image::codecs::png::PngEncoder::new(file.as_file_mut()).write_image(
                &media.data,
                media.width,
                media.height,
                image::ExtendedColorType::Rgb8,
            )?;
        }
        MediaKind::WavPcm16(spec) => {
            if !media.data.len().is_multiple_of(2) {
                anyhow::bail!("PCM output has an incomplete sample");
            }
            let mut writer = hound::WavWriter::new(file.as_file_mut(), spec)?;
            for bytes in media.data.as_chunks::<2>().0 {
                writer.write_sample(i16::from_le_bytes(*bytes))?;
            }
            writer.finalize()?;
        }
        MediaKind::RawS16Le | MediaKind::RawRgb8 => {
            use std::io::Write;
            file.write_all(&media.data)?;
        }
    }
    publish_output(file, destination, false)
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
    #[test]
    fn atomic_outputs_do_not_clobber_or_follow_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("carrier");
        let alias = directory.path().join("alias");
        std::fs::write(&input, b"original carrier").unwrap();
        std::fs::hard_link(&input, &alias).unwrap();
        assert!(atomic_write(&alias, b"payload", false, false).is_err());
        atomic_write(&alias, b"payload", true, false).unwrap();
        assert_eq!(std::fs::read(&input).unwrap(), b"original carrier");
        assert_eq!(std::fs::read(&alias).unwrap(), b"payload");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_outputs_replace_links_and_create_private_secrets() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("missing");
        let link = directory.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(atomic_write(&link, b"secret", false, true).is_err());
        assert!(!target.exists());
        atomic_write(&link, b"secret", true, true).unwrap();
        assert!(!target.exists());
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::metadata(&link).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn raw_target_format_mismatch_fails_without_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("carrier.png");
        let media = MediaInput {
            data: vec![0; 3],
            width: 1,
            height: 1,
            encoded_len: 3,
            kind: MediaKind::RawRgb8,
        };
        assert!(write_output(output.to_str().unwrap(), &media, "lsb_video").is_err());
        assert!(!output.exists());
    }
}
