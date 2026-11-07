//! Video filter using GStreamer AppSink/AppSrc pattern.
//!
//! Pulls video frames from an AppSink, processes them through a
//! [`VideoStegoModule`], and pushes the modified frames via AppSrc.

use crate::{BridgeOutput, BridgeSource, SigningKernel};
use anyhow::Context;
use gstreamer_video::VideoFrameExt;
use steganographer_core::crypto::{SignaturePayload, Signer};
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

struct AutoReleasePool {
    #[cfg(target_os = "macos")]
    pool: *mut std::ffi::c_void,
}

impl AutoReleasePool {
    #[cfg(target_os = "macos")]
    fn new() -> Self {
        #[link(name = "objc", kind = "dylib")]
        extern "C" {
            fn objc_autoreleasePoolPush() -> *mut std::ffi::c_void;
        }
        Self {
            pool: unsafe { objc_autoreleasePoolPush() },
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for AutoReleasePool {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            #[link(name = "objc", kind = "dylib")]
            extern "C" {
                fn objc_autoreleasePoolPop(pool: *mut std::ffi::c_void);
            }
            unsafe { objc_autoreleasePoolPop(self.pool) };
        }
    }
}

/// Endpoint-free launch fragments and the actual embedding kernel's binding.
#[derive(Clone)]
pub struct VideoFilterConfig {
    pub source_pipeline: String,
    /// Caller-owned output chain. Later verification requires exact pixels;
    /// lossy encoding or color conversion after the bridge can destroy them.
    pub sink_pipeline: String,
    /// Required when signing. Must describe the module actually embedding.
    pub signing_kernel: Option<SigningKernel>,
}

/// Process packed RGB/BGRA pixels, preserving padding and buffer timing.
/// Signed modules must permit extraction and canonical verification of their
/// actual output; unsupported compositions fail rather than claiming success.
/// Verification here checks module output before AppSrc, not arbitrary sink
/// encoders. Use `process_video_file` for an exact-pixel file output chain.
/// Headless pipelines run on the calling thread. On macOS, applications using
/// camera or GUI elements must arrange their Cocoa main loop at application
/// entry; this library never creates or runs NSApplication.
pub fn run_video_filter(
    config: &VideoFilterConfig,
    mut stego: Box<dyn VideoStegoModule>,
    signer: Option<&Signer>,
    max_frames: Option<u64>,
) -> anyhow::Result<()> {
    if let Some(signer) = signer {
        steganographer_core::revocation::check_known_revocations(
            signer.verifying_key().as_bytes(),
        )?;
        match config
            .signing_kernel
            .context("video signing requires signing_kernel")?
        {
            SigningKernel::Lsb { bits } => {
                anyhow::ensure!((1..=4).contains(&bits), "LSB signing bits must be 1-4")
            }
            SigningKernel::Dct => {}
            SigningKernel::SpreadSpectrum => anyhow::bail!(
                "spread-spectrum video signing has no supported canonical trait binding"
            ),
        }
    }
    let source = BridgeSource::new(&config.source_pipeline)?;
    let output = BridgeOutput::new(&config.sink_pipeline)?;
    output.start()?;
    source.start()?;
    let mut index = 0;
    while max_frames.is_none_or(|max| index < max) {
        let _pool = AutoReleasePool::new();
        let Some(sample) = source.pull(Some(&output))? else {
            break;
        };
        let caps = sample.caps().context("video sample has no caps")?;
        let info = gstreamer_video::VideoInfo::from_caps(caps).context("invalid video caps")?;
        let (format, row_bytes) = packed_format(&info)?;
        let mut buffer = sample
            .buffer()
            .context("video sample has no buffer")?
            .copy();
        {
            let mut mapped =
                gstreamer_video::VideoFrameRef::from_buffer_ref_writable(buffer.make_mut(), &info)
                    .context("mapping video frame")?;
            let stride = checked_stride(mapped.plane_stride()[0], row_bytes, info.height())?;
            let plane = mapped
                .plane_data_mut(0)
                .context("mapping video pixel plane")?;
            // Tight frames can be processed in place; gather only when the
            // native layout contains padding that is not carrier content.
            let mut packed = if stride == row_bytes {
                None
            } else {
                Some(gather_pixels(plane, stride, row_bytes, info.height())?)
            };
            let pixels = match packed.as_mut() {
                Some(pixels) => pixels.as_mut_slice(),
                None => plane
                    .get_mut(..row_bytes * info.height() as usize)
                    .context("video plane is shorter than its pixel layout")?,
            };
            let signature = if let Some(signer) = signer {
                let kernel = config
                    .signing_kernel
                    .context("video signing requires signing_kernel")?;
                anyhow::ensure!(
                    format == VideoFormat::Rgb8 || matches!(kernel, SigningKernel::Lsb { .. }),
                    "DCT and spread-spectrum video signing require RGB pixels"
                );
                Some(signer.sign_frame(
                    index,
                    &kernel.video_binding(pixels, info.width(), info.height())?,
                    None,
                ))
            } else {
                None
            };
            let mut frame = VideoFrame {
                width: info.width(),
                height: info.height(),
                stride: row_bytes as u32,
                format,
                data: pixels,
                frame_index: index,
            };
            stego
                .embed(&mut frame, signature.as_ref())
                .context("video stego embed failed")?;
            if let Some(signer) = signer {
                let extracted = stego
                    .extract(&frame)
                    .context("extracting actual signed video output")?
                    .context("module did not embed an extractable video signature")?;
                let binding = config
                    .signing_kernel
                    .context("missing signing kernel")?
                    .video_binding(frame.data, info.width(), info.height())?;
                let verifier = steganographer_core::crypto::Verifier::with_hash_algorithm(
                    signer.verifying_key(),
                    signer.hash_algorithm(),
                );
                anyhow::ensure!(
                    extracted.frame_index == index && verifier.verify(&extracted, &binding, None),
                    "video module output is incompatible with its signing binding"
                );
            }
            if let Some(pixels) = packed {
                scatter_pixels(plane, stride, row_bytes, &pixels);
            }
        }
        output.push(&source, &sample, &buffer)?;
        index += 1;
    }
    output.finish(&source)
}

fn packed_format(info: &gstreamer_video::VideoInfo) -> anyhow::Result<(VideoFormat, usize)> {
    let (format, bpp) = match info.format() {
        gstreamer_video::VideoFormat::Rgb => (VideoFormat::Rgb8, 3usize),
        gstreamer_video::VideoFormat::Bgra => (VideoFormat::Bgra8, 4usize),
        other => anyhow::bail!("video bridge requires packed RGB or BGRA; got {other:?}"),
    };
    anyhow::ensure!(
        info.width() > 0 && info.height() > 0,
        "empty video dimensions"
    );
    let row = (info.width() as usize)
        .checked_mul(bpp)
        .context("video row length overflow")?;
    anyhow::ensure!(
        u32::try_from(row).is_ok(),
        "video row length exceeds core stride"
    );
    Ok((format, row))
}

fn checked_stride(stride: i32, row: usize, height: u32) -> anyhow::Result<usize> {
    let stride = usize::try_from(stride).context("negative video stride is unsupported")?;
    anyhow::ensure!(stride >= row, "video stride is smaller than packed row");
    let size = stride
        .checked_mul(height as usize)
        .context("video plane size overflow")?;
    // gstreamer-video's plane_data accessor computes this extent as u32.
    anyhow::ensure!(
        size <= u32::MAX as usize,
        "video plane exceeds supported map extent"
    );
    Ok(stride)
}

fn gather_pixels(plane: &[u8], stride: usize, row: usize, height: u32) -> anyhow::Result<Vec<u8>> {
    let required = (height as usize - 1)
        .checked_mul(stride)
        .and_then(|v| v.checked_add(row))
        .context("video pixel extent overflow")?;
    anyhow::ensure!(
        plane.len() >= required,
        "video plane is shorter than its pixel layout"
    );
    let mut pixels = Vec::with_capacity(
        row.checked_mul(height as usize)
            .context("pixel size overflow")?,
    );
    for y in 0..height as usize {
        pixels.extend_from_slice(&plane[y * stride..y * stride + row]);
    }
    Ok(pixels)
}

fn scatter_pixels(plane: &mut [u8], stride: usize, row: usize, pixels: &[u8]) {
    for (y, packed_row) in pixels.chunks_exact(row).enumerate() {
        plane[y * stride..y * stride + row].copy_from_slice(packed_row);
    }
}

/// Extract from packed pixels only. Timeouts and source errors are failures,
/// not a successful empty/partial extraction.
pub fn extract_from_source(
    source_pipeline_str: &str,
    stego: &dyn VideoStegoModule,
    max_frames: Option<u64>,
) -> anyhow::Result<Vec<(u64, Option<SignaturePayload>)>> {
    let source = BridgeSource::new(source_pipeline_str)?;
    source.start()?;
    let mut results = Vec::new();
    let mut index = 0;
    while max_frames.is_none_or(|max| index < max) {
        let Some(sample) = source.pull(None)? else {
            break;
        };
        let caps = sample.caps().context("video sample has no caps")?;
        let info = gstreamer_video::VideoInfo::from_caps(caps).context("invalid video caps")?;
        let (format, row_bytes) = packed_format(&info)?;
        let mapped = gstreamer_video::VideoFrameRef::from_buffer_ref_readable(
            sample.buffer().context("video sample has no buffer")?,
            &info,
        )
        .context("mapping video frame")?;
        let stride = checked_stride(mapped.plane_stride()[0], row_bytes, info.height())?;
        let mut pixels = gather_pixels(mapped.plane_data(0)?, stride, row_bytes, info.height())?;
        let frame = VideoFrame {
            width: info.width(),
            height: info.height(),
            stride: row_bytes as u32,
            format,
            data: &mut pixels,
            frame_index: index,
        };
        results.push((index, stego.extract(&frame)?));
        index += 1;
    }
    Ok(results)
}

/// Decode input to RGB and write exact processed pixels as raw-RGB Matroska.
/// Only `.mkv` output is supported: lossy/color-converted output destroys LSBs.
/// `signing_kernel` must describe `stego` when a signer is supplied.
pub fn process_video_file(
    input_path: &str,
    output_path: &str,
    stego: Box<dyn VideoStegoModule>,
    signer: Option<&Signer>,
    signing_kernel: Option<SigningKernel>,
    max_frames: Option<u64>,
) -> anyhow::Result<()> {
    require_extension(
        output_path,
        "mkv",
        "video file output requires .mkv (exact raw RGB Matroska)",
    )?;
    let config = VideoFilterConfig {
        source_pipeline: format!(
            "filesrc location={} ! decodebin ! videoconvert ! video/x-raw,format=RGB",
            crate::quote_location(input_path)?,
        ),
        sink_pipeline: format!(
            "matroskamux ! filesink location={}",
            crate::quote_location(output_path)?,
        ),
        signing_kernel,
    };
    run_video_filter(&config, stego, signer, max_frames)
}

/// Decode to interleaved S16LE and write exact processed PCM to `.wav`.
/// No resampling or conversion occurs after embedding.
/// Selected decoded PCM is one logical frame at index zero, bounded to 64 MiB.
/// `max_buffers` explicitly limits input collection; absent means the complete
/// file. Extract the signature from the whole delivered PCM, not decoder chunks.
pub fn process_audio_file(
    input_path: &str,
    output_path: &str,
    stego: &mut dyn steganographer_core::audio::AudioStegoModule,
    signer: Option<&Signer>,
    signing_kernel: Option<SigningKernel>,
    max_buffers: Option<u64>,
) -> anyhow::Result<()> {
    require_extension(
        output_path,
        "wav",
        "audio file output requires .wav (exact S16LE PCM)",
    )?;
    let config = crate::audio_filter::AudioFilterConfig {
        source_pipeline: format!(
            "filesrc location={} ! decodebin ! audioconvert ! audio/x-raw,format=S16LE,layout=interleaved",
            crate::quote_location(input_path)?,
        ),
        sink_pipeline: format!("wavenc ! filesink location={}", crate::quote_location(output_path)?),
        signing_kernel,
    };
    crate::audio_filter::run_audio_file(&config, stego, signer, max_buffers)
}

fn require_extension(path: &str, extension: &str, message: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        std::path::Path::new(path)
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.eq_ignore_ascii_case(extension)),
        "{message}"
    );
    Ok(())
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use steganographer_core::lsb_video::LsbVideo;

    #[test]
    fn metadata_offsets_and_padding_are_not_signed_or_embedded() {
        gstreamer::init().unwrap();
        let width = 62u32;
        let height = 8u32;
        let row = width as usize * 3;
        let offset = 37usize;
        let stride = 200usize;
        let before = vec![0xff; offset + stride * height as usize + 19];
        let mut buffer = gstreamer::Buffer::from_mut_slice(before.clone());
        gstreamer_video::VideoMeta::add_full(
            buffer.get_mut().unwrap(),
            gstreamer_video::VideoFrameFlags::empty(),
            gstreamer_video::VideoFormat::Rgb,
            width,
            height,
            &[offset],
            &[stride as i32],
        )
        .unwrap();
        let info =
            gstreamer_video::VideoInfo::builder(gstreamer_video::VideoFormat::Rgb, width, height)
                .build()
                .unwrap();
        let signer = Signer::from_bytes(&[0x42; 32]);
        let module = &mut LsbVideo::new(1);
        {
            let mut mapped =
                gstreamer_video::VideoFrameRef::from_buffer_ref_writable(buffer.make_mut(), &info)
                    .unwrap();
            assert_eq!(mapped.plane_stride()[0] as usize, stride);
            let plane = mapped.plane_data_mut(0).unwrap();
            let mut pixels = gather_pixels(plane, stride, row, height).unwrap();
            let binding = SigningKernel::Lsb { bits: 1 }
                .video_binding(&pixels, width, height)
                .unwrap();
            let signature = signer.sign_frame(0, &binding, None);
            let mut frame = VideoFrame {
                width,
                height,
                stride: row as u32,
                format: VideoFormat::Rgb8,
                data: &mut pixels,
                frame_index: 0,
            };
            module.embed(&mut frame, Some(&signature)).unwrap();
            let extracted = module.extract(&frame).unwrap().unwrap();
            let delivered_binding = SigningKernel::Lsb { bits: 1 }
                .video_binding(frame.data, width, height)
                .unwrap();
            assert!(
                steganographer_core::crypto::Verifier::new(signer.verifying_key()).verify(
                    &extracted,
                    &delivered_binding,
                    None
                )
            );
            scatter_pixels(plane, stride, row, &pixels);
        }
        let map = buffer.map_readable().unwrap();
        for (i, expected) in before.iter().enumerate() {
            let is_pixel =
                i >= offset && i < offset + stride * height as usize && (i - offset) % stride < row;
            if !is_pixel {
                assert_eq!(map.as_ref()[i], *expected, "nonpixel byte {i} changed");
            }
        }
    }
}
