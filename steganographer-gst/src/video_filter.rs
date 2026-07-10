//! Video filter using GStreamer AppSink/AppSrc pattern.
//!
//! Pulls video frames from an AppSink, processes them through a
//! [`VideoStegoModule`], and pushes the modified frames via AppSrc.

use anyhow::Context;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};
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

/// Configuration for the video filter pipeline.
pub struct VideoFilterConfig {
    /// GStreamer source pipeline string (e.g., "videotestsrc ! videoconvert ! video/x-raw,format=RGB")
    pub source_pipeline: String,
    /// GStreamer sink pipeline string (e.g., "videoconvert ! autovideosink")
    pub sink_pipeline: String,
}

/// Run a video filter pipeline using AppSink/AppSrc.
///
/// This function:
/// 1. Creates a source pipeline ending in an AppSink
/// 2. Creates a sink pipeline starting from an AppSrc
/// 3. Pulls frames from the AppSink, processes them, and pushes to AppSrc
///
/// # Arguments
/// * `config` — Pipeline configuration
/// * `stego` — The steganography module to apply
/// * `signer` — Optional signer for generating frame signatures
/// * `max_frames` — Optional limit on frames to process (None = unlimited)
pub fn run_video_filter(
    config: &VideoFilterConfig,
    stego: Box<dyn VideoStegoModule>,
    signer: Option<&Signer>,
    max_frames: Option<u64>,
) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // On macOS, ALL GStreamer pipeline construction and state management
        // MUST happen inside gstreamer::macos_main(). This function:
        //   1. Runs the closure on the main thread
        //   2. Starts the NSRunLoop on the main thread
        // avfvideosrc and osxvideosink require an active NSRunLoop to function.
        let config_clone = VideoFilterConfig {
            source_pipeline: config.source_pipeline.clone(),
            sink_pipeline: config.sink_pipeline.clone(),
        };
        let signer_clone = signer.map(|s| Signer::from_bytes(&s.signing_key_bytes()));
        let stego_box = stego;

        gstreamer::macos_main(move || {
            if let Err(e) = run_video_filter_internal(
                &config_clone,
                stego_box,
                signer_clone.as_ref(),
                max_frames,
            ) {
                log::error!("Pipeline error: {}", e);
            }
        });

        #[allow(clippy::needless_return)]
        return Ok(());
    }

    #[cfg(not(target_os = "macos"))]
    {
        run_video_filter_internal(config, stego, signer, max_frames)
    }
}

fn run_video_filter_internal(
    config: &VideoFilterConfig,
    stego: Box<dyn VideoStegoModule>,
    signer: Option<&Signer>,
    max_frames: Option<u64>,
) -> anyhow::Result<()> {
    log::info!("Starting video filter pipeline");
    log::info!("  Source: {}", config.source_pipeline);
    log::info!("  Sink:   {}", config.sink_pipeline);

    // Build source pipeline with appsink
    // emit-signals=false, we will use try_pull_sample directly (no callbacks)
    let full_source_str = format!(
        "{} ! queue max-size-buffers=10 ! appsink name=sink emit-signals=false sync=false max-buffers=5 drop=true",
        config.source_pipeline
    );
    log::info!("  Full source: {}", full_source_str);

    let source_pipeline = gstreamer::parse::launch(&full_source_str)
        .context("Failed to create source pipeline")?;
    let source_bin = source_pipeline
        .downcast::<gstreamer::Bin>()
        .map_err(|_| anyhow::anyhow!("Source pipeline is not a Bin"))?;
    let appsink = source_bin
        .by_name("sink")
        .ok_or_else(|| anyhow::anyhow!("Could not find appsink"))?
        .downcast::<AppSink>()
        .map_err(|_| anyhow::anyhow!("Not an AppSink"))?;

    // Build sink pipeline with appsrc
    let full_sink_str = format!(
        "appsrc name=src format=time is-live=true ! queue max-size-buffers=10 ! {}",
        config.sink_pipeline
    );
    log::info!("  Full sink: {}", full_sink_str);

    let sink_pipeline = gstreamer::parse::launch(&full_sink_str)
        .context("Failed to create sink pipeline")?;
    let sink_bin = sink_pipeline
        .downcast::<gstreamer::Bin>()
        .map_err(|_| anyhow::anyhow!("Sink pipeline is not a Bin"))?;
    let appsrc = sink_bin
        .by_name("src")
        .ok_or_else(|| anyhow::anyhow!("Could not find appsrc"))?
        .downcast::<AppSrc>()
        .map_err(|_| anyhow::anyhow!("Not an AppSrc"))?;

    appsrc.set_format(gstreamer::Format::Time);

    // Start sink pipeline first so it's ready to receive
    log::info!("Starting sink pipeline...");
    sink_bin
        .set_state(gstreamer::State::Playing)
        .context("Failed to set sink pipeline to Playing")?;

    // Start source pipeline
    log::info!("Starting source pipeline...");
    source_bin
        .set_state(gstreamer::State::Playing)
        .context("Failed to set source pipeline to Playing")?;

    log::info!("Pipelines started. Entering pull-based processing loop...");

    // ── Direct pull-based processing loop ──
    // We use try_pull_sample directly on this thread — NO callbacks, NO channels.
    // This avoids blocking the GStreamer streaming thread, which is critical on macOS
    // because avfvideosrc's CVPixelBuffer pool gets exhausted if we hold references.
    let mut stego = stego;
    let mut frame_index: u64 = 0;
    let mut consecutive_misses: u32 = 0;

    loop {
        // macOS autorelease pool for Objective-C objects created by AVFoundation
        let _pool = AutoReleasePool::new();

        if let Some(max) = max_frames {
            if frame_index >= max {
                log::info!("Reached max frame count: {}", max);
                break;
            }
        }

        // Check source bus for errors/EOS
        if let Some(bus) = source_bin.bus() {
            while let Some(msg) = bus.timed_pop(gstreamer::ClockTime::ZERO) {
                use gstreamer::MessageView;
                match msg.view() {
                    MessageView::Error(err) => {
                        let src_name = err.src().map(|s| s.name().to_string()).unwrap_or_default();
                        log::error!(
                            "GStreamer error from '{}': {} (debug: {:?})",
                            src_name,
                            err.error(),
                            err.debug()
                        );
                        source_bin.set_state(gstreamer::State::Null).ok();
                        sink_bin.set_state(gstreamer::State::Null).ok();
                        anyhow::bail!("Pipeline error: {}", err.error());
                    }
                    MessageView::Eos(_) => {
                        log::info!("End of stream");
                        source_bin.set_state(gstreamer::State::Null).ok();
                        sink_bin.set_state(gstreamer::State::Null).ok();
                        log::info!("Video filter complete: {} frames processed", frame_index);
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // Pull sample directly — this is the KEY difference from the callback approach.
        // try_pull_sample returns immediately (with timeout) so we don't block the streaming thread.
        let pull_timeout = if frame_index == 0 {
            // Longer timeout for first frame: camera needs time to start
            gstreamer::ClockTime::from_seconds(10)
        } else {
            gstreamer::ClockTime::from_mseconds(500)
        };

        let sample = match appsink.try_pull_sample(pull_timeout) {
            Some(sample) => {
                consecutive_misses = 0;
                sample
            }
            None => {
                consecutive_misses += 1;
                if consecutive_misses >= 6 {
                    log::warn!("No frames after {} attempts. Stopping.", consecutive_misses);
                    break;
                }
                if frame_index == 0 {
                    log::warn!("Waiting for first frame (attempt {})...", consecutive_misses);
                }
                continue;
            }
        };

        // Extract what we need from the sample, then DROP it immediately
        // to release the CVPixelBuffer back to the avfvideosrc pool.
        let buffer = sample
            .buffer()
            .ok_or_else(|| anyhow::anyhow!("Sample has no buffer"))?;
        let caps = sample
            .caps()
            .ok_or_else(|| anyhow::anyhow!("Sample has no caps"))?;
        let video_info = gstreamer_video::VideoInfo::from_caps(caps)
            .map_err(|_| anyhow::anyhow!("Could not parse video caps"))?;

        // Copy the buffer data so we can release the original immediately
        let mut buffer_copy = buffer.copy();
        let caps_owned = caps.to_owned();

        // CRITICAL: Drop the sample NOW to release the CVPixelBuffer
        drop(sample);

        if frame_index == 0 {
            log::info!("First frame received! {} bytes, {:?} {}x{}", 
                buffer_copy.size(), video_info.format(), video_info.width(), video_info.height());
            appsrc.set_caps(Some(&caps_owned));
        }

        let mut map = buffer_copy
            .make_mut()
            .map_writable()
            .map_err(|_| anyhow::anyhow!("Could not map buffer writable"))?;

        let format = match video_info.format() {
            gstreamer_video::VideoFormat::Rgb => VideoFormat::Rgb8,
            gstreamer_video::VideoFormat::Bgra => VideoFormat::Bgra8,
            other => {
                log::warn!("Unsupported video format {:?}, skipping", other);
                continue;
            }
        };

        // Sign and embed steganography
        let sig = signer.map(|s| s.sign_frame(frame_index, map.as_ref(), None));
        let mut core_frame = VideoFrame {
            width: video_info.width(),
            height: video_info.height(),
            stride: video_info.stride()[0] as u32,
            format,
            data: map.as_mut(),
            frame_index,
        };

        stego
            .embed(&mut core_frame, sig.as_ref())
            .context("Stego embed failed")?;

        drop(map);

        // Push processed frame to output
        match appsrc.push_buffer(buffer_copy) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("Failed to push buffer: {:?}", e);
                break;
            }
        }

        frame_index += 1;
        if frame_index.is_multiple_of(30) {
            log::info!("Processed {} frames", frame_index);
        }
    }

    // Cleanup
    log::info!("Shutting down pipelines...");
    source_bin.set_state(gstreamer::State::Null)?;
    sink_bin.set_state(gstreamer::State::Null)?;
    log::info!("Video filter complete: {} frames processed", frame_index);

    Ok(())
}


/// Extract signatures from a video source pipeline.
///
/// Pulls frames and extracts embedded signature payloads for verification.
pub fn extract_from_source(
    source_pipeline_str: &str,
    stego: &dyn VideoStegoModule,
    max_frames: Option<u64>,
) -> anyhow::Result<Vec<(u64, Option<SignaturePayload>)>> {
    let source_str = format!("{} ! appsink name=sink", source_pipeline_str);
    let source_pipeline = gstreamer::parse::launch(&source_str)?;
    let source_bin = source_pipeline
        .downcast::<gstreamer::Bin>()
        .map_err(|_| anyhow::anyhow!("Not a Bin"))?;
    let appsink = source_bin
        .by_name("sink")
        .ok_or_else(|| anyhow::anyhow!("No appsink"))?
        .downcast::<AppSink>()
        .map_err(|_| anyhow::anyhow!("Not AppSink"))?;

    source_bin.set_state(gstreamer::State::Playing)?;

    let mut results = Vec::new();
    let mut frame_index: u64 = 0;

    loop {
        if let Some(max) = max_frames {
            if frame_index >= max {
                break;
            }
        }

        let sample = match appsink.try_pull_sample(gstreamer::ClockTime::from_seconds(5)) {
            Some(s) => s,
            None => break,
        };

        let buffer = sample.buffer().ok_or_else(|| anyhow::anyhow!("No buffer"))?;
        let map = buffer
            .map_readable()
            .map_err(|_| anyhow::anyhow!("Cannot map"))?;

        let caps = sample.caps().ok_or_else(|| anyhow::anyhow!("No caps"))?;
        let video_info = gstreamer_video::VideoInfo::from_caps(caps)
            .map_err(|_| anyhow::anyhow!("Bad caps"))?;

        let format = match video_info.format() {
            gstreamer_video::VideoFormat::Rgb => VideoFormat::Rgb8,
            gstreamer_video::VideoFormat::Bgra => VideoFormat::Bgra8,
            _ => {
                frame_index += 1;
                continue;
            }
        };

        // We need a non-mutable reference for extraction, so create a temporary
        // copy of the data to work with VideoFrame (which requires &mut for data).
        let mut data_copy = map.as_ref().to_vec();
        let frame = VideoFrame {
            width: video_info.width(),
            height: video_info.height(),
            stride: video_info.stride()[0] as u32,
            format,
            data: &mut data_copy,
            frame_index,
        };

        let payload = stego.extract(&frame)?;
        results.push((frame_index, payload));

        frame_index += 1;
    }

    source_bin.set_state(gstreamer::State::Null)?;
    Ok(results)
}

/// Process a video container file (MP4, MKV, AVI) through steganography.
///
/// Uses `decodebin` to automatically detect the container format and decode
/// to raw RGB frames, processes them through the stego module, then re-encodes
/// with `encodebin` or writes as raw frames.
///
/// # Arguments
/// * `input_path` — Path to input video file (MP4, MKV, AVI, etc.)
/// * `output_path` — Path to output file
/// * `stego` — The steganography module to apply
/// * `signer` — Optional signer for generating frame signatures
/// * `max_frames` — Optional limit on frames to process
pub fn process_video_file(
    input_path: &str,
    output_path: &str,
    stego: Box<dyn VideoStegoModule>,
    signer: Option<&Signer>,
    max_frames: Option<u64>,
) -> anyhow::Result<()> {
    log::info!("Processing video file: {} -> {}", input_path, output_path);

    // Use decodebin for automatic format detection
    let source_str = format!(
        "filesrc location={} ! decodebin ! videoconvert ! video/x-raw,format=RGB ! queue max-size-buffers=10 ! appsink name=sink emit-signals=false sync=false max-buffers=5 drop=true",
        input_path
    );

    // For output, use encodebin or filesink with raw
    let sink_str = format!(
        "appsrc name=src format=time is-live=true ! queue max-size-buffers=10 ! videoconvert ! x264enc ! mp4mux ! filesink location={}",
        output_path
    );

    let config = VideoFilterConfig {
        source_pipeline: source_str,
        sink_pipeline: sink_str,
    };

    // Reuse the existing filter pipeline
    run_video_filter(&config, stego, signer, max_frames)?;

    log::info!("Video file processing complete");
    Ok(())
}

/// Process an audio container file (WAV, MP3, FLAC) through steganography.
///
/// Uses `decodebin` for automatic format detection and decodes to
/// raw S16LE PCM samples.
pub fn process_audio_file(
    input_path: &str,
    output_path: &str,
    stego: &mut dyn steganographer_core::audio::AudioStegoModule,
    signer: Option<&Signer>,
    max_buffers: Option<u64>,
) -> anyhow::Result<()> {
    log::info!("Processing audio file: {} -> {}", input_path, output_path);

    let source_str = format!(
        "filesrc location={} ! decodebin ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100 ! queue ! appsink name=sink",
        input_path
    );
    let sink_str = format!(
        "appsrc name=src ! queue ! audioconvert ! wavenc ! filesink location={}",
        output_path
    );

    let config = crate::audio_filter::AudioFilterConfig {
        source_pipeline: source_str,
        sink_pipeline: sink_str,
    };

    crate::audio_filter::run_audio_filter(&config, stego, signer, max_buffers)?;

    log::info!("Audio file processing complete");
    Ok(())
}
