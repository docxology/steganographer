//! Audio filter using GStreamer AppSink/AppSrc pattern.
//!
//! Pulls audio buffers from an AppSink, processes them through an
//! [`AudioStegoModule`], and pushes the modified buffers via AppSrc.

use anyhow::Context;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};
use steganographer_core::audio::{AudioBuffer, AudioStegoModule};
use steganographer_core::crypto::{SignaturePayload, Signer};

/// Configuration for the audio filter pipeline.
pub struct AudioFilterConfig {
    /// GStreamer source pipeline string
    pub source_pipeline: String,
    /// GStreamer sink pipeline string
    pub sink_pipeline: String,
}

/// Run an audio filter pipeline using AppSink/AppSrc.
///
/// Pulls audio buffers, applies the steganography module, and pushes
/// modified buffers to the output.
pub fn run_audio_filter(
    config: &AudioFilterConfig,
    stego: &mut dyn AudioStegoModule,
    signer: Option<&Signer>,
    max_buffers: Option<u64>,
) -> anyhow::Result<()> {
    log::info!("Starting audio filter pipeline");
    log::info!("  Source: {}", config.source_pipeline);
    log::info!("  Sink:   {}", config.sink_pipeline);

    let source_str = format!("{} ! appsink name=sink", config.source_pipeline);
    let source_pipeline =
        gstreamer::parse::launch(&source_str).context("Failed to create source pipeline")?;
    let source_bin = source_pipeline
        .downcast::<gstreamer::Bin>()
        .map_err(|_| anyhow::anyhow!("Source pipeline is not a Bin"))?;
    let appsink = source_bin
        .by_name("sink")
        .ok_or_else(|| anyhow::anyhow!("No appsink in source pipeline"))?
        .downcast::<AppSink>()
        .map_err(|_| anyhow::anyhow!("Not AppSink"))?;

    let sink_str = format!("appsrc name=src ! {}", config.sink_pipeline);
    let sink_pipeline =
        gstreamer::parse::launch(&sink_str).context("Failed to create sink pipeline")?;
    let sink_bin = sink_pipeline
        .downcast::<gstreamer::Bin>()
        .map_err(|_| anyhow::anyhow!("Sink pipeline is not a Bin"))?;
    let appsrc = sink_bin
        .by_name("src")
        .ok_or_else(|| anyhow::anyhow!("No appsrc in sink pipeline"))?
        .downcast::<AppSrc>()
        .map_err(|_| anyhow::anyhow!("Not AppSrc"))?;

    source_bin.set_state(gstreamer::State::Playing)?;
    sink_bin.set_state(gstreamer::State::Playing)?;

    log::info!("Audio pipelines started, processing buffers...");

    let mut buffer_index: u64 = 0;
    let mut consecutive_misses: u32 = 0;

    loop {
        if let Some(max) = max_buffers {
            if buffer_index >= max {
                log::info!("Reached max buffer count: {}", max);
                break;
            }
        }

        // Check source bus for errors/EOS (mirrors run_video_filter_internal:
        // a blocking pull_sample would deadlock on a pipeline error since
        // there is no bus watch).
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
                        log::info!(
                            "Audio filter pipeline complete: {} buffers processed",
                            buffer_index
                        );
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        let pull_timeout = if buffer_index == 0 {
            // Longer timeout for the first buffer: the source needs time to
            // start.
            gstreamer::ClockTime::from_seconds(10)
        } else {
            gstreamer::ClockTime::from_mseconds(500)
        };

        let sample = match appsink.try_pull_sample(pull_timeout) {
            Some(s) => {
                consecutive_misses = 0;
                s
            }
            None => {
                consecutive_misses += 1;
                if consecutive_misses >= 6 {
                    log::warn!(
                        "No buffers after {} attempts. Stopping.",
                        consecutive_misses
                    );
                    break;
                }
                if buffer_index == 0 {
                    log::warn!(
                        "Waiting for first buffer (attempt {})...",
                        consecutive_misses
                    );
                }
                continue;
            }
        };

        let buffer = sample
            .buffer()
            .ok_or_else(|| anyhow::anyhow!("Sample has no buffer"))?;

        let caps = sample.caps().ok_or_else(|| anyhow::anyhow!("No caps"))?;
        let audio_info = gstreamer_audio::AudioInfo::from_caps(caps)
            .map_err(|_| anyhow::anyhow!("Cannot parse audio caps"))?;
        // Only interleaved S16LE is addressed as little-endian 16-bit
        // samples; anything else would silently corrupt the PCM stream.
        if audio_info.format() != gstreamer_audio::AudioFormat::S16le
            || audio_info.layout() != gstreamer_audio::AudioLayout::Interleaved
        {
            source_bin.set_state(gstreamer::State::Null).ok();
            sink_bin.set_state(gstreamer::State::Null).ok();
            anyhow::bail!(
                "audio filter requires interleaved S16LE input; got format {:?} layout {:?}",
                audio_info.format(),
                audio_info.layout()
            );
        }

        let mut buffer = buffer.copy();
        let caps_owned = caps.to_owned();

        // CRITICAL: Drop the sample NOW (mirrors the video path) so source
        // resources are released before processing.
        drop(sample);

        if buffer_index == 0 {
            log::info!(
                "First audio buffer: {} bytes, {:?} {} ch @ {} Hz",
                buffer.size(),
                audio_info.format(),
                audio_info.channels(),
                audio_info.rate()
            );
            appsrc.set_caps(Some(&caps_owned));
        }

        let mut map = buffer
            .make_mut()
            .map_writable()
            .map_err(|_| anyhow::anyhow!("Cannot map buffer writable"))?;

        let sig = signer.map(|s| s.sign_frame(buffer_index, map.as_ref(), None));

        // Safe little-endian reinterpretation via as_chunks (no unsafe
        // pointer cast); a trailing byte, impossible for S16LE caps, would
        // surface as `_remainder` and is left untouched.
        let (chunks, _remainder) = map.as_mut().as_chunks_mut::<2>();
        let mut samples: Vec<i16> = chunks.iter().map(|c| i16::from_le_bytes(*c)).collect();

        let mut audio_buf = AudioBuffer {
            channels: audio_info.channels() as u16,
            sample_rate: audio_info.rate(),
            samples: &mut samples,
            frame_index: buffer_index,
        };

        stego
            .embed(&mut audio_buf, sig.as_ref())
            .context("Audio stego embed failed")?;

        for (chunk, sample16) in chunks.iter_mut().zip(&samples) {
            chunk.copy_from_slice(&sample16.to_le_bytes());
        }

        drop(map);

        appsrc
            .push_buffer(buffer)
            .map_err(|_| anyhow::anyhow!("Failed to push to AppSrc"))?;

        buffer_index += 1;
        if buffer_index.is_multiple_of(1000) {
            log::info!("Processed {} audio buffers", buffer_index);
        }
    }

    source_bin.set_state(gstreamer::State::Null)?;
    sink_bin.set_state(gstreamer::State::Null)?;
    log::info!("Audio filter pipeline complete: {} buffers", buffer_index);

    Ok(())
}

/// Extract signatures from an audio source pipeline.
pub fn extract_from_source(
    source_pipeline_str: &str,
    stego: &dyn AudioStegoModule,
    max_buffers: Option<u64>,
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
    let mut buffer_index: u64 = 0;

    loop {
        if let Some(max) = max_buffers {
            if buffer_index >= max {
                break;
            }
        }

        let sample = match appsink.pull_sample() {
            Ok(s) => s,
            Err(_) => break,
        };

        let buffer = sample
            .buffer()
            .ok_or_else(|| anyhow::anyhow!("No buffer"))?;
        let map = buffer
            .map_readable()
            .map_err(|_| anyhow::anyhow!("Cannot map"))?;

        let caps = sample.caps().ok_or_else(|| anyhow::anyhow!("No caps"))?;
        let audio_info =
            gstreamer_audio::AudioInfo::from_caps(caps).map_err(|_| anyhow::anyhow!("Bad caps"))?;

        let sample_bytes = map.as_ref();
        let (pcm_chunks, _remainder) = sample_bytes.as_chunks::<2>();
        let mut samples_copy: Vec<i16> =
            pcm_chunks.iter().map(|c| i16::from_le_bytes(*c)).collect();

        let buf = AudioBuffer {
            channels: audio_info.channels() as u16,
            sample_rate: audio_info.rate(),
            samples: &mut samples_copy,
            frame_index: buffer_index,
        };

        let payload = stego.extract(&buf)?;
        results.push((buffer_index, payload));
        buffer_index += 1;
    }

    source_bin.set_state(gstreamer::State::Null)?;
    Ok(results)
}
