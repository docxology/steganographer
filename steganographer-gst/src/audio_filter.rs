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
    let source_pipeline = gstreamer::parse::launch(&source_str)
        .context("Failed to create source pipeline")?;
    let source_bin = source_pipeline
        .downcast::<gstreamer::Bin>()
        .map_err(|_| anyhow::anyhow!("Source pipeline is not a Bin"))?;
    let appsink = source_bin
        .by_name("sink")
        .ok_or_else(|| anyhow::anyhow!("No appsink in source pipeline"))?
        .downcast::<AppSink>()
        .map_err(|_| anyhow::anyhow!("Not AppSink"))?;

    let sink_str = format!("appsrc name=src ! {}", config.sink_pipeline);
    let sink_pipeline = gstreamer::parse::launch(&sink_str)
        .context("Failed to create sink pipeline")?;
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
    loop {
        if let Some(max) = max_buffers {
            if buffer_index >= max {
                log::info!("Reached max buffer count: {}", max);
                break;
            }
        }

        let sample = match appsink.pull_sample() {
            Ok(s) => s,
            Err(_) => {
                log::info!("AppSink EOS after {} buffers", buffer_index);
                break;
            }
        };

        let buffer = sample
            .buffer()
            .ok_or_else(|| anyhow::anyhow!("Sample has no buffer"))?;

        let mut buffer = buffer.copy();
        let mut map = buffer
            .make_mut()
            .map_writable()
            .map_err(|_| anyhow::anyhow!("Cannot map buffer writable"))?;

        let caps = sample.caps().ok_or_else(|| anyhow::anyhow!("No caps"))?;
        let audio_info = gstreamer_audio::AudioInfo::from_caps(caps)
            .map_err(|_| anyhow::anyhow!("Cannot parse audio caps"))?;

        // Convert raw bytes to i16 samples
        let sample_bytes = map.as_mut();
        let samples: &mut [i16] = unsafe {
            std::slice::from_raw_parts_mut(
                sample_bytes.as_mut_ptr() as *mut i16,
                sample_bytes.len() / 2,
            )
        };

        let sig = signer.map(|s| {
            let raw: &[u8] = unsafe {
                std::slice::from_raw_parts(samples.as_ptr() as *const u8, samples.len() * 2)
            };
            s.sign_frame(buffer_index, raw, None)
        });

        let mut audio_buf = AudioBuffer {
            channels: audio_info.channels() as u16,
            sample_rate: audio_info.rate(),
            samples,
            frame_index: buffer_index,
        };

        stego
            .embed(&mut audio_buf, sig.as_ref())
            .context("Audio stego embed failed")?;

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

        let buffer = sample.buffer().ok_or_else(|| anyhow::anyhow!("No buffer"))?;
        let map = buffer
            .map_readable()
            .map_err(|_| anyhow::anyhow!("Cannot map"))?;

        let caps = sample.caps().ok_or_else(|| anyhow::anyhow!("No caps"))?;
        let audio_info = gstreamer_audio::AudioInfo::from_caps(caps)
            .map_err(|_| anyhow::anyhow!("Bad caps"))?;

        let sample_bytes = map.as_ref();
        let mut samples_copy: Vec<i16> = sample_bytes
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

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
