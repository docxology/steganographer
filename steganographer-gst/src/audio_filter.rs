//! Bounded AppSink/AppSrc processing of interleaved S16LE PCM.

use crate::{BridgeOutput, BridgeSource, SigningKernel};
use anyhow::Context;
use steganographer_core::audio::{AudioBuffer, AudioStegoModule};
use steganographer_core::crypto::{SignaturePayload, Signer, Verifier};

/// Endpoint-free launch fragments and the actual embedding kernel's binding.
pub struct AudioFilterConfig {
    pub source_pipeline: String,
    /// Caller-owned output chain. Later verification needs exact PCM and the
    /// original buffer boundaries/index; resampling or lossy encoding breaks it.
    pub sink_pipeline: String,
    /// Required when signing; audio currently supports canonical LSB only.
    pub signing_kernel: Option<SigningKernel>,
}

/// Process complete S16LE interleaved frames and drain output before returning.
/// The post-embed check authenticates PCM before AppSrc, not arbitrary sink
/// processing. Audio supports canonical LSB signatures, not DCT/spread signing.
pub fn run_audio_filter(
    config: &AudioFilterConfig,
    stego: &mut dyn AudioStegoModule,
    signer: Option<&Signer>,
    max_buffers: Option<u64>,
) -> anyhow::Result<()> {
    if let Some(signer) = signer {
        steganographer_core::revocation::check_known_revocations(
            signer.verifying_key().as_bytes(),
        )?;
        let kernel = config
            .signing_kernel
            .context("audio signing requires signing_kernel")?;
        // Validate unsupported kernels and bit depths before opening pipelines.
        kernel.audio_binding(&[])?;
    }
    let source = BridgeSource::new(&config.source_pipeline)?;
    let output = BridgeOutput::new(&config.sink_pipeline)?;
    output.start()?;
    source.start()?;
    let mut index = 0;
    while max_buffers.is_none_or(|max| index < max) {
        let Some(sample) = source.pull(Some(&output))? else {
            break;
        };
        let caps = sample.caps().context("audio sample has no caps")?;
        let info = gstreamer_audio::AudioInfo::from_caps(caps).context("invalid audio caps")?;
        let mut buffer = sample
            .buffer()
            .context("audio sample has no buffer")?
            .copy();
        process_pcm(
            &mut buffer,
            &info,
            stego,
            signer,
            config.signing_kernel,
            index,
        )?;
        output.push(&source, &sample, &buffer)?;
        index += 1;
    }
    output.finish(&source)
}

/// Collect at most 64 MiB of selected S16LE PCM into one logical audio frame,
/// sign/embed once at index zero, then drain output to EOS.
///
/// Caps must stay consistent. The caller's sink must preserve exact PCM;
/// `.wav` output retains whole-selection recovery independently of input chunks.
pub fn run_audio_file(
    config: &AudioFilterConfig,
    stego: &mut dyn AudioStegoModule,
    signer: Option<&Signer>,
    max_buffers: Option<u64>,
) -> anyhow::Result<()> {
    if let Some(signer) = signer {
        steganographer_core::revocation::check_known_revocations(
            signer.verifying_key().as_bytes(),
        )?;
        config
            .signing_kernel
            .context("audio signing requires signing_kernel")?
            .audio_binding(&[])?;
    }
    let source = BridgeSource::new(&config.source_pipeline)?;
    source.start()?;
    let (info, caps, pcm) = collect_file_pcm(&source, max_buffers, 64 * 1024 * 1024)?;
    let duration_ns = (pcm.len() as u64 / u64::from(info.bpf()))
        .checked_mul(1_000_000_000)
        .context("audio file duration overflow")?
        / u64::from(info.rate());
    let mut buffer = gstreamer::Buffer::from_mut_slice(pcm);
    buffer
        .get_mut()
        .context("audio file buffer is not writable")?
        .set_pts(gstreamer::ClockTime::ZERO);
    buffer
        .get_mut()
        .context("audio file buffer is not writable")?
        .set_duration(gstreamer::ClockTime::from_nseconds(duration_ns));
    process_pcm(&mut buffer, &info, stego, signer, config.signing_kernel, 0)?;
    let segment = gstreamer::FormattedSegment::<gstreamer::ClockTime>::new();
    let sample = gstreamer::Sample::builder()
        .buffer(&buffer)
        .caps(&caps)
        .segment(&segment)
        .build();
    let output = BridgeOutput::new(&config.sink_pipeline)?;
    output.start()?;
    output.push(&source, &sample, &buffer)?;
    output.finish(&source)
}

fn collect_file_pcm(
    source: &BridgeSource,
    max_buffers: Option<u64>,
    max_bytes: usize,
) -> anyhow::Result<(gstreamer_audio::AudioInfo, gstreamer::Caps, Vec<u8>)> {
    let mut first: Option<(gstreamer_audio::AudioInfo, gstreamer::Caps)> = None;
    let mut pcm = Vec::new();
    let mut index = 0;
    while max_buffers.is_none_or(|max| index < max) {
        let Some(sample) = source.pull(None)? else {
            break;
        };
        let caps = sample.caps().context("audio sample has no caps")?;
        let info = gstreamer_audio::AudioInfo::from_caps(caps).context("invalid audio caps")?;
        let buffer = sample.buffer().context("audio sample has no buffer")?;
        validate_pcm(&info, buffer.size())?;
        if let Some((_, initial_caps)) = &first {
            anyhow::ensure!(
                initial_caps == caps,
                "audio file changes PCM format/rate/channels midstream"
            );
        } else {
            first = Some((info, caps.to_owned()));
        }
        let total = pcm
            .len()
            .checked_add(buffer.size())
            .context("audio file PCM length overflow")?;
        anyhow::ensure!(
            total <= max_bytes,
            "decoded audio file exceeds PCM byte limit ({max_bytes} bytes)"
        );
        let map = buffer.map_readable().context("mapping audio file PCM")?;
        pcm.try_reserve(map.len())
            .context("allocating bounded audio file PCM")?;
        pcm.extend_from_slice(map.as_ref());
        index += 1;
    }
    anyhow::ensure!(
        !pcm.is_empty(),
        "audio file contains no selected PCM samples"
    );
    let (info, caps) = first.context("audio file contains no PCM caps")?;
    Ok((info, caps, pcm))
}

fn process_pcm(
    buffer: &mut gstreamer::Buffer,
    info: &gstreamer_audio::AudioInfo,
    stego: &mut dyn AudioStegoModule,
    signer: Option<&Signer>,
    signing_kernel: Option<SigningKernel>,
    index: u64,
) -> anyhow::Result<()> {
    validate_pcm(info, buffer.size())?;
    let mut map = buffer
        .make_mut()
        .map_writable()
        .context("mapping audio buffer")?;
    let signature = if let Some(signer) = signer {
        let binding = signing_kernel
            .context("missing signing kernel")?
            .audio_binding(map.as_ref())?;
        Some(signer.sign_frame(index, &binding, None))
    } else {
        None
    };
    let mut samples = decode_pcm(map.as_ref());
    let mut audio = AudioBuffer {
        channels: info.channels() as u16,
        sample_rate: info.rate(),
        samples: &mut samples,
        frame_index: index,
    };
    stego
        .embed(&mut audio, signature.as_ref())
        .context("audio stego embed failed")?;
    let extracted = if signer.is_some() {
        Some(
            stego
                .extract(&audio)
                .context("extracting actual signed audio output")?
                .context("module did not embed an extractable audio signature")?,
        )
    } else {
        None
    };
    for (chunk, value) in map.as_mut().as_chunks_mut::<2>().0.iter_mut().zip(&samples) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    if let (Some(signer), Some(extracted)) = (signer, extracted) {
        let binding = signing_kernel
            .context("missing signing kernel")?
            .audio_binding(map.as_ref())?;
        let verifier =
            Verifier::with_hash_algorithm(signer.verifying_key(), signer.hash_algorithm());
        anyhow::ensure!(
            extracted.frame_index == index && verifier.verify(&extracted, &binding, None),
            "audio module output is incompatible with its signing binding"
        );
    }
    Ok(())
}

/// Extract only from complete S16LE interleaved PCM frames. Source errors and
/// stalled streams return errors, never successful partial results.
pub fn extract_from_source(
    source_pipeline_str: &str,
    stego: &dyn AudioStegoModule,
    max_buffers: Option<u64>,
) -> anyhow::Result<Vec<(u64, Option<SignaturePayload>)>> {
    let source = BridgeSource::new(source_pipeline_str)?;
    source.start()?;
    let mut results = Vec::new();
    let mut index = 0;
    while max_buffers.is_none_or(|max| index < max) {
        let Some(sample) = source.pull(None)? else {
            break;
        };
        let caps = sample.caps().context("audio sample has no caps")?;
        let info = gstreamer_audio::AudioInfo::from_caps(caps).context("invalid audio caps")?;
        let buffer = sample.buffer().context("audio sample has no buffer")?;
        validate_pcm(&info, buffer.size())?;
        let map = buffer.map_readable().context("mapping audio buffer")?;
        let mut samples = decode_pcm(map.as_ref());
        let audio = AudioBuffer {
            channels: info.channels() as u16,
            sample_rate: info.rate(),
            samples: &mut samples,
            frame_index: index,
        };
        results.push((index, stego.extract(&audio)?));
        index += 1;
    }
    Ok(results)
}

fn validate_pcm(info: &gstreamer_audio::AudioInfo, bytes: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        info.format() == gstreamer_audio::AudioFormat::S16le
            && info.layout() == gstreamer_audio::AudioLayout::Interleaved,
        "audio bridge requires interleaved S16LE; got {:?} {:?}",
        info.format(),
        info.layout()
    );
    anyhow::ensure!(
        info.rate() > 0 && info.channels() > 0 && info.channels() <= u16::MAX as u32,
        "audio rate/channels exceed the supported PCM contract"
    );
    let frame_bytes = (info.channels() as usize)
        .checked_mul(2)
        .context("PCM frame size overflow")?;
    anyhow::ensure!(
        bytes.is_multiple_of(frame_bytes),
        "audio buffer contains an incomplete S16LE interleaved frame"
    );
    Ok(())
}

fn decode_pcm(bytes: &[u8]) -> Vec<i16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use gstreamer::prelude::*;

    #[test]
    fn whole_file_collection_rejects_pcm_budget_overflow_without_truncation() {
        gstreamer::init().unwrap();
        let source = BridgeSource::new(
            "fakesrc num-buffers=2 sizetype=fixed sizemax=64 ! audio/x-raw,format=S16LE,layout=interleaved,channels=1,rate=8000"
        ).unwrap();
        source.start().unwrap();
        let error = collect_file_pcm(&source, None, 100).unwrap_err();
        assert!(error.to_string().contains("PCM byte limit"));
    }

    #[test]
    fn whole_file_collection_rejects_renegotiated_rate_or_channels() {
        gstreamer::init().unwrap();
        let source = BridgeSource::new("appsrc name=input format=time").unwrap();
        let input = source
            .bin
            .by_name("input")
            .unwrap()
            .downcast::<gstreamer_app::AppSrc>()
            .unwrap();
        source.start().unwrap();
        for (rate, channels) in [(8000, 1), (16000, 2)] {
            let caps = gstreamer_audio::AudioInfo::builder(
                gstreamer_audio::AudioFormat::S16le,
                rate,
                channels,
            )
            .build()
            .unwrap()
            .to_caps()
            .unwrap();
            let buffer = gstreamer::Buffer::from_mut_slice(vec![0xff; 4096]);
            input
                .push_sample(
                    &gstreamer::Sample::builder()
                        .buffer(&buffer)
                        .caps(&caps)
                        .build(),
                )
                .unwrap();
        }
        input.end_of_stream().unwrap();
        let error = collect_file_pcm(&source, None, 8192).unwrap_err();
        assert!(error.to_string().contains("changes PCM"));
    }
}
