//! # steganographer-gst
//!
//! GStreamer integration for the steganographer toolkit.
//!
//! Provides:
//! - `pipeline` — AppSink/AppSrc helper utilities for building GStreamer pipelines
//! - [`video_filter`] — Video buffer processing with `VideoStegoModule`
//! - [`audio_filter`] — Audio buffer processing with `AudioStegoModule`
//! - [`plugin`] — GStreamer plugin registration (loadable `steganographer_gst` cdylib)
//! - [`elements`] — native `BaseTransform` elements (`stegovideo`, `stegoaudio`)
//!
//! ## Usage Pattern
//!
//! The primary approach uses `AppSink` to pull frames from a GStreamer source,
//! process them through `steganographer-core` modules, and push the modified
//! frames via `AppSrc` to a GStreamer sink. This avoids needing to compile and
//! install a GStreamer plugin.

pub mod audio_element;
pub mod audio_filter;
pub mod elements;
pub mod plugin;
pub mod video_filter;

/// Canonical carrier binding used when signing legacy bridge output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKernel {
    Lsb { bits: u8 },
    Dct,
    SpreadSpectrum,
}

impl SigningKernel {
    pub(crate) fn video_binding(
        self,
        data: &[u8],
        width: u32,
        height: u32,
    ) -> anyhow::Result<Vec<u8>> {
        let (name, bits) = match self {
            Self::Lsb { bits } => ("lsb_video", bits),
            Self::Dct => ("dct_video", 1),
            Self::SpreadSpectrum => anyhow::bail!(
                "spread-spectrum video signing has no supported canonical trait binding"
            ),
        };
        steganographer_core::carrier_binding::canonicalize(
            data,
            name,
            bits,
            width,
            height,
            steganographer_core::crypto::SignaturePayload::SERIALIZED_SIZE,
        )
    }

    pub(crate) fn audio_binding(self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Self::Lsb { bits } = self else {
            anyhow::bail!("audio signing requires an LSB signing kernel");
        };
        steganographer_core::carrier_binding::canonicalize(data, "lsb_audio", bits, 0, 0, 0)
    }
}

use anyhow::Context;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};
use std::time::{Duration, Instant};

const BRIDGE_TIMEOUT: Duration = Duration::from_secs(15);
const PULL_INTERVAL: gstreamer::ClockTime = gstreamer::ClockTime::from_mseconds(100);

/// Owns shutdown even if parsing, startup, processing, or draining fails.
pub(crate) struct BridgeSource {
    pub(crate) bin: gstreamer::Bin,
    appsink: AppSink,
}

impl BridgeSource {
    pub(crate) fn new(fragment: &str) -> anyhow::Result<Self> {
        let bin = gstreamer::parse::launch(&format!(
            "{fragment} ! appsink name=bridge_sink sync=false emit-signals=false max-buffers=8 drop=false"
        ))?.downcast::<gstreamer::Bin>()
            .map_err(|_| anyhow::anyhow!("source pipeline is not a Bin"))?;
        let appsink = bin
            .by_name("bridge_sink")
            .context("missing bridge appsink")?
            .downcast::<AppSink>()
            .map_err(|_| anyhow::anyhow!("bridge endpoint is not an AppSink"))?;
        Ok(Self { bin, appsink })
    }

    pub(crate) fn start(&self) -> anyhow::Result<()> {
        self.bin
            .set_state(gstreamer::State::Playing)
            .context("starting source pipeline")?;
        Ok(())
    }

    pub(crate) fn pull(
        &self,
        output: Option<&BridgeOutput>,
    ) -> anyhow::Result<Option<gstreamer::Sample>> {
        let deadline = Instant::now() + BRIDGE_TIMEOUT;
        loop {
            // Source EOS does not mean its appsink queue has been consumed.
            poll_bus(&self.bin, "source")?;
            if let Some(output) = output {
                anyhow::ensure!(
                    !poll_bus(&output.bin, "sink")?,
                    "sink ended before input was drained"
                );
            }
            if let Some(sample) = self.appsink.try_pull_sample(PULL_INTERVAL) {
                return Ok(Some(sample));
            }
            poll_bus(&self.bin, "source")?;
            if let Some(output) = output {
                anyhow::ensure!(
                    !poll_bus(&output.bin, "sink")?,
                    "sink ended before input was drained"
                );
            }
            if self.appsink.is_eos() {
                return Ok(None);
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "source timed out waiting for a sample or EOS"
            );
        }
    }
}

impl Drop for BridgeSource {
    fn drop(&mut self) {
        let _ = self.bin.set_state(gstreamer::State::Null);
    }
}

pub(crate) struct BridgeOutput {
    pub(crate) bin: gstreamer::Bin,
    appsrc: AppSrc,
}

impl BridgeOutput {
    pub(crate) fn new(fragment: &str) -> anyhow::Result<Self> {
        let bin = gstreamer::parse::launch(&format!(
            "appsrc name=bridge_src format=time is-live=false block=false max-buffers=8 handle-segment-change=true ! {fragment}"
        ))?.downcast::<gstreamer::Bin>()
            .map_err(|_| anyhow::anyhow!("sink pipeline is not a Bin"))?;
        let appsrc = bin
            .by_name("bridge_src")
            .context("missing bridge appsrc")?
            .downcast::<AppSrc>()
            .map_err(|_| anyhow::anyhow!("bridge endpoint is not an AppSrc"))?;
        Ok(Self { bin, appsrc })
    }

    pub(crate) fn start(&self) -> anyhow::Result<()> {
        self.bin
            .set_state(gstreamer::State::Playing)
            .context("starting sink pipeline")?;
        Ok(())
    }

    pub(crate) fn push(
        &self,
        source: &BridgeSource,
        sample: &gstreamer::Sample,
        buffer: &gstreamer::Buffer,
    ) -> anyhow::Result<()> {
        let deadline = Instant::now() + BRIDGE_TIMEOUT;
        loop {
            poll_bus(&source.bin, "source")?;
            anyhow::ensure!(
                !poll_bus(&self.bin, "sink")?,
                "sink ended before input was drained"
            );
            if self.appsrc.current_level_buffers() < 8 {
                break;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "sink timed out accepting a buffer"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // push_sample updates caps on renegotiation and forwards the matching
        // TIME segment, while the copied buffer preserves its timestamps.
        let caps = sample.caps().map(ToOwned::to_owned);
        let output = gstreamer::Sample::builder()
            .buffer(buffer)
            .caps_if_some(caps.as_ref())
            .segment_if_some(sample.segment())
            .build();
        if let Err(error) = self.appsrc.push_sample(&output) {
            poll_bus(&source.bin, "source")?;
            poll_bus(&self.bin, "sink")?;
            return Err(error).context("pushing processed buffer");
        }
        Ok(())
    }

    pub(crate) fn finish(&self, source: &BridgeSource) -> anyhow::Result<()> {
        if let Err(error) = self.appsrc.end_of_stream() {
            poll_bus(&source.bin, "source")?;
            poll_bus(&self.bin, "sink")?;
            return Err(error).context("signalling output EOS");
        }
        let deadline = Instant::now() + BRIDGE_TIMEOUT;
        loop {
            poll_bus(&source.bin, "source")?;
            if poll_bus(&self.bin, "sink")? {
                return Ok(());
            }
            anyhow::ensure!(Instant::now() < deadline, "sink timed out draining to EOS");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for BridgeOutput {
    fn drop(&mut self) {
        let _ = self.bin.set_state(gstreamer::State::Null);
    }
}

fn poll_bus(bin: &gstreamer::Bin, role: &str) -> anyhow::Result<bool> {
    let bus = bin
        .bus()
        .with_context(|| format!("{role} pipeline has no bus"))?;
    let mut eos = false;
    while let Some(message) = bus.timed_pop(gstreamer::ClockTime::ZERO) {
        match message.view() {
            gstreamer::MessageView::Error(error) => anyhow::bail!(
                "{role} pipeline error from {}: {} (debug: {:?})",
                error
                    .src()
                    .map(|s| s.path_string().to_string())
                    .unwrap_or_default(),
                error.error(),
                error.debug()
            ),
            gstreamer::MessageView::Eos(_) => eos = true,
            _ => {}
        }
    }
    Ok(eos)
}

/// Quote a literal launch-property value, never a pipeline fragment.
/// Files, device identifiers and URIs share these escaping rules.
pub fn quote_location(value: &str) -> anyhow::Result<String> {
    anyhow::ensure!(!value.contains('\0'), "pipeline property contains NUL");
    let escapes = value
        .bytes()
        .filter(|byte| matches!(byte, b'\\' | b'"'))
        .count();
    let capacity = value
        .len()
        .checked_add(escapes)
        .and_then(|len| len.checked_add(2))
        .context("quoted property length overflow")?;
    let mut quoted = String::with_capacity(capacity);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    Ok(quoted)
}

/// GStreamer plugin entry point.
///
/// Invoked by the GStreamer loader when the crate is built as a `cdylib` and
/// discovered via `GST_PLUGIN_PATH`, and available for direct application-side
/// registration via [`plugin_desc::plugin_register_static`]. Registers the
/// native `stegovideo` and `stegoaudio` elements.
fn plugin_init(plugin: &gstreamer::Plugin) -> Result<(), gstreamer::glib::BoolError> {
    crate::elements::register(Some(plugin))
}

// The plugin name MUST match the cdylib file stem ("steganographer_gst" for
// libsteganographer_gst.dylib): GStreamer's loader derives the entry-point
// symbol `gst_plugin_<file-stem>_get_desc` from the file name.
gstreamer::plugin_define!(
    steganographer_gst,
    env!("CARGO_PKG_DESCRIPTION"),
    plugin_init,
    env!("CARGO_PKG_VERSION"),
    "MIT/X11",
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_REPOSITORY")
);

/// Initialize GStreamer. Must be called before any pipeline operations.
///
/// This does not create NSApplication or enter a platform event loop, so
/// headless callers may initialize and process media on worker threads.
/// Applications using macOS camera or GUI elements must own the Cocoa main
/// loop at process entry, for example with `gstreamer::macos_main`, before
/// starting their pipeline work or an asynchronous runtime.
pub fn init() -> anyhow::Result<()> {
    gstreamer::init()?;
    log::info!(
        "GStreamer initialized: version {}",
        gstreamer::version_string()
    );
    Ok(())
}

/// Build a simple GStreamer pipeline from a launch string.
///
/// # Example
/// ```no_run
/// # steganographer_gst::init().unwrap();
/// let pipeline = steganographer_gst::launch("videotestsrc ! autovideosink").unwrap();
/// ```
pub fn launch(pipeline_str: &str) -> anyhow::Result<gstreamer::Element> {
    let pipeline = gstreamer::parse::launch(pipeline_str)?;
    log::info!("Pipeline created: {}", pipeline_str);
    Ok(pipeline)
}

#[cfg(test)]
mod bridge_tests {
    use super::*;

    #[test]
    fn caps_and_segments_follow_each_renegotiated_sample() {
        gstreamer::init().unwrap();
        for audio in [false, true] {
            // This fixture is itself an AppSrc bridge: without segment-change
            // handling it discards the supplied segments before we can forward
            // them, independently of the output bridge's configuration.
            let source =
                BridgeSource::new("appsrc name=input format=time handle-segment-change=true")
                    .unwrap();
            let output =
                BridgeOutput::new("appsink name=reader sync=false wait-on-eos=false").unwrap();
            let input = source
                .bin
                .by_name("input")
                .unwrap()
                .downcast::<AppSrc>()
                .unwrap();
            let reader = output
                .bin
                .by_name("reader")
                .unwrap()
                .downcast::<AppSink>()
                .unwrap();
            output.start().unwrap();
            source.start().unwrap();
            // Change caps once, then change only the segment. Both must reach
            // the consumer in order, not just the first segment after startup.
            for index in 0..3 {
                let (caps, size) = if audio {
                    let info = gstreamer_audio::AudioInfo::builder(
                        gstreamer_audio::AudioFormat::S16le,
                        if index == 0 { 8000 } else { 16000 },
                        if index == 0 { 1 } else { 2 },
                    )
                    .build()
                    .unwrap();
                    (info.to_caps().unwrap(), 2048 * info.bpf() as usize)
                } else {
                    let info = gstreamer_video::VideoInfo::builder(
                        gstreamer_video::VideoFormat::Rgb,
                        if index == 0 { 62 } else { 64 },
                        8,
                    )
                    .build()
                    .unwrap();
                    (info.to_caps().unwrap(), info.size())
                };
                let mut segment = gstreamer::FormattedSegment::<gstreamer::ClockTime>::new();
                segment.set_start(gstreamer::ClockTime::from_seconds(index));
                segment.set_time(gstreamer::ClockTime::from_seconds(index));
                let mut buffer = gstreamer::Buffer::from_mut_slice(vec![0xff; size]);
                buffer
                    .get_mut()
                    .unwrap()
                    .set_pts(gstreamer::ClockTime::from_seconds(index));
                let sample = gstreamer::Sample::builder()
                    .buffer(&buffer)
                    .caps(&caps)
                    .segment(&segment)
                    .build();
                input.push_sample(&sample).unwrap();
                let pulled = source.pull(Some(&output)).unwrap().unwrap();
                assert_eq!(pulled.segment().unwrap(), segment.upcast_ref());
                output.push(&source, &pulled, &buffer).unwrap();
                let delivered = reader
                    .try_pull_sample(gstreamer::ClockTime::from_seconds(3))
                    .unwrap();
                assert_eq!(delivered.caps().unwrap(), &caps);
                assert_eq!(delivered.buffer().unwrap().size(), size);
                assert_eq!(
                    delivered.buffer().unwrap().pts(),
                    Some(gstreamer::ClockTime::from_seconds(index))
                );
                assert_eq!(delivered.segment().unwrap(), segment.upcast_ref());
            }
            input.end_of_stream().unwrap();
            assert!(source.pull(Some(&output)).unwrap().is_none());
            output.finish(&source).unwrap();
        }
    }

    #[test]
    fn guards_stop_both_pipelines_after_real_downstream_failure() {
        gstreamer::init().unwrap();
        let source =
            BridgeSource::new("videotestsrc num-buffers=9 ! video/x-raw,format=RGB").unwrap();
        let output = BridgeOutput::new("identity error-after=2 ! fakesink sync=false").unwrap();
        let source_ref = source.bin.clone();
        let output_ref = output.bin.clone();
        let result = (|| -> anyhow::Result<()> {
            output.start()?;
            source.start()?;
            while let Some(sample) = source.pull(Some(&output))? {
                output.push(&source, &sample, &sample.buffer().unwrap().to_owned())?;
            }
            output.finish(&source)
        })();
        assert!(result.is_err());
        drop(output);
        drop(source);
        assert_eq!(source_ref.current_state(), gstreamer::State::Null);
        assert_eq!(output_ref.current_state(), gstreamer::State::Null);
    }

    #[test]
    fn guards_stop_both_pipelines_after_real_embedding_failure() {
        use steganographer_core::video::VideoStegoModule;
        gstreamer::init().unwrap();
        let source = BridgeSource::new(
            "videotestsrc num-buffers=1 ! video/x-raw,format=RGB,width=8,height=8",
        )
        .unwrap();
        let output = BridgeOutput::new("fakesink sync=false").unwrap();
        let source_ref = source.bin.clone();
        let output_ref = output.bin.clone();
        let result = (|| -> anyhow::Result<()> {
            output.start()?;
            source.start()?;
            let sample = source.pull(Some(&output))?.unwrap();
            let mut pixels = sample.buffer().unwrap().map_readable()?.as_ref().to_vec();
            let mut frame = steganographer_core::video::VideoFrame {
                width: 8,
                height: 8,
                stride: 24,
                format: steganographer_core::video::VideoFormat::Rgb8,
                data: &mut pixels,
                frame_index: 0,
            };
            let signer = steganographer_core::crypto::Signer::from_bytes(&[7; 32]);
            let signature = signer.sign_frame(0, frame.data, None);
            steganographer_core::lsb_video::LsbVideo::new(1).embed(&mut frame, Some(&signature))?;
            Ok(())
        })();
        assert!(result.unwrap_err().to_string().contains("capacity"));
        drop(output);
        drop(source);
        assert_eq!(source_ref.current_state(), gstreamer::State::Null);
        assert_eq!(output_ref.current_state(), gstreamer::State::Null);
    }

    #[test]
    fn guards_stop_first_pipeline_when_second_start_fails() {
        gstreamer::init().unwrap();
        let source = BridgeSource::new(
            "filesrc location=/definitely-not-a-steganographer-test-file ! identity",
        )
        .unwrap();
        let output = BridgeOutput::new("fakesink sync=false").unwrap();
        let source_ref = source.bin.clone();
        let output_ref = output.bin.clone();
        output.start().unwrap();
        assert!(source.start().is_err());
        drop(output);
        drop(source);
        assert_eq!(source_ref.current_state(), gstreamer::State::Null);
        assert_eq!(output_ref.current_state(), gstreamer::State::Null);
    }

    #[test]
    fn stalled_source_returns_a_bounded_error_not_empty_success() {
        gstreamer::init().unwrap();
        let source = BridgeSource::new("appsrc format=time is-live=true").unwrap();
        source.start().unwrap();
        let start = Instant::now();
        let error = source.pull(None).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() < BRIDGE_TIMEOUT + Duration::from_secs(3));
    }
}
