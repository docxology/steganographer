//! gst-launch acceptance round-trip for the `stegoaudio` element.
//!
//! Acceptance (2) of the Native GStreamer plugin backlog item: the element
//! must round-trip a PCM S16 packet, verified by a decode check. The
//! `print_packet_hex` helper prints the encoded packet to stdout so a shell
//! gst-launch run can embed it live; the in-process test proves the same
//! bytes decode through the core extractor (the element's sequential embed
//! path IS the core `AudioSpatialLsb` kernel).
//!
//! The lower half of this file adds direct element-level tests that run the
//! real `stegovideo`/`stegoaudio` elements in-process (no gst-launch binary):
//! pad-template allowlists, negotiation gates, stride-padded frame embedding,
//! clear-payload footprints and multi-channel audio. Keyed placement
//! divergence is covered by the `#[cfg(test)]` unit tests in
//! `src/elements.rs` and `src/audio_element.rs`.

use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use steganographer_core::carrier::SpatialLsb;
use steganographer_core::carrier::{
    AudioSpatialLsb, CarrierEmbedder, CarrierExtractor, EmbeddingConfig,
};
use steganographer_core::packet::{
    AlgorithmDescriptor, DecodeLimits, GenericPacket, PayloadKind, KERNEL_SPATIAL_LSB,
    PLACEMENT_SEQUENTIAL,
};

fn encode_test_packet(payload: &[u8], bits: u8) -> Vec<u8> {
    let limits = DecodeLimits::default();
    let packet = GenericPacket::new_untransformed(
        payload.to_vec(),
        [0x42u8; 16],
        [0x24u8; 8],
        PayloadKind::Text,
        AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
        AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits]),
        &limits,
    )
    .expect("packet builds");
    packet.encode(&limits).expect("packet encodes")
}

/// Decode check: packet bytes embedded the way the element embeds them
/// (sequential audio LSB, low byte of every second sample) decode back to
/// the original payload.
#[test]
fn stegoaudio_wire_format_round_trips() {
    let limits = DecodeLimits::default();
    let packet_bytes = encode_test_packet(b"stegoaudio gst-launch acceptance", 2);
    let mut pcm = vec![0x40u8; 2 * 16384];
    AudioSpatialLsb
        .embed_packet(&mut pcm, &packet_bytes, &EmbeddingConfig::new(2).unwrap())
        .expect("embeds into 16384 samples at 2 bits");
    let report = AudioSpatialLsb
        .extract_packet(&pcm, &EmbeddingConfig::new(2).unwrap(), &limits)
        .expect("decodes");
    assert_eq!(report.packet.body, b"stegoaudio gst-launch acceptance");
}

/// Print the encoded packet hex for shell gst-launch runs:
/// `cargo test -p steganographer-gst --test gst_roundtrip print_packet_hex -- --nocapture`
#[test]
fn print_packet_hex() {
    let packet_bytes = encode_test_packet(b"stegoaudio gst-launch acceptance", 2);
    let hex: String = packet_bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("PACKET_HEX_LEN={}", packet_bytes.len());
    println!("PACKET_HEX={hex}");
}

// ── Element-level tests ─────────────────────────────────────────────────────
fn ensure_elements_registered() {
    static REGISTERED: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        gstreamer::init().unwrap();
        steganographer_gst::elements::register(None).expect("registers stegovideo/stegoaudio");
    });
    std::sync::LazyLock::force(&REGISTERED);
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Launch a pipeline string and return its Bin plus the named AppSink.
fn launch_with_appsink(pipeline_str: &str, sink_name: &str) -> (gstreamer::Bin, AppSink) {
    let element = gstreamer::parse::launch(pipeline_str).expect("pipeline parses");
    let bin = element
        .downcast::<gstreamer::Bin>()
        .expect("pipeline is a Bin");
    let appsink = bin
        .by_name(sink_name)
        .expect("appsink present")
        .downcast::<AppSink>()
        .expect("named element is an AppSink");
    (bin, appsink)
}

fn start(bin: &gstreamer::Bin) {
    bin.set_state(gstreamer::State::Playing)
        .expect("pipeline starts");
}

fn stop(bin: &gstreamer::Bin) {
    bin.set_state(gstreamer::State::Null).ok();
}

/// Expect a negotiation failure: rejected at PARSE/link time (gst refuses to
/// link caps the restricted pad templates cannot handle — the loud rejection
/// these templates exist for), at state change, or as a bus Error message —
/// never a clean EOS.
fn expect_negotiation_error(pipeline_str: &str) {
    let element = match gstreamer::parse::launch(pipeline_str) {
        Ok(element) => element,
        // Parse-time link failure IS the negotiation rejection (gst refuses
        // to link caps the restricted templates cannot handle).
        Err(error) => {
            assert!(
                format!("{error}").contains("could not link"),
                "unexpected parse error: {error}"
            );
            return;
        }
    };
    let bus = element.bus().expect("pipeline has bus");
    if element.set_state(gstreamer::State::Playing).is_err() {
        return; // rejected synchronously
    }
    let msg = bus
        .timed_pop_filtered(
            gstreamer::ClockTime::from_seconds(10),
            &[gstreamer::MessageType::Error, gstreamer::MessageType::Eos],
        )
        .expect("pipeline posts Error or Eos within 10s");
    assert!(
        matches!(msg.view(), gstreamer::MessageView::Error(_)),
        "expected a negotiation error, got {msg:?}"
    );
    stop(
        &element
            .downcast::<gstreamer::Bin>()
            .expect("pipeline is a Bin"),
    );
}

/// Pad templates restrict `stegovideo` to packed one-plane RGB variants:
/// NV12 (or anything else) must fail negotiation instead of silently
/// passing through unembedded.
#[test]
fn stegovideo_pad_templates_allow_packed_rgb_only() {
    ensure_elements_registered();
    let el = gstreamer::glib::Object::new::<steganographer_gst::elements::StegoVideo>();
    let template = el.pad_template("sink").expect("sink template");
    let caps = template.caps();
    for format in ["RGB", "BGR", "RGBx", "BGRx", "XRGB", "XBGR"] {
        let allow = gstreamer::Caps::builder("video/x-raw")
            .field("format", format)
            .build();
        assert!(
            !caps.intersect(&allow).is_empty(),
            "{format} must negotiate"
        );
    }
    let nv12 = gstreamer::Caps::builder("video/x-raw")
        .field("format", "NV12")
        .build();
    assert!(caps.intersect(&nv12).is_empty(), "NV12 must be rejected");
    let audio = gstreamer::Caps::builder("audio/x-raw")
        .field("format", "S16LE")
        .build();
    assert!(
        caps.intersect(&audio).is_empty(),
        "audio caps must not negotiate on video pads"
    );
    let src_template = el.pad_template("src").expect("src template");
    let src_caps = src_template.caps();
    assert!(*src_caps == *caps, "src template mirrors sink template");
}

/// Pad templates restrict `stegoaudio` to interleaved S16LE: S24LE and
/// non-interleaved layouts must fail negotiation.
#[test]
fn stegoaudio_pad_templates_allow_s16le_interleaved_only() {
    ensure_elements_registered();
    let el = gstreamer::glib::Object::new::<steganographer_gst::audio_element::StegoAudio>();
    let template = el.pad_template("sink").expect("sink template");
    let caps = template.caps();
    let s16_interleaved = gstreamer::Caps::builder("audio/x-raw")
        .field("format", "S16LE")
        .field("layout", "interleaved")
        .build();
    assert!(
        !caps.intersect(&s16_interleaved).is_empty(),
        "S16LE interleaved must negotiate"
    );
    let s24 = gstreamer::Caps::builder("audio/x-raw")
        .field("format", "S24LE")
        .field("layout", "interleaved")
        .build();
    assert!(caps.intersect(&s24).is_empty(), "S24LE must be rejected");
    let planar = gstreamer::Caps::builder("audio/x-raw")
        .field("format", "S16LE")
        .field("layout", "non-interleaved")
        .build();
    assert!(
        caps.intersect(&planar).is_empty(),
        "non-interleaved layout must be rejected"
    );
}

/// End-to-end negotiation gate: an NV12 stream must fail at `stegovideo`
/// (its caps templates no longer accept anything).
#[test]
fn stegovideo_rejects_nv12_negotiation() {
    ensure_elements_registered();
    expect_negotiation_error(
        "videotestsrc num-buffers=1 ! video/x-raw,format=NV12,width=64,height=64 ! stegovideo ! fakesink",
    );
}

/// End-to-end negotiation gate: audioconvert can produce S32LE, which
/// `stegoaudio` must refuse at negotiation.
#[test]
fn stegoaudio_rejects_non_s16le_negotiation() {
    ensure_elements_registered();
    expect_negotiation_error(
        "audiotestsrc num-buffers=1 ! audioconvert ! audio/x-raw,format=S32LE,rate=8000,channels=1 ! stegoaudio ! fakesink",
    );
}

/// Stride safety through the real element: a 638-wide RGB frame has
/// stride-padded rows (1916 vs 1914 bytes). The element must place packet
/// bits only in pixel bytes; the gathered pixel-only stream decodes with the
/// core extractor — the CLI `lsb_video` wire format.
#[test]
fn stegovideo_stride_padded_frame_round_trips() {
    ensure_elements_registered();
    let limits = DecodeLimits::default();
    let packet_bytes = encode_test_packet(b"stride padded video", 1);
    let pipeline_str = format!(
        "videotestsrc num-buffers=1 pattern=black ! \
         video/x-raw,format=RGB,width=638,height=4 ! \
         stegovideo packet-hex={} bits-per-unit=1 ! \
         appsink name=sink emit-signals=false sync=false max-buffers=4",
        hex_encode_bytes(&packet_bytes)
    );
    let (bin, appsink) = launch_with_appsink(&pipeline_str, "sink");
    start(&bin);
    let sample = appsink
        .try_pull_sample(gstreamer::ClockTime::from_seconds(10))
        .expect("first frame arrives within 10s");
    stop(&bin);

    let buffer = sample.buffer().expect("sample has buffer");
    let caps = sample.caps().expect("sample has caps");
    let info = gstreamer_video::VideoInfo::from_caps(caps).expect("video caps parse");
    let width = info.width() as usize;
    let height = info.height() as usize;
    let stride = info.stride()[0] as usize;
    let bpp = 3usize; // RGB
    assert_eq!(width, 638);
    assert_eq!(height, 4);
    assert_eq!(
        stride, 1916,
        "638-wide RGB rows must be stride-padded (1914 rounded up to 4 bytes)"
    );

    let map = buffer.map_readable().expect("buffer maps readable");
    let data = map.as_ref();
    assert_eq!(data.len(), stride * height);

    // Reference frame: identical pipeline WITHOUT the packet. Row padding is
    // producer/pool garbage (unstable across runs), so padding is NOT asserted
    // against the reference. The load-bearing guarantee is below: the packet
    // must decode from the PIXEL-ONLY stream — if any packet bits had landed
    // in padding, the pixel stream would be missing them and decode would
    // fail. The pixel region must also actually differ from the reference
    // (bits embedded), while both runs see identical pixel data otherwise.
    let ref_pipeline = "videotestsrc num-buffers=1 pattern=black ! \
         video/x-raw,format=RGB,width=638,height=4 ! \
         stegovideo ! \
         appsink name=sink emit-signals=false sync=false max-buffers=4";
    let (ref_bin, ref_sink) = launch_with_appsink(ref_pipeline, "sink");
    start(&ref_bin);
    let ref_sample = ref_sink
        .try_pull_sample(gstreamer::ClockTime::from_seconds(10))
        .expect("reference frame arrives within 10s");
    stop(&ref_bin);
    let ref_map = ref_sample
        .buffer()
        .expect("reference sample has buffer")
        .map_readable()
        .expect("reference buffer maps readable");
    let ref_data = ref_map.as_ref();
    assert_eq!(ref_data.len(), data.len());
    // (Pixel bytes intentionally NOT compared: embedding modifies their LSBs.)
    assert_ne!(
        data, ref_data,
        "embedded frame must differ from the reference (bits landed somewhere)"
    );

    // Gather the pixel-only stream with the element's slot mapping (logical
    // unit i -> (i / row_units) * stride + i % row_units) and decode through
    // the core extractor.
    let row_units = width * bpp;
    let mut pixel = Vec::with_capacity(row_units * height);
    for row in 0..height {
        pixel.extend_from_slice(&data[row * stride..row * stride + row_units]);
    }
    let report = SpatialLsb
        .extract_packet(&pixel, &EmbeddingConfig::new(1).unwrap(), &limits)
        .expect("packet decodes from the pixel-only stream");
    assert_eq!(report.packet.body, b"stride padded video".to_vec());
}

/// clear-payload at every supported strength: frame 0 carries the packet and
/// frame 1's cleared footprint equals the fresh (all-zero) carrier.
#[test]
fn stegovideo_clear_payload_footprint_equals_fresh_carrier() {
    ensure_elements_registered();
    let limits = DecodeLimits::default();
    for bits in 1u8..=4 {
        let packet_bytes = encode_test_packet(b"clear me", bits);
        let pipeline_str = format!(
            "videotestsrc num-buffers=2 pattern=black ! \
             video/x-raw,format=RGB,width=64,height=8 ! \
             stegovideo packet-hex={} bits-per-unit={} clear-payload=true ! \
             appsink name=sink emit-signals=false sync=false max-buffers=4",
            hex_encode_bytes(&packet_bytes),
            bits
        );
        let (bin, appsink) = launch_with_appsink(&pipeline_str, "sink");
        start(&bin);
        let sample0 = appsink
            .try_pull_sample(gstreamer::ClockTime::from_seconds(10))
            .expect("frame 0 arrives within 10s");
        let sample1 = appsink
            .try_pull_sample(gstreamer::ClockTime::from_seconds(10))
            .expect("frame 1 arrives within 10s");
        stop(&bin);

        let map0 = sample0.buffer().unwrap().map_readable().unwrap();
        let map1 = sample1.buffer().unwrap().map_readable().unwrap();
        let frame0 = map0.as_ref();
        let frame1 = map1.as_ref();

        // Frame 0 carries the packet (64x8 RGB = 1536 pixel units, contiguous
        // stride, so the flat frame is the pixel-only stream).
        let config = EmbeddingConfig::new(bits).unwrap();
        let report = SpatialLsb
            .extract_packet(frame0, &config, &limits)
            .expect("frame 0 decodes");
        assert_eq!(report.packet.body, b"clear me".to_vec());
        assert!(
            frame0.iter().any(|&b| b != 0),
            "packet bits landed in frame 0"
        );

        // Frame 1: the cleared footprint equals the fresh carrier — nothing
        // of the packet survives, including the bits > 1 packing cases.
        assert!(
            frame1.iter().all(|&b| b == 0),
            "frame 1 must be fully cleared for bits={bits}"
        );
        assert!(
            SpatialLsb.extract_packet(frame1, &config, &limits).is_err(),
            "cleared frame must not carry a packet"
        );
    }
}

/// The `stegoaudio` element embeds into interleaved S16LE PCM of any channel
/// count; the resulting buffer decodes through the core audio extractor.
#[test]
fn stegoaudio_round_trips_multi_channel_interleaved() {
    let limits = DecodeLimits::default();
    let packet_bytes = encode_test_packet(b"audio element acceptance", 1);
    for channels in [1u32, 2] {
        ensure_elements_registered();
        let pipeline_str = format!(
            "audiotestsrc num-buffers=1 samplesperbuffer=8192 ! \
             audio/x-raw,format=S16LE,rate=8000,channels={channels} ! \
             stegoaudio packet-hex={} bits-per-unit=1 ! \
             appsink name=sink emit-signals=false sync=false max-buffers=4",
            hex_encode_bytes(&packet_bytes)
        );
        let (bin, appsink) = launch_with_appsink(&pipeline_str, "sink");
        start(&bin);
        let sample = appsink
            .try_pull_sample(gstreamer::ClockTime::from_seconds(10))
            .expect("first audio buffer arrives within 10s");
        stop(&bin);

        let buffer = sample.buffer().expect("sample has buffer");
        assert_eq!(
            buffer.size(),
            8192 * channels as usize * 2,
            "buffer must hold {channels} interleaved S16LE channels"
        );
        let map = buffer.map_readable().expect("buffer maps readable");
        let report = AudioSpatialLsb
            .extract_packet(map.as_ref(), &EmbeddingConfig::new(1).unwrap(), &limits)
            .expect("packet decodes from the interleaved S16LE buffer");
        assert_eq!(report.packet.body, b"audio element acceptance".to_vec());
    }
}
