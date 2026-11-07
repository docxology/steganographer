//! Real native-element regressions. Packet recovery is checked from the
//! transformed carrier, including per-buffer layouts and stream lifecycles.

use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};
use steganographer_core::carrier::{
    AudioSpatialLsb, CarrierExtractor, EmbeddingConfig, KeyedAudioSpatialLsb, KeyedSpatialLsb,
    SpatialLsb,
};
use steganographer_core::crypto::encode_hex;
use steganographer_core::kdf::derive_frame_embedding_key;
use steganographer_core::packet::{
    AlgorithmDescriptor, DecodeLimits, GenericPacket, PayloadKind, KERNEL_SPATIAL_LSB,
    PLACEMENT_KEYED, PLACEMENT_SEQUENTIAL,
};

fn encode_test_packet(payload: &[u8], bits: u8) -> Vec<u8> {
    encode_packet(payload, bits, false)
}

fn encode_packet(payload: &[u8], bits: u8, keyed: bool) -> Vec<u8> {
    let limits = DecodeLimits::default();
    let packet = GenericPacket::new_untransformed(
        payload.to_vec(),
        [0x42u8; 16],
        [0x24u8; 8],
        PayloadKind::Text,
        AlgorithmDescriptor::new(
            if keyed {
                PLACEMENT_KEYED
            } else {
                PLACEMENT_SEQUENTIAL
            },
            1,
            Vec::new(),
        ),
        AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits]),
        &limits,
    )
    .expect("packet builds");
    packet.encode(&limits).expect("packet encodes")
}

// ── Element-level tests ─────────────────────────────────────────────────────
fn ensure_elements_registered() {
    static REGISTERED: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        gstreamer::init().unwrap();
        steganographer_gst::elements::register(None).expect("registers stegovideo/stegoaudio");
    });
    std::sync::LazyLock::force(&REGISTERED);
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
    let payload = vec![b'x'; 300];
    let packet_bytes = encode_test_packet(&payload, 1);
    assert!(
        packet_bytes.len() * 8 > 638 * 3,
        "packet must cross a padded row"
    );
    let pipeline_str = format!(
        "videotestsrc num-buffers=1 pattern=black ! \
         video/x-raw,format=RGB,width=638,height=4 ! \
         stegovideo packet-hex={} bits-per-unit=1 ! \
         appsink name=sink emit-signals=false sync=false max-buffers=4",
        encode_hex(&packet_bytes)
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
    assert_eq!(report.packet.body, payload);
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
            encode_hex(&packet_bytes),
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
            encode_hex(&packet_bytes)
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

/// AppSrc keeps buffers and property changes under the test's control. The
/// guard also shuts down streaming if a carrier assertion fails.
struct ElementHarness {
    bin: gstreamer::Bin,
    source: AppSrc,
    sink: AppSink,
    stego: gstreamer::Element,
}

impl ElementHarness {
    fn new(audio: bool, width: u32, height: u32) -> Self {
        ensure_elements_registered();
        let kind = if audio { "stegoaudio" } else { "stegovideo" };
        let (bin, sink) = launch_with_appsink(
            &format!(
                "appsrc name=source format=time ! {kind} name=stego ! \
                 appsink name=sink sync=false async=false"
            ),
            "sink",
        );
        let source = bin.by_name("source").unwrap().downcast::<AppSrc>().unwrap();
        let caps = if audio {
            gstreamer_audio::AudioInfo::builder(gstreamer_audio::AudioFormat::S16le, 8000, 1)
                .build()
                .unwrap()
                .to_caps()
                .unwrap()
        } else {
            gstreamer_video::VideoInfo::builder(gstreamer_video::VideoFormat::Rgb, width, height)
                .build()
                .unwrap()
                .to_caps()
                .unwrap()
        };
        source.set_caps(Some(&caps));
        let stego = bin.by_name("stego").unwrap();
        Self {
            bin,
            source,
            sink,
            stego,
        }
    }

    fn exchange(&self, input: gstreamer::Buffer) -> Vec<u8> {
        self.source.push_buffer(input).expect("buffer accepted");
        let sample = self
            .sink
            .try_pull_sample(gstreamer::ClockTime::from_seconds(10))
            .expect("transformed buffer arrives");
        let bytes = sample
            .buffer()
            .unwrap()
            .map_readable()
            .unwrap()
            .as_ref()
            .to_vec();
        bytes
    }

    fn fresh(&self, audio: bool) -> Vec<u8> {
        self.exchange(gstreamer::Buffer::from_mut_slice(vec![
            0x40;
            if audio {
                16384
            } else {
                64 * 32 * 3
            }
        ]))
    }
}

impl Drop for ElementHarness {
    fn drop(&mut self) {
        self.bin
            .set_state(gstreamer::State::Null)
            .expect("pipeline stops");
    }
}

fn recover(carrier: &[u8], audio: bool, key: Option<[u8; 32]>, bits: u8) -> Option<Vec<u8>> {
    let config = EmbeddingConfig::new(bits).unwrap();
    let limits = DecodeLimits::default();
    let report = match (audio, key) {
        (false, None) => SpatialLsb.extract_packet(carrier, &config, &limits),
        (false, Some(key)) => KeyedSpatialLsb::new(key).extract_packet(carrier, &config, &limits),
        (true, None) => AudioSpatialLsb.extract_packet(carrier, &config, &limits),
        (true, Some(key)) => {
            KeyedAudioSpatialLsb::new(key).extract_packet(carrier, &config, &limits)
        }
    };
    report.ok().map(|report| report.packet.body)
}

#[test]
fn stegovideo_keyed_and_sequential_preserve_actual_layout() {
    for (width, offset, extra_stride) in [(640u32, 0usize, 0usize), (638, 0, 0), (638, 37, 12)] {
        for keyed in [false, true] {
            let height = 4usize;
            let harness = ElementHarness::new(false, width, height as u32);
            let info = gstreamer_video::VideoInfo::builder(
                gstreamer_video::VideoFormat::Rgb,
                width,
                height as u32,
            )
            .build()
            .unwrap();
            let row = width as usize * 3;
            let stride = info.stride()[0] as usize + extra_stride;
            let payload = vec![b'p'; 300];
            let packet = encode_packet(&payload, 1, keyed);
            assert!(packet.len() * 8 > row);
            let key = [0x59; 32];
            harness
                .stego
                .set_property("packet-hex", encode_hex(&packet));
            if keyed {
                harness.stego.set_property("key-hex", encode_hex(&key));
            }
            let mut bytes = vec![0xa5; offset + stride * height + 29];
            for y in 0..height {
                bytes[offset + y * stride..offset + y * stride + row].fill(0x40);
            }
            let before = bytes.clone();
            let mut buffer = gstreamer::Buffer::from_mut_slice(bytes);
            if offset != 0 {
                gstreamer_video::VideoMeta::add_full(
                    buffer.get_mut().unwrap(),
                    gstreamer_video::VideoFrameFlags::empty(),
                    gstreamer_video::VideoFormat::Rgb,
                    width,
                    height as u32,
                    &[offset],
                    &[stride as i32],
                )
                .expect("explicit VideoMeta layout");
            }
            start(&harness.bin);
            let output = harness.exchange(buffer);
            assert_eq!(output.len(), before.len());
            let mut pixel = Vec::new();
            for y in 0..height {
                pixel.extend_from_slice(&output[offset + y * stride..offset + y * stride + row]);
            }
            assert_eq!(
                recover(&pixel, false, keyed.then_some(key), 1),
                Some(payload)
            );
            for (i, (&old, &new)) in before.iter().zip(&output).enumerate() {
                let pixel =
                    i >= offset && i < offset + stride * height && (i - offset) % stride < row;
                if !pixel {
                    assert_eq!(old, new, "sentinel/padding byte {i} changed");
                }
            }
        }
    }
}

#[test]
fn native_elements_restart_delivery_and_key_timeline() {
    for audio in [false, true] {
        for keyed in [false, true] {
            let harness = ElementHarness::new(audio, 64, 32);
            let key = [0x73; 32];
            harness.stego.set_property(
                "packet-hex",
                encode_hex(&encode_packet(b"restart", 1, keyed)),
            );
            harness.stego.set_property("clear-payload", !keyed);
            if keyed {
                harness.stego.set_property("key-hex", encode_hex(&key));
            }
            for _ in 0..2 {
                start(&harness.bin);
                let first = harness.fresh(audio);
                assert_eq!(
                    recover(&first, audio, keyed.then_some(key), 1),
                    Some(b"restart".to_vec())
                );
                let second = harness.fresh(audio);
                if keyed {
                    assert_eq!(
                        recover(&second, audio, Some(derive_frame_embedding_key(&key, 1)), 1),
                        Some(b"restart".to_vec())
                    );
                    assert!(recover(&second, audio, Some(key), 1).is_none());
                } else {
                    assert!(recover(&second, audio, None, 1).is_none());
                }
                harness
                    .bin
                    .set_state(gstreamer::State::Null)
                    .expect("stream stops");
            }
        }
    }
}

#[test]
fn native_elements_deliver_each_replacement_once_without_resetting_key_timeline() {
    for audio in [false, true] {
        for keyed in [false, true] {
            let harness = ElementHarness::new(audio, 64, 32);
            let key = [0x35; 32];
            harness.stego.set_property("clear-payload", !keyed);
            if keyed {
                harness.stego.set_property("key-hex", encode_hex(&key));
            }
            start(&harness.bin);
            let mut index = 0;
            for payload in [b"packet A".as_slice(), b"packet B".as_slice()] {
                harness
                    .stego
                    .set_property("packet-hex", encode_hex(&encode_packet(payload, 1, keyed)));
                let delivered = harness.fresh(audio);
                let expected_key = keyed.then(|| derive_frame_embedding_key(&key, index));
                assert_eq!(
                    recover(&delivered, audio, expected_key, 1),
                    Some(payload.to_vec())
                );
                index += 1;
                if !keyed {
                    let cleared = harness.fresh(audio);
                    assert!(recover(&cleared, audio, None, 1).is_none());
                    index += 1;
                }
            }
        }
    }
}

#[test]
fn native_elements_reject_unicode_hex_without_losing_previous_carrier_settings() {
    for audio in [false, true] {
        let harness = ElementHarness::new(audio, 64, 32);
        let key = [0x92; 32];
        harness.stego.set_property(
            "packet-hex",
            encode_hex(&encode_packet(b"unchanged", 1, true)),
        );
        harness.stego.set_property("key-hex", encode_hex(&key));
        for invalid in ["aéa".to_owned(), "xyz".to_owned(), "zz".to_owned()] {
            harness.stego.set_property("packet-hex", invalid);
        }
        harness
            .stego
            .set_property("key-hex", format!("aé{}", "a".repeat(61)));
        start(&harness.bin);
        assert_eq!(
            recover(&harness.fresh(audio), audio, Some(key), 1),
            Some(b"unchanged".to_vec())
        );
    }
}

#[test]
fn native_elements_report_invalid_packet_configuration_as_pipeline_error() {
    ensure_elements_registered();
    for (packet, bits) in [
        (encode_test_packet(b"wrong strength", 1), 2),
        (encode_packet(b"missing placement key", 1, true), 1),
        (vec![0xff], 1),
    ] {
        for (source, element) in [
            (
                "videotestsrc num-buffers=1 ! video/x-raw,format=RGB,width=64,height=64",
                "stegovideo",
            ),
            (
                "audiotestsrc num-buffers=1 samplesperbuffer=4096 ! audio/x-raw,format=S16LE,channels=1,rate=44100",
                "stegoaudio",
            ),
        ] {
            expect_negotiation_error(&format!(
                "{source} ! {element} packet-hex={} bits-per-unit={bits} ! fakesink",
                encode_hex(&packet),
            ));
        }
    }
}
