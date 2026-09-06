//! Native GStreamer element: `stegovideo` (in-place `BaseTransform`).
//!
//! Runs as a real pipeline element — no AppSink/AppSrc handoff. The
//! embedding mutates only LSB sample slots, so buffers stay the same size
//! and caps never change. Wire format matches the sequential spatial-LSB
//! carrier paths in steganographer-core (`carrier::SpatialLsb`), so output
//! verifies with the existing `packet extract` CLI command and the same
//! bits-per-unit setting.
//!
//! Element behavior:
//! - `packet-hex`: pre-encoded generic packet bytes (hex). When set, every
//!   frame is embedded with the packet (fresh frames re-embed; the packet
//!   overwrites the same leading slots so extraction from any frame works).
//! - `clear-payload`: when true and `packet-hex` is set, embedded bytes are
//!   cleared from the first `packet_len` units of every frame after the
//!   frame carrying the packet (single-frame delivery).
//! - When no packet is set, buffers pass through untouched.

use gstreamer::glib;
use gstreamer::prelude::*;
use gstreamer::subclass::prelude::*;
use gstreamer_base::subclass::base_transform::BaseTransformImpl;
use gstreamer_base::subclass::BaseTransformMode;
use gstreamer_base::BaseTransform;
use gstreamer_video::VideoFormat;
use gstreamer_video::VideoInfo;
use steganographer_core::carrier::{CarrierEmbedder, EmbeddingConfig, KeyedSpatialLsb, SpatialLsb};
use steganographer_core::kdf::derive_frame_embedding_key;

mod imp {
    use super::*;

    /// Per-element state.
    pub struct StegoVideo {
        info: parking_lot::Mutex<Option<VideoInfo>>,
        key: parking_lot::Mutex<Option<[u8; 32]>>,
        packet: parking_lot::Mutex<Option<Vec<u8>>>,
        clear_payload: parking_lot::Mutex<bool>,
        bits_per_unit: parking_lot::Mutex<u8>,
        /// Frames that already carried the full packet.
        embedded_frames: parking_lot::Mutex<u64>,
        /// Frames skipped (capacity or format limits); logged once.
        skipped_frames: parking_lot::Mutex<u64>,
        /// Whether the keyed `clear-payload` warning was already emitted.
        clear_unsupported_warned: parking_lot::Mutex<bool>,
    }

    impl Default for StegoVideo {
        fn default() -> Self {
            Self {
                info: parking_lot::Mutex::new(None),
                key: parking_lot::Mutex::new(None),
                packet: parking_lot::Mutex::new(None),
                clear_payload: parking_lot::Mutex::new(false),
                bits_per_unit: parking_lot::Mutex::new(1),
                embedded_frames: parking_lot::Mutex::new(0),
                skipped_frames: parking_lot::Mutex::new(0),
                clear_unsupported_warned: parking_lot::Mutex::new(false),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for StegoVideo {
        const NAME: &'static str = "StegoVideo";
        type Type = super::StegoVideo;
        type ParentType = BaseTransform;
    }

    impl ObjectImpl for StegoVideo {
        fn properties() -> &'static [glib::ParamSpec] {
            static PROPS: std::sync::OnceLock<Vec<glib::ParamSpec>> = std::sync::OnceLock::new();
            PROPS.get_or_init(|| {
                vec![
                    glib::ParamSpecString::builder("key-hex").build(),
                    glib::ParamSpecString::builder("packet-hex").build(),
                    glib::ParamSpecBoolean::builder("clear-payload")
                        .default_value(false)
                        .build(),
                    glib::ParamSpecUInt::builder("bits-per-unit")
                        .minimum(1)
                        .maximum(4)
                        .default_value(1)
                        .build(),
                ]
            })
        }

        fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
            match pspec.name() {
                "key-hex" => {
                    let hex = value.get::<String>().unwrap_or_default();
                    if hex.is_empty() {
                        *self.key.lock() = None;
                    } else if let Some(key) = decode_key(&hex) {
                        *self.key.lock() = Some(key);
                    } else {
                        gstreamer::warning!(
                            gstreamer::CAT_DEFAULT,
                            imp = self,
                            "key-hex must be 64 hex chars; keeping previous key"
                        );
                    }
                }
                "packet-hex" => {
                    let hex = value.get::<String>().unwrap_or_default();
                    *self.packet.lock() = decode_hex_fixed(&hex, hex.len() / 2);
                }
                "clear-payload" => {
                    *self.clear_payload.lock() = value.get::<bool>().unwrap_or(false);
                }
                "bits-per-unit" => {
                    let bits = value.get::<u32>().unwrap_or(1).min(u8::MAX as u32) as u8;
                    *self.bits_per_unit.lock() = bits;
                }
                _ => unimplemented!(),
            }
        }

        fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
            match pspec.name() {
                "key-hex" => match self.key.lock().as_ref() {
                    Some(key) => hex_encode(*key).to_value(),
                    None => String::new().to_value(),
                },
                "packet-hex" => {
                    let packet = self.packet.lock();
                    match packet.as_deref() {
                        Some(bytes) => hex_encode_slice(bytes).to_value(),
                        None => String::new().to_value(),
                    }
                }
                "clear-payload" => (*self.clear_payload.lock()).to_value(),
                "bits-per-unit" => (*self.bits_per_unit.lock() as u32).to_value(),
                _ => unimplemented!(),
            }
        }
    }

    impl GstObjectImpl for StegoVideo {}

    impl ElementImpl for StegoVideo {
        fn metadata() -> Option<&'static gstreamer::subclass::ElementMetadata> {
            static ELEMENT_METADATA: std::sync::LazyLock<gstreamer::subclass::ElementMetadata> =
                std::sync::LazyLock::new(|| {
                    gstreamer::subclass::ElementMetadata::new(
                        "Steganographer Video",
                        "Filter/Effect/Video",
                        "Embeds a generic steganography packet into packed raw video frames (LSB)",
                        "docxology contributors",
                    )
                });
            Some(&ELEMENT_METADATA)
        }

        fn pad_templates() -> &'static [gstreamer::PadTemplate] {
            // Any-caps templates: the transform is in-place and pass-through
            // for formats outside the packed allowlist, so caps negotiation
            // stays open and set_caps enforces the real constraints.
            static PAD_TEMPLATES: std::sync::LazyLock<Vec<gstreamer::PadTemplate>> =
                std::sync::LazyLock::new(|| {
                    let caps = gstreamer::Caps::new_any();
                    vec![
                        gstreamer::PadTemplate::new(
                            "sink",
                            gstreamer::PadDirection::Sink,
                            gstreamer::PadPresence::Always,
                            &caps,
                        )
                        .unwrap(),
                        gstreamer::PadTemplate::new(
                            "src",
                            gstreamer::PadDirection::Src,
                            gstreamer::PadPresence::Always,
                            &caps,
                        )
                        .unwrap(),
                    ]
                });
            &PAD_TEMPLATES
        }
    }

    impl BaseTransformImpl for StegoVideo {
        const MODE: BaseTransformMode = BaseTransformMode::AlwaysInPlace;
        const PASSTHROUGH_ON_SAME_CAPS: bool = false;
        const TRANSFORM_IP_ON_PASSTHROUGH: bool = false;

        fn set_caps(
            &self,
            incaps: &gstreamer::Caps,
            _outcaps: &gstreamer::Caps,
        ) -> Result<(), gstreamer::LoggableError> {
            let info = VideoInfo::from_caps(incaps)
                .map_err(|e| gstreamer::loggable_error!(gstreamer::CAT_DEFAULT, "bad caps: {e}"))?;
            *self.info.lock() = Some(info);
            Ok(())
        }

        fn transform_ip(
            &self,
            buf: &mut gstreamer::BufferRef,
        ) -> Result<gstreamer::FlowSuccess, gstreamer::FlowError> {
            let packet = self.packet.lock().clone();
            let Some(packet_bytes) = packet else {
                return Ok(gstreamer::FlowSuccess::Ok);
            };
            let bits = *self.bits_per_unit.lock();
            let Ok(config) = EmbeddingConfig::new(bits) else {
                gstreamer::warning!(
                    gstreamer::CAT_PERFORMANCE,
                    imp = self,
                    "bits-per-unit out of range 1-4; passing buffer through"
                );
                return Ok(gstreamer::FlowSuccess::Ok);
            };

            let Some(info) = self.info.lock().clone() else {
                gstreamer::warning!(
                    gstreamer::CAT_PERFORMANCE,
                    imp = self,
                    "no negotiated caps yet; passing buffer through"
                );
                return Ok(gstreamer::FlowSuccess::Ok);
            };

            let stride_bytes = info.stride()[0] as usize;
            if stride_bytes == 0 {
                gstreamer::warning!(
                    gstreamer::CAT_PERFORMANCE,
                    imp = self,
                    "zero plane stride; passing buffer through"
                );
                return Ok(gstreamer::FlowSuccess::Ok);
            }

            let mut map = buf.map_writable().map_err(|e| {
                gstreamer::error!(
                    gstreamer::CAT_DEFAULT,
                    imp = self,
                    "failed to map buffer writable: {e}"
                );
                gstreamer::FlowError::Error
            })?;
            let data = map.as_mut_slice();

            // Only interleaved packed one-byte-per-channel raw layouts are
            // addressed byte-sequentially in this slice; other formats pass
            // through unembedded (logged once).
            match info.format() {
                VideoFormat::Rgb
                | VideoFormat::Bgr
                | VideoFormat::Rgbx
                | VideoFormat::Bgrx
                | VideoFormat::Xrgb
                | VideoFormat::Xbgr => {
                    embed_into_packed_frame(
                        self,
                        data,
                        stride_bytes,
                        &info,
                        &packet_bytes,
                        &config,
                    );
                }
                other => {
                    note_skip(
                        self,
                        &format!(
                            "unsupported video format {other:?}; frames pass through unembedded"
                        ),
                    );
                }
            }
            Ok(gstreamer::FlowSuccess::Ok)
        }
    }

    fn note_skip(state: &StegoVideo, message: &str) {
        let mut skipped = state.skipped_frames.lock();
        *skipped += 1;
        if *skipped == 1 {
            gstreamer::warning!(gstreamer::CAT_PERFORMANCE, "{}", message);
        }
    }

    fn embed_into_packed_frame(
        state: &StegoVideo,
        data: &mut [u8],
        stride_bytes: usize,
        info: &VideoInfo,
        packet_bytes: &[u8],
        config: &EmbeddingConfig,
    ) {
        let frame_bytes = stride_bytes * info.height() as usize;
        if frame_bytes > data.len() {
            note_skip(
                state,
                &format!(
                    "frame bytes {frame_bytes} exceed mapped buffer {}",
                    data.len()
                ),
            );
            return;
        }
        let frame = &mut data[..frame_bytes];
        let clear = *state.clear_payload.lock();
        let key = *state.key.lock();
        let already = *state.embedded_frames.lock();
        if key.is_some() && clear && already > 0 {
            let mut warned = state.clear_unsupported_warned.lock();
            if !*warned {
                gstreamer::warning!(
                    gstreamer::CAT_PERFORMANCE,
                    "clear-payload is unsupported with keyed placement; re-embedding every frame"
                );
                *warned = true;
            }
        } else if already > 0 && clear {
            // Clear the packet slots (packet_len * 8 LSB bits at the leading
            // sequential slots) and stop embedding after the first delivery
            // frame.
            clear_sequential_slots(frame, packet_bytes.len(), config.bits_per_unit);
            *state.embedded_frames.lock() += 1;
            return;
        }
        let result = match key {
            // Keyed placement is frame-scoped: frame 0 uses the raw key (so
            // first-frame/CLI decode works unchanged), later frames mix the
            // frame index into the derivation — equal buffers then embed to
            // different slots per frame while remaining decodable via the
            // same derivation with the frame index.
            Some(embedding_key) => {
                let frame_key =
                    derive_frame_embedding_key(&embedding_key, *state.embedded_frames.lock());
                KeyedSpatialLsb::new(frame_key).embed_packet(frame, packet_bytes, config)
            }
            None => SpatialLsb.embed_packet(frame, packet_bytes, config),
        };
        match result {
            Ok(report) => {
                *state.embedded_frames.lock() += 1;
                gstreamer::debug!(
                    gstreamer::CAT_DEFAULT,
                    imp = state,
                    "embedded {} packet bytes into {} units",
                    report.packet_bytes,
                    report.modified_units
                );
            }
            Err(e) => {
                note_skip(
                    state,
                    &format!("packet does not fit frame capacity: {e}; frames remain unembedded"),
                );
            }
        }
    }

    /// Zero the LSB slots that carried the packet: the first
    /// `packet_len * 8 / bits` carrier bytes' low bits, sequential layout.
    /// This is the exact inverse footprint of a sequential embed of
    /// `packet_len` bytes, so nothing of the packet survives.
    fn clear_sequential_slots(frame: &mut [u8], packet_len: usize, bits: u8) {
        let mask = !((1u16 << bits) - 1) as u8;
        let needed_units = (packet_len.saturating_mul(8)).div_ceil(bits as usize);
        for slot in frame.iter_mut().take(needed_units) {
            *slot &= mask;
        }
    }
}

glib::wrapper! {
    pub struct StegoVideo(ObjectSubclass<imp::StegoVideo>)
        @extends BaseTransform, gstreamer::Element, gstreamer::Object;
}

/// Decode a hex string into exactly `out_len` bytes.
fn decode_hex_fixed(s: &str, out_len: usize) -> Option<Vec<u8>> {
    if s.len() != out_len * 2 || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..out_len)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Decode a hex string into a 32-byte key.
fn decode_key(s: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex_fixed(s, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn hex_encode(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_encode_slice(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Register steganographer elements, optionally under a loaded plugin.
pub fn register(plugin: Option<&gstreamer::Plugin>) -> Result<(), glib::BoolError> {
    gstreamer::Element::register(
        plugin,
        "stegovideo",
        gstreamer::Rank::NONE,
        StegoVideo::static_type(),
    )?;
    gstreamer::Element::register(
        plugin,
        "stegoaudio",
        gstreamer::Rank::NONE,
        crate::audio_element::StegoAudio::static_type(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gstreamer_video::VideoFormat;
    use steganographer_core::carrier::{CarrierEmbedder, CarrierExtractor};
    use steganographer_core::packet::{
        AlgorithmDescriptor, DecodeLimits, GenericPacket, PayloadKind, KERNEL_SPATIAL_LSB,
        PLACEMENT_SEQUENTIAL,
    };

    #[test]
    fn decodes_fixed_hex_keys() {
        let key = decode_key(&"ab".repeat(32)).expect("valid 64-char hex");
        assert_eq!(key[0], 0xab);
        assert!(decode_key("zz").is_none());
        assert!(decode_key("ab").is_none()); // wrong length
    }

    #[test]
    fn decodes_arbitrary_hex_payloads() {
        assert_eq!(
            decode_hex_fixed("deadbeef", 4).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(decode_hex_fixed("", 0).unwrap(), Vec::<u8>::new());
        assert!(decode_hex_fixed("abc", 1).is_none()); // odd length
        assert!(decode_hex_fixed("zzzz", 2).is_none()); // bad digits
    }
    #[test]
    fn registers_element_type() {
        gstreamer::init().unwrap();
        let el = glib::Object::new::<StegoVideo>();
        let kv: String = el.property("key-hex");
        assert!(kv.is_empty());
        assert!(!el.name().is_empty());
        let ph: String = el.property("packet-hex");
        assert!(ph.is_empty());
        assert!(!el.property::<bool>("clear-payload"));
        assert_eq!(el.property::<u32>("bits-per-unit"), 1);
    }

    #[test]
    fn keyed_embed_differences_follow_frame_index() {
        gstreamer::init().unwrap();
        use steganographer_core::packet::PLACEMENT_KEYED;
        let limits = DecodeLimits::default();
        let payload = b"keyed placement".to_vec();
        let packet = GenericPacket::new_untransformed(
            payload,
            [7u8; 16],
            [9u8; 8],
            PayloadKind::Text,
            AlgorithmDescriptor::new(PLACEMENT_KEYED, 1, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![1]),
            &limits,
        )
        .unwrap();
        let packet_bytes = packet.encode(&limits).unwrap();
        let config = EmbeddingConfig::new(1).unwrap();

        // Two equal carrier frames embedded under different keys produce
        // different modified-slot sets: the keyed schedule (derived from the
        // key) spreads the packet differently, not at the leading slots.
        let mut frame_a = vec![0x40u8; 4096];
        KeyedSpatialLsb::new([1u8; 32])
            .embed_packet(&mut frame_a, &packet_bytes, &config)
            .unwrap();
        let mut frame_b = vec![0x40u8; 4096];
        KeyedSpatialLsb::new([2u8; 32])
            .embed_packet(&mut frame_b, &packet_bytes, &config)
            .unwrap();
        let changed: Vec<usize> = frame_a
            .iter()
            .zip(&frame_b)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert!(
            !changed.is_empty(),
            "different keys must embed to different slot sets"
        );
        assert!(
            changed.iter().any(|i| *i >= 64),
            "keyed placement must reach beyond the leading bootstrap slots"
        );
    }

    #[test]
    fn keyed_frames_diverge_by_frame_index() {
        gstreamer::init().unwrap();
        use steganographer_core::kdf::derive_frame_embedding_key;
        use steganographer_core::packet::PLACEMENT_KEYED;
        let limits = DecodeLimits::default();
        let packet = GenericPacket::new_untransformed(
            b"frame-indexed".to_vec(),
            [7u8; 16],
            [9u8; 8],
            PayloadKind::Text,
            AlgorithmDescriptor::new(PLACEMENT_KEYED, 1, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![1]),
            &limits,
        )
        .unwrap();
        let packet_bytes = packet.encode(&limits).unwrap();
        let config = EmbeddingConfig::new(1).unwrap();

        // The element's exact embed rule: frame i uses the frame-scoped key.
        let embed_frame = |index: u64| {
            let mut frame = vec![0x40u8; 4096];
            KeyedSpatialLsb::new(derive_frame_embedding_key(&[5u8; 32], index))
                .embed_packet(&mut frame, &packet_bytes, &config)
                .unwrap();
            frame
        };

        let frame0 = embed_frame(0);
        let frame1 = embed_frame(1);
        let frame2 = embed_frame(2);

        // Equal buffers, different frame indices: different slot sets.
        assert_ne!(frame0, frame1, "frame 0 and 1 must embed differently");
        assert_ne!(frame1, frame2, "frame 1 and 2 must embed differently");

        // Each frame decodes with its own frame-scoped key.
        for (index, frame) in [(0u64, &frame0), (1, &frame1), (2, &frame2)] {
            let report = KeyedSpatialLsb::new(derive_frame_embedding_key(&[5u8; 32], index))
                .extract_packet(frame, &config, &limits)
                .unwrap();
            assert_eq!(report.packet.body, b"frame-indexed");
        }

        // A frame-N carrier does not decode under the raw (frame-0) key.
        assert!(KeyedSpatialLsb::new([5u8; 32])
            .extract_packet(&frame1, &config, &limits)
            .is_err());
    }

    #[test]
    fn element_round_trips_packet_through_core_lsb() {
        gstreamer::init().unwrap();
        let limits = DecodeLimits::default();
        let payload = b"hello gst roundtrip".to_vec();
        let packet = GenericPacket::new_untransformed(
            payload,
            [7u8; 16],
            [9u8; 8],
            PayloadKind::Text,
            AlgorithmDescriptor::new(PLACEMENT_SEQUENTIAL, 1, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![1]),
            &limits,
        )
        .unwrap();
        let packet_bytes = packet.encode(&limits).unwrap();

        // Element property accepts and echoes the hex packet.
        let el = glib::Object::new::<StegoVideo>();
        el.set_property("packet-hex", hex_encode_slice(&packet_bytes));
        el.set_property("bits-per-unit", 1u32);
        let read_back: String = el.property("packet-hex");
        assert_eq!(read_back, hex_encode_slice(&packet_bytes));
        assert_eq!(el.property::<u32>("bits-per-unit"), 1);

        // The same wire format verifies through the core extractor.
        let mut frame = vec![0x40u8; 1920 * 1080 * 3];
        let config = EmbeddingConfig::new(1).unwrap();
        SpatialLsb
            .embed_packet(&mut frame, &packet_bytes, &config)
            .unwrap();
        let report = SpatialLsb.extract_packet(&frame, &config, &limits).unwrap();
        assert_eq!(report.packet.body, b"hello gst roundtrip".to_vec());
        assert_eq!(report.packet.envelope.packet_id, [7u8; 16]);
    }

    #[test]
    fn video_info_round_trips_packed_formats() {
        gstreamer::init().unwrap();
        // Guards the format allowlist against drift: each allowlisted packed
        // format must yield exactly one plane at 8 bits per component, which
        // is what the byte-sequential kernel assumes.
        for fmt in [
            VideoFormat::Rgb,
            VideoFormat::Bgr,
            VideoFormat::Rgbx,
            VideoFormat::Bgrx,
            VideoFormat::Xrgb,
            VideoFormat::Xbgr,
        ] {
            let info = gstreamer_video::VideoInfo::builder(fmt, 64, 32)
                .build()
                .unwrap_or_else(|e| panic!("{fmt:?}: {e}"));
            assert_eq!(info.n_planes(), 1, "{fmt:?} must stay single-plane");
            assert_eq!(info.height(), 32);
        }
    }
}
