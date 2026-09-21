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
//! - Pad templates are restricted to packed one-plane `video/x-raw` formats
//!   (RGB/BGR/RGBx/BGRx/XRGB/XBGR): negotiation fails loudly for anything
//!   else. The runtime allowlist in `transform_ip` stays as a backstop.
//! - Embedding is stride-safe: the wire format is the CLI packet path over
//!   the *pixel-only* byte stream (`width * height * bpp` units); padded row
//!   padding bytes never carry packet bits.
//! - Property changes apply at frame granularity (see `StreamState` in the
//!   imp module); `key-hex`/`bits-per-unit` changes reset the frame counter.

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

    /// One-shot warning flags, keyed by reason: the first occurrence of each
    /// reason warns, later occurrences stay silent.
    #[derive(Clone, Copy, Default)]
    struct WarnFlags {
        unsupported_format: bool,
        frame_size: bool,
        capacity: bool,
        keyed_clear: bool,
    }

    /// Skip-reason selector for [`StreamState::note_skip`].
    #[derive(Clone, Copy)]
    enum SkipReason {
        UnsupportedFormat,
        FrameSize,
        Capacity,
    }

    impl WarnFlags {
        fn slot(&mut self, reason: SkipReason) -> &mut bool {
            match reason {
                SkipReason::UnsupportedFormat => &mut self.unsupported_format,
                SkipReason::FrameSize => &mut self.frame_size,
                SkipReason::Capacity => &mut self.capacity,
            }
        }
    }

    /// Property-driven streaming parameters plus per-stream progress
    /// counters, under one lock so a property write cannot interleave with a
    /// `transform_ip` snapshot (stale counters, half-updated key/packet/bits).
    ///
    /// Streaming-order note: property changes apply at *frame granularity*.
    /// Each in-flight frame works on the snapshot taken when it arrived; the
    /// next frame after a `key-hex` or `bits-per-unit` change sees the new
    /// value with the progress counters reset (it is treated as frame 0 and,
    /// in keyed mode, embedded with the raw key). Keyed mode therefore
    /// expects `key-hex` to be set before the pipeline reaches PLAYING, so
    /// frame 0 is embedded with the raw key and decodes via the CLI
    /// `--embedding-key` path.
    #[derive(Clone)]
    struct StreamState {
        packet: Option<Vec<u8>>,
        key: Option<[u8; 32]>,
        bits_per_unit: u8,
        clear_payload: bool,
        /// Frames that already carried the full packet.
        embedded_frames: u64,
        /// Frames skipped (format or capacity limits); warned once per reason.
        skipped_frames: u64,
        warned: WarnFlags,
    }

    impl Default for StreamState {
        fn default() -> Self {
            Self {
                packet: None,
                key: None,
                bits_per_unit: 1,
                clear_payload: false,
                embedded_frames: 0,
                skipped_frames: 0,
                warned: WarnFlags::default(),
            }
        }
    }

    impl StreamState {
        /// Count a skipped frame; returns true only the first time for the
        /// reason so callers warn once per reason.
        fn note_skip(&mut self, reason: SkipReason) -> bool {
            self.skipped_frames += 1;
            let slot = self.warned.slot(reason);
            let first = !*slot;
            *slot = true;
            first
        }

        /// Reset per-stream progress after a property change that alters the
        /// placement or wire format: the next frame starts from frame 0.
        fn reset_progress(&mut self) {
            self.embedded_frames = 0;
            self.skipped_frames = 0;
            self.warned = WarnFlags::default();
        }
    }

    /// Per-element state.
    pub struct StegoVideo {
        info: parking_lot::Mutex<Option<VideoInfo>>,
        /// Streaming parameters + counters; see [`StreamState`] for the
        /// ordering contract.
        stream: parking_lot::Mutex<StreamState>,
    }

    impl Default for StegoVideo {
        fn default() -> Self {
            Self {
                info: parking_lot::Mutex::new(None),
                stream: parking_lot::Mutex::new(StreamState::default()),
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
                    let mut stream = self.stream.lock();
                    if hex.is_empty() {
                        if stream.key.take().is_some() {
                            stream.reset_progress();
                            gstreamer::info!(
                                gstreamer::CAT_DEFAULT,
                                imp = self,
                                "key-hex cleared; sequential placement from the next frame"
                            );
                        }
                    } else if let Some(key) = decode_key(&hex) {
                        if stream.key != Some(key) {
                            stream.key = Some(key);
                            stream.reset_progress();
                        }
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
                    if hex.is_empty() {
                        gstreamer::info!(
                            gstreamer::CAT_DEFAULT,
                            imp = self,
                            "packet-hex cleared; embedding disabled"
                        );
                        self.stream.lock().packet = None;
                    } else if let Some(bytes) = decode_hex_fixed(&hex, hex.len() / 2) {
                        self.stream.lock().packet = Some(bytes);
                    } else {
                        gstreamer::warning!(
                            gstreamer::CAT_DEFAULT,
                            imp = self,
                            "packet-hex must be valid even-length hex; keeping previous packet"
                        );
                    }
                }
                "clear-payload" => {
                    self.stream.lock().clear_payload = value.get::<bool>().unwrap_or(false);
                }
                "bits-per-unit" => {
                    let bits = value.get::<u32>().unwrap_or(1).clamp(1, 4) as u8;
                    let mut stream = self.stream.lock();
                    if stream.bits_per_unit != bits {
                        stream.bits_per_unit = bits;
                        stream.reset_progress();
                    }
                }
                _ => unimplemented!(),
            }
        }

        fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
            match pspec.name() {
                "key-hex" => match self.stream.lock().key {
                    Some(key) => hex_encode(key).to_value(),
                    None => String::new().to_value(),
                },
                "packet-hex" => {
                    let stream = self.stream.lock();
                    match stream.packet.as_deref() {
                        Some(bytes) => hex_encode_slice(bytes).to_value(),
                        None => String::new().to_value(),
                    }
                }
                "clear-payload" => self.stream.lock().clear_payload.to_value(),
                "bits-per-unit" => (self.stream.lock().bits_per_unit as u32).to_value(),
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
            // Restricted templates: negotiation fails loudly for anything
            // outside the packed one-plane formats the byte-sequential kernel
            // can address, instead of silently passing buffers through
            // unembedded. The runtime allowlist in transform_ip stays as a
            // backstop; the legacy AppSink/AppSrc filters negotiate their own
            // caps and are unaffected.
            static PAD_TEMPLATES: std::sync::LazyLock<Vec<gstreamer::PadTemplate>> =
                std::sync::LazyLock::new(|| {
                    let caps = gstreamer::Caps::builder_full()
                        .structure(
                            gstreamer::Structure::builder("video/x-raw")
                                .field(
                                    "format",
                                    gstreamer::List::new([
                                        "RGB", "BGR", "RGBx", "BGRx", "XRGB", "XBGR",
                                    ]),
                                )
                                .field("width", gstreamer::IntRange::new(1, i32::MAX))
                                .field("height", gstreamer::IntRange::new(1, i32::MAX))
                                .field(
                                    "framerate",
                                    gstreamer::FractionRange::new(
                                        gstreamer::Fraction::new(0, 1),
                                        gstreamer::Fraction::new(i32::MAX, 1),
                                    ),
                                )
                                .build(),
                        )
                        .build();
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
            // One short lock: snapshot the streaming parameters for this
            // frame so a concurrent property write cannot split the
            // packet/key/bits triple or the frame counter across the embed.
            let snap = self.stream.lock().clone();
            let Some(packet_bytes) = snap.packet.as_deref() else {
                return Ok(gstreamer::FlowSuccess::Ok);
            };
            let Ok(config) = EmbeddingConfig::new(snap.bits_per_unit) else {
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

            // Only packed one-byte-per-channel interleaved layouts are
            // addressed byte-sequentially; other formats pass through
            // unembedded (checked before the writable map so discarded frames
            // are never copied; warned once per reason).
            let Some(bpp) = packed_bytes_per_pixel(info.format()) else {
                self.note_skip(
                    SkipReason::UnsupportedFormat,
                    &format!(
                        "unsupported video format {:?}; frames pass through unembedded",
                        info.format()
                    ),
                );
                return Ok(gstreamer::FlowSuccess::Ok);
            };

            let stride_bytes = info.stride()[0] as usize;
            let row_units = info.width() as usize * bpp;
            let height = info.height() as usize;
            if stride_bytes == 0 || stride_bytes < row_units {
                gstreamer::warning!(
                    gstreamer::CAT_PERFORMANCE,
                    imp = self,
                    "plane stride {stride_bytes} smaller than one pixel row {row_units}; passing buffer through"
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
            if data.len() < stride_bytes * height {
                self.note_skip(
                    SkipReason::FrameSize,
                    &format!(
                        "frame bytes {} exceed mapped buffer {}",
                        stride_bytes * height,
                        data.len()
                    ),
                );
                return Ok(gstreamer::FlowSuccess::Ok);
            }

            embed_into_packed_frame(
                self,
                data,
                stride_bytes,
                row_units,
                height,
                packet_bytes,
                &config,
                &snap,
            );
            Ok(gstreamer::FlowSuccess::Ok)
        }
    }

    impl StegoVideo {
        /// Count a skipped frame and warn once per skip reason.
        fn note_skip(&self, reason: SkipReason, message: &str) {
            if self.stream.lock().note_skip(reason) {
                gstreamer::warning!(gstreamer::CAT_PERFORMANCE, imp = self, "{}", message);
            }
        }
    }

    /// Bytes per pixel for the packed single-plane formats the element
    /// addresses byte-sequentially; `None` for anything else.
    fn packed_bytes_per_pixel(format: VideoFormat) -> Option<usize> {
        match format {
            VideoFormat::Rgb | VideoFormat::Bgr => Some(3),
            VideoFormat::Rgbx | VideoFormat::Bgrx | VideoFormat::Xrgb | VideoFormat::Xbgr => {
                Some(4)
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)] // element transform context
    fn embed_into_packed_frame(
        state: &StegoVideo,
        data: &mut [u8],
        stride_bytes: usize,
        row_units: usize,
        height: usize,
        packet_bytes: &[u8],
        config: &EmbeddingConfig,
        snap: &StreamState,
    ) {
        if snap.key.is_some() && snap.clear_payload && snap.embedded_frames > 0 {
            let first = {
                let mut stream = state.stream.lock();
                let first = !stream.warned.keyed_clear;
                stream.warned.keyed_clear = true;
                first
            };
            if first {
                gstreamer::warning!(
                    gstreamer::CAT_PERFORMANCE,
                    imp = state,
                    "clear-payload is unsupported with keyed placement; re-embedding every frame"
                );
            }
        } else if snap.embedded_frames > 0 && snap.clear_payload {
            // Clear the packet slots (packet_len * 8 LSB bits at the leading
            // sequential slots over the pixel-only stream) and stop embedding
            // after the first delivery frame.
            clear_sequential_slots(
                data,
                stride_bytes,
                row_units,
                height,
                packet_bytes.len(),
                config.bits_per_unit,
            );
            state.stream.lock().embedded_frames += 1;
            return;
        }

        // Wire format: the CLI packet path over the pixel-only byte stream —
        // `row_units * height` units, one per pixel byte, no row padding.
        // With no padding (stride == row_units) that stream is the frame
        // prefix itself; otherwise each logical unit `i` maps to physical
        // byte `(i / row_units) * stride_bytes + i % row_units` via
        // gather/scatter so packet bits never land in row padding.
        let frame_units = row_units * height;
        let embed = |carrier: &mut [u8]| match snap.key {
            // Keyed placement is frame-scoped: frame 0 uses the raw key (so
            // first-frame/CLI decode works unchanged), later frames mix the
            // frame index into the derivation — equal buffers then embed to
            // different slots per frame while remaining decodable via the
            // same derivation with the frame index.
            Some(embedding_key) => {
                let frame_key = derive_frame_embedding_key(&embedding_key, snap.embedded_frames);
                KeyedSpatialLsb::new(frame_key).embed_packet(carrier, packet_bytes, config)
            }
            None => SpatialLsb.embed_packet(carrier, packet_bytes, config),
        };

        let result = if stride_bytes == row_units {
            embed(&mut data[..frame_units])
        } else {
            let mut pixel = gather_pixel_stream(data, stride_bytes, row_units, height);
            let result = embed(&mut pixel);
            if let Ok(report) = &result {
                scatter_pixel_units(&pixel, data, stride_bytes, row_units, report.modified_units);
            }
            result
        };

        match result {
            Ok(report) => {
                state.stream.lock().embedded_frames += 1;
                gstreamer::debug!(
                    gstreamer::CAT_DEFAULT,
                    imp = state,
                    "embedded {} packet bytes into {} units",
                    report.packet_bytes,
                    report.modified_units
                );
            }
            Err(e) => state.note_skip(
                SkipReason::Capacity,
                &format!("packet does not fit frame capacity: {e}; frames remain unembedded"),
            ),
        }
    }

    /// Copy the pixel-only byte stream out of a stride-padded frame: logical
    /// pixel-unit `i` (over `row_units * height` bytes) lives at physical
    /// byte `(i / row_units) * stride_bytes + i % row_units`. The result is
    /// exactly what a stride-1 layout of the frame's pixel bytes produces.
    fn gather_pixel_stream(
        frame: &[u8],
        stride_bytes: usize,
        row_units: usize,
        height: usize,
    ) -> Vec<u8> {
        let mut pixel = Vec::with_capacity(row_units * height);
        for row in 0..height {
            let start = row * stride_bytes;
            pixel.extend_from_slice(&frame[start..start + row_units]);
        }
        pixel
    }

    /// Write back the first `units` modified pixel units from the gathered
    /// pixel-only stream (the inverse of [`gather_pixel_stream`]). The core
    /// kernels only mutate the units they report as modified and never write
    /// on the error path, so `units` bounds the write-back exactly.
    fn scatter_pixel_units(
        pixel: &[u8],
        frame: &mut [u8],
        stride_bytes: usize,
        row_units: usize,
        units: usize,
    ) {
        debug_assert!(pixel.len() >= units);
        for (i, value) in pixel.iter().enumerate().take(units) {
            frame[(i / row_units) * stride_bytes + i % row_units] = *value;
        }
    }

    /// Zero the LSB slots that carried the packet: the first
    /// `packet_len * 8 / bits` pixel-only units' low bits, sequential layout,
    /// mapped through the same stride-aware slot mapping as embed/extract.
    /// This is the exact inverse footprint of a sequential embed of
    /// `packet_len` bytes, so nothing of the packet survives.
    fn clear_sequential_slots(
        frame: &mut [u8],
        stride_bytes: usize,
        row_units: usize,
        height: usize,
        packet_len: usize,
        bits: u8,
    ) {
        let mask = !((1u16 << bits) - 1) as u8;
        let needed_units = (packet_len.saturating_mul(8)).div_ceil(bits as usize);
        let total_units = row_units * height;
        for i in 0..needed_units.min(total_units) {
            frame[(i / row_units) * stride_bytes + i % row_units] &= mask;
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
