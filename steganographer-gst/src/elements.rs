//! Native GStreamer element: `stegovideo` (in-place `BaseTransform`).
//!
//! Runs as a real pipeline element — no AppSink/AppSrc handoff. The
//! embedding mutates only LSB sample slots, so buffers stay the same size
//! and caps never change. Wire format matches the sequential spatial-LSB
//! carrier paths in steganographer-core (`carrier::SpatialLsb`), so output
//! decodes with the existing `decode` CLI command and the same
//! bits-per-unit setting.
//!
//! Element behavior:
//! - `packet-hex`: pre-encoded generic packet bytes (hex). Fresh frames
//!   re-embed the packet unless single-delivery mode is selected.
//! - `clear-payload`: sequential mode delivers each replacement packet once
//!   per stream, then clears its sequential LSB footprint on later frames.
//!   Keyed mode warns and continues re-embedding instead of claiming erasure.
//! - When no packet is set, buffers pass through untouched.
//! - Malformed packets and descriptor/configuration mismatches fail the
//!   pipeline; insufficient-capacity frames remain warned skips.
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
use gstreamer_video::{VideoFormat, VideoFrameRef, VideoInfo};
use std::sync::Arc;
use steganographer_core::carrier::{
    CarrierEmbedder, CarrierError, EmbeddingConfig, KeyedSpatialLsb, SpatialLsb,
};
use steganographer_core::crypto::{decode_hex, encode_hex};
use steganographer_core::kdf::derive_frame_embedding_key;
mod imp {
    use super::*;
    use gstreamer_base::subclass::base_transform::BaseTransformImplExt;

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

    /// Frame snapshots own immutable packet bytes. Placement generations guard
    /// completion against key/bits/lifecycle resets; payload generations guard
    /// one-shot delivery without restarting the keyed frame timeline.
    #[derive(Clone)]
    struct StreamState {
        packet: Option<Arc<[u8]>>,
        key: Option<[u8; 32]>,
        bits_per_unit: u8,
        clear_payload: bool,
        /// Frames that already carried the full packet.
        embedded_frames: u64,
        generation: u64,
        payload_generation: u64,
        payload_delivered: bool,
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
                generation: 0,
                payload_generation: 0,
                payload_delivered: false,
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
            self.generation = self.generation.wrapping_add(1);
            self.payload_delivered = false;
            self.embedded_frames = 0;
            self.skipped_frames = 0;
            self.warned = WarnFlags::default();
        }

        fn replace_packet(&mut self, packet: Option<Arc<[u8]>>) {
            self.packet = packet;
            self.payload_generation = self.payload_generation.wrapping_add(1);
            self.payload_delivered = false;
        }

        fn complete(&mut self, snapshot: &Self, delivered: bool) {
            if self.generation != snapshot.generation {
                return;
            }
            self.embedded_frames = self.embedded_frames.saturating_add(1);
            if delivered && self.payload_generation == snapshot.payload_generation {
                self.payload_delivered = true;
            }
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
                    } else if let Some(key) = decode_hex(&hex).ok().and_then(|b| b.try_into().ok())
                    {
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
                        self.stream.lock().replace_packet(None);
                    } else if let Ok(bytes) = decode_hex(&hex) {
                        self.stream.lock().replace_packet(Some(bytes.into()));
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
                    Some(key) => encode_hex(&key).to_value(),
                    None => String::new().to_value(),
                },
                "packet-hex" => {
                    let stream = self.stream.lock();
                    match stream.packet.as_deref() {
                        Some(bytes) => encode_hex(bytes).to_value(),
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

        fn start(&self) -> Result<(), gstreamer::ErrorMessage> {
            self.parent_start()?;
            self.stream.lock().reset_progress();
            Ok(())
        }

        fn stop(&self) -> Result<(), gstreamer::ErrorMessage> {
            self.stream.lock().reset_progress();
            *self.info.lock() = None;
            self.parent_stop()
        }

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
            // Completion is conditional on this snapshot's generations.
            let snap = self.stream.lock().clone();
            self.transform_snapshot(buf, snap)
        }
    }

    impl StegoVideo {
        fn transform_snapshot(
            &self,
            buf: &mut gstreamer::BufferRef,
            snap: StreamState,
        ) -> Result<gstreamer::FlowSuccess, gstreamer::FlowError> {
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

            let mut frame = VideoFrameRef::from_buffer_ref_writable(buf, &info).map_err(|e| {
                gstreamer::error!(
                    gstreamer::CAT_DEFAULT,
                    imp = self,
                    "failed to map writable video frame: {e}"
                );
                gstreamer::FlowError::Error
            })?;
            let row_units = (info.width() as usize)
                .checked_mul(bpp)
                .ok_or(gstreamer::FlowError::Error)?;
            let height = info.height() as usize;
            let stride_bytes =
                crate::checked_packed_plane(&frame, &info, row_units).map_err(|error| {
                    self.note_skip(
                        SkipReason::FrameSize,
                        &format!("invalid mapped video plane: {error}"),
                    );
                    gstreamer::FlowError::Error
                })?;
            let data = frame
                .plane_data_mut(0)
                .map_err(|_| gstreamer::FlowError::Error)?;

            embed_into_packed_frame(
                self,
                data,
                stride_bytes,
                row_units,
                height,
                packet_bytes,
                &config,
                &snap,
            )
        }
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
    ) -> Result<gstreamer::FlowSuccess, gstreamer::FlowError> {
        if snap.key.is_some() && snap.clear_payload && snap.payload_delivered {
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
        } else if snap.payload_delivered && snap.clear_payload {
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
            state.stream.lock().complete(snap, false);
            return Ok(gstreamer::FlowSuccess::Ok);
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
                let units = if snap.key.is_some() {
                    pixel.len()
                } else {
                    report.modified_units
                };
                scatter_pixel_units(&pixel, data, stride_bytes, row_units, units);
            }
            result
        };

        match result {
            Ok(report) => {
                state.stream.lock().complete(snap, true);
                gstreamer::debug!(
                    gstreamer::CAT_DEFAULT,
                    imp = state,
                    "embedded {} packet bytes into {} units",
                    report.packet_bytes,
                    report.modified_units
                );
            }
            Err(e @ CarrierError::InsufficientCapacity { .. }) => state.note_skip(
                SkipReason::Capacity,
                &format!("packet does not fit frame capacity: {e}; frames remain unembedded"),
            ),
            Err(e) => {
                gstreamer::element_imp_error!(
                    state,
                    gstreamer::StreamError::Format,
                    ("invalid packet embedding configuration: {e}")
                );
                return Err(gstreamer::FlowError::Error);
            }
        }
        Ok(gstreamer::FlowSuccess::Ok)
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

    /// Write back logical pixel units, never row padding. Sequential placement
    /// modifies a prefix; keyed placement requires the complete logical stream
    /// because modified_units is a count, not the last mutated index.
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use steganographer_core::carrier::CarrierExtractor;
        use steganographer_core::packet::{
            AlgorithmDescriptor, DecodeLimits, GenericPacket, PayloadKind, KERNEL_SPATIAL_LSB,
            PLACEMENT_KEYED,
        };

        #[test]
        fn stale_frame_cannot_advance_reset_key_or_bits() {
            gstreamer::init().unwrap();
            for reset_bits in [false, true] {
                let element = glib::Object::new::<super::super::StegoVideo>();
                let imp = element.imp();
                let limits = DecodeLimits::default();
                let packet = |bits| {
                    GenericPacket::new_untransformed(
                        b"new generation".to_vec(),
                        [3; 16],
                        [4; 8],
                        PayloadKind::Text,
                        AlgorithmDescriptor::new(PLACEMENT_KEYED, 1, Vec::new()),
                        AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![bits]),
                        &limits,
                    )
                    .unwrap()
                    .encode(&limits)
                    .unwrap()
                };
                element.set_property("key-hex", encode_hex(&[1; 32]));
                element.set_property("packet-hex", encode_hex(&packet(1)));
                let info = VideoInfo::builder(VideoFormat::Rgb, 64, 32)
                    .build()
                    .unwrap();
                *imp.info.lock() = Some(info.clone());
                // Pause after the exact snapshot used by transform_ip, reset,
                // then finish the old transform before processing the new one.
                let stale = imp.stream.lock().clone();
                let (key, bits) = if reset_bits {
                    element.set_property("bits-per-unit", 2u32);
                    element.set_property("packet-hex", encode_hex(&packet(2)));
                    ([1; 32], 2)
                } else {
                    element.set_property("key-hex", encode_hex(&[2; 32]));
                    ([2; 32], 1)
                };
                let mut old = gstreamer::Buffer::from_mut_slice(vec![0x40; info.size()]);
                imp.transform_snapshot(old.get_mut().unwrap(), stale)
                    .unwrap();
                let mut new = gstreamer::Buffer::from_mut_slice(vec![0x40; info.size()]);
                imp.transform_ip(new.get_mut().unwrap()).unwrap();
                let map = new.map_readable().unwrap();
                let report = KeyedSpatialLsb::new(key)
                    .extract_packet(map.as_ref(), &EmbeddingConfig::new(bits).unwrap(), &limits)
                    .expect("first frame of the reset generation uses its raw key");
                assert_eq!(report.packet.body, b"new generation");
            }
        }

        #[test]
        fn stale_packet_completion_does_not_deliver_its_replacement() {
            gstreamer::init().unwrap();
            let element = glib::Object::new::<super::super::StegoVideo>();
            let imp = element.imp();
            let limits = DecodeLimits::default();
            let packet = |body: &[u8]| {
                GenericPacket::new_untransformed(
                    body.to_vec(),
                    [3; 16],
                    [4; 8],
                    PayloadKind::Text,
                    AlgorithmDescriptor::new(
                        steganographer_core::packet::PLACEMENT_SEQUENTIAL,
                        1,
                        Vec::new(),
                    ),
                    AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![1]),
                    &limits,
                )
                .unwrap()
                .encode(&limits)
                .unwrap()
            };
            let info = VideoInfo::builder(VideoFormat::Rgb, 64, 32)
                .build()
                .unwrap();
            *imp.info.lock() = Some(info.clone());
            element.set_property("clear-payload", true);
            element.set_property("packet-hex", encode_hex(&packet(b"A")));
            let stale = imp.stream.lock().clone();
            element.set_property("packet-hex", encode_hex(&packet(b"B")));
            let mut old = gstreamer::Buffer::from_mut_slice(vec![0x40; info.size()]);
            imp.transform_snapshot(old.get_mut().unwrap(), stale)
                .unwrap();
            let mut new = gstreamer::Buffer::from_mut_slice(vec![0x40; info.size()]);
            imp.transform_ip(new.get_mut().unwrap()).unwrap();
            let map = new.map_readable().unwrap();
            assert_eq!(
                SpatialLsb
                    .extract_packet(map.as_ref(), &EmbeddingConfig::new(1).unwrap(), &limits)
                    .unwrap()
                    .packet
                    .body,
                b"B",
            );
        }
    }
}

glib::wrapper! {
    pub struct StegoVideo(ObjectSubclass<imp::StegoVideo>)
        @extends BaseTransform, gstreamer::Element, gstreamer::Object;
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
