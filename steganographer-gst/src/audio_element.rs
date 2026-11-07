//! Native GStreamer element: `stegoaudio` (in-place `BaseTransform`).
//!
//! Audio sibling of `stegovideo`. Embeds a pre-encoded generic packet into
//! interleaved little-endian S16 PCM samples without changing buffer sizes or
//! caps, using the sequential `carrier::AudioSpatialLsb` kernel by default and
//! the keyed `carrier::KeyedAudioSpatialLsb` carrier when `key-hex` is set.
//! Wire format matches the sequential/keyed spatial-LSB audio paths in
//! steganographer-core, so output decodes with the existing `decode`
//! CLI command (`--stego-type lsb_audio`, plus `--embedding-key` for keyed
//! carriers).
//!
//! Element behavior:
//! - `packet-hex`: pre-encoded generic packet bytes (hex). Every buffer is
//!   embedded with the packet (fresh buffers re-embed; the packet lands in the
//!   leading slots of each buffer so extraction from the first buffer works).
//! - `key-hex`: 32-byte hex embedding key. When set, packet bits are placed by
//!   the keyed permutation (and a keyed recognition tag occupies the canonical
//!   bootstrap slots); extraction then requires `decode --embedding-key`.
//!   Keyed placement is carrier-scoped in steganographer-core
//!   (the recognition tag binds the unit count), so keyed output decodes from a
//!   single buffer, not from a multi-buffer concatenation.
//! - `clear-payload`: sequential mode delivers each replacement packet once
//!   per stream, then clears the packet LSB slots on later buffers. With a
//!   key set, it is ignored with a one-time warning: re-embedding continues.
//! - When no packet is set, buffers pass through untouched.
//! - Malformed packets and descriptor/configuration mismatches fail the
//!   pipeline; insufficient-capacity buffers remain warned skips.
//! - Pad templates are restricted to `audio/x-raw, format=S16LE,
//!   layout=interleaved`: negotiation fails loudly for anything else. The
//!   `set_caps` gate stays as a backstop.
//! - Property changes apply at frame granularity (see `StreamState` in the
//!   imp module); `key-hex`/`bits-per-unit` changes reset the buffer counter.

use gstreamer::glib;
use gstreamer::prelude::*;
use gstreamer::subclass::prelude::*;
use gstreamer_audio::AudioFormat;
use gstreamer_audio::AudioInfo;
use gstreamer_audio::AudioLayout;
use gstreamer_base::subclass::base_transform::BaseTransformImpl;
use gstreamer_base::subclass::BaseTransformMode;
use gstreamer_base::BaseTransform;
use std::sync::Arc;
use steganographer_core::carrier::{
    AudioSpatialLsb, CarrierEmbedder, CarrierError, EmbeddingConfig, KeyedAudioSpatialLsb,
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
        unaligned_buffer: bool,
        capacity: bool,
        keyed_clear: bool,
    }

    /// Skip-reason selector for [`StreamState::note_skip`].
    #[derive(Clone, Copy)]
    enum SkipReason {
        UnalignedBuffer,
        Capacity,
    }

    impl WarnFlags {
        fn slot(&mut self, reason: SkipReason) -> &mut bool {
            match reason {
                SkipReason::UnalignedBuffer => &mut self.unaligned_buffer,
                SkipReason::Capacity => &mut self.capacity,
            }
        }
    }

    /// Immutable frame snapshots with separate placement and payload generations:
    /// old completions cannot advance a reset key or deliver a replacement packet.
    #[derive(Clone)]
    struct StreamState {
        packet: Option<Arc<[u8]>>,
        key: Option<[u8; 32]>,
        bits_per_unit: u8,
        clear_payload: bool,
        /// Buffers that already carried the full packet.
        embedded_buffers: u64,
        generation: u64,
        payload_generation: u64,
        payload_delivered: bool,
        /// Buffers skipped (capacity or alignment limits); warned once per
        /// reason.
        skipped_buffers: u64,
        warned: WarnFlags,
    }

    impl Default for StreamState {
        fn default() -> Self {
            Self {
                packet: None,
                key: None,
                bits_per_unit: 1,
                clear_payload: false,
                embedded_buffers: 0,
                generation: 0,
                payload_generation: 0,
                payload_delivered: false,
                skipped_buffers: 0,
                warned: WarnFlags::default(),
            }
        }
    }

    impl StreamState {
        /// Count a skipped buffer; returns true only the first time for the
        /// reason so callers warn once per reason.
        fn note_skip(&mut self, reason: SkipReason) -> bool {
            self.skipped_buffers += 1;
            let slot = self.warned.slot(reason);
            let first = !*slot;
            *slot = true;
            first
        }

        /// Reset per-stream progress after a property change that alters the
        /// placement or wire format: the next buffer starts from buffer 0.
        fn reset_progress(&mut self) {
            self.generation = self.generation.wrapping_add(1);
            self.payload_delivered = false;
            self.embedded_buffers = 0;
            self.skipped_buffers = 0;
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
            self.embedded_buffers = self.embedded_buffers.saturating_add(1);
            if delivered && self.payload_generation == snapshot.payload_generation {
                self.payload_delivered = true;
            }
        }
    }

    /// Per-element state.
    pub struct StegoAudio {
        info: parking_lot::Mutex<Option<AudioInfo>>,
        /// Streaming parameters + counters; see [`StreamState`] for the
        /// ordering contract.
        stream: parking_lot::Mutex<StreamState>,
    }

    impl Default for StegoAudio {
        fn default() -> Self {
            Self {
                info: parking_lot::Mutex::new(None),
                stream: parking_lot::Mutex::new(StreamState::default()),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for StegoAudio {
        const NAME: &'static str = "StegoAudio";
        type Type = super::StegoAudio;
        type ParentType = BaseTransform;
    }

    impl ObjectImpl for StegoAudio {
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
                                "key-hex cleared; sequential placement from the next buffer"
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

    impl GstObjectImpl for StegoAudio {}

    impl ElementImpl for StegoAudio {
        fn metadata() -> Option<&'static gstreamer::subclass::ElementMetadata> {
            static ELEMENT_METADATA: std::sync::LazyLock<gstreamer::subclass::ElementMetadata> =
                std::sync::LazyLock::new(|| {
                    gstreamer::subclass::ElementMetadata::new(
                        "Steganographer Audio",
                        "Filter/Effect/Audio",
                        "Embeds a generic steganography packet into interleaved S16LE PCM samples (LSB)",
                        "docxology contributors",
                    )
                });
            Some(&ELEMENT_METADATA)
        }

        fn pad_templates() -> &'static [gstreamer::PadTemplate] {
            // Restricted templates: negotiation fails loudly for anything
            // outside interleaved S16LE, instead of silently passing buffers
            // through unembedded. The set_caps gate stays as a backstop; the
            // legacy AppSink/AppSrc filters negotiate their own caps and are
            // unaffected.
            static PAD_TEMPLATES: std::sync::LazyLock<Vec<gstreamer::PadTemplate>> =
                std::sync::LazyLock::new(|| {
                    let caps = gstreamer::Caps::builder_full()
                        .structure(
                            gstreamer::Structure::builder("audio/x-raw")
                                .field("format", "S16LE")
                                .field("layout", "interleaved")
                                .field("rate", gstreamer::IntRange::new(1, i32::MAX))
                                .field("channels", gstreamer::IntRange::new(1, i32::MAX))
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

    impl BaseTransformImpl for StegoAudio {
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
            let info = AudioInfo::from_caps(incaps).map_err(|e| {
                gstreamer::loggable_error!(gstreamer::CAT_DEFAULT, "bad audio caps: {e}")
            })?;
            if info.format() != AudioFormat::S16le || info.layout() != AudioLayout::Interleaved {
                return Err(gstreamer::loggable_error!(
                    gstreamer::CAT_DEFAULT,
                    "stegoaudio requires interleaved S16LE audio; got {:?}/{:?}",
                    info.format(),
                    info.layout()
                ));
            }
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

    impl StegoAudio {
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
            if self.info.lock().is_none() {
                gstreamer::warning!(
                    gstreamer::CAT_PERFORMANCE,
                    imp = self,
                    "no negotiated caps yet; passing buffer through"
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
            if data.len() % 2 != 0 {
                self.note_skip(
                    SkipReason::UnalignedBuffer,
                    "buffer length is not a whole number of S16 samples; passing through",
                );
                return Ok(gstreamer::FlowSuccess::Ok);
            }

            if snap.key.is_some() && snap.clear_payload && snap.payload_delivered {
                let first = {
                    let mut stream = self.stream.lock();
                    let first = !stream.warned.keyed_clear;
                    stream.warned.keyed_clear = true;
                    first
                };
                if first {
                    gstreamer::warning!(
                        gstreamer::CAT_PERFORMANCE,
                        imp = self,
                        "clear-payload is unsupported with keyed placement; re-embedding every buffer"
                    );
                }
            } else if snap.payload_delivered && snap.clear_payload {
                // Clear the packet slots (packet_len * 8 LSB bits at the
                // leading sequential sample slots) and stop embedding after
                // the first delivery buffer.
                clear_packet_slots(data, packet_bytes.len(), snap.bits_per_unit);
                self.stream.lock().complete(&snap, false);
                return Ok(gstreamer::FlowSuccess::Ok);
            }

            let result = match snap.key {
                // Frame-scoped keyed placement (see stegovideo): buffer 0
                // keeps the raw key, later buffers mix the buffer counter in.
                Some(embedding_key) => {
                    let frame_key =
                        derive_frame_embedding_key(&embedding_key, snap.embedded_buffers);
                    KeyedAudioSpatialLsb::new(frame_key).embed_packet(data, packet_bytes, &config)
                }
                None => AudioSpatialLsb.embed_packet(data, packet_bytes, &config),
            };
            match result {
                Ok(report) => {
                    self.stream.lock().complete(&snap, true);
                    gstreamer::debug!(
                        gstreamer::CAT_DEFAULT,
                        imp = self,
                        "embedded {} packet bytes into {} units",
                        report.packet_bytes,
                        report.modified_units
                    );
                }
                Err(e @ CarrierError::InsufficientCapacity { .. }) => self.note_skip(
                    SkipReason::Capacity,
                    &format!("packet does not fit buffer capacity: {e}; buffer remains unembedded"),
                ),
                Err(e) => {
                    gstreamer::element_imp_error!(
                        self,
                        gstreamer::StreamError::Format,
                        ("invalid packet embedding configuration: {e}")
                    );
                    return Err(gstreamer::FlowError::Error);
                }
            }
            Ok(gstreamer::FlowSuccess::Ok)
        }
        /// Count a skipped buffer and warn once per skip reason.
        fn note_skip(&self, reason: SkipReason, message: &str) {
            if self.stream.lock().note_skip(reason) {
                gstreamer::warning!(gstreamer::CAT_PERFORMANCE, imp = self, "{}", message);
            }
        }
    }

    /// Zero the LSB slots that carried the packet: the first
    /// `packet_len * 8 / bits` S16 samples' low bytes, sequential layout.
    fn clear_packet_slots(data: &mut [u8], packet_len: usize, bits: u8) {
        let mask = !((1u16 << bits) - 1) as u8;
        let needed_units = (packet_len.saturating_mul(8)).div_ceil(bits as usize);
        let max_units = data.len() / 2;
        for unit in 0..needed_units.min(max_units) {
            let slot = unit * 2;
            data[slot] &= mask;
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
        fn stale_buffer_cannot_advance_reset_key_or_bits() {
            gstreamer::init().unwrap();
            for reset_bits in [false, true] {
                let element = glib::Object::new::<super::super::StegoAudio>();
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
                *imp.info.lock() = Some(
                    AudioInfo::builder(AudioFormat::S16le, 8000, 1)
                        .build()
                        .unwrap(),
                );
                let stale = imp.stream.lock().clone();
                let (key, bits) = if reset_bits {
                    element.set_property("bits-per-unit", 2u32);
                    element.set_property("packet-hex", encode_hex(&packet(2)));
                    ([1; 32], 2)
                } else {
                    element.set_property("key-hex", encode_hex(&[2; 32]));
                    ([2; 32], 1)
                };
                let mut old = gstreamer::Buffer::from_mut_slice(vec![0x40; 16384]);
                imp.transform_snapshot(old.get_mut().unwrap(), stale)
                    .unwrap();
                let mut new = gstreamer::Buffer::from_mut_slice(vec![0x40; 16384]);
                imp.transform_ip(new.get_mut().unwrap()).unwrap();
                let map = new.map_readable().unwrap();
                let report = KeyedAudioSpatialLsb::new(key)
                    .extract_packet(map.as_ref(), &EmbeddingConfig::new(bits).unwrap(), &limits)
                    .expect("first buffer of the reset generation uses its raw key");
                assert_eq!(report.packet.body, b"new generation");
            }
        }

        #[test]
        fn stale_packet_completion_does_not_deliver_its_replacement() {
            gstreamer::init().unwrap();
            let element = glib::Object::new::<super::super::StegoAudio>();
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
            *imp.info.lock() = Some(
                AudioInfo::builder(AudioFormat::S16le, 8000, 1)
                    .build()
                    .unwrap(),
            );
            element.set_property("clear-payload", true);
            element.set_property("packet-hex", encode_hex(&packet(b"A")));
            let stale = imp.stream.lock().clone();
            element.set_property("packet-hex", encode_hex(&packet(b"B")));
            let mut old = gstreamer::Buffer::from_mut_slice(vec![0x40; 16384]);
            imp.transform_snapshot(old.get_mut().unwrap(), stale)
                .unwrap();
            let mut new = gstreamer::Buffer::from_mut_slice(vec![0x40; 16384]);
            imp.transform_ip(new.get_mut().unwrap()).unwrap();
            let map = new.map_readable().unwrap();
            assert_eq!(
                AudioSpatialLsb
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
    pub struct StegoAudio(ObjectSubclass<imp::StegoAudio>)
        @extends BaseTransform, gstreamer::Element, gstreamer::Object;
}
