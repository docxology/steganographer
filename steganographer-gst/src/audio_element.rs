//! Native GStreamer element: `stegoaudio` (in-place `BaseTransform`).
//!
//! Audio sibling of `stegovideo`. Embeds a pre-encoded generic packet into
//! interleaved little-endian S16 PCM samples without changing buffer sizes or
//! caps, using the sequential `carrier::AudioSpatialLsb` kernel by default and
//! the keyed `carrier::KeyedAudioSpatialLsb` carrier when `key-hex` is set.
//! Wire format matches the sequential/keyed spatial-LSB audio paths in
//! steganographer-core, so output verifies with the existing `packet extract`
//! CLI command (`--stego-type lsb_audio`, plus `--embedding-key` for keyed
//! carriers).
//!
//! Element behavior:
//! - `packet-hex`: pre-encoded generic packet bytes (hex). Every buffer is
//!   embedded with the packet (fresh buffers re-embed; the packet lands in the
//!   leading slots of each buffer so extraction from the first buffer works).
//! - `key-hex`: 32-byte hex embedding key. When set, packet bits are placed by
//!   the keyed permutation (and a keyed recognition tag occupies the canonical
//!   bootstrap slots); extraction then requires `packet extract
//!   --embedding-key`. Keyed placement is carrier-scoped in steganographer-core
//!   (the recognition tag binds the unit count), so keyed output decodes from a
//!   single buffer, not from a multi-buffer concatenation.
//! - `clear-payload`: sequential mode only. After the first embedded buffer,
//!   clear the packet LSB slots instead of re-embedding (single-buffer
//!   delivery). With a key set, `clear-payload` is ignored with a one-time
//!   warning (keyed slots are permutation-scattered; re-embedding is kept).
//! - When no packet is set, buffers pass through untouched.

use gstreamer::glib;
use gstreamer::prelude::*;
use gstreamer::subclass::prelude::*;
use gstreamer_audio::AudioFormat;
use gstreamer_audio::AudioInfo;
use gstreamer_audio::AudioLayout;
use gstreamer_base::subclass::base_transform::BaseTransformImpl;
use gstreamer_base::subclass::BaseTransformMode;
use gstreamer_base::BaseTransform;
use steganographer_core::carrier::{
    AudioSpatialLsb, CarrierEmbedder, EmbeddingConfig, KeyedAudioSpatialLsb,
};
use steganographer_core::kdf::derive_frame_embedding_key;

mod imp {
    use super::*;

    /// Per-element state.
    pub struct StegoAudio {
        info: parking_lot::Mutex<Option<AudioInfo>>,
        key: parking_lot::Mutex<Option<[u8; 32]>>,
        packet: parking_lot::Mutex<Option<Vec<u8>>>,
        clear_payload: parking_lot::Mutex<bool>,
        bits_per_unit: parking_lot::Mutex<u8>,
        /// Buffers that already carried the full packet.
        embedded_buffers: parking_lot::Mutex<u64>,
        /// Buffers skipped (capacity or format limits); logged once.
        skipped_buffers: parking_lot::Mutex<u64>,
        /// Whether the keyed `clear-payload` warning was already emitted.
        clear_unsupported_warned: parking_lot::Mutex<bool>,
    }

    impl Default for StegoAudio {
        fn default() -> Self {
            Self {
                info: parking_lot::Mutex::new(None),
                key: parking_lot::Mutex::new(None),
                packet: parking_lot::Mutex::new(None),
                clear_payload: parking_lot::Mutex::new(false),
                bits_per_unit: parking_lot::Mutex::new(1),
                embedded_buffers: parking_lot::Mutex::new(0),
                skipped_buffers: parking_lot::Mutex::new(0),
                clear_unsupported_warned: parking_lot::Mutex::new(false),
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
            // Any-caps templates: set_caps enforces interleaved S16LE and
            // pass-through keeps non-audio-raw formats negotiable.
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

    impl BaseTransformImpl for StegoAudio {
        const MODE: BaseTransformMode = BaseTransformMode::AlwaysInPlace;
        const PASSTHROUGH_ON_SAME_CAPS: bool = false;
        const TRANSFORM_IP_ON_PASSTHROUGH: bool = false;

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
                note_skip(
                    self,
                    "buffer length is not a whole number of S16 samples; passing through",
                );
                return Ok(gstreamer::FlowSuccess::Ok);
            }

            let key = *self.key.lock();
            let clear = *self.clear_payload.lock();
            let already = *self.embedded_buffers.lock();

            if key.is_some() && clear && already > 0 {
                let mut warned = self.clear_unsupported_warned.lock();
                if !*warned {
                    gstreamer::warning!(
                        gstreamer::CAT_PERFORMANCE,
                        "clear-payload is unsupported with keyed placement; re-embedding every buffer"
                    );
                    *warned = true;
                }
            } else if clear && already > 0 {
                clear_packet_slots(data, packet_bytes.len(), bits);
                *self.embedded_buffers.lock() += 1;
                return Ok(gstreamer::FlowSuccess::Ok);
            }

            let result = match key {
                // Frame-scoped keyed placement (see stegovideo): frame 0
                // keeps the raw key, later frames mix the buffer counter in.
                Some(embedding_key) => {
                    let frame_key =
                        derive_frame_embedding_key(&embedding_key, *self.embedded_buffers.lock());
                    KeyedAudioSpatialLsb::new(frame_key).embed_packet(data, &packet_bytes, &config)
                }
                None => AudioSpatialLsb.embed_packet(data, &packet_bytes, &config),
            };
            match result {
                Ok(report) => {
                    *self.embedded_buffers.lock() += 1;
                    gstreamer::debug!(
                        gstreamer::CAT_DEFAULT,
                        imp = self,
                        "embedded {} packet bytes into {} units",
                        report.packet_bytes,
                        report.modified_units
                    );
                }
                Err(e) => {
                    note_skip(
                        self,
                        &format!(
                            "packet does not fit buffer capacity: {e}; buffer remains unembedded"
                        ),
                    );
                }
            }
            Ok(gstreamer::FlowSuccess::Ok)
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

    fn note_skip(state: &StegoAudio, message: &str) {
        let mut skipped = state.skipped_buffers.lock();
        *skipped += 1;
        if *skipped == 1 {
            gstreamer::warning!(gstreamer::CAT_PERFORMANCE, "{}", message);
        }
    }
}

glib::wrapper! {
    pub struct StegoAudio(ObjectSubclass<imp::StegoAudio>)
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

#[cfg(test)]
mod tests {
    use super::*;
    use steganographer_core::carrier::{CarrierExtractor, EmbeddingConfig};
    use steganographer_core::packet::{
        AlgorithmDescriptor, DecodeLimits, GenericPacket, PayloadKind, KERNEL_SPATIAL_LSB,
        PLACEMENT_KEYED, PLACEMENT_SEQUENTIAL,
    };

    fn test_packet(payload: &[u8], keyed: bool) -> Vec<u8> {
        let limits = DecodeLimits::default();
        let placement = if keyed {
            PLACEMENT_KEYED
        } else {
            PLACEMENT_SEQUENTIAL
        };
        let packet = GenericPacket::new_untransformed(
            payload.to_vec(),
            [7u8; 16],
            [9u8; 8],
            PayloadKind::Text,
            AlgorithmDescriptor::new(placement, 1, Vec::new()),
            AlgorithmDescriptor::new(KERNEL_SPATIAL_LSB, 1, vec![1]),
            &limits,
        )
        .unwrap();
        packet.encode(&limits).unwrap()
    }

    #[test]
    fn registers_element_type() {
        gstreamer::init().unwrap();
        let el = glib::Object::new::<StegoAudio>();
        assert!(!el.name().is_empty());
        let kv: String = el.property("key-hex");
        assert!(kv.is_empty());
        let ph: String = el.property("packet-hex");
        assert!(ph.is_empty());
        assert!(!el.property::<bool>("clear-payload"));
        assert_eq!(el.property::<u32>("bits-per-unit"), 1);
    }

    #[test]
    fn set_property_parses_key_and_clears_on_empty() {
        gstreamer::init().unwrap();
        let el = glib::Object::new::<StegoAudio>();
        el.set_property("key-hex", hex_encode([9u8; 32]));
        assert_eq!(el.property::<String>("key-hex"), hex_encode([9u8; 32]));
        el.set_property("key-hex", String::new());
        assert_eq!(el.property::<String>("key-hex"), "");
    }

    #[test]
    fn sequential_round_trips_through_core_audio_lsb() {
        gstreamer::init().unwrap();
        let limits = DecodeLimits::default();
        let packet_bytes = test_packet(b"stegoaudio roundtrip", false);

        // The element's sequential embed path is the core audio kernel: the
        // same wire format verifies through the core extractor.
        let mut pcm = vec![0x10u8; 2 * 4096];
        AudioSpatialLsb
            .embed_packet(&mut pcm, &packet_bytes, &EmbeddingConfig::new(1).unwrap())
            .unwrap();
        let report = AudioSpatialLsb
            .extract_packet(&pcm, &EmbeddingConfig::new(1).unwrap(), &limits)
            .unwrap();
        assert_eq!(report.packet.body, b"stegoaudio roundtrip".to_vec());
    }

    #[test]
    fn keyed_round_trips_and_diverges_by_key() {
        gstreamer::init().unwrap();
        let limits = DecodeLimits::default();
        let packet_bytes = test_packet(b"keyed audio", true);
        let config = EmbeddingConfig::new(1).unwrap();

        let mut carrier_a = vec![0x20u8; 2 * 8192];
        KeyedAudioSpatialLsb::new([1u8; 32])
            .embed_packet(&mut carrier_a, &packet_bytes, &config)
            .unwrap();
        let mut carrier_b = vec![0x20u8; 2 * 8192];
        KeyedAudioSpatialLsb::new([2u8; 32])
            .embed_packet(&mut carrier_b, &packet_bytes, &config)
            .unwrap();

        // Equal buffers, different embedding keys: the modified slot sets
        // differ (keyed placement, not a fixed leading layout).
        let changed: Vec<usize> = carrier_a
            .iter()
            .zip(&carrier_b)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert!(
            !changed.is_empty(),
            "keyed embeddings must differ between keys"
        );
        // Both carriers embed the same keyed packet: each decodes under its
        // own key and fails under the other's.
        let report = KeyedAudioSpatialLsb::new([1u8; 32])
            .extract_packet(&carrier_a, &config, &limits)
            .unwrap();
        assert_eq!(report.packet.body, b"keyed audio".to_vec());
        assert!(
            KeyedAudioSpatialLsb::new([2u8; 32])
                .extract_packet(&carrier_a, &config, &limits)
                .is_err(),
            "wrong key must not decode a keyed audio carrier"
        );
    }

    #[test]
    fn keyed_buffers_diverge_by_frame_index() {
        gstreamer::init().unwrap();
        use steganographer_core::kdf::derive_frame_embedding_key;
        let limits = DecodeLimits::default();
        let packet_bytes = test_packet(b"frame-indexed audio", true);
        let config = EmbeddingConfig::new(1).unwrap();

        let embed_buffer = |index: u64| {
            let mut pcm = vec![0x20u8; 2 * 8192];
            KeyedAudioSpatialLsb::new(derive_frame_embedding_key(&[7u8; 32], index))
                .embed_packet(&mut pcm, &packet_bytes, &config)
                .unwrap();
            pcm
        };

        let buf0 = embed_buffer(0);
        let buf1 = embed_buffer(1);
        assert_ne!(buf0, buf1, "equal buffers at different indices must differ");

        for (index, buf) in [(0u64, &buf0), (1, &buf1)] {
            let report = KeyedAudioSpatialLsb::new(derive_frame_embedding_key(&[7u8; 32], index))
                .extract_packet(buf, &config, &limits)
                .unwrap();
            assert_eq!(report.packet.body, b"frame-indexed audio");
        }
        assert!(KeyedAudioSpatialLsb::new([7u8; 32])
            .extract_packet(&buf1, &config, &limits)
            .is_err());
    }

    #[test]
    fn decode_key_rejects_bad_hex() {
        assert!(decode_key(&"ab".repeat(32)).is_some());
        assert!(decode_key("zz").is_none());
        assert!(decode_key("ab").is_none());
    }
}
