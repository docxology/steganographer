//! Native GStreamer element: `stegovideo` (in-place `BaseTransform`).
//!
//! Runs as a real pipeline element — no AppSink/AppSrc handoff. The
//! embedding mutates only LSB sample slots, so buffers stay the same size
//! and caps never change. Wire format matches the raw LSB paths in
//! steganographer-core, so output verifies with the existing `verify`
//! command and the same key.
//!
//! This first slice wires negotiation and in-place access; the payload
//! writer hooks into [`LsbVideo`] below.

use gstreamer::glib;
use gstreamer::prelude::*;
use gstreamer::subclass::prelude::*;
use gstreamer_base::subclass::base_transform::BaseTransformImpl;
use gstreamer_base::subclass::BaseTransformMode;
use gstreamer_base::BaseTransform;
use gstreamer_video::VideoInfo;

mod imp {
    use super::*;

    /// Per-element state.
    #[derive(Default)]
    pub struct StegoVideo {
        info: std::sync::Mutex<Option<VideoInfo>>,
        key: std::sync::Mutex<[u8; 32]>,
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
            PROPS.get_or_init(|| vec![glib::ParamSpecString::builder("key-hex").build()])
        }

        fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
            match pspec.name() {
                "key-hex" => {
                    if let Some(key) =
                        decode_key(value.get::<String>().unwrap_or_default().as_str())
                    {
                        *self.key.lock().unwrap() = key;
                    }
                }
                _ => unimplemented!(),
            }
        }

        fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
            match pspec.name() {
                "key-hex" => hex_encode(*self.key.lock().unwrap()).to_value(),
                _ => unimplemented!(),
            }
        }
    }

    impl GstObjectImpl for StegoVideo {}
    impl ElementImpl for StegoVideo {}

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
            *self.info.lock().unwrap() = Some(info);
            Ok(())
        }

        fn transform_ip(
            &self,
            _buf: &mut gstreamer::BufferRef,
        ) -> Result<gstreamer::FlowSuccess, gstreamer::FlowError> {
            // Payload-embedding slice lands with the LsbVideo byte-slot API.
            Ok(gstreamer::FlowSuccess::Ok)
        }
    }
}

glib::wrapper! {
    pub struct StegoVideo(ObjectSubclass<imp::StegoVideo>)
        @extends BaseTransform, gstreamer::Element, gstreamer::Object;
}

/// Decode a hex string into exactly `out_len` bytes.
fn decode_hex_fixed(s: &str, out_len: usize) -> Option<Vec<u8>> {
    if s.len() != out_len * 2 {
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

/// Register steganographer elements, optionally under a loaded plugin.
pub fn register(plugin: Option<&mut gstreamer::Plugin>) -> Result<(), glib::BoolError> {
    gstreamer::Element::register(
        plugin.as_deref(),
        "stegovideo",
        gstreamer::Rank::NONE,
        StegoVideo::static_type(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_fixed_hex_keys() {
        let key = decode_key(&"ab".repeat(32)).expect("valid 64-char hex");
        assert_eq!(key[0], 0xab);
        assert!(decode_key("zz").is_none());
        assert!(decode_key("ab").is_none()); // wrong length
    }

    #[test]
    fn registers_element_type() {
        gstreamer::init().unwrap();
        let el = glib::Object::new::<StegoVideo>();
        assert!(!el.name().is_empty());
        let kv: String = el.property("key-hex");
        assert_eq!(kv.len(), 64);
    }
}
