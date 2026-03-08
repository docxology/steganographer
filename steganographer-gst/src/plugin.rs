//! GStreamer plugin registration skeleton.
//!
//! This module provides the boilerplate for registering steganographer filters
//! as native GStreamer elements. When compiled as a `cdylib`, GStreamer can
//! discover and load the plugin dynamically.
//!
//! ## Building as a plugin
//!
//! To build as a loadable GStreamer plugin, add to Cargo.toml:
//! ```toml
//! [lib]
//! crate-type = ["cdylib"]
//! ```
//!
//! Then set `GST_PLUGIN_PATH` to the directory containing the built `.so`/`.dylib`.

/// Plugin metadata.
pub const PLUGIN_NAME: &str = "steganographer";
pub const PLUGIN_DESCRIPTION: &str = "Steganographic video and audio filters";
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Register all steganographer elements with GStreamer.
///
/// This is called by the GStreamer plugin loader. In the current AppSink/AppSrc
/// approach, this is not strictly needed — it's provided as a skeleton for
/// future native plugin development.
pub fn register_elements() -> Result<(), gstreamer::glib::BoolError> {
    log::info!(
        "Registering GStreamer plugin: {} v{}",
        PLUGIN_NAME,
        PLUGIN_VERSION
    );
    // Element registration would go here when implementing BaseTransform subclasses.
    // For now, the AppSink/AppSrc pattern in video_filter and audio_filter is used.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_metadata() {
        assert_eq!(PLUGIN_NAME, "steganographer");
        assert!(!PLUGIN_DESCRIPTION.is_empty());
        assert!(!PLUGIN_VERSION.is_empty());
    }
}
