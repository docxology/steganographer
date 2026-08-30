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

/// Register all steganographer elements with a GStreamer plugin.
///
/// `plugin` is `Some` when called by the GStreamer plugin loader (cdylib on
/// `GST_PLUGIN_PATH`) and `None` when an application registers the elements
/// directly into the running registry. Registers the native `BaseTransform`
/// element(s) from [`crate::elements`]; the AppSink/AppSrc helpers remain
/// available for applications that build pipelines without native elements.
pub fn register_elements(
    plugin: Option<&mut gstreamer::Plugin>,
) -> Result<(), gstreamer::glib::BoolError> {
    log::info!(
        "Registering GStreamer plugin: {} v{}",
        PLUGIN_NAME,
        PLUGIN_VERSION
    );
    crate::elements::register(plugin)
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
