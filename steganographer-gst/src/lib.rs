//! # steganographer-gst
//!
//! GStreamer integration for the steganographer toolkit.
//!
//! Provides:
//! - `pipeline` — AppSink/AppSrc helper utilities for building GStreamer pipelines
//! - [`video_filter`] — Video buffer processing with `VideoStegoModule`
//! - [`audio_filter`] — Audio buffer processing with `AudioStegoModule`
//! - [`plugin`] — GStreamer plugin registration skeleton
//!
//! ## Usage Pattern
//!
//! The primary approach uses `AppSink` to pull frames from a GStreamer source,
//! process them through `steganographer-core` modules, and push the modified
//! frames via `AppSrc` to a GStreamer sink. This avoids needing to compile and
//! install a GStreamer plugin.

pub mod audio_filter;
pub mod plugin;
pub mod video_filter;

/// Initialize GStreamer. Must be called before any pipeline operations.
///
/// On macOS, this also initializes NSApplication to satisfy the NSRunLoop
/// requirement of AVFoundation-based elements (avfvideosrc, osxvideosink).
pub fn init() -> anyhow::Result<()> {
    // macOS: AVFoundation and AppKit elements require an NSApplication
    // to be initialized on the main thread for the NSRunLoop.
    #[cfg(target_os = "macos")]
    {
        init_macos();
    }

    gstreamer::init()?;
    log::info!("GStreamer initialized: version {}", gstreamer::version_string());
    Ok(())
}

/// Initialize NSApplication on macOS.
///
/// This is required for GStreamer elements that use AVFoundation (avfvideosrc)
/// or AppKit (osxvideosink) which need an NSRunLoop on the main thread.
#[cfg(target_os = "macos")]
fn init_macos() {
    #[link(name = "AppKit", kind = "framework")]
    #[link(name = "objc", kind = "dylib")]
    extern "C" {
        fn objc_getClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn sel_registerName(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn objc_msgSend(obj: *mut std::ffi::c_void, sel: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    unsafe {
        // [NSApplication sharedApplication]
        let ns_app_class = objc_getClass(c"NSApplication".as_ptr());
        let shared_app_sel = sel_registerName(c"sharedApplication".as_ptr());
        objc_msgSend(ns_app_class, shared_app_sel);
    }
    log::info!("macOS: [NSApplication sharedApplication] initialized for AppKit support");
}

/// Run the native macOS UI event loop.
/// This must be called from the main thread and will block indefinitely.
#[cfg(target_os = "macos")]
pub fn run_macos_main_loop() {
    #[link(name = "AppKit", kind = "framework")]
    #[link(name = "objc", kind = "dylib")]
    extern "C" {
        fn objc_getClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn sel_registerName(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
        fn objc_msgSend(obj: *mut std::ffi::c_void, sel: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    unsafe {
        let ns_app_class = objc_getClass(c"NSApplication".as_ptr());
        let shared_app_sel = sel_registerName(c"sharedApplication".as_ptr());
        let app = objc_msgSend(ns_app_class, shared_app_sel);

        // [app run]
        let run_sel = sel_registerName(c"run".as_ptr());
        objc_msgSend(app, run_sel);
    }
}

/// Build a simple GStreamer pipeline from a launch string.
///
/// # Example
/// ```no_run
/// # steganographer_gst::init().unwrap();
/// let pipeline = steganographer_gst::launch("videotestsrc ! autovideosink").unwrap();
/// ```
pub fn launch(pipeline_str: &str) -> anyhow::Result<gstreamer::Element> {
    let pipeline = gstreamer::parse::launch(pipeline_str)?;
    log::info!("Pipeline created: {}", pipeline_str);
    Ok(pipeline)
}
