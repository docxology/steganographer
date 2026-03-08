//! Video frame types and steganography trait.

use crate::crypto::SignaturePayload;

/// Pixel format of a video frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoFormat {
    /// 3 bytes per pixel: R, G, B
    Rgb8,
    /// 4 bytes per pixel: B, G, R, A
    Bgra8,
    /// Planar YUV 4:2:0
    Yuv420,
}

impl VideoFormat {
    /// Bytes per pixel for packed formats. Returns `None` for planar formats.
    pub fn bytes_per_pixel(&self) -> Option<usize> {
        match self {
            VideoFormat::Rgb8 => Some(3),
            VideoFormat::Bgra8 => Some(4),
            VideoFormat::Yuv420 => None, // planar
        }
    }
}

/// A mutable reference to a video frame's raw pixel data.
pub struct VideoFrame<'a> {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: VideoFormat,
    pub data: &'a mut [u8],
    pub frame_index: u64,
}

impl<'a> VideoFrame<'a> {
    /// Total number of usable pixel bytes (width * height * bpp for packed formats).
    pub fn pixel_byte_count(&self) -> usize {
        match self.format.bytes_per_pixel() {
            Some(bpp) => self.width as usize * self.height as usize * bpp,
            None => {
                // YUV420: Y plane = w*h, U and V planes = w*h/4 each
                let y = self.width as usize * self.height as usize;
                y + y / 2
            }
        }
    }
}

/// Trait for video steganography modules.
///
/// Implementors embed data into or extract data from video frames.
pub trait VideoStegoModule: Send {
    /// Embed a signature payload into a video frame.
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()>;

    /// Extract a signature payload from a video frame.
    fn extract(&self, frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>>;
}
