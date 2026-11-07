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
    /// Validate a packed RGB/BGRA view, including padding and the final row.
    /// Planar formats require a separate plane-layout contract.
    pub fn validate_packed_layout(&self) -> anyhow::Result<usize> {
        let bpp = self
            .format
            .bytes_per_pixel()
            .ok_or_else(|| anyhow::anyhow!("Planar video is not supported by this module"))?;
        anyhow::ensure!(
            self.width > 0 && self.height > 0,
            "Video dimensions must be positive"
        );
        let row_bytes = (self.width as usize)
            .checked_mul(bpp)
            .ok_or_else(|| anyhow::anyhow!("Video row size overflow"))?;
        anyhow::ensure!(
            self.stride as usize >= row_bytes,
            "Video stride is smaller than a pixel row"
        );
        let extent = (self.height as usize - 1)
            .checked_mul(self.stride as usize)
            .and_then(|offset| offset.checked_add(row_bytes))
            .ok_or_else(|| anyhow::anyhow!("Video extent overflow"))?;
        anyhow::ensure!(extent <= self.data.len(), "Video data is truncated");
        Ok(bpp)
    }

    /// Logical byte count, excluding padding; rejects unrepresentable sizes.
    /// This does not validate the backing view: use [`Self::validate_packed_layout`].
    pub fn pixel_byte_count(&self) -> anyhow::Result<usize> {
        let pixels = (self.width as usize)
            .checked_mul(self.height as usize)
            .ok_or_else(|| anyhow::anyhow!("Video pixel count overflow"))?;
        let count = match self.format.bytes_per_pixel() {
            Some(bpp) => pixels.checked_mul(bpp),
            None => (self.width as usize)
                .div_ceil(2)
                .checked_mul((self.height as usize).div_ceil(2))
                .and_then(|chroma| chroma.checked_mul(2))
                .and_then(|chroma| pixels.checked_add(chroma)),
        };
        count.ok_or_else(|| anyhow::anyhow!("Video pixel byte count overflow"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_layout_checks_stride_truncation_and_overflow() {
        let mut data = [0; 21];
        let mut frame = VideoFrame {
            width: 3,
            height: 2,
            stride: 12,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        assert_eq!(frame.validate_packed_layout().unwrap(), 3);
        assert_eq!(frame.pixel_byte_count().unwrap(), 18);
        frame.stride = 8;
        assert!(frame.validate_packed_layout().is_err());
        frame.stride = 13;
        assert!(frame.validate_packed_layout().is_err());
        frame.width = u32::MAX;
        frame.height = u32::MAX;
        frame.stride = u32::MAX;
        assert!(frame.validate_packed_layout().is_err());
        assert!(frame.pixel_byte_count().is_err());
        frame.width = 0;
        assert!(frame.validate_packed_layout().is_err());
        frame.format = VideoFormat::Yuv420;
        assert!(frame.validate_packed_layout().is_err());
    }

    #[test]
    fn planar_420_counts_both_rounded_chroma_planes() {
        for (width, height, expected) in [(2, 2, 6), (3, 1, 7), (1, 3, 7), (3, 3, 17)] {
            let frame = VideoFrame {
                width,
                height,
                stride: width,
                format: VideoFormat::Yuv420,
                data: &mut [],
                frame_index: 0,
            };
            assert_eq!(frame.pixel_byte_count().unwrap(), expected);
        }
        let frame = VideoFrame {
            width: u32::MAX,
            height: u32::MAX,
            stride: u32::MAX,
            format: VideoFormat::Yuv420,
            data: &mut [],
            frame_index: 0,
        };
        assert!(frame.pixel_byte_count().is_err());
    }
}
