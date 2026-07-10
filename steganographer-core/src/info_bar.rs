//! Exoteric information bar overlay for video frames.
//!
//! Renders a rich information strip at the bottom of the frame containing:
//! - Timestamp (current date/time)
//! - Barcode pattern generated from the signature hash
//! - QR code encoding the signature + frame metadata
//! - Text details of what is being encoded
//!
//! This is the "exoteric" (visible, outward-facing) complement to the
//! "esoteric" (hidden) LSB steganography.

use crate::crypto::SignaturePayload;
use crate::overlay::get_glyph;
use crate::video::{VideoFormat, VideoFrame, VideoStegoModule};
use qrcode::QrCode;

/// Height of the info bar in pixels.
const BAR_HEIGHT: u32 = 80;
/// Background color for the bar (dark semi-transparent).
const BAR_BG: [u8; 3] = [16, 16, 24];
/// Primary text color (bright cyan).
const TEXT_PRIMARY: [u8; 3] = [0, 220, 255];
/// Secondary text color (dim gray).
const TEXT_SECONDARY: [u8; 3] = [160, 160, 170];
/// Accent color for barcode bars.
const BARCODE_COLOR: [u8; 3] = [0, 255, 128];
/// QR code module color.
const QR_COLOR: [u8; 3] = [255, 255, 255];
/// QR code background.
const QR_BG: [u8; 3] = [16, 16, 24];

/// Exoteric info bar renderer.
///
/// Draws a visible information strip at the bottom of each video frame
/// showing timestamp, barcode, QR code, and encoding details.
pub struct InfoBar {
    /// Label text (e.g., "STEGANOGRAPHER" or custom identifier)
    label: String,
    /// Whether to show the barcode
    show_barcode: bool,
    /// Whether to show the QR code
    show_qr: bool,
    /// Whether to show the timestamp
    show_timestamp: bool,
}

impl InfoBar {
    /// Create a new info bar with default settings (all features enabled).
    pub fn new(label: String) -> Self {
        Self {
            label,
            show_barcode: true,
            show_qr: true,
            show_timestamp: true,
        }
    }

    /// Toggle barcode display.
    pub fn with_barcode(mut self, enabled: bool) -> Self {
        self.show_barcode = enabled;
        self
    }

    /// Toggle QR code display.
    pub fn with_qr(mut self, enabled: bool) -> Self {
        self.show_qr = enabled;
        self
    }

    /// Toggle timestamp display.
    pub fn with_timestamp(mut self, enabled: bool) -> Self {
        self.show_timestamp = enabled;
        self
    }

    /// Render the info bar into a frame.
    fn render_bar(
        &self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            VideoFormat::Yuv420 => return Ok(()), // not supported
        };

        let bar_height = BAR_HEIGHT.min(frame.height / 4); // don't exceed 25% of frame
        if bar_height < 20 || frame.width < 100 {
            return Ok(());
        }

        let bar_top = frame.height - bar_height;

        // 1. Draw background bar
        for y in bar_top..frame.height {
            for x in 0..frame.width {
                let offset = (y * frame.stride + x * bpp as u32) as usize;
                if offset + bpp <= frame.data.len() {
                    match frame.format {
                        VideoFormat::Rgb8 => {
                            frame.data[offset] = BAR_BG[0];
                            frame.data[offset + 1] = BAR_BG[1];
                            frame.data[offset + 2] = BAR_BG[2];
                        }
                        VideoFormat::Bgra8 => {
                            frame.data[offset] = BAR_BG[2];
                            frame.data[offset + 1] = BAR_BG[1];
                            frame.data[offset + 2] = BAR_BG[0];
                            frame.data[offset + 3] = 230; // semi-transparent
                        }
                        _ => {}
                    }
                }
            }
        }

        // 2. Top border line (accent)
        for x in 0..frame.width {
            let offset = (bar_top * frame.stride + x * bpp as u32) as usize;
            if offset + bpp <= frame.data.len() {
                Self::set_pixel(frame, offset, TEXT_PRIMARY);
            }
        }

        let text_y = bar_top + 4;
        let mut cursor_x = 4u32;

        // 3. Timestamp
        if self.show_timestamp {
            let now = chrono::Local::now();
            let ts = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            cursor_x = self.render_text_small(frame, cursor_x, text_y, &ts, TEXT_PRIMARY);
            cursor_x += 12;
        }

        // 4. Frame index
        if let Some(payload) = sig {
            let frame_text = format!("F:{}", payload.frame_index);
            cursor_x = self.render_text_small(frame, cursor_x, text_y, &frame_text, TEXT_PRIMARY);
            cursor_x += 12;
        } else {
            let frame_text = format!("F:{}", frame.frame_index);
            cursor_x = self.render_text_small(frame, cursor_x, text_y, &frame_text, TEXT_PRIMARY);
            cursor_x += 12;
        }

        // 5. Label
        if !self.label.is_empty() {
            let _cx = self.render_text_small(frame, cursor_x, text_y, &self.label, TEXT_SECONDARY);
        }

        // 6. Second row: hash excerpt + signature status
        let text_y2 = text_y + 12;
        let mut cursor_x2 = 4u32;

        if let Some(payload) = sig {
            // Show hash excerpt
            let hash_hex: String = payload
                .hash
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect();
            let hash_text = format!("H:{}", hash_hex);
            cursor_x2 =
                self.render_text_small(frame, cursor_x2, text_y2, &hash_text, TEXT_SECONDARY);
            cursor_x2 += 8;

            // Show "SIGNED" indicator
            cursor_x2 = self.render_text_small(frame, cursor_x2, text_y2, "SIGNED", BARCODE_COLOR);
            cursor_x2 += 8;

            // Show stego type indicator
            let _cx =
                self.render_text_small(frame, cursor_x2, text_y2, "LSB+OVERLAY", TEXT_SECONDARY);
        }

        // 7. Barcode from hash (right portion of bar)
        if self.show_barcode {
            if let Some(payload) = sig {
                let barcode_x = frame.width.saturating_sub(200);
                self.render_barcode(frame, barcode_x, text_y, &payload.hash, bar_height - 8);
            }
        }

        // 8. QR code (far right)
        if self.show_qr {
            if let Some(payload) = sig {
                let qr_size = (bar_height - 8).min(64);
                let qr_x = frame.width.saturating_sub(qr_size + 4);
                let qr_y = bar_top + 4;
                self.render_qr(frame, qr_x, qr_y, payload, qr_size);
            }
        }

        // 9. Third row: encoding details
        let text_y3 = text_y2 + 12;
        if text_y3 + 8 < frame.height && sig.is_some() {
            let detail = "BLAKE3+Ed25519 | 109B payload";
            self.render_text_small(frame, 4, text_y3, detail, TEXT_SECONDARY);
        }

        Ok(())
    }

    /// Render small text (8px, scale 1) at a position. Returns cursor X after text.
    fn render_text_small(
        &self,
        frame: &mut VideoFrame,
        x: u32,
        y: u32,
        text: &str,
        color: [u8; 3],
    ) -> u32 {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            _ => return x,
        };

        for (ci, ch) in text.chars().enumerate() {
            let glyph = get_glyph(ch);
            for row in 0..8u32 {
                for col in 0..8u32 {
                    if glyph[row as usize] & (1 << (7 - col)) != 0 {
                        let px = x + ci as u32 * 8 + col;
                        let py = y + row;
                        if px < frame.width && py < frame.height {
                            let offset = (py * frame.stride + px * bpp as u32) as usize;
                            if offset + bpp <= frame.data.len() {
                                Self::set_pixel(frame, offset, color);
                            }
                        }
                    }
                }
            }
        }
        x + text.len() as u32 * 8
    }

    /// Render a barcode pattern from hash bytes.
    ///
    /// Each bit in the hash becomes a vertical bar (1 = colored, 0 = background).
    fn render_barcode(
        &self,
        frame: &mut VideoFrame,
        start_x: u32,
        start_y: u32,
        hash: &[u8; 32],
        height: u32,
    ) {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            _ => return,
        };

        let bar_width = 1u32; // 1 pixel per bit
        let total_bits = 32 * 8; // 256 bits in hash

        // Render barcode: each bit = one vertical bar
        for bit_idx in 0..total_bits {
            let byte_idx = bit_idx / 8;
            let bit_pos = 7 - (bit_idx % 8);
            let is_set = (hash[byte_idx] >> bit_pos) & 1 == 1;

            let x = start_x + bit_idx as u32 * bar_width;
            if x >= frame.width {
                break;
            }

            for dy in 0..height.min(40) {
                let y = start_y + dy;
                if y >= frame.height {
                    break;
                }
                let offset = (y * frame.stride + x * bpp as u32) as usize;
                if offset + bpp <= frame.data.len() && is_set {
                    Self::set_pixel(frame, offset, BARCODE_COLOR);
                }
            }
        }
    }

    /// Render a QR code from the signature payload.
    fn render_qr(
        &self,
        frame: &mut VideoFrame,
        start_x: u32,
        start_y: u32,
        payload: &SignaturePayload,
        max_size: u32,
    ) {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            _ => return,
        };

        // Encode frame index + hash excerpt as QR content
        let hash_hex: String = payload
            .hash
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect();
        let qr_content = format!("F:{} H:{}", payload.frame_index, hash_hex);

        let code = match QrCode::new(qr_content.as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };

        let matrix = code.to_colors();
        let qr_width = code.width();
        let scale = (max_size as usize / qr_width).max(1);

        for (idx, &color_val) in matrix.iter().enumerate() {
            let qr_x = idx % qr_width;
            let qr_y = idx / qr_width;
            let is_dark = color_val == qrcode::Color::Dark;

            for sy in 0..scale {
                for sx in 0..scale {
                    let px = start_x + (qr_x * scale + sx) as u32;
                    let py = start_y + (qr_y * scale + sy) as u32;
                    if px < frame.width && py < frame.height {
                        let offset = (py * frame.stride + px * bpp as u32) as usize;
                        if offset + bpp <= frame.data.len() {
                            if is_dark {
                                Self::set_pixel(frame, offset, QR_COLOR);
                            } else {
                                Self::set_pixel(frame, offset, QR_BG);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Set a pixel at the given byte offset.
    #[inline]
    fn set_pixel(frame: &mut VideoFrame, offset: usize, color: [u8; 3]) {
        match frame.format {
            VideoFormat::Rgb8 => {
                frame.data[offset] = color[0];
                frame.data[offset + 1] = color[1];
                frame.data[offset + 2] = color[2];
            }
            VideoFormat::Bgra8 => {
                frame.data[offset] = color[2];
                frame.data[offset + 1] = color[1];
                frame.data[offset + 2] = color[0];
                frame.data[offset + 3] = 255;
            }
            _ => {}
        }
    }
}

impl VideoStegoModule for InfoBar {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        log::debug!(
            "InfoBar: rendering on frame {} ({}x{})",
            frame.frame_index,
            frame.width,
            frame.height
        );
        self.render_bar(frame, sig)
    }

    fn extract(&self, _frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        // Info bar is visible, not extractable
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_bar_renders_without_panic() {
        let mut data = vec![128u8; 640 * 480 * 3];
        let mut frame = VideoFrame {
            width: 640,
            height: 480,
            stride: 640 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 42,
        };

        let mut bar = InfoBar::new("STEGANOGRAPHER".to_string());
        bar.embed(&mut frame, None).unwrap();

        // Bottom region should have the bar background. Check a pixel at the bar area
        // but below the text rows (text is at y+4, y+16, y+28; bar extends to frame.height)
        let bar_top = 480 - 80;
        // Pick a pixel at y=bar_top+60 (below text rows) and x=10 (left side, no barcode/QR)
        let check_y = bar_top + 60;
        let offset = (check_y as usize * 640 * 3 + 10 * 3) as usize;
        assert_eq!(data[offset], BAR_BG[0], "Bar background should be rendered");
    }

    #[test]
    fn test_info_bar_with_signature() {
        use crate::crypto::Signer;

        let signer = Signer::generate();
        let payload = signer.sign_frame(100, b"test frame data", None);

        let mut data = vec![200u8; 640 * 480 * 3];
        let mut frame = VideoFrame {
            width: 640,
            height: 480,
            stride: 640 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 100,
        };

        let mut bar = InfoBar::new("SIGNED".to_string());
        bar.embed(&mut frame, Some(&payload)).unwrap();

        // Verify some pixels changed in the bar region
        let bar_top = 480 - 80;
        let bar_region = &data[(bar_top * 640 * 3) as usize..];
        assert!(
            bar_region.iter().any(|&b| b != 200),
            "Bar should modify pixels"
        );
    }

    #[test]
    fn test_info_bar_tiny_frame_no_panic() {
        let mut data = vec![0u8; 50 * 50 * 3];
        let mut frame = VideoFrame {
            width: 50,
            height: 50,
            stride: 50 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };

        let mut bar = InfoBar::new("TEST".to_string());
        // Should not panic on small frames
        bar.embed(&mut frame, None).unwrap();
    }

    #[test]
    fn test_info_bar_bgra() {
        let mut data = vec![128u8; 640 * 480 * 4];
        let mut frame = VideoFrame {
            width: 640,
            height: 480,
            stride: 640 * 4,
            format: VideoFormat::Bgra8,
            data: &mut data,
            frame_index: 0,
        };

        let mut bar = InfoBar::new("BGRA".to_string());
        bar.embed(&mut frame, None).unwrap();
    }

    #[test]
    fn test_info_bar_qr_generation() {
        use crate::crypto::Signer;

        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"qr test", None);

        let mut data = vec![0u8; 800 * 600 * 3];
        let mut frame = VideoFrame {
            width: 800,
            height: 600,
            stride: 800 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };

        let mut bar = InfoBar::new("QR TEST".to_string())
            .with_barcode(true)
            .with_qr(true);
        bar.embed(&mut frame, Some(&payload)).unwrap();

        // QR region should have white pixels
        let qr_region_y = 600 - 80 + 4;
        let qr_region_x = 800 - 68;
        let offset = (qr_region_y * 800 * 3 + qr_region_x * 3) as usize;
        // At least some pixels in that region should be non-zero
        let region = &data[offset..offset + 200.min(data.len() - offset)];
        assert!(
            region.iter().any(|&b| b != 0),
            "QR region should have rendered pixels"
        );
    }
}
