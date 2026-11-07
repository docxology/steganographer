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
/// Dark QR modules on a light background, including the quiet zone.
const QR_COLOR: [u8; 3] = [0, 0, 0];
/// QR code background.
const QR_BG: [u8; 3] = [255, 255, 255];

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
    /// Whether to render the OTS (OpenTimestamps) status badge.
    /// When `true`, a small "OTS" indicator is drawn in the info bar.
    /// Default: `false` — OTS is opt-in.
    include_ots_indicator: bool,
}

impl InfoBar {
    /// Create a new info bar with default settings (all features enabled).
    pub fn new(label: String) -> Self {
        Self {
            label,
            show_barcode: true,
            show_qr: true,
            show_timestamp: true,
            include_ots_indicator: false,
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

    /// Toggle the OpenTimestamps status indicator badge in the info bar.
    pub fn with_ots_indicator(mut self, enabled: bool) -> Self {
        self.include_ots_indicator = enabled;
        self
    }

    /// Whether the OTS indicator is enabled.
    pub fn includes_ots_indicator(&self) -> bool {
        self.include_ots_indicator
    }

    /// Render the info bar into a frame.
    fn render_bar(
        &self,
        frame: &mut VideoFrame,
        sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        let bpp = frame.validate_packed_layout()?;
        let bar_height = BAR_HEIGHT.min(frame.height / 4);
        anyhow::ensure!(bar_height >= 20, "Info bar does not fit the frame");
        let bar_top = frame.height - bar_height;

        // Measure every requested machine-code footprint before modifying pixels.
        let qr = if self.show_qr {
            sig.map(|payload| {
                let hash_hex: String = payload
                    .hash
                    .iter()
                    .take(16)
                    .map(|b| format!("{:02x}", b))
                    .collect();
                QrCode::new(format!("F:{} H:{}", payload.frame_index, hash_hex).as_bytes())
            })
            .transpose()?
        } else {
            None
        };
        let qr_size = if let Some(code) = &qr {
            let modules = code.width() as u32 + 8; // Four-module quiet zone.
            let max_size = bar_height - 8;
            anyhow::ensure!(
                modules <= max_size,
                "Requested QR code does not fit the info bar"
            );
            modules * (max_size / modules)
        } else {
            0
        };
        let barcode_width = if self.show_barcode && sig.is_some() {
            256
        } else {
            0
        };
        let reserved = 4
            + if qr_size > 0 { qr_size + 8 } else { 0 }
            + if barcode_width > 0 {
                barcode_width + 8
            } else {
                0
            };
        let text_right = frame
            .width
            .checked_sub(reserved)
            .ok_or_else(|| anyhow::anyhow!("Requested info-bar codes do not fit the frame"))?;
        let frame_index = sig.map_or(frame.frame_index, |payload| payload.frame_index);
        let mut line = String::new();
        if self.show_timestamp {
            line.push_str(
                &chrono::Local::now()
                    .format("%Y-%m-%d %H:%M:%S%.3f")
                    .to_string(),
            );
            line.push(' ');
        }
        line.push_str(&format!("F:{}", frame_index));
        if !self.label.is_empty() {
            line.push(' ');
            line.push_str(&self.label);
        }
        let mut lines = vec![line];
        if let Some(payload) = sig {
            let hash_hex: String = payload
                .hash
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect();
            lines.push(format!("H:{} SIGNED", hash_hex));
            lines.push(if self.include_ots_indicator {
                "109B payload | OTS configured".to_string()
            } else {
                "109B signature payload".to_string()
            });
        }
        anyhow::ensure!(
            4 + lines.len() as u32 * 12 <= bar_height,
            "Requested info-bar text does not fit its height"
        );
        for line in &lines {
            let width = u32::try_from(line.chars().count())?
                .checked_mul(8)
                .ok_or_else(|| anyhow::anyhow!("Info-bar text width overflow"))?;
            anyhow::ensure!(
                width
                    .checked_add(4)
                    .is_some_and(|right| right <= text_right),
                "Requested info-bar text and codes do not fit without overlap"
            );
        }
        for y in bar_top..frame.height {
            for x in 0..frame.width {
                let offset = y as usize * frame.stride as usize + x as usize * bpp;
                Self::set_pixel(frame, offset, BAR_BG);
            }
        }
        for x in 0..frame.width {
            let offset = bar_top as usize * frame.stride as usize + x as usize * bpp;
            Self::set_pixel(frame, offset, TEXT_PRIMARY);
        }
        for (row, line) in lines.iter().enumerate() {
            self.render_text_small(
                frame,
                4,
                bar_top + 4 + row as u32 * 12,
                line,
                if row == 0 {
                    TEXT_PRIMARY
                } else {
                    TEXT_SECONDARY
                },
            );
        }
        let qr_x = frame.width - 4 - qr_size;
        if let Some(code) = &qr {
            self.render_qr(frame, qr_x, bar_top + 4, code, qr_size);
        }
        if barcode_width > 0 {
            let barcode_x = if qr_size > 0 {
                qr_x - 8 - 256
            } else {
                frame.width - 4 - 256
            };
            self.render_barcode(
                frame,
                barcode_x,
                bar_top + 4,
                &sig.expect("measured signed barcode").hash,
                bar_height - 8,
            );
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
                            let offset = py as usize * frame.stride as usize + px as usize * bpp;
                            if offset + bpp <= frame.data.len() {
                                Self::set_pixel(frame, offset, color);
                            }
                        }
                    }
                }
            }
        }
        x.saturating_add(
            u32::try_from(text.chars().count())
                .unwrap_or(u32::MAX)
                .saturating_mul(8),
        )
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
                let offset = y as usize * frame.stride as usize + x as usize * bpp;
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
        code: &QrCode,
        max_size: u32,
    ) {
        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3usize,
            VideoFormat::Bgra8 => 4usize,
            _ => return,
        };

        let matrix = code.to_colors();
        let qr_width = code.width();
        let modules = qr_width + 8;
        let scale = max_size as usize / modules;

        for module_y in 0..modules {
            for module_x in 0..modules {
                let is_dark = module_x >= 4
                    && module_x < qr_width + 4
                    && module_y >= 4
                    && module_y < qr_width + 4
                    && matrix[(module_y - 4) * qr_width + module_x - 4] == qrcode::Color::Dark;

                for sy in 0..scale {
                    for sx in 0..scale {
                        let px = start_x + (module_x * scale + sx) as u32;
                        let py = start_y + (module_y * scale + sy) as u32;
                        if px < frame.width && py < frame.height {
                            let offset = py as usize * frame.stride as usize + px as usize * bpp;
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
    fn full_hash_barcode_includes_the_final_bit() {
        let mut payload = crate::crypto::Signer::generate().sign_frame(0, b"barcode", None);
        payload.hash = [0; 32];
        payload.hash[31] = 1;
        let mut data = vec![0; 800 * 600 * 3];
        let mut frame = VideoFrame {
            width: 800,
            height: 600,
            stride: 2400,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        InfoBar::new(String::new())
            .with_qr(false)
            .with_timestamp(false)
            .embed(&mut frame, Some(&payload))
            .unwrap();
        let last_bit = (520 + 4) * 2400 + (800 - 4 - 1) * 3;
        assert_eq!(&data[last_bit..last_bit + 3], &BARCODE_COLOR);
        assert_eq!(&data[last_bit - 3..last_bit], &BAR_BG);
    }

    #[test]
    fn requested_codes_that_do_not_fit_fail_without_mutation() {
        let payload = crate::crypto::Signer::generate().sign_frame(0, b"small QR", None);
        let mut data = vec![0x80; 100 * 80 * 3];
        let before = data.clone();
        let mut frame = VideoFrame {
            width: 100,
            height: 80,
            stride: 300,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let mut bar = InfoBar::new(String::new())
            .with_barcode(false)
            .with_timestamp(false);
        assert!(bar.embed(&mut frame, Some(&payload)).is_err());
        assert_eq!(data, before);
    }

    #[test]
    fn qr_matrix_and_quiet_zone_are_complete() {
        let payload = crate::crypto::Signer::generate().sign_frame(0, b"QR", None);
        let hash: String = payload
            .hash
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect();
        let code = QrCode::new(format!("F:0 H:{}", hash).as_bytes()).unwrap();
        let modules = code.width() + 8;
        let side = modules * (72 / modules);
        let start_x = 800 - 4 - side;
        let mut data = vec![0x80; 800 * 600 * 3];
        let mut frame = VideoFrame {
            width: 800,
            height: 600,
            stride: 2400,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        InfoBar::new(String::new())
            .with_barcode(false)
            .with_timestamp(false)
            .embed(&mut frame, Some(&payload))
            .unwrap();
        let scale = side / modules;
        for y in 0..modules {
            for x in 0..modules {
                let dark = x >= 4
                    && x < modules - 4
                    && y >= 4
                    && y < modules - 4
                    && code[(x - 4, y - 4)] == qrcode::Color::Dark;
                let offset = (524 + y * scale) * 2400 + (start_x + x * scale) * 3;
                assert_eq!(
                    &data[offset..offset + 3],
                    if dark { &QR_COLOR } else { &QR_BG }
                );
            }
        }
    }

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
        let offset = check_y as usize * 640 * 3 + 10 * 3;
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
        assert!(bar.embed(&mut frame, None).is_err());
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

    #[test]
    fn test_info_bar_ots_indicator_default_off() {
        let bar = InfoBar::new("TEST".to_string());
        assert!(!bar.includes_ots_indicator());
    }

    #[test]
    fn test_info_bar_ots_indicator_enabled() {
        use crate::crypto::Signer;

        let signer = Signer::generate();
        let payload = signer.sign_frame(0, b"ots test", None);

        let mut data = vec![0u8; 640 * 480 * 3];
        let mut frame = VideoFrame {
            width: 640,
            height: 480,
            stride: 640 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };

        let mut bar = InfoBar::new("OTS TEST".to_string()).with_ots_indicator(true);
        assert!(bar.includes_ots_indicator());
        bar.embed(&mut frame, Some(&payload)).unwrap();

        // The info bar should render without panic. The OTS badge is in the
        // third row of the bar; verify the bar region was modified.
        let bar_top = 480 - 80;
        let bar_region = &data[(bar_top * 640 * 3) as usize..];
        assert!(
            bar_region.iter().any(|&b| b != 0),
            "Bar with OTS indicator should modify pixels"
        );
    }
}
