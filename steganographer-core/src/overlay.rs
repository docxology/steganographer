//! Text overlay watermark for video frames.
//!
//! Burns text directly into pixel data using a simple bitmap font renderer.
//! No external font libraries required — uses a built-in 8×8 pixel font for
//! ASCII characters. This is intentionally simple; for production use, consider
//! integrating with a font rasterizer.
//!
//! ## Template Placeholders
//!
//! Overlay text supports dynamic substitution at embed-time:
//! - `{timestamp}` — current UTC datetime (`YYYY-MM-DD HH:MM:SS`)
//! - `{frame_index}` — current frame number
//! - `{date}` — current UTC date (`YYYY-MM-DD`)
//! - `{time}` — current UTC time (`HH:MM:SS`)

use crate::crypto::SignaturePayload;
use crate::video::{VideoFormat, VideoFrame, VideoStegoModule};
use chrono::Utc;

/// Text overlay positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayPosition {
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
    Center,
}

impl OverlayPosition {
    /// Parse from a config string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().replace('-', "_").as_str() {
            "top_left" => Self::TopLeft,
            "top_right" => Self::TopRight,
            "bottom_left" => Self::BottomLeft,
            "bottom_right" => Self::BottomRight,
            "center" => Self::Center,
            _ => Self::BottomRight,
        }
    }
}

/// Text overlay steganography module.
///
/// Burns visible text into the video frame. While not hidden (unlike LSB),
/// visually watermarking frames is a complementary anti-tamper technique.
pub struct TextOverlay {
    text: String,
    position: OverlayPosition,
    color: [u8; 3], // RGB
    scale: u8,      // character scale multiplier
}

impl TextOverlay {
    /// Create a new text overlay.
    pub fn new(text: String, position: OverlayPosition) -> Self {
        Self {
            text,
            position,
            color: [255, 255, 255], // white
            scale: 2,
        }
    }

    /// Set the overlay text color (RGB).
    pub fn with_color(mut self, r: u8, g: u8, b: u8) -> Self {
        self.color = [r, g, b];
        self
    }

    /// Set the character scale multiplier (1 = 8px, 2 = 16px, etc).
    pub fn with_scale(mut self, scale: u8) -> Self {
        self.scale = scale.max(1);
        self
    }

    /// Expand template placeholders in the overlay text.
    ///
    /// Supported placeholders:
    /// - `{timestamp}` — current UTC datetime (`YYYY-MM-DD HH:MM:SS`)
    /// - `{frame_index}` — current video frame index
    /// - `{date}` — current UTC date (`YYYY-MM-DD`)
    /// - `{time}` — current UTC time (`HH:MM:SS`)
    pub fn expand_template(text: &str, frame_index: u64) -> String {
        let now = Utc::now();
        text.replace("{timestamp}", &now.format("%Y-%m-%d %H:%M:%S").to_string())
            .replace("{frame_index}", &frame_index.to_string())
            .replace("{date}", &now.format("%Y-%m-%d").to_string())
            .replace("{time}", &now.format("%H:%M:%S").to_string())
    }

    /// Render text into a frame at the configured position.
    fn render_text(&self, frame: &mut VideoFrame) -> anyhow::Result<()> {
        if self.text.is_empty() {
            return Ok(());
        }

        let char_w = 8 * self.scale as u32;
        let char_h = 8 * self.scale as u32;
        let text_w = self.text.len() as u32 * char_w;
        let text_h = char_h;
        let margin = 4u32;

        // Compute origin based on position
        let (start_x, start_y) = match self.position {
            OverlayPosition::TopLeft => (margin, margin),
            OverlayPosition::TopRight => (frame.width.saturating_sub(text_w + margin), margin),
            OverlayPosition::BottomLeft => (margin, frame.height.saturating_sub(text_h + margin)),
            OverlayPosition::BottomRight => (
                frame.width.saturating_sub(text_w + margin),
                frame.height.saturating_sub(text_h + margin),
            ),
            OverlayPosition::Center => (
                frame.width.saturating_sub(text_w) / 2,
                frame.height.saturating_sub(text_h) / 2,
            ),
        };

        let bpp = match frame.format {
            VideoFormat::Rgb8 => 3,
            VideoFormat::Bgra8 => 4,
            VideoFormat::Yuv420 => return Ok(()), // not supported for overlay
        };

        for (ci, ch) in self.text.chars().enumerate() {
            let glyph = get_glyph(ch);
            for row in 0..8u32 {
                for col in 0..8u32 {
                    if glyph[row as usize] & (1 << (7 - col)) != 0 {
                        // Scale up the pixel
                        for sy in 0..self.scale as u32 {
                            for sx in 0..self.scale as u32 {
                                let px =
                                    start_x + ci as u32 * char_w + col * self.scale as u32 + sx;
                                let py = start_y + row * self.scale as u32 + sy;
                                if px < frame.width && py < frame.height {
                                    let offset = (py * frame.stride + px * bpp as u32) as usize;
                                    if offset + bpp <= frame.data.len() {
                                        match frame.format {
                                            VideoFormat::Rgb8 => {
                                                frame.data[offset] = self.color[0];
                                                frame.data[offset + 1] = self.color[1];
                                                frame.data[offset + 2] = self.color[2];
                                            }
                                            VideoFormat::Bgra8 => {
                                                frame.data[offset] = self.color[2]; // B
                                                frame.data[offset + 1] = self.color[1]; // G
                                                frame.data[offset + 2] = self.color[0]; // R
                                                frame.data[offset + 3] = 255; // A
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl VideoStegoModule for TextOverlay {
    fn embed(
        &mut self,
        frame: &mut VideoFrame,
        _sig: Option<&SignaturePayload>,
    ) -> anyhow::Result<()> {
        // Expand template placeholders before rendering
        let original_text = self.text.clone();
        self.text = Self::expand_template(&original_text, frame.frame_index);
        log::debug!(
            "Overlay: rendering '{}' at {:?} (frame {})",
            self.text,
            self.position,
            frame.frame_index
        );
        let result = self.render_text(frame);
        // Restore original template text for next frame
        self.text = original_text;
        result
    }

    fn extract(&self, _frame: &VideoFrame) -> anyhow::Result<Option<SignaturePayload>> {
        // Text overlay is visible, not extractable as data
        Ok(None)
    }
}

/// Built-in 8×8 bitmap font for printable ASCII (subset).
/// Each character is 8 rows, each row is a u8 bitmask.
pub fn get_glyph(ch: char) -> [u8; 8] {
    match ch {
        ' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '!' => [0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00],
        '#' => [0x24, 0x7E, 0x24, 0x24, 0x7E, 0x24, 0x00, 0x00],
        ':' => [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00],
        '-' => [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
        '/' => [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00],
        '0' => [0x3C, 0x42, 0x46, 0x4A, 0x52, 0x62, 0x3C, 0x00],
        '1' => [0x08, 0x18, 0x08, 0x08, 0x08, 0x08, 0x1C, 0x00],
        '2' => [0x3C, 0x42, 0x02, 0x0C, 0x30, 0x40, 0x7E, 0x00],
        '3' => [0x3C, 0x42, 0x02, 0x1C, 0x02, 0x42, 0x3C, 0x00],
        '4' => [0x04, 0x0C, 0x14, 0x24, 0x7E, 0x04, 0x04, 0x00],
        '5' => [0x7E, 0x40, 0x7C, 0x02, 0x02, 0x42, 0x3C, 0x00],
        '6' => [0x1C, 0x20, 0x40, 0x7C, 0x42, 0x42, 0x3C, 0x00],
        '7' => [0x7E, 0x02, 0x04, 0x08, 0x10, 0x10, 0x10, 0x00],
        '8' => [0x3C, 0x42, 0x42, 0x3C, 0x42, 0x42, 0x3C, 0x00],
        '9' => [0x3C, 0x42, 0x42, 0x3E, 0x02, 0x04, 0x38, 0x00],
        'A' | 'a' => [0x18, 0x24, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x00],
        'B' | 'b' => [0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C, 0x00],
        'C' | 'c' => [0x3C, 0x42, 0x40, 0x40, 0x40, 0x42, 0x3C, 0x00],
        'D' | 'd' => [0x78, 0x44, 0x42, 0x42, 0x42, 0x44, 0x78, 0x00],
        'E' | 'e' => [0x7E, 0x40, 0x40, 0x7C, 0x40, 0x40, 0x7E, 0x00],
        'F' | 'f' => [0x7E, 0x40, 0x40, 0x7C, 0x40, 0x40, 0x40, 0x00],
        'G' | 'g' => [0x3C, 0x42, 0x40, 0x4E, 0x42, 0x42, 0x3C, 0x00],
        'H' | 'h' => [0x42, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x42, 0x00],
        'I' | 'i' => [0x3E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x3E, 0x00],
        'J' | 'j' => [0x1E, 0x04, 0x04, 0x04, 0x04, 0x44, 0x38, 0x00],
        'K' | 'k' => [0x42, 0x44, 0x48, 0x70, 0x48, 0x44, 0x42, 0x00],
        'L' | 'l' => [0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x7E, 0x00],
        'M' | 'm' => [0x42, 0x66, 0x5A, 0x42, 0x42, 0x42, 0x42, 0x00],
        'N' | 'n' => [0x42, 0x62, 0x52, 0x4A, 0x46, 0x42, 0x42, 0x00],
        'O' | 'o' => [0x3C, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C, 0x00],
        'P' | 'p' => [0x7C, 0x42, 0x42, 0x7C, 0x40, 0x40, 0x40, 0x00],
        'Q' | 'q' => [0x3C, 0x42, 0x42, 0x42, 0x4A, 0x44, 0x3A, 0x00],
        'R' | 'r' => [0x7C, 0x42, 0x42, 0x7C, 0x48, 0x44, 0x42, 0x00],
        'S' | 's' => [0x3C, 0x42, 0x40, 0x3C, 0x02, 0x42, 0x3C, 0x00],
        'T' | 't' => [0x7F, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00],
        'U' | 'u' => [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C, 0x00],
        'V' | 'v' => [0x42, 0x42, 0x42, 0x42, 0x24, 0x24, 0x18, 0x00],
        'W' | 'w' => [0x42, 0x42, 0x42, 0x42, 0x5A, 0x66, 0x42, 0x00],
        'X' | 'x' => [0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x42, 0x00],
        'Y' | 'y' => [0x41, 0x22, 0x14, 0x08, 0x08, 0x08, 0x08, 0x00],
        'Z' | 'z' => [0x7E, 0x04, 0x08, 0x10, 0x20, 0x40, 0x7E, 0x00],
        '{' => [0x0E, 0x08, 0x08, 0x30, 0x08, 0x08, 0x0E, 0x00],
        '}' => [0x70, 0x10, 0x10, 0x0C, 0x10, 0x10, 0x70, 0x00],
        '_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00],
        _ => [0x7E, 0x42, 0x42, 0x42, 0x42, 0x42, 0x7E, 0x00], // box for unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::video::VideoFormat;

    #[test]
    fn test_overlay_renders_without_panic() {
        let mut data = vec![0u8; 320 * 240 * 3];
        let mut frame = VideoFrame {
            width: 320,
            height: 240,
            stride: 320 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };

        let mut overlay = TextOverlay::new("HELLO".to_string(), OverlayPosition::TopLeft);
        overlay.embed(&mut frame, None).unwrap();

        // Check that some pixels were written (text starts at margin=4, scale=2)
        // So the first rendered row is at y=4
        assert!(
            data.iter().any(|&b| b != 0),
            "Overlay should write pixels somewhere in the frame"
        );
    }

    #[test]
    fn test_overlay_positions() {
        for pos in &[
            OverlayPosition::TopLeft,
            OverlayPosition::TopRight,
            OverlayPosition::BottomLeft,
            OverlayPosition::BottomRight,
            OverlayPosition::Center,
        ] {
            let mut data = vec![0u8; 320 * 240 * 3];
            let mut frame = VideoFrame {
                width: 320,
                height: 240,
                stride: 320 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            let mut overlay = TextOverlay::new("TEST".to_string(), *pos);
            let result = overlay.embed(&mut frame, None);
            assert!(result.is_ok(), "Overlay at {:?} should not fail", pos);
        }
    }

    #[test]
    fn test_overlay_bgra() {
        let mut data = vec![0u8; 320 * 240 * 4];
        let mut frame = VideoFrame {
            width: 320,
            height: 240,
            stride: 320 * 4,
            format: VideoFormat::Bgra8,
            data: &mut data,
            frame_index: 0,
        };

        let mut overlay = TextOverlay::new("BGRA".to_string(), OverlayPosition::Center);
        overlay.embed(&mut frame, None).unwrap();
    }

    #[test]
    fn test_overlay_color() {
        let mut data = vec![0u8; 320 * 240 * 3];
        let mut frame = VideoFrame {
            width: 320,
            height: 240,
            stride: 320 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };

        let mut overlay =
            TextOverlay::new("RED".to_string(), OverlayPosition::TopLeft).with_color(255, 0, 0);
        overlay.embed(&mut frame, None).unwrap();

        // Find first non-zero pixel and check it's red
        for i in (0..data.len()).step_by(3) {
            if data[i] != 0 || data[i + 1] != 0 || data[i + 2] != 0 {
                assert_eq!(data[i], 255, "R channel should be 255");
                assert_eq!(data[i + 1], 0, "G channel should be 0");
                assert_eq!(data[i + 2], 0, "B channel should be 0");
                break;
            }
        }
    }

    #[test]
    fn test_position_from_str() {
        assert_eq!(OverlayPosition::parse("top-left"), OverlayPosition::TopLeft);
        assert_eq!(
            OverlayPosition::parse("bottom_right"),
            OverlayPosition::BottomRight
        );
        assert_eq!(OverlayPosition::parse("CENTER"), OverlayPosition::Center);
        assert_eq!(
            OverlayPosition::parse("unknown"),
            OverlayPosition::BottomRight
        );
    }

    #[test]
    fn test_empty_text() {
        let mut data = vec![0u8; 320 * 240 * 3];
        let original = data.clone();
        let mut frame = VideoFrame {
            width: 320,
            height: 240,
            stride: 320 * 3,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let mut overlay = TextOverlay::new(String::new(), OverlayPosition::TopLeft);
        overlay.embed(&mut frame, None).unwrap();
        assert_eq!(data, original, "Empty text should not modify frame");
    }

    #[test]
    fn test_template_timestamp() {
        let expanded = TextOverlay::expand_template("TS:{timestamp}", 0);
        // Should be something like "TS:2026-03-07 20:25:52"
        assert!(
            expanded.starts_with("TS:20"),
            "Should start with year prefix, got: {}",
            expanded
        );
        assert!(expanded.contains('-'), "Should contain date separator");
        assert!(expanded.contains(':'), "Should contain time separator");
        assert!(
            !expanded.contains("{timestamp}"),
            "Placeholder should be replaced"
        );
    }

    #[test]
    fn test_template_frame_index() {
        let expanded = TextOverlay::expand_template("F:{frame_index}", 42);
        assert_eq!(expanded, "F:42");

        let expanded2 = TextOverlay::expand_template("Frame {frame_index} of stream", 1000);
        assert_eq!(expanded2, "Frame 1000 of stream");
    }

    #[test]
    fn test_template_multiple() {
        let expanded = TextOverlay::expand_template("{date} F{frame_index} {time}", 7);
        assert!(
            !expanded.contains("{date}"),
            "date placeholder should be replaced"
        );
        assert!(expanded.contains("F7"), "frame_index should be 7");
        assert!(
            !expanded.contains("{time}"),
            "time placeholder should be replaced"
        );

        // No placeholders should pass through unchanged
        let plain = TextOverlay::expand_template("HELLO WORLD", 0);
        assert_eq!(plain, "HELLO WORLD");
    }
}
