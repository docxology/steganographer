#![no_main]

use libfuzzer_sys::fuzz_target;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

// Fuzz LSB video extraction: the extractor must never panic on adversarial data.
fuzz_target!(|data: &[u8]| {
    let Some((&control, pixels)) = data.split_first() else {
        return;
    };
    if pixels.len() > u32::MAX as usize {
        return;
    }
    // Keep the depth independent of carrier bits so every valid header is reachable.
    let bits = (control % 4) + 1;
    let lsb = LsbVideo::new(bits);
    let mut owned = pixels.to_vec();
    let frame = VideoFrame {
        width: pixels.len() as u32 / 3,
        height: 1,
        stride: pixels.len() as u32,
        format: VideoFormat::Rgb8,
        data: &mut owned,
        frame_index: 0,
    };
    let _ = lsb.extract(&frame);
});
