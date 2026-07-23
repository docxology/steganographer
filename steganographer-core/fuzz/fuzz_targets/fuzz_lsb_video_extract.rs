#![no_main]

use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};
use libfuzzer_sys::fuzz_target;

// Fuzz LSB video extraction: the extractor must never panic on adversarial data.
fuzz_target!(|data: &[u8]| {
    if data.len() < 100 {
        return;
    }
    let bits = (data[0] % 4) + 1;
    let lsb = LsbVideo::new(bits);
    let mut owned = data.to_vec();
    let frame = VideoFrame {
        width: data.len() as u32 / 3,
        height: 1,
        stride: data.len() as u32,
        format: VideoFormat::Rgb8,
        data: &mut owned,
        frame_index: 0,
    };
    let _ = lsb.extract(&frame);
});
