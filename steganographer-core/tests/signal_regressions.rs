//! Public behavioral regressions for integer signal kernels and ECC.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use steganographer_core::audio::{AudioBuffer, AudioStegoModule};
use steganographer_core::crypto::{SignaturePayload, Signer};
use steganographer_core::dct_video::DctVideo;
use steganographer_core::error_correction::{decode, encode};
use steganographer_core::mdct_audio::MdctAudio;
use steganographer_core::spread_spectrum::{SpreadSpectrumAudio, SpreadSpectrumVideo};
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
struct CountingAllocator;
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|enabled| {
            if enabled.get() {
                ALLOCATIONS.with(|count| count.set(count.get() + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        COUNTING.with(|enabled| {
            if enabled.get() {
                ALLOCATIONS.with(|count| count.set(count.get() + 1));
            }
        });
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn rgb(data: &mut [u8], width: u32, height: u32) -> VideoFrame<'_> {
    VideoFrame {
        width,
        height,
        stride: width * 3,
        format: VideoFormat::Rgb8,
        data,
        frame_index: 0,
    }
}

#[test]
fn short_audio_rejection_is_atomic_even_after_many_available_bits() {
    let payload = Signer::from_bytes(&[7; 32]).sign_frame(0, b"short", None);
    let mut ss = SpreadSpectrumAudio::with_key([0; 32]);
    for len in [0, 1024, 55807] {
        let mut samples = vec![1234; len];
        let mut buf = AudioBuffer {
            channels: 1,
            sample_rate: 48000,
            samples: &mut samples,
            frame_index: 0,
        };
        assert!(ss.embed(&mut buf, Some(&payload)).is_err());
        assert!(buf.samples.iter().all(|&sample| sample == 1234));
    }
}

#[test]
fn spread_audio_preserves_separate_channels_and_roundtrips_at_exact_capacity() {
    let payload = Signer::from_bytes(&[7; 32]).sign_frame(0, b"stereo", None);
    let mut samples: Vec<i16> = [30000, -30000]
        .into_iter()
        .cycle()
        .take(55808 * 2)
        .collect();
    let mut buf = AudioBuffer {
        channels: 2,
        sample_rate: 48000,
        samples: &mut samples,
        frame_index: 0,
    };
    let mut ss = SpreadSpectrumAudio::with_key([0; 32]);
    ss.embed(&mut buf, Some(&payload)).unwrap();
    for pair in buf.samples.as_chunks::<2>().0 {
        assert!((pair[0] as i32 - 30000).abs() <= 3);
        assert_eq!(pair[1], -30000);
    }
    assert_eq!(
        ss.extract(&buf).unwrap().unwrap().to_bytes(),
        payload.to_bytes()
    );
}

#[test]
fn spread_video_preserves_alpha_colors_and_padding() {
    let payload = Signer::from_bytes(&[7; 32]).sign_frame(0, b"BGRA", None);
    let width = 256usize;
    let height = 218usize; // exactly 55808 green pixels
    let stride = width * 4 + 7;
    let mut data = vec![91; stride * height];
    for row in data.chunks_exact_mut(stride) {
        for pixel in row[..width * 4].as_chunks_mut::<4>().0 {
            pixel.copy_from_slice(&[0, 0, 0, 255]);
        }
    }
    let mut frame = VideoFrame {
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
        format: VideoFormat::Bgra8,
        data: &mut data,
        frame_index: 0,
    };
    let mut ss = SpreadSpectrumVideo::with_key([0; 32]);
    ss.embed(&mut frame, Some(&payload)).unwrap();
    assert_eq!(
        ss.extract(&frame).unwrap().unwrap().to_bytes(),
        payload.to_bytes()
    );
    for row in frame.data.chunks_exact(stride) {
        for pixel in row[..width * 4].as_chunks::<4>().0 {
            assert_eq!(pixel[0], 0);
            assert!(pixel[1] <= 3);
            assert_eq!(pixel[2], 0);
            assert_eq!(pixel[3], 255);
        }
        assert!(row[width * 4..].iter().all(|&byte| byte == 91));
    }
}

#[test]
fn spread_scalar_gradient_random_and_extreme_covers_recover_framed_signature() {
    let payload = Signer::from_bytes(&[17; 32]).sign_frame(0, b"textured scalar cover", None);
    let mut framed = (SignaturePayload::SERIALIZED_SIZE as u32)
        .to_le_bytes()
        .to_vec();
    framed.extend_from_slice(&payload.to_bytes());
    let used = framed.len() * 8 * 64;
    let ss = SpreadSpectrumVideo::with_key([13; 32]);
    for cover in 0..3 {
        let mut state = 0x82a2_b175_229d_6a5bu64;
        // The first cover is the unchanged CLI's 640x480 raw RGB fixture.
        let mut data: Vec<u8> = (0..640 * 480 * 3)
            .map(|i| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                match cover {
                    0 => (i % 251) as u8,
                    1 => (state >> 32) as u8,
                    _ => {
                        if i % 2 == 0 {
                            0
                        } else {
                            255
                        }
                    }
                }
            })
            .collect();
        let before = data.clone();
        for pos in 0..framed.len() * 8 {
            ss.embed_bit(
                &mut data,
                pos * 64,
                (framed[pos / 8] >> (pos % 8)) & 1,
                pos,
                0,
            )
            .unwrap();
        }
        let mut recovered = vec![0u8; framed.len()];
        for pos in 0..framed.len() * 8 {
            recovered[pos / 8] |= ss.extract_bit(&data, pos * 64, pos, 0).unwrap() << (pos % 8);
        }
        assert_eq!(recovered, framed);
        assert!(data[..used]
            .iter()
            .zip(&before)
            .all(|(&after, &before)| (i32::from(after) - i32::from(before)).abs() <= 3));
        assert_eq!(data[used..], before[used..]);
    }
}

#[test]
fn spread_video_random_and_endpoint_covers_agree_with_scalar_helpers() {
    let payload = Signer::from_bytes(&[19; 32]).sign_frame(27, b"integer video projection", None);
    let bytes = payload.to_bytes();
    let spread = 9;
    let width = 109usize;
    let height = 72usize; // Exactly 109 * 8 * 9 green pixels.
    let stride = width * 4 + 5;
    for amplitude in [1, 3, 4, 255] {
        for cover in 0..3 {
            let mut state = 0xbef9_a3f7_859a_cdedu64;
            let mut data: Vec<u8> = (0..stride * height + 11)
                .map(|_| {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    (state >> 32) as u8
                })
                .collect();
            for unit in 0..width * height {
                let at = (unit / width) * stride + (unit % width) * 4 + 1;
                if cover == 1 {
                    data[at] = if unit % 2 == 0 { 0 } else { 255 };
                }
                if cover == 2 {
                    data[at] = 255;
                }
            }
            let before = data.clone();
            let mut scalars: Vec<u8> = (0..width * height)
                .map(|unit| before[(unit / width) * stride + (unit % width) * 4 + 1])
                .collect();
            let mut ss = SpreadSpectrumVideo::new([23; 32], amplitude, spread);
            for pos in 0..bytes.len() * 8 {
                ss.embed_bit(
                    &mut scalars,
                    pos * spread,
                    (bytes[pos / 8] >> (pos % 8)) & 1,
                    pos,
                    27,
                )
                .unwrap();
            }
            let mut expected = before.clone();
            for (unit, &scalar) in scalars.iter().enumerate() {
                let at = (unit / width) * stride + (unit % width) * 4 + 1;
                assert!((i32::from(scalar) - i32::from(before[at])).abs() <= amplitude);
                expected[at] = scalar;
            }
            let mut frame = VideoFrame {
                width: width as u32,
                height: height as u32,
                stride: stride as u32,
                format: VideoFormat::Bgra8,
                data: &mut data,
                frame_index: 27,
            };
            ss.embed(&mut frame, Some(&payload)).unwrap();
            assert_eq!(&*frame.data, expected.as_slice());
            assert_eq!(ss.extract(&frame).unwrap().unwrap().to_bytes(), bytes);
            let mut recovered = [0; SignaturePayload::SERIALIZED_SIZE];
            for pos in 0..bytes.len() * 8 {
                recovered[pos / 8] |=
                    ss.extract_bit(&scalars, pos * spread, pos, 27).unwrap() << (pos % 8);
            }
            assert_eq!(recovered, bytes);
        }
    }
}

#[test]
fn spread_pcm_random_and_endpoint_covers_agree_with_scalar_helpers() {
    let payload = Signer::from_bytes(&[29; 32]).sign_frame(41, b"integer PCM projection", None);
    let bytes = payload.to_bytes();
    let spread = 9;
    let channels = 3;
    let used = bytes.len() * 8 * spread;
    for amplitude in [1, 3, 4, 32767] {
        for cover in 0..4 {
            let mut state = 0x6204_d9ac_850a_ea99u64;
            let mut samples: Vec<i16> = (0..(used + 2) * channels)
                .map(|_| {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    (state >> 32) as i16
                })
                .collect();
            for unit in 0..used {
                match cover {
                    1 => samples[unit * channels] = if unit % 2 == 0 { i16::MIN } else { i16::MAX },
                    2 => samples[unit * channels] = i16::MIN,
                    3 => samples[unit * channels] = i16::MAX,
                    _ => {}
                }
            }
            let before = samples.clone();
            let mut scalars: Vec<i16> = before
                .chunks_exact(channels)
                .map(|frame| frame[0])
                .collect();
            let mut ss = SpreadSpectrumAudio::new([31; 32], amplitude, spread);
            for pos in 0..bytes.len() * 8 {
                ss.embed_bit(
                    &mut scalars,
                    pos * spread,
                    (bytes[pos / 8] >> (pos % 8)) & 1,
                    pos,
                    41,
                )
                .unwrap();
            }
            let mut expected = before.clone();
            for unit in 0..used {
                assert!(
                    (i32::from(scalars[unit]) - i32::from(before[unit * channels])).abs()
                        <= amplitude
                );
                expected[unit * channels] = scalars[unit];
            }
            let mut buf = AudioBuffer {
                channels: channels as u16,
                sample_rate: 48000,
                samples: &mut samples,
                frame_index: 41,
            };
            ss.embed(&mut buf, Some(&payload)).unwrap();
            assert_eq!(&*buf.samples, expected.as_slice());
            assert_eq!(ss.extract(&buf).unwrap().unwrap().to_bytes(), bytes);
            let mut recovered = [0; SignaturePayload::SERIALIZED_SIZE];
            for pos in 0..bytes.len() * 8 {
                recovered[pos / 8] |=
                    ss.extract_bit(&scalars, pos * spread, pos, 41).unwrap() << (pos % 8);
            }
            assert_eq!(recovered, bytes);
        }
    }
}

#[test]
fn spread_invalid_scalar_arguments_and_video_capacity_leave_carriers_unchanged() {
    let ss = SpreadSpectrumAudio::with_key([37; 32]);
    let mut samples = [i16::MAX; 64];
    for (start, bit) in [(usize::MAX, 0), (1, 0), (0, 2)] {
        assert!(ss.embed_bit(&mut samples, start, bit, 0, 0).is_err());
        assert_eq!(samples, [i16::MAX; 64]);
    }
    assert!(ss.extract_bit(&samples, 1, 0, 0).is_err());
    let payload = Signer::from_bytes(&[37; 32]).sign_frame(0, b"atomic video", None);
    for (width, height, stride, len) in [
        (256, 217, 768, 256 * 217 * 3),
        (256, 218, 767, 256 * 218 * 3),
        (256, 218, 768, 256 * 218 * 3 - 1),
        (0, 218, 768, 256 * 218 * 3),
    ] {
        let mut data = vec![255; len];
        let mut frame = VideoFrame {
            width,
            height,
            stride,
            format: VideoFormat::Rgb8,
            data: &mut data,
            frame_index: 0,
        };
        let mut ss = SpreadSpectrumVideo::with_key([37; 32]);
        assert!(ss.embed(&mut frame, Some(&payload)).is_err());
        assert!(frame.data.iter().all(|&value| value == 255));
    }
}

#[test]
fn dct_rejects_unrecoverable_saturated_blocks_before_writing() {
    let payload = Signer::from_bytes(&[7; 32]).sign_frame(0, b"clipping", None);
    for value in [0, 255] {
        let mut data = vec![value; 320 * 320 * 3];
        let mut frame = rgb(&mut data, 320, 320);
        assert!(DctVideo::default()
            .embed(&mut frame, Some(&payload))
            .is_err());
        assert!(frame.data.iter().all(|&byte| byte == value));
    }
}

#[test]
fn subinteger_quantization_is_rejected_without_mutation() {
    let payload = Signer::from_bytes(&[7; 32]).sign_frame(0, b"integer", None);
    let mut data = vec![128; 320 * 320 * 3];
    let mut frame = rgb(&mut data, 320, 320);
    assert!(DctVideo::new(20, 1, 1)
        .embed(&mut frame, Some(&payload))
        .is_err());
    assert!(frame.data.iter().all(|&byte| byte == 128));
    let mut samples = vec![0; 904 * 16];
    let mut buf = AudioBuffer {
        channels: 1,
        sample_rate: 48000,
        samples: &mut samples,
        frame_index: 0,
    };
    assert!(MdctAudio::new(3, 1)
        .embed(&mut buf, Some(&payload))
        .is_err());
    assert!(buf.samples.iter().all(|&sample| sample == 0));
}

#[test]
fn ecc_empty_message_corrects_only_within_radius() {
    for errors in 0..=3 {
        let mut codeword = encode(b"", 4).unwrap();
        for (index, byte) in codeword.iter_mut().take(errors).enumerate() {
            *byte = index as u8 + 1;
        }
        if errors <= 2 {
            assert_eq!(decode(&codeword, 0, 4).unwrap(), b"");
        } else {
            assert!(decode(&codeword, 0, 4).is_err());
        }
    }
}

#[test]
fn intact_ecc_chunk_has_constant_allocation_count() {
    let message: Vec<u8> = (0..239).map(|n| (n * 37 + 11) as u8).collect();
    let codeword = encode(&message, 16).unwrap();
    ALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|enabled| enabled.set(true));
    let decoded = decode(&codeword, 239, 16);
    COUNTING.with(|enabled| enabled.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    assert_eq!(decoded.unwrap(), message);
    assert!(
        allocations <= 2,
        "intact chunk allocated {allocations} times; expected only result storage"
    );
}
