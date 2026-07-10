//! Benchmarks for steganographer-core.
//!
//! Run with: cargo bench -p steganographer-core

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use steganographer_core::audio::{AudioBuffer, AudioStegoModule};
use steganographer_core::crypto::Signer;
use steganographer_core::dct_video::DctVideo;
use steganographer_core::lsb_audio::LsbAudio;
use steganographer_core::lsb_video::LsbVideo;
use steganographer_core::spread_spectrum::SpreadSpectrumVideo;
use steganographer_core::video::{VideoFormat, VideoFrame, VideoStegoModule};

fn bench_sign(c: &mut Criterion) {
    let signer = Signer::generate();
    let data = vec![128u8; 640 * 480 * 3];

    c.bench_function("sign_frame_640x480", |b| {
        b.iter(|| signer.sign_frame(black_box(0), black_box(&data), None));
    });
}

fn bench_lsb_embed(c: &mut Criterion) {
    let signer = Signer::generate();
    let mut lsb = LsbVideo::new(1);
    let payload = signer.sign_frame(0, &[0u8; 1024], None);

    let mut group = c.benchmark_group("lsb_video_embed");
    for size in [320 * 240, 640 * 480, 1280 * 720] {
        let bpp = 3;
        let mut data = vec![128u8; size * bpp];
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let mut frame = VideoFrame {
                    width: (size as f64).sqrt() as u32,
                    height: (size as f64).sqrt() as u32,
                    stride: (size as f64).sqrt() as u32 * 3,
                    format: VideoFormat::Rgb8,
                    data: &mut data,
                    frame_index: 0,
                };
                lsb.embed(&mut frame, Some(&payload)).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_lsb_extract(c: &mut Criterion) {
    let signer = Signer::generate();
    let mut lsb = LsbVideo::new(1);
    let payload = signer.sign_frame(0, &[0u8; 1024], None);
    let mut data = vec![128u8; 640 * 480 * 3];
    let mut frame = VideoFrame {
        width: 640,
        height: 480,
        stride: 640 * 3,
        format: VideoFormat::Rgb8,
        data: &mut data,
        frame_index: 0,
    };
    lsb.embed(&mut frame, Some(&payload)).unwrap();

    c.bench_function("lsb_video_extract_640x480", |b| {
        b.iter(|| {
            let frame = VideoFrame {
                width: 640,
                height: 480,
                stride: 640 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            lsb.extract(&frame).unwrap();
        });
    });
}

fn bench_spread_spectrum(c: &mut Criterion) {
    let signer = Signer::generate();
    let key = [42u8; 32];
    let mut ss = SpreadSpectrumVideo::with_key(key);
    let payload = signer.sign_frame(0, &[0u8; 1024], None);
    let mut data = vec![128u8; 1024 * 1024];

    c.bench_function("spread_spectrum_embed_1MB", |b| {
        b.iter(|| {
            let mut frame = VideoFrame {
                width: 1024,
                height: 1024,
                stride: 1024 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            ss.embed(&mut frame, Some(&payload)).unwrap();
        });
    });
}

fn bench_dct(c: &mut Criterion) {
    let signer = Signer::generate();
    let mut dct = DctVideo::default();
    let payload = signer.sign_frame(0, &[0u8; 1024], None);
    let mut data = vec![128u8; 320 * 320 * 3];

    c.bench_function("dct_embed_320x320", |b| {
        b.iter(|| {
            let mut frame = VideoFrame {
                width: 320,
                height: 320,
                stride: 320 * 3,
                format: VideoFormat::Rgb8,
                data: &mut data,
                frame_index: 0,
            };
            dct.embed(&mut frame, Some(&payload)).unwrap();
        });
    });
}

fn bench_audio_lsb(c: &mut Criterion) {
    let signer = Signer::generate();
    let key = [42u8; 32];
    let mut lsb = LsbAudio::new(1, key);
    let payload = signer.sign_frame(0, &[0u8; 1024], None);
    let mut samples = vec![1000i16; 44100]; // 1 second of audio

    c.bench_function("lsb_audio_embed_1s", |b| {
        b.iter(|| {
            let mut buf = AudioBuffer {
                channels: 1,
                sample_rate: 44100,
                samples: &mut samples,
                frame_index: 0,
            };
            lsb.embed(&mut buf, Some(&payload)).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_sign,
    bench_lsb_embed,
    bench_lsb_extract,
    bench_spread_spectrum,
    bench_dct,
    bench_audio_lsb,
);
criterion_main!(benches);
