//! Real finite-source, file, signature, error, and PCM-contract regressions.
//! Required GStreamer plugins are test prerequisites, never silently skipped.
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use gstreamer_video::VideoFrameExt;
use std::path::Path;
use steganographer_core::{
    audio::{AudioBuffer, AudioStegoModule},
    crypto::{HashAlgorithm, SignaturePayload, Signer, Verifier},
    lsb_audio::LsbAudio,
    lsb_video::LsbVideo,
    video::{VideoFormat, VideoFrame, VideoStegoModule},
};
use steganographer_gst::{audio_filter, video_filter, SigningKernel};

fn init() {
    steganographer_gst::init().unwrap();
}

fn finite_file(fragment: &str, path: &Path) {
    let pipeline = gstreamer::parse::launch(&format!("{fragment} ! filesink name=destination"))
        .unwrap()
        .downcast::<gstreamer::Bin>()
        .unwrap();
    pipeline
        .by_name("destination")
        .unwrap()
        .set_property("location", path.to_str().unwrap());
    let result = (|| -> anyhow::Result<()> {
        pipeline.set_state(gstreamer::State::Playing)?;
        let message = pipeline
            .bus()
            .unwrap()
            .timed_pop_filtered(
                gstreamer::ClockTime::from_seconds(15),
                &[gstreamer::MessageType::Eos, gstreamer::MessageType::Error],
            )
            .ok_or_else(|| anyhow::anyhow!("fixture pipeline timed out"))?;
        if let gstreamer::MessageView::Error(error) = message.view() {
            anyhow::bail!("{} {:?}", error.error(), error.debug());
        }
        Ok(())
    })();
    pipeline.set_state(gstreamer::State::Null).unwrap();
    result.unwrap();
}

fn read_file(path: &Path, decode: &str) -> Vec<gstreamer::Sample> {
    let pipeline = gstreamer::parse::launch(&format!(
        "filesrc name=input ! {decode} ! appsink name=reader sync=false max-buffers=8 drop=false"
    ))
    .unwrap()
    .downcast::<gstreamer::Bin>()
    .unwrap();
    pipeline
        .by_name("input")
        .unwrap()
        .set_property("location", path.to_str().unwrap());
    let sink = pipeline
        .by_name("reader")
        .unwrap()
        .downcast::<AppSink>()
        .unwrap();
    let result = (|| -> anyhow::Result<Vec<gstreamer::Sample>> {
        pipeline.set_state(gstreamer::State::Playing)?;
        let mut samples = Vec::new();
        loop {
            if let Some(sample) = sink.try_pull_sample(gstreamer::ClockTime::from_seconds(2)) {
                samples.push(sample);
                continue;
            }
            while let Some(message) = pipeline.bus().unwrap().pop() {
                if let gstreamer::MessageView::Error(error) = message.view() {
                    anyhow::bail!("{} {:?}", error.error(), error.debug());
                }
            }
            anyhow::ensure!(sink.is_eos(), "file reader timed out without EOS");
            return Ok(samples);
        }
    })();
    pipeline.set_state(gstreamer::State::Null).unwrap();
    result.unwrap()
}

fn rgb_pixels(sample: &gstreamer::Sample) -> (u32, u32, Vec<u8>) {
    let info = gstreamer_video::VideoInfo::from_caps(sample.caps().unwrap()).unwrap();
    assert_eq!(info.format(), gstreamer_video::VideoFormat::Rgb);
    let mapped =
        gstreamer_video::VideoFrameRef::from_buffer_ref_readable(sample.buffer().unwrap(), &info)
            .unwrap();
    let plane = mapped.plane_data(0).unwrap();
    let stride = mapped.plane_stride()[0] as usize;
    let row = info.width() as usize * 3;
    let pixels = (0..info.height() as usize)
        .flat_map(|y| plane[y * stride..y * stride + row].iter().copied())
        .collect();
    (info.width(), info.height(), pixels)
}

#[test]
fn video_file_is_literal_lossless_finalized_and_output_verifiable() {
    init();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input with spaces \"quoted\" !.mkv");
    let output = dir.path().join("output with spaces \"quoted\" !.mkv");
    finite_file("videotestsrc num-buffers=7 pattern=white ! video/x-raw,format=RGB,width=62,height=8,framerate=30/1 ! matroskamux", &input);
    let signer = Signer::from_bytes_with_algo(&[0x31; 32], HashAlgorithm::Sha256);
    video_filter::process_video_file(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        Box::new(LsbVideo::new(1)),
        Some(&signer),
        Some(SigningKernel::Lsb { bits: 1 }),
        None,
    )
    .unwrap();
    let original = read_file(&input, "matroskademux");
    let delivered = read_file(&output, "matroskademux");
    assert_eq!(original.len(), 7);
    assert_eq!(
        delivered.len(),
        original.len(),
        "queued finite-source tail must not be dropped"
    );
    let verifier = Verifier::with_hash_algorithm(signer.verifying_key(), HashAlgorithm::Sha256);
    let module = LsbVideo::new(1);
    for (index, (before, after)) in original.iter().zip(&delivered).enumerate() {
        let (width, height, original_pixels) = rgb_pixels(before);
        let (out_width, out_height, mut pixels) = rgb_pixels(after);
        assert_eq!((width, height), (out_width, out_height));
        let binding = steganographer_core::carrier_binding::canonicalize(
            &pixels,
            "lsb_video",
            1,
            width,
            height,
            SignaturePayload::SERIALIZED_SIZE,
        )
        .unwrap();
        assert_eq!(
            binding,
            steganographer_core::carrier_binding::canonicalize(
                &original_pixels,
                "lsb_video",
                1,
                width,
                height,
                SignaturePayload::SERIALIZED_SIZE
            )
            .unwrap()
        );
        let frame = VideoFrame {
            width,
            height,
            stride: width * 3,
            format: VideoFormat::Rgb8,
            data: &mut pixels,
            frame_index: index as u64,
        };
        let payload = module.extract(&frame).unwrap().unwrap();
        assert_eq!(payload.frame_index, index as u64);
        assert!(verifier.verify(&payload, &binding, None));
    }
}

#[test]
fn audio_file_is_literal_exact_pcm_and_signature_survives_wav_finalization() {
    init();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input \" ! pcm.wav");
    let output = dir.path().join("output \" ! pcm.wav");
    finite_file("audiotestsrc num-buffers=7 samplesperbuffer=2048 ! audio/x-raw,format=S16LE,layout=interleaved,channels=1,rate=44100 ! wavenc", &input);
    let signer = Signer::from_bytes(&[0x72; 32]);
    let key = [0x26; 32];
    let mut module = LsbAudio::new(1, key);
    video_filter::process_audio_file(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        &mut module,
        Some(&signer),
        Some(SigningKernel::Lsb { bits: 1 }),
        None,
    )
    .unwrap();
    let flatten = |path: &Path| -> Vec<u8> {
        read_file(path, "wavparse")
            .iter()
            .flat_map(|s| {
                s.buffer()
                    .unwrap()
                    .map_readable()
                    .unwrap()
                    .as_slice()
                    .to_vec()
            })
            .collect()
    };
    let before = flatten(&input);
    let after = flatten(&output);
    assert_eq!(
        after.len(),
        7 * 2048 * 2,
        "absent max_buffers must preserve the full input"
    );
    assert_eq!(after.len(), before.len());
    let binding =
        steganographer_core::carrier_binding::canonicalize(&after, "lsb_audio", 1, 0, 0, 0)
            .unwrap();
    assert_eq!(
        binding,
        steganographer_core::carrier_binding::canonicalize(&before, "lsb_audio", 1, 0, 0, 0)
            .unwrap()
    );
    let mut samples: Vec<i16> = after
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let audio = AudioBuffer {
        channels: 1,
        sample_rate: 44100,
        samples: &mut samples,
        frame_index: 0,
    };
    let payload = module.extract(&audio).unwrap().unwrap();
    assert!(Verifier::new(signer.verifying_key()).verify(&payload, &binding, None));
}

#[test]
fn finite_audio_source_drains_every_queued_buffer() {
    init();
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("finite.wav");
    let config = audio_filter::AudioFilterConfig {
        source_pipeline: "audiotestsrc num-buffers=19 samplesperbuffer=1024 ! audio/x-raw,format=S16LE,layout=interleaved,channels=2,rate=8000".into(),
        sink_pipeline: format!("wavenc ! filesink location=\"{}\"", output.display()),
        signing_kernel: None,
    };
    audio_filter::run_audio_filter(&config, &mut LsbAudio::new(1, [1; 32]), None, None).unwrap();
    let bytes: usize = read_file(&output, "wavparse")
        .iter()
        .map(|s| s.buffer().unwrap().size())
        .sum();
    assert_eq!(bytes, 19 * 1024 * 2 * 2);
}

#[test]
fn source_and_asynchronous_downstream_errors_propagate() {
    init();
    for fail_source in [false, true] {
        let error_fragment = "identity error-after=2";
        let video = video_filter::VideoFilterConfig {
            source_pipeline: format!(
                "videotestsrc num-buffers=8 ! video/x-raw,format=RGB,width=64,height=16{}",
                if fail_source {
                    " ! identity error-after=2"
                } else {
                    ""
                }
            ),
            sink_pipeline: if fail_source {
                "fakesink sync=false".into()
            } else {
                format!("{error_fragment} ! fakesink sync=false")
            },
            signing_kernel: None,
        };
        let error = video_filter::run_video_filter(&video, Box::new(LsbVideo::new(1)), None, None)
            .unwrap_err();
        assert!(format!("{error:#}").contains("error"));
        let audio = audio_filter::AudioFilterConfig {
            source_pipeline: format!("audiotestsrc num-buffers=8 ! audio/x-raw,format=S16LE,layout=interleaved,channels=1,rate=8000{}", if fail_source { " ! identity error-after=2" } else { "" }),
            sink_pipeline: video.sink_pipeline,
            signing_kernel: None,
        };
        assert!(
            audio_filter::run_audio_filter(&audio, &mut LsbAudio::new(1, [1; 32]), None, None)
                .is_err()
        );
    }
    assert!(video_filter::extract_from_source(
        "videotestsrc num-buffers=8 ! video/x-raw,format=RGB ! identity error-after=1",
        &LsbVideo::new(1),
        None
    )
    .is_err());
    assert!(audio_filter::extract_from_source("audiotestsrc num-buffers=8 ! audio/x-raw,format=S16LE,layout=interleaved ! identity error-after=1", &LsbAudio::new(1, [1; 32]), None).is_err());
}

#[test]
fn audio_rejects_wrong_format_planar_and_incomplete_frames_in_both_paths() {
    init();
    for fragment in [
        "audiotestsrc num-buffers=1 ! audio/x-raw,format=F32LE,layout=interleaved,channels=1,rate=8000",
        "audiotestsrc num-buffers=1 ! audio/x-raw,format=S16LE,layout=non-interleaved,channels=2,rate=8000",
        "fakesrc num-buffers=1 sizetype=fixed sizemax=3 ! audio/x-raw,format=S16LE,layout=interleaved,channels=1,rate=8000",
        "fakesrc num-buffers=1 sizetype=fixed sizemax=6 ! audio/x-raw,format=S16LE,layout=interleaved,channels=2,rate=8000",
    ] {
        let module = LsbAudio::new(1, [1; 32]);
        assert!(audio_filter::extract_from_source(fragment, &module, None).is_err(), "{fragment}");
        let config = audio_filter::AudioFilterConfig { source_pipeline: fragment.into(), sink_pipeline: "fakesink sync=false".into(), signing_kernel: None };
        assert!(audio_filter::run_audio_filter(&config, &mut LsbAudio::new(1, [1; 32]), None, None).is_err(), "{fragment}");
    }
}

#[test]
fn missing_binding_invalid_source_and_incompatible_file_formats_are_errors() {
    init();
    let signer = Signer::from_bytes(&[4; 32]);
    let video = video_filter::VideoFilterConfig {
        source_pipeline: "element_that_does_not_exist".into(),
        sink_pipeline: "fakesink".into(),
        signing_kernel: Some(SigningKernel::Lsb { bits: 1 }),
    };
    // Library calls must return pipeline errors without entering an app loop.
    assert!(video_filter::run_video_filter(
        &video,
        Box::new(LsbVideo::new(1)),
        Some(&signer),
        None
    )
    .is_err());
    let no_binding = video_filter::VideoFilterConfig {
        signing_kernel: None,
        ..video
    };
    assert!(video_filter::run_video_filter(
        &no_binding,
        Box::new(LsbVideo::new(1)),
        Some(&signer),
        None
    )
    .unwrap_err()
    .to_string()
    .contains("signing_kernel"));
    assert!(video_filter::process_video_file(
        "missing",
        "lossy.mp4",
        Box::new(LsbVideo::new(1)),
        None,
        None,
        None
    )
    .unwrap_err()
    .to_string()
    .contains(".mkv"));
    assert!(video_filter::process_audio_file(
        "missing",
        "lossy.mp3",
        &mut LsbAudio::new(1, [1; 32]),
        None,
        None,
        None
    )
    .unwrap_err()
    .to_string()
    .contains(".wav"));
    let audio = audio_filter::AudioFilterConfig {
        source_pipeline: "element_that_does_not_exist".into(),
        sink_pipeline: "fakesink".into(),
        signing_kernel: Some(SigningKernel::Dct),
    };
    assert!(audio_filter::run_audio_filter(
        &audio,
        &mut LsbAudio::new(1, [1; 32]),
        Some(&signer),
        None
    )
    .unwrap_err()
    .to_string()
    .contains("LSB"));
}

#[test]
fn max_frame_limit_still_drains_and_finalizes_muxed_output() {
    init();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.mkv");
    let output = dir.path().join("limited.mkv");
    finite_file("videotestsrc num-buffers=9 ! video/x-raw,format=RGB,width=64,height=16,framerate=30/1 ! matroskamux", &input);
    video_filter::process_video_file(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        Box::new(LsbVideo::new(1)),
        None,
        None,
        Some(3),
    )
    .unwrap();
    assert_eq!(read_file(&output, "matroskademux").len(), 3);
}

#[test]
fn signing_rejects_incompatible_module_binding_and_unsupported_spread() {
    init();
    let signer = Signer::from_bytes(&[0x17; 32]);
    let config = video_filter::VideoFilterConfig {
        source_pipeline:
            "videotestsrc num-buffers=1 pattern=white ! video/x-raw,format=RGB,width=64,height=16"
                .into(),
        sink_pipeline: "fakesink sync=false".into(),
        signing_kernel: Some(SigningKernel::Lsb { bits: 1 }),
    };
    let error =
        video_filter::run_video_filter(&config, Box::new(LsbVideo::new(2)), Some(&signer), None)
            .unwrap_err();
    assert!(error.to_string().contains("signing binding"));
    let spread = video_filter::VideoFilterConfig {
        source_pipeline: "element_that_does_not_exist".into(),
        signing_kernel: Some(SigningKernel::SpreadSpectrum),
        ..config
    };
    assert!(video_filter::run_video_filter(
        &spread,
        Box::new(LsbVideo::new(1)),
        Some(&signer),
        None
    )
    .unwrap_err()
    .to_string()
    .contains("canonical trait binding"));
}

#[test]
fn audio_file_explicit_buffer_limit_bounds_selection_not_logical_signature_chunks() {
    init();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.wav");
    let output = dir.path().join("limited.wav");
    finite_file("audiotestsrc num-buffers=7 samplesperbuffer=2048 ! audio/x-raw,format=S16LE,layout=interleaved,channels=1,rate=44100 ! wavenc", &input);
    let signer = Signer::from_bytes(&[0x71; 32]);
    let module = &mut LsbAudio::new(1, [1; 32]);
    video_filter::process_audio_file(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        module,
        Some(&signer),
        Some(SigningKernel::Lsb { bits: 1 }),
        Some(1),
    )
    .unwrap();
    let samples = read_file(&output, "wavparse");
    let pcm: Vec<u8> = samples
        .iter()
        .flat_map(|s| {
            s.buffer()
                .unwrap()
                .map_readable()
                .unwrap()
                .as_ref()
                .to_vec()
        })
        .collect();
    assert!(!pcm.is_empty() && pcm.len() < 7 * 2048 * 2);
    let binding =
        steganographer_core::carrier_binding::canonicalize(&pcm, "lsb_audio", 1, 0, 0, 0).unwrap();
    let mut values: Vec<i16> = pcm
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let audio = AudioBuffer {
        channels: 1,
        sample_rate: 44100,
        samples: &mut values,
        frame_index: 0,
    };
    let payload = module.extract(&audio).unwrap().unwrap();
    assert!(Verifier::new(signer.verifying_key()).verify(&payload, &binding, None));
}

#[test]
fn headless_worker_can_initialize_repeat_and_recover_after_pipeline_errors() {
    std::thread::spawn(|| {
        let dir = tempfile::tempdir().unwrap();
        for attempt in 0..2 {
            // Initialization and media operations are library calls, not
            // process entry points, even on macOS and after a previous error.
            init();
            let output = dir.path().join(format!("worker-{attempt}.mkv"));
            let mut config = video_filter::VideoFilterConfig {
                source_pipeline: "filesrc location=/definitely-not-a-steganographer-worker-file ! decodebin ! videoconvert ! video/x-raw,format=RGB".into(),
                sink_pipeline: "fakesink sync=false".into(),
                signing_kernel: None,
            };
            assert!(video_filter::run_video_filter(
                &config, Box::new(LsbVideo::new(1)), None, None,
            ).is_err());
            config.source_pipeline = "videotestsrc num-buffers=3 pattern=white ! video/x-raw,format=RGB,width=64,height=16,framerate=30/1".into();
            config.sink_pipeline = "identity error-after=1 ! fakesink sync=false".into();
            assert!(video_filter::run_video_filter(
                &config, Box::new(LsbVideo::new(1)), None, None,
            ).is_err());
            config.sink_pipeline = format!("matroskamux ! filesink location=\"{}\"", output.display());
            video_filter::run_video_filter(
                &config, Box::new(LsbVideo::new(1)), None, None,
            ).unwrap();
            let delivered = read_file(&output, "matroskademux");
            assert_eq!(delivered.len(), 3);
            for sample in delivered {
                let (width, height, pixels) = rgb_pixels(&sample);
                assert_eq!((width, height), (64, 16));
                assert!(pixels.iter().all(|&pixel| pixel == 255));
            }

            let output = dir.path().join(format!("worker-{attempt}.wav"));
            let config = audio_filter::AudioFilterConfig {
                source_pipeline: "audiotestsrc num-buffers=3 samplesperbuffer=1024 wave=silence ! audio/x-raw,format=S16LE,layout=interleaved,channels=1,rate=8000".into(),
                sink_pipeline: format!("wavenc ! filesink location=\"{}\"", output.display()),
                signing_kernel: None,
            };
            audio_filter::run_audio_filter(
                &config, &mut LsbAudio::new(1, [1; 32]), None, None,
            ).unwrap();
            let delivered = read_file(&output, "wavparse");
            assert_eq!(delivered.iter().map(|sample| sample.buffer().unwrap().size()).sum::<usize>(), 3 * 1024 * 2);
            for sample in delivered {
                let pcm = sample.buffer().unwrap().map_readable().unwrap();
                assert!(pcm.iter().all(|&byte| byte == 0));
            }
        }
    }).join().unwrap();
}
