#![cfg(feature = "gst")]

use std::process::Command;

#[test]
fn native_video_rejects_unsupported_payload_protection_before_writing() {
    let directory = tempfile::tempdir().unwrap();
    for (index, setting) in [
        "encrypt = true",
        "error_correction = \"reed_solomon\"",
        "multi_frame_spread = 2",
        "type = \"custom\"",
        "size = 108",
    ]
    .iter()
    .enumerate()
    {
        let config = directory.path().join(format!("{index}.toml"));
        let output = directory.path().join(format!("{index}.rgb"));
        std::fs::write(
            &config,
            format!(
                "[global]\nhash_algorithm=\"sha256\"\n[video.pipeline.payload]\n{setting}\n\
                 [video.input]\ntype=\"test\"\n[video.output]\ntype=\"test\"\n\
                 [video.stego]\npipeline=[\"lsb_signature\"]\n\
                 [video.stego.lsb_signature]\nbits=1\n"
            ),
        )
        .unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_steganographer"))
            .args(["--quiet", "--config"])
            .arg(&config)
            .args([
                "video",
                "--source",
                "videotestsrc num-buffers=1 ! video/x-raw,format=RGB,width=64,height=16",
                "--sink",
            ])
            .arg(format!("filesink location=\"{}\"", output.display()))
            .args(["--max-frames", "1"])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1), "setting: {setting}");
        assert!(
            !output.exists(),
            "protection was silently ignored: {setting}"
        );
    }
}

#[test]
fn native_file_rebinding_preserves_finite_frame_count_without_rate_resampling() {
    use gstreamer::prelude::*;
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.mkv");
    let output = directory.path().join("output.mkv");
    for (index, target) in [&input, &output].into_iter().enumerate() {
        let config = directory.path().join(format!("file-{index}.toml"));
        let source = if index == 0 {
            "type=\"test\"\n".to_string()
        } else {
            format!("type=\"file\"\npath={:?}\n", input.to_str().unwrap())
        };
        std::fs::write(
            &config,
            format!(
                "[global]\n[video.pipeline]\nwidth=62\nheight=8\nframerate=12\n\
             [video.input]\n{source}[video.output]\ntype=\"file\"\npath={:?}\n\
             [video.stego]\npipeline=[\"lsb_signature\"]\n\
             [video.stego.lsb_signature]\nbits=1\n",
                target.to_str().unwrap()
            ),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_steganographer"));
        command
            .args(["--quiet", "--config"])
            .arg(config)
            .arg("video");
        if index == 0 {
            command.args(["--max-frames", "3"]);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    gstreamer::init().unwrap();
    let pipeline = gstreamer::parse::launch(&format!(
        "filesrc location={} ! matroskademux ! appsink name=reader sync=false",
        steganographer_gst::quote_location(output.to_str().unwrap()).unwrap()
    ))
    .unwrap()
    .downcast::<gstreamer::Pipeline>()
    .unwrap();
    let reader = pipeline.by_name("reader").unwrap();
    pipeline.set_state(gstreamer::State::Playing).unwrap();
    let mut geometries = Vec::new();
    while let Some(sample) =
        reader.emit_by_name::<Option<gstreamer::Sample>>("try-pull-sample", &[&3_000_000_000u64])
    {
        let caps = sample.caps().unwrap().structure(0).unwrap();
        geometries.push((
            caps.get::<i32>("width").unwrap(),
            caps.get::<i32>("height").unwrap(),
        ));
    }
    let eos = reader.property::<bool>("eos");
    pipeline.set_state(gstreamer::State::Null).unwrap();
    assert!(eos, "finite file reader stalled");
    assert_eq!(
        geometries,
        [(62, 8); 3],
        "file rebinding added/dropped frames"
    );
}
