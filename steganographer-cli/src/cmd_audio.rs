//! `steganographer audio` subcommand — live audio pipeline.

use anyhow::Context;
use steganographer_core::config::Config;
use steganographer_core::crypto::encode_hex;

pub fn run(
    config_path: &str,
    source: Option<String>,
    sink: Option<String>,
    max_buffers: Option<u64>,
    signing_key: Option<String>,
) -> anyhow::Result<()> {
    let cfg = Config::from_file(config_path)?;
    log::info!("Running audio pipeline");

    let audio_cfg = cfg
        .audio
        .ok_or_else(|| anyhow::anyhow!("No [audio] section in config"))?;
    if audio_cfg.stego.pipeline.as_slice() != ["lsb_signature"] {
        anyhow::bail!("Signed audio supports exactly one lsb_signature kernel; spread-spectrum/multi-kernel audio signing is unsupported");
    }
    anyhow::ensure!(
        max_buffers.is_none_or(|limit| limit > 0),
        "--max-buffers must be positive"
    );
    let managed_file = sink.is_none() && audio_cfg.output.r#type == "file";
    anyhow::ensure!(
        !managed_file
            || max_buffers.is_some()
            || (source.is_none() && audio_cfg.input.r#type == "file"),
        "whole-file audio capture from a live or explicit source requires --max-buffers"
    );
    let signing_kernel = Some(steganographer_gst::SigningKernel::Lsb {
        bits: audio_cfg
            .stego
            .lsb_signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("LSB signing requires [lsb_signature]"))?
            .bits,
    });

    let source_str = match source {
        Some(source) => source,
        None => build_source_pipeline(&audio_cfg.input)?,
    };
    let output_file = if managed_file {
        let path = audio_cfg
            .output
            .path
            .as_deref()
            .filter(|path| !path.is_empty())
            .context("audio file output requires path")?;
        let path = std::path::Path::new(path);
        anyhow::ensure!(
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("wav")),
            "signed audio file output requires exact PCM WAV (.wav)"
        );
        Some((path, crate::media_io::output_temp(path, false)?))
    } else {
        None
    };
    let sink_str = match sink {
        Some(sink) => sink,
        None => build_sink_pipeline(
            &audio_cfg.output,
            output_file.as_ref().map(|(_, file)| file.path()),
        )?,
    };
    let mut stego = build_audio_stego(&audio_cfg.stego, cfg.global.key_file.as_deref())?;

    let hash_algo =
        steganographer_core::crypto::HashAlgorithm::parse(cfg.global.hash_algorithm_name());
    let signer = if let Some(key_path) = &signing_key {
        let key = crate::key_policy::load_signing_key(std::path::Path::new(key_path))?;
        steganographer_core::crypto::Signer::with_hash_algorithm(key, hash_algo)
    } else {
        steganographer_core::crypto::Signer::with_hash_algorithm(
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            hash_algo,
        )
    };
    eprintln!(
        "Signing public key (hex): {}",
        encode_hex(&signer.verifying_key().to_bytes())
    );

    let filter_config = steganographer_gst::audio_filter::AudioFilterConfig {
        source_pipeline: source_str,
        sink_pipeline: sink_str,
        signing_kernel,
    };

    steganographer_gst::init()?;
    if managed_file {
        steganographer_gst::audio_filter::run_audio_file(
            &filter_config,
            stego.as_mut(),
            Some(&signer),
            max_buffers,
        )?;
    } else {
        steganographer_gst::audio_filter::run_audio_filter(
            &filter_config,
            stego.as_mut(),
            Some(&signer),
            max_buffers,
        )?;
    }
    if let Some((path, file)) = output_file {
        crate::media_io::publish_output(file, path, false)?;
    }

    Ok(())
}

fn build_source_pipeline(
    endpoint: &steganographer_core::config::EndpointConfig,
) -> anyhow::Result<String> {
    let (source, retain_layout) = match endpoint.r#type.as_str() {
        "test" => ("audiotestsrc wave=sine freq=440".to_string(), false),
        "file" => {
            let path = endpoint
                .path
                .as_deref()
                .filter(|path| !path.is_empty())
                .context("audio file input requires path")?;
            (
                format!(
                    "filesrc location={} ! decodebin",
                    steganographer_gst::quote_location(path)?
                ),
                true,
            )
        }
        "network" => {
            let uri = endpoint
                .path
                .as_deref()
                .filter(|uri| !uri.is_empty())
                .context("audio network input requires a URI in path")?;
            (
                format!(
                    "uridecodebin uri={}",
                    steganographer_gst::quote_location(uri)?
                ),
                true,
            )
        }
        "device" => {
            let source = match endpoint.backend.as_deref() {
                Some("pulseaudio") => match endpoint.device.as_deref() {
                    Some(device) => format!("pulsesrc device={}", steganographer_gst::quote_location(device)?),
                    None => "pulsesrc".to_string(),
                },
                Some("pipewire") => match endpoint.device.as_deref() {
                    Some(device) => format!("pipewiresrc path={}", steganographer_gst::quote_location(device)?),
                    None => "pipewiresrc".to_string(),
                },
                Some("coreaudio") => match endpoint.device.as_deref() {
                    Some(device) => format!("osxaudiosrc device={}", device.parse::<u32>().context("coreaudio device must be a numeric device identifier")?),
                    None => "osxaudiosrc".to_string(),
                },
                _ => anyhow::bail!("audio device input requires backend pulseaudio, pipewire or coreaudio; use type='test' for synthetic audio"),
            };
            (source, false)
        }
        _ => anyhow::bail!("unsupported audio input type"),
    };
    let layout = if retain_layout {
        ""
    } else {
        ",channels=1,rate=44100"
    };
    Ok(format!(
        "{source} ! audioconvert ! audio/x-raw,format=S16LE,layout=interleaved{layout}"
    ))
}

fn build_sink_pipeline(
    endpoint: &steganographer_core::config::EndpointConfig,
    file_path: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    match endpoint.r#type.as_str() {
        "test" => Ok("fakesink sync=false".to_string()),
        "file" => {
            let path = file_path
                .context("file output requires an atomic temporary file")?
                .to_str()
                .context("non-UTF-8 temporary path")?;
            Ok(format!(
                "wavenc ! filesink location={}",
                steganographer_gst::quote_location(path)?
            ))
        }
        "network" => anyhow::bail!("network output requires an explicit exact-PCM --sink pipeline"),
        "device" => match endpoint.backend.as_deref() {
            Some("pulseaudio") => match endpoint.device.as_deref() {
                Some(device) => Ok(format!(
                    "pulsesink device={}",
                    steganographer_gst::quote_location(device)?
                )),
                None => Ok("pulsesink".to_string()),
            },
            Some("pipewire") => match endpoint.device.as_deref() {
                Some(device) => Ok(format!(
                    "pipewiresink path={}",
                    steganographer_gst::quote_location(device)?
                )),
                None => Ok("pipewiresink".to_string()),
            },
            Some("coreaudio") => match endpoint.device.as_deref() {
                Some(device) => Ok(format!(
                    "osxaudiosink device={}",
                    device
                        .parse::<u32>()
                        .context("coreaudio device must be a numeric device identifier")?
                )),
                None => Ok("osxaudiosink".to_string()),
            },
            None if endpoint.device.is_none() => Ok("autoaudiosink".to_string()),
            _ => anyhow::bail!(
                "unsupported audio output backend/device; use an explicit --sink pipeline"
            ),
        },
        _ => anyhow::bail!("unsupported audio output type"),
    }
}

fn build_audio_stego(
    stego_cfg: &steganographer_core::config::AudioStegoConfig,
    global_key_file: Option<&str>,
) -> anyhow::Result<Box<dyn steganographer_core::audio::AudioStegoModule>> {
    let config = stego_cfg
        .lsb_signature
        .as_ref()
        .context("LSB audio requires [lsb_signature]")?;
    let key = steganographer_core::config::resolve_key(
        config.key.as_deref(),
        config.key_file.as_deref().or(global_key_file),
    )?;
    Ok(Box::new(steganographer_core::lsb_audio::LsbAudio::try_new(
        config.bits,
        key,
    )?))
}
