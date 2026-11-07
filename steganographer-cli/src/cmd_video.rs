//! `steganographer video` subcommand — live video pipeline.

use anyhow::Context;
use steganographer_core::config::Config;
use steganographer_core::crypto::encode_hex;

pub fn run(
    config_path: &str,
    source: Option<String>,
    sink: Option<String>,
    max_frames: Option<u64>,
    signing_key: Option<String>,
) -> anyhow::Result<()> {
    let cfg = Config::from_file(config_path)?;
    log::info!("Running video pipeline");

    // Determine source/sink from config or CLI overrides
    let video_cfg = cfg
        .video
        .ok_or_else(|| anyhow::anyhow!("No [video] section in config"))?;
    validate_live_pipeline(video_cfg.pipeline.as_ref())?;
    anyhow::ensure!(
        max_frames.is_none_or(|limit| limit > 0),
        "--max-frames must be positive"
    );
    let managed_file = sink.is_none() && video_cfg.output.r#type == "file";
    anyhow::ensure!(
        !managed_file
            || max_frames.is_some()
            || (source.is_none() && video_cfg.input.r#type == "file"),
        "file capture from a live or explicit source requires --max-frames"
    );
    let signing_kernel = match video_cfg.stego.pipeline.as_slice() {
        [step] if step == "lsb_signature" => Some(steganographer_gst::SigningKernel::Lsb {
            bits: video_cfg
                .stego
                .lsb_signature
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("LSB signing requires [lsb_signature]"))?
                .bits,
        }),
        [step] if step == "dct" => Some(steganographer_gst::SigningKernel::Dct),
        [step] if step == "spread_spectrum" => anyhow::bail!(
            "Native signed spread-spectrum is unsupported; use the offline scalar carrier workflow"
        ),
        steps
            if steps.iter().any(|step| {
                matches!(step.as_str(), "lsb_signature" | "dct" | "spread_spectrum")
            }) =>
        {
            anyhow::bail!("Signed video requires exactly one kernel; overlays and multi-kernel signing are unsupported");
        }
        _ => None,
    };
    if signing_key.is_some() && signing_kernel.is_none() {
        anyhow::bail!("--signing-key requires a signing kernel");
    }

    let source_str = match source {
        Some(source) => source,
        None => build_source_pipeline(&video_cfg.input, video_cfg.pipeline.as_ref())?,
    };
    let output_file = if managed_file {
        let path = video_cfg
            .output
            .path
            .as_deref()
            .filter(|path| !path.is_empty())
            .context("video file output requires path")?;
        let path = std::path::Path::new(path);
        anyhow::ensure!(
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("mkv")),
            "signed video file output requires lossless RGB Matroska (.mkv)"
        );
        Some((path, crate::media_io::output_temp(path, false)?))
    } else {
        None
    };
    let sink_str = match sink {
        Some(sink) => sink,
        None => build_sink_pipeline(
            &video_cfg.output,
            output_file.as_ref().map(|(_, file)| file.path()),
        )?,
    };

    // Build the steganography module chain
    let stego_modules = build_video_stego_chain(&video_cfg.stego)?;

    if stego_modules.is_empty() {
        anyhow::bail!("No steganography modules configured in pipeline");
    }

    log::info!("Stego pipeline has {} modules", stego_modules.len());

    let hash_algo =
        steganographer_core::crypto::HashAlgorithm::parse(cfg.global.hash_algorithm_name());
    let signer = if signing_kernel.is_some() {
        let s = if let Some(ref key_path) = signing_key {
            let key = crate::key_policy::load_signing_key(std::path::Path::new(key_path))?;
            log::info!("Using persistent signing key from: {}", key_path);
            steganographer_core::crypto::Signer::with_hash_algorithm(key, hash_algo)
        } else {
            // Generate ephemeral keypair
            let s = steganographer_core::crypto::Signer::with_hash_algorithm(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                hash_algo,
            );
            log::info!("Hash algorithm: {}", hash_algo.name());
            s
        };
        Some(s)
    } else {
        None
    };

    if let Some(ref s) = signer {
        let pub_key = s.verifying_key();
        let pub_hex = encode_hex(&pub_key.to_bytes());
        // Print to stderr unconditionally so --quiet doesn't hide the public key.
        // The stream is unverifiable without it.
        eprintln!("Signing public key (hex): {}", pub_hex);
    }

    // Run the pipeline with a composite stego that applies all modules
    let filter_config = steganographer_gst::video_filter::VideoFilterConfig {
        source_pipeline: source_str,
        sink_pipeline: sink_str,
        signing_kernel,
    };

    let composite = Box::new(CompositeVideoStego {
        modules: stego_modules,
    });

    steganographer_gst::init()?;

    steganographer_gst::video_filter::run_video_filter(
        &filter_config,
        composite,
        signer.as_ref(),
        max_frames,
    )?;
    if let Some((path, file)) = output_file {
        crate::media_io::publish_output(file, path, false)?;
    }

    Ok(())
}

fn validate_live_pipeline(
    pipeline: Option<&steganographer_core::config::VideoPipelineConfig>,
) -> anyhow::Result<()> {
    let Some(pipeline) = pipeline else {
        return Ok(());
    };
    for dimension in [
        pipeline.width_or_default(),
        pipeline.height_or_default(),
        pipeline.framerate_or_default(),
    ] {
        anyhow::ensure!(
            dimension > 0 && dimension <= i32::MAX as u32,
            "video dimensions/framerate must be positive GStreamer integers"
        );
    }
    anyhow::ensure!(
        pipeline.opacity_or_default() == 1.0,
        "native video opacity is unsupported; use 1.0 (dashboard preview opacity is display-only)"
    );
    if let Some(payload) = &pipeline.payload {
        anyhow::ensure!(
            payload
                .r#type
                .as_deref()
                .is_none_or(|kind| kind == "signature"),
            "native video requires a signature payload"
        );
        anyhow::ensure!(
            payload.size.is_none_or(|size| size as usize
                == steganographer_core::crypto::SignaturePayload::SERIALIZED_SIZE),
            "native video requires the fixed 109-byte signature payload"
        );
        anyhow::ensure!(
            !payload.encrypt_enabled(),
            "live payload encryption is unsupported; use offline encode"
        );
        anyhow::ensure!(
            payload
                .error_correction
                .as_deref()
                .is_none_or(|algorithm| algorithm.eq_ignore_ascii_case("none")),
            "live error correction is unsupported; use offline encode"
        );
        anyhow::ensure!(
            payload.spread_count() == 1,
            "live signature spreading is unsupported; use offline RGB LSB encode"
        );
    }
    Ok(())
}

/// A composite stego module that applies a chain of modules in sequence.
struct CompositeVideoStego {
    modules: Vec<Box<dyn steganographer_core::video::VideoStegoModule>>,
}

impl steganographer_core::video::VideoStegoModule for CompositeVideoStego {
    fn embed(
        &mut self,
        frame: &mut steganographer_core::video::VideoFrame,
        sig: Option<&steganographer_core::crypto::SignaturePayload>,
    ) -> anyhow::Result<()> {
        for module in &mut self.modules {
            module.embed(frame, sig)?;
        }
        Ok(())
    }

    fn extract(
        &self,
        frame: &steganographer_core::video::VideoFrame,
    ) -> anyhow::Result<Option<steganographer_core::crypto::SignaturePayload>> {
        // Extract from the first module that can (typically LSB)
        for module in &self.modules {
            if let Some(payload) = module.extract(frame)? {
                return Ok(Some(payload));
            }
        }
        Ok(None)
    }
}

fn build_source_pipeline(
    endpoint: &steganographer_core::config::EndpointConfig,
    pipeline: Option<&steganographer_core::config::VideoPipelineConfig>,
) -> anyhow::Result<String> {
    let source = match endpoint.r#type.as_str() {
        "test" => "videotestsrc".to_string(),
        "file" => {
            let path = endpoint.path.as_deref().filter(|path| !path.is_empty()).context("video file input requires path")?;
            format!("filesrc location={} ! decodebin", steganographer_gst::quote_location(path)?)
        }
        "network" => {
            let uri = endpoint.path.as_deref().filter(|uri| !uri.is_empty()).context("video network input requires a URI in path")?;
            format!("uridecodebin uri={}", steganographer_gst::quote_location(uri)?)
        }
        "device" => match endpoint.backend.as_deref() {
            Some("v4l2") => format!("v4l2src device={}", steganographer_gst::quote_location(endpoint.device.as_deref().unwrap_or("/dev/video0"))?),
            Some("avfoundation") => match endpoint.device.as_deref() {
                Some(device) => {
                    let index: i32 = device.parse().context("avfoundation device must be a numeric device index")?;
                    anyhow::ensure!(index >= -1, "avfoundation device index must be -1 or greater");
                    format!("avfvideosrc device-index={index}")
                }
                None => "avfvideosrc".to_string(),
            },
            _ => anyhow::bail!("video device input requires backend v4l2 or avfoundation; use type='test' for synthetic video"),
        },
        _ => anyhow::bail!("unsupported video input type"),
    };
    let width = pipeline.map_or(640, |config| config.width_or_default());
    let height = pipeline.map_or(480, |config| config.height_or_default());
    let framerate = pipeline.map_or(30, |config| config.framerate_or_default());
    Ok(format!("{source} ! videoconvert ! videoscale ! video/x-raw,format=RGB,width={width},height={height},framerate={framerate}/1"))
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
                "matroskamux ! filesink location={}",
                steganographer_gst::quote_location(path)?
            ))
        }
        "device" => match endpoint.backend.as_deref() {
            Some("v4l2loopback") => Ok(format!(
                "v4l2sink device={}",
                steganographer_gst::quote_location(
                    endpoint.device.as_deref().unwrap_or("/dev/video42")
                )?
            )),
            None if endpoint.device.is_none() => Ok("autovideosink".to_string()),
            _ => anyhow::bail!(
                "unsupported video output backend/device; use an explicit --sink pipeline"
            ),
        },
        "network" => anyhow::bail!("network output requires an explicit lossless --sink pipeline"),
        _ => anyhow::bail!("unsupported video output type"),
    }
}

fn build_video_stego_chain(
    stego_cfg: &steganographer_core::config::VideoStegoConfig,
) -> anyhow::Result<Vec<Box<dyn steganographer_core::video::VideoStegoModule>>> {
    let mut modules: Vec<Box<dyn steganographer_core::video::VideoStegoModule>> = Vec::new();

    for step in &stego_cfg.pipeline {
        match step.as_str() {
            "lsb_signature" => {
                let lsb_cfg = stego_cfg.lsb_signature.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Pipeline includes 'lsb_signature' but no [lsb_signature] config"
                    )
                })?;
                let lsb = steganographer_core::lsb_video::LsbVideo::try_new(lsb_cfg.bits)?;
                modules.push(Box::new(lsb));
                log::info!("Added LSB video module ({} bits)", lsb_cfg.bits);
            }
            "dct" => {
                let dct = steganographer_core::dct_video::DctVideo::default();
                modules.push(Box::new(dct));
                log::info!("Added DCT video module");
            }
            "overlay" => {
                let ov_cfg = stego_cfg.overlay.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Pipeline includes 'overlay' but no [overlay] config")
                })?;
                let text = ov_cfg
                    .text
                    .clone()
                    .unwrap_or_else(|| "STEGANOGRAPHER".to_string());
                let pos = steganographer_core::overlay::OverlayPosition::parse(
                    ov_cfg.position.as_deref().unwrap_or("bottom-right"),
                );
                let mut overlay = steganographer_core::overlay::TextOverlay::new(text, pos);
                if let Some(size) = ov_cfg.font_size {
                    overlay = overlay.with_scale((size / 8).max(1) as u8);
                }
                modules.push(Box::new(overlay));
                log::info!("Added text overlay module");
            }
            "info_bar" => {
                let config = stego_cfg
                    .info_bar
                    .as_ref()
                    .context("info_bar requires [video.stego.info_bar]")?;
                anyhow::ensure!(!config.show_barcode() && !config.show_qr(), "visible-only info_bar requires show_barcode=false and show_qr=false; cryptographic renderers need a supplied payload");
                let bar = steganographer_core::info_bar::InfoBar::new(
                    config.label_or_default().to_string(),
                )
                .with_barcode(false)
                .with_qr(false)
                .with_timestamp(config.show_timestamp());
                modules.push(Box::new(bar));
                log::info!("Added visible info bar module");
            }
            other => {
                anyhow::bail!("Unknown stego pipeline step: '{}'", other);
            }
        }
    }

    Ok(modules)
}
