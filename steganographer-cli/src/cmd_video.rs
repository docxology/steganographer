//! `steganographer video` subcommand — live video pipeline.

use steganographer_core::config::Config;

pub fn run(
    config_path: &str,
    source: Option<String>,
    sink: Option<String>,
    max_frames: Option<u64>,
) -> anyhow::Result<()> {
    let cfg = Config::from_file(config_path)?;
    log::info!("Running video pipeline");

    // Initialize GStreamer
    steganographer_gst::init()?;

    // Determine source/sink from config or CLI overrides
    let video_cfg = cfg
        .video
        .ok_or_else(|| anyhow::anyhow!("No [video] section in config"))?;

    let source_str = source.unwrap_or_else(|| {
        build_source_pipeline(&video_cfg.input)
    });
    let sink_str = sink.unwrap_or_else(|| {
        build_sink_pipeline(&video_cfg.output)
    });

    // Build the steganography module chain
    let stego_modules = build_video_stego_chain(&video_cfg.stego)?;

    if stego_modules.is_empty() {
        anyhow::bail!("No steganography modules configured in pipeline");
    }

    log::info!("Stego pipeline has {} modules", stego_modules.len());

    // Create signer if LSB signature is configured
    let hash_algo = steganographer_core::crypto::HashAlgorithm::parse(
        cfg.global.hash_algorithm_name()
    );
    let signer = if video_cfg.stego.lsb_signature.is_some()
        || video_cfg.stego.pipeline.iter().any(|s| s == "spread_spectrum" || s == "dct")
    {
        let s = steganographer_core::crypto::Signer::with_hash_algorithm(
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            hash_algo,
        );
        log::info!("Hash algorithm: {}", hash_algo.name());
        Some(s)
    } else {
        None
    };

    if let Some(ref s) = signer {
        let pub_key = s.verifying_key();
        log::info!(
            "Generated signing key. Public key (hex): {}",
            hex_encode(&pub_key.to_bytes())
        );
    }

    // Run the pipeline with a composite stego that applies all modules
    let filter_config = steganographer_gst::video_filter::VideoFilterConfig {
        source_pipeline: source_str,
        sink_pipeline: sink_str,
    };

    let composite = Box::new(CompositeVideoStego { modules: stego_modules });

    steganographer_gst::video_filter::run_video_filter(
        &filter_config,
        composite,
        signer.as_ref(),
        max_frames,
    )?;

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

fn build_source_pipeline(endpoint: &steganographer_core::config::EndpointConfig) -> String {
    match endpoint.backend.as_deref() {
        Some("v4l2") => {
            let device = endpoint.device.as_deref().unwrap_or("/dev/video0");
            format!(
                "v4l2src device={} ! videoconvert ! video/x-raw,format=RGB",
                device
            )
        }
        Some("avfoundation") => {
            "avfvideosrc ! videoconvert ! video/x-raw,format=RGB".to_string()
        }
        _ => {
            // Default: test source
            "videotestsrc ! videoconvert ! video/x-raw,format=RGB,width=640,height=480".to_string()
        }
    }
}

fn build_sink_pipeline(endpoint: &steganographer_core::config::EndpointConfig) -> String {
    match endpoint.backend.as_deref() {
        Some("v4l2loopback") => {
            let device = endpoint.device.as_deref().unwrap_or("/dev/video42");
            format!("videoconvert ! v4l2sink device={}", device)
        }
        _ => "videoconvert ! autovideosink".to_string(),
    }
}

fn build_video_stego_chain(
    stego_cfg: &steganographer_core::config::VideoStegoConfig,
) -> anyhow::Result<Vec<Box<dyn steganographer_core::video::VideoStegoModule>>> {
    let mut modules: Vec<Box<dyn steganographer_core::video::VideoStegoModule>> = Vec::new();

    for step in &stego_cfg.pipeline {
        match step.as_str() {
            "lsb_signature" => {
                let lsb_cfg = stego_cfg
                    .lsb_signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Pipeline includes 'lsb_signature' but no [lsb_signature] config"))?;
                let lsb = steganographer_core::lsb_video::LsbVideo::try_new(lsb_cfg.bits)?;
                modules.push(Box::new(lsb));
                log::info!("Added LSB video module ({} bits)", lsb_cfg.bits);
            }
            "spread_spectrum" => {
                let lsb_cfg = stego_cfg
                    .lsb_signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Pipeline includes 'spread_spectrum' but no [lsb_signature] config for key"))?;
                let key = lsb_cfg.key_bytes()?;
                let ss = steganographer_core::spread_spectrum::SpreadSpectrumVideo::with_key(key);
                modules.push(Box::new(ss));
                log::info!("Added spread-spectrum video module");
            }
            "dct" => {
                let dct = steganographer_core::dct_video::DctVideo::default();
                modules.push(Box::new(dct));
                log::info!("Added DCT video module");
            }
            "overlay" => {
                let ov_cfg = stego_cfg
                    .overlay
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Pipeline includes 'overlay' but no [overlay] config"))?;
                let text = ov_cfg.text.clone().unwrap_or_else(|| "STEGANOGRAPHER".to_string());
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
                let label = stego_cfg
                    .overlay
                    .as_ref()
                    .and_then(|o| o.text.clone())
                    .unwrap_or_else(|| "STEGANOGRAPHER".to_string());
                let bar = steganographer_core::info_bar::InfoBar::new(label);
                modules.push(Box::new(bar));
                log::info!("Added info bar module (timestamp, barcode, QR)");
            }
            other => {
                log::warn!("Unknown stego pipeline step: '{}', skipping", other);
            }
        }
    }

    // Always add the info bar at the end (exoteric overlay)
    // unless it was already explicitly added in the pipeline config
    if !stego_cfg.pipeline.iter().any(|s| s == "info_bar") {
        let label = stego_cfg
            .overlay
            .as_ref()
            .and_then(|o| o.text.clone())
            .unwrap_or_else(|| "STEGANOGRAPHER".to_string());
        let bar = steganographer_core::info_bar::InfoBar::new(label);
        modules.push(Box::new(bar));
        log::info!("Auto-added info bar module (exoteric overlay)");
    }

    Ok(modules)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
