//! `steganographer audio` subcommand — live audio pipeline.

use steganographer_core::config::Config;

pub fn run(
    config_path: &str,
    source: Option<String>,
    sink: Option<String>,
    max_buffers: Option<u64>,
    signing_key: Option<String>,
) -> anyhow::Result<()> {
    let cfg = Config::from_file(config_path)?;
    log::info!("Running audio pipeline");

    steganographer_gst::init()?;

    let audio_cfg = cfg
        .audio
        .ok_or_else(|| anyhow::anyhow!("No [audio] section in config"))?;

    let source_str = source.unwrap_or_else(|| build_source_pipeline(&audio_cfg.input));
    let sink_str = sink.unwrap_or_else(|| build_sink_pipeline(&audio_cfg.output));

    let mut stego = build_audio_stego(&audio_cfg.stego)?;

    let hash_algo = steganographer_core::crypto::HashAlgorithm::parse(
        cfg.global.hash_algorithm_name()
    );
    let signer = if audio_cfg.stego.lsb_signature.is_some() {
        let s = if let Some(ref key_path) = signing_key {
            let key_hex = std::fs::read_to_string(key_path)?;
            let key_bytes = hex_decode(key_hex.trim())?;
            if key_bytes.len() != 32 {
                anyhow::bail!("Signing key must be 32 bytes (64 hex chars), got {}", key_bytes.len());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
            log::info!("Using persistent signing key from: {}", key_path);
            steganographer_core::crypto::Signer::with_hash_algorithm(sk, hash_algo)
        } else {
            let s = steganographer_core::crypto::Signer::with_hash_algorithm(
                ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
                hash_algo,
            );
            log::info!("Hash algorithm: {}", hash_algo.name());
            s
        };
        // Print to stderr unconditionally so --quiet doesn't hide the public key.
        let pub_hex = hex_encode(&s.verifying_key().to_bytes());
        eprintln!("Generated signing key. Public key (hex): {}", pub_hex);
        Some(s)
    } else {
        None
    };

    let filter_config = steganographer_gst::audio_filter::AudioFilterConfig {
        source_pipeline: source_str,
        sink_pipeline: sink_str,
    };

    steganographer_gst::audio_filter::run_audio_filter(
        &filter_config,
        stego.as_mut(),
        signer.as_ref(),
        max_buffers,
    )?;

    Ok(())
}

fn build_source_pipeline(endpoint: &steganographer_core::config::EndpointConfig) -> String {
    match endpoint.backend.as_deref() {
        Some("pulseaudio") => {
            "pulsesrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100".to_string()
        }
        Some("pipewire") => {
            "pipewiresrc ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100"
                .to_string()
        }
        _ => {
            "audiotestsrc wave=sine freq=440 ! audioconvert ! audio/x-raw,format=S16LE,channels=1,rate=44100"
                .to_string()
        }
    }
}

fn build_sink_pipeline(endpoint: &steganographer_core::config::EndpointConfig) -> String {
    match endpoint.backend.as_deref() {
        Some("pulseaudio") => "audioconvert ! pulsesink".to_string(),
        Some("pipewire") => "audioconvert ! pipewiresink".to_string(),
        _ => "audioconvert ! autoaudiosink".to_string(),
    }
}

fn build_audio_stego(
    stego_cfg: &steganographer_core::config::AudioStegoConfig,
) -> anyhow::Result<Box<dyn steganographer_core::audio::AudioStegoModule>> {
    for step in &stego_cfg.pipeline {
        if step == "lsb_signature" {
            let lsb_cfg = stego_cfg
                .lsb_signature
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!("Pipeline includes 'lsb_signature' but no config")
                })?;
            let key = lsb_cfg.key_bytes()?;
            let lsb = steganographer_core::lsb_audio::LsbAudio::try_new(lsb_cfg.bits, key)?;
            log::info!("Using LSB audio module ({} bits)", lsb_cfg.bits);
            return Ok(Box::new(lsb));
        }
        if step == "spread_spectrum" {
            let lsb_cfg = stego_cfg
                .lsb_signature
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Pipeline includes 'spread_spectrum' but no [lsb_signature] config for key"))?;
            let key = lsb_cfg.key_bytes()?;
            let ss = steganographer_core::spread_spectrum::SpreadSpectrumAudio::with_key(key);
            log::info!("Using spread-spectrum audio module");
            return Ok(Box::new(ss));
        }
    }
    anyhow::bail!("No supported audio stego module in pipeline config")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("Hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}
