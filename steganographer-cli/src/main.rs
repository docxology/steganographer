//! Steganographer CLI — user-facing binary for the steganographer toolkit.

use clap::{Parser, Subcommand};

mod cmd_audio;
mod cmd_encode;
mod cmd_verify;
mod cmd_video;

#[derive(Parser)]
#[command(
    name = "steganographer",
    about = "Real-time steganographic watermarking for video and audio streams",
    version,
    long_about = "Steganographer embeds cryptographic signatures and visible watermarks into \
                   live video/audio streams using LSB steganography, spread-spectrum modulation, \
                   DCT-domain embedding, and text overlays. Supports GStreamer pipelines for \
                   real-time processing and offline file encoding/verification. \
                   BLAKE3/SHA-256/SHA-3 hashing + Ed25519/secp256k1 signing."
)]
pub struct Cli {
    /// Path to configuration file (TOML)
    #[arg(long, short, global = true, default_value = "config/example.toml")]
    config: String,

    /// Log verbosity level
    #[arg(long, short, global = true, default_value = "info")]
    log_level: String,

    /// Suppress all output except final result (for scripting)
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run live video pipeline: capture → steganography → virtual device
    Video {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        sink: Option<String>,
        #[arg(long)]
        max_frames: Option<u64>,
    },

    /// Run live audio pipeline: capture → steganography → virtual device
    Audio {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        sink: Option<String>,
        #[arg(long)]
        max_buffers: Option<u64>,
    },

    /// Encode steganographic data into a file (offline)
    Encode {
        #[arg(long, short)]
        input: String,
        #[arg(long, short)]
        output: String,
        /// Type of steganography: "lsb_video", "lsb_audio", "spread_spectrum_video", "dct_video"
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// LSB bits per sample/pixel (1-4)
        #[arg(long, default_value = "1")]
        bits: u8,
        /// Output format: "plain" (human-readable) or "json" (machine-readable)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Verify steganographic signatures in a media file
    Verify {
        #[arg(long, short)]
        input: String,
        /// Public key (hex-encoded) for signature verification
        #[arg(long)]
        public_key: Option<String>,
        /// Type of steganography to verify: "lsb_video", "lsb_audio", "spread_spectrum_video", "dct_video"
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// Embedding key (hex-encoded, 32 bytes) for audio/spread-spectrum extraction
        #[arg(long)]
        embedding_key: Option<String>,
        /// Output format: "plain" (human-readable) or "json" (machine-readable)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Generate a new Ed25519 signing key pair
    Keygen {
        #[arg(long, short, default_value = "steganographer")]
        output: String,
    },

    /// Report steganographic capacity of a media file
    Info {
        #[arg(long, short)]
        input: String,
        /// Type of steganography to report capacity for
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// LSB bits per sample/pixel (1-4)
        #[arg(long, default_value = "1")]
        bits: u8,
        /// Output format: "plain" (human-readable) or "json" (machine-readable)
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Launch the live round-trip verification dashboard (web GUI)
    Dashboard {
        #[arg(long, short, default_value = "8080")]
        port: u16,
        /// Signing backend: "ed25519" or "ethereum"
        #[arg(long, default_value = "ed25519")]
        backend: String,
    },

    /// Validate a TOML configuration file without running any pipeline
    Config {
        #[arg(default_value = "check")]
        action: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.quiet {
        log::LevelFilter::Off
    } else {
        match cli.log_level.as_str() {
            "trace" => log::LevelFilter::Trace,
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            _ => log::LevelFilter::Info,
        }
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    log::info!("Steganographer v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Config: {}", cli.config);

    match cli.command {
        Commands::Video {
            source,
            sink,
            max_frames,
        } => cmd_video::run(&cli.config, source, sink, max_frames),

        Commands::Audio {
            source,
            sink,
            max_buffers,
        } => cmd_audio::run(&cli.config, source, sink, max_buffers),

        Commands::Encode {
            input,
            output,
            stego_type,
            bits,
            format,
        } => cmd_encode::run(&cli.config, &input, &output, &stego_type, bits, &format),

        Commands::Verify {
            input,
            public_key,
            stego_type,
            embedding_key,
            format,
        } => cmd_verify::run_with_key(
            &cli.config,
            &input,
            public_key.as_deref(),
            &stego_type,
            &format,
            embedding_key.as_deref(),
        ),

        Commands::Keygen { output } => {
            cmd_encode::keygen(&output)
        }

        Commands::Info {
            input,
            stego_type,
            bits,
            format,
        } => cmd_encode::info(&input, &stego_type, bits, &format),

        Commands::Config { action } => {
            match action.as_str() {
                "check" => {
                    match steganographer_core::config::Config::from_file(&cli.config) {
                        Ok(cfg) => {
                            let mut sections = vec!["global"];
                            if cfg.video.is_some() { sections.push("video"); }
                            if cfg.audio.is_some() { sections.push("audio"); }
                            println!("✓ Configuration valid: {}", cli.config);
                            println!("  Sections: {}", sections.join(", "));
                            if let Some(ref algo) = cfg.global.hash_algorithm {
                                println!("  Hash algorithm: {}", algo);
                            }
                            if let Some(ref kf) = cfg.global.key_file {
                                println!("  Key file: {}", kf);
                            }
                            Ok(())
                        }
                        Err(e) => {
                            eprintln!("✗ Configuration error in {}: {}", cli.config, e);
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    anyhow::bail!("Unknown config action: {}. Use 'check'.", action);
                }
            }
        }

        Commands::Dashboard { port, backend } => {
            use std::sync::Arc;
            use steganographer_core::StegoMetrics;

            let identity_backend: Box<dyn steganographer_core::SignerBackend> = match backend.as_str() {
                #[cfg(feature = "ethereum")]
                "ethereum" => Box::new(steganographer_core::EthereumBackend::generate()),
                _ => Box::new(steganographer_core::Ed25519Backend::generate()),
            };

            let state = Arc::new(steganographer_dashboard::DashboardState {
                metrics: Arc::new(StegoMetrics::new()),
                signing_backend: identity_backend.name().to_string(),
                identity: identity_backend.display_identity(),
                width: 640,
                height: 480,
                last_encoded_frame: std::sync::Mutex::new(None),
                last_encoded_audio: std::sync::Mutex::new(None),
                live_config: std::sync::Mutex::new(steganographer_dashboard::LiveConfig::default()),
                session_start: std::time::Instant::now(),
            });

            log::info!("Starting dashboard on port {} with {} backend", port, backend);
            log::info!("Identity: {}", identity_backend.display_identity());

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(steganographer_dashboard::start_server(state, port))?;
            Ok(())
        }
    }
}
