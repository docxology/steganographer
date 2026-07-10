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
                   BLAKE3/SHA-256/SHA-3 hashing + Ed25519/secp256k1 signing. \
                   Optional ChaCha20-Poly1305 payload encryption, Reed-Solomon error correction, \
                   and multi-frame signature spreading."
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
        /// Input file format: "raw_rgb", "raw_s16le", "png", "wav" (auto-detected if omitted)
        #[arg(long)]
        input_format: Option<String>,
        /// Enable payload encryption (ChaCha20-Poly1305)
        #[arg(long)]
        encrypt: bool,
        /// Encryption key (hex-encoded 32 bytes) for payload encryption
        #[arg(long)]
        encryption_key: Option<String>,
        /// Path to encryption key file
        #[arg(long)]
        encryption_key_file: Option<String>,
        /// Enable Reed-Solomon error correction
        #[arg(long)]
        ecc: bool,
        /// Number of Reed-Solomon parity symbols (default: 4)
        #[arg(long, default_value = "4")]
        ecc_parity: usize,
        /// Multi-frame spreading: spread one signature across N frames (1 = no spreading)
        #[arg(long, default_value = "1")]
        spread: u32,
        /// Hash algorithm: "blake3" (default), "sha256", "sha3-256"
        #[arg(long)]
        hash_algorithm: Option<String>,
        /// Path to signing key file (hex-encoded 32-byte Ed25519 private key)
        #[arg(long)]
        signing_key: Option<String>,
        /// Batch mode: process all files in the input directory
        #[arg(long)]
        dir: bool,
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
        /// Input file format: "raw_rgb", "raw_s16le", "png", "wav" (auto-detected if omitted)
        #[arg(long)]
        input_format: Option<String>,
        /// Enable payload decryption (ChaCha20-Poly1305)
        #[arg(long)]
        decrypt: bool,
        /// Decryption key (hex-encoded 32 bytes)
        #[arg(long)]
        decryption_key: Option<String>,
        /// Path to decryption key file
        #[arg(long)]
        decryption_key_file: Option<String>,
        /// Enable Reed-Solomon error correction during extraction
        #[arg(long)]
        ecc: bool,
        /// Number of Reed-Solomon parity symbols (default: 4)
        #[arg(long, default_value = "4")]
        ecc_parity: usize,
        /// Multi-frame spreading: signature was spread across N frames
        #[arg(long, default_value = "1")]
        spread: u32,
        /// Hash algorithm: "blake3" (default), "sha256", "sha3-256"
        #[arg(long)]
        hash_algorithm: Option<String>,
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

    /// Analyze a file for steganographic artifacts (chi-squared test)
    Analyze {
        #[arg(long, short)]
        input: String,
        /// Analysis type: "chi_squared" (default)
        #[arg(long, default_value = "chi_squared")]
        analysis_type: String,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Derive keys (signing, encryption, embedding) from a master secret
    Derive {
        /// Master secret (hex-encoded, any length)
        #[arg(long)]
        master_secret: String,
        /// Output directory for derived keys
        #[arg(long, short, default_value = "keys")]
        output: String,
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
        Commands::Video { source, sink, max_frames } => {
            cmd_video::run(&cli.config, source, sink, max_frames)
        }

        Commands::Audio { source, sink, max_buffers } => {
            cmd_audio::run(&cli.config, source, sink, max_buffers)
        }

        Commands::Encode {
            input, output, stego_type, bits, format,
            input_format, encrypt, encryption_key, encryption_key_file,
            ecc, ecc_parity, spread, hash_algorithm, signing_key, dir,
        } => {
            let opts = cmd_encode::EncodeOptions {
                encrypt,
                encryption_key,
                encryption_key_file,
                ecc,
                ecc_parity,
                spread,
                hash_algorithm,
                signing_key,
                input_format,
            };
            if dir {
                cmd_encode::batch_process(&cli.config, &input, &output, &stego_type, bits, &format, &opts)
            } else {
                cmd_encode::run(&cli.config, &input, &output, &stego_type, bits, &format, &opts)
            }
        }

        Commands::Verify {
            input, public_key, stego_type, embedding_key, format,
            input_format, decrypt, decryption_key, decryption_key_file,
            ecc, ecc_parity, spread, hash_algorithm,
        } => {
            let opts = cmd_verify::VerifyOptions {
                decrypt,
                decryption_key,
                decryption_key_file,
                ecc,
                ecc_parity,
                spread,
                hash_algorithm,
                input_format,
            };
            cmd_verify::run_with_key(
                &cli.config, &input, public_key.as_deref(),
                &stego_type, &format, embedding_key.as_deref(), &opts,
            )
        }

        Commands::Keygen { output } => {
            cmd_encode::keygen(&output)
        }

        Commands::Info { input, stego_type, bits, format } => {
            cmd_encode::info(&input, &stego_type, bits, &format)
        }

        Commands::Analyze { input, analysis_type, format } => {
            cmd_encode::analyze(&input, &analysis_type, &format)
        }

        Commands::Derive { master_secret, output } => {
            cmd_encode::derive_keys(&master_secret, &output)
        }

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
                _ => anyhow::bail!("Unknown config action: {}. Use 'check'.", action),
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
