//! Steganographer CLI — user-facing binary for the steganographer toolkit.

use clap::{Parser, Subcommand};

mod carrier_binding;
mod cmd_audio;
mod cmd_encode;
mod cmd_ots;
mod cmd_packet;
mod cmd_verify;
mod cmd_video;
mod media_io;

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
        /// Path to signing key file (hex-encoded 32-byte Ed25519 private key).
        /// If omitted, an ephemeral keypair is generated per run.
        #[arg(long)]
        signing_key: Option<String>,
    },

    /// Run live audio pipeline: capture → steganography → virtual device
    Audio {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        sink: Option<String>,
        #[arg(long)]
        max_buffers: Option<u64>,
        /// Path to signing key file (hex-encoded 32-byte Ed25519 private key).
        /// If omitted, an ephemeral keypair is generated per run.
        #[arg(long)]
        signing_key: Option<String>,
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
        /// Width for headerless raw RGB input (requires --height)
        #[arg(long)]
        width: Option<u32>,
        /// Height for headerless raw RGB input (requires --width)
        #[arg(long)]
        height: Option<u32>,
        /// Enable payload encryption (ChaCha20-Poly1305)
        #[arg(long)]
        encrypt: bool,
        /// Encryption key (hex-encoded 32 bytes) for payload encryption
        #[arg(long)]
        encryption_key: Option<String>,
        /// Path to encryption key file
        #[arg(long)]
        encryption_key_file: Option<String>,
        /// Embedding key (hex-encoded, 32 bytes) for keyed audio/spread-spectrum placement
        #[arg(long)]
        embedding_key: Option<String>,
        /// Path to a hex-encoded 32-byte embedding key file
        #[arg(long)]
        embedding_key_file: Option<String>,
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
        /// Embed an arbitrary file in the opt-in generic packet v1 alpha
        #[arg(long, conflicts_with = "payload_text")]
        payload_file: Option<String>,
        /// Embed UTF-8 text in the opt-in generic packet v1 alpha
        #[arg(long, conflicts_with = "payload_file")]
        payload_text: Option<String>,
        /// Public MIME type for a generic packet payload
        #[arg(long)]
        mime_type: Option<String>,
        /// Safe display filename for a generic packet payload
        #[arg(long)]
        filename: Option<String>,
    },

    /// Decode an opt-in generic packet payload from a carrier
    Decode {
        #[arg(long, short)]
        input: String,
        #[arg(long, short)]
        output: String,
        /// Generic carrier kernel (currently lsb_video)
        #[arg(long, default_value = "lsb_video")]
        stego_type: String,
        /// LSB bits per unit: "auto" or 1-4
        #[arg(long, default_value = "auto")]
        bits: String,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
        /// Input format: raw_rgb or png/image (auto-detected if omitted)
        #[arg(long)]
        input_format: Option<String>,
        /// Replace an existing decoded payload output
        #[arg(long)]
        force: bool,
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
        /// Path to a hex-encoded 32-byte embedding key file
        #[arg(long)]
        embedding_key_file: Option<String>,
        /// LSB bits per sample/pixel: "auto" or 1-4
        #[arg(long, default_value = "auto")]
        bits: String,
        /// Output format: "plain" (human-readable) or "json" (machine-readable)
        #[arg(long, default_value = "plain")]
        format: String,
        /// Input file format: "raw_rgb", "raw_s16le", "png", "wav" (auto-detected if omitted)
        #[arg(long)]
        input_format: Option<String>,
        /// Width for headerless raw RGB input (requires --height)
        #[arg(long)]
        width: Option<u32>,
        /// Height for headerless raw RGB input (requires --width)
        #[arg(long)]
        height: Option<u32>,
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
        /// Width for headerless raw RGB input (requires --height)
        #[arg(long)]
        width: Option<u32>,
        /// Height for headerless raw RGB input (requires --width)
        #[arg(long)]
        height: Option<u32>,
    },

    /// Analyze a file for steganographic artifacts
    Analyze {
        #[arg(long, short)]
        input: String,
        /// Analysis type: "combined" (default), "chi_squared", "sample_pairs", or "rs"
        #[arg(long, default_value = "combined")]
        analysis_type: String,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Derive keys (signing, encryption, embedding) from a master secret
    /// (high-entropy BLAKE3 KDF) or a human-chosen password (Argon2id)
    Derive {
        /// Master secret (hex-encoded, any length).
        /// WARNING: this is visible in shell history and `ps` output.
        /// Prefer --master-secret-file for interactive use.
        #[arg(long)]
        master_secret: Option<String>,
        /// Read master secret from a file (hex-encoded). Safer than --master-secret.
        #[arg(long)]
        master_secret_file: Option<String>,
        /// Read master secret from stdin (hex-encoded). Use `-` as the value.
        #[arg(long)]
        master_secret_stdin: bool,
        /// Derive from a human-chosen password via Argon2id (memory-hard KDF).
        /// WARNING: visible in shell history and `ps` output.
        /// Prefer --password-file for interactive use.
        #[arg(long)]
        password: Option<String>,
        /// Read the password from a file (raw bytes, trailing newline trimmed).
        #[arg(long)]
        password_file: Option<String>,
        /// Read the password from stdin (raw bytes, trailing newline trimmed).
        #[arg(long)]
        password_stdin: bool,
        /// Hex-encoded Argon2id salt (at least 16 bytes). Generated and printed if omitted.
        #[arg(long)]
        salt: Option<String>,
        /// Argon2id memory cost in KiB (default 19456 = 19 MiB).
        #[arg(long, default_value_t = steganographer_core::password::RECOMMENDED_MEMORY_KIB)]
        argon2_memory: u32,
        /// Argon2id iteration count (default 2).
        #[arg(long, default_value_t = steganographer_core::password::RECOMMENDED_ITERATIONS)]
        argon2_iterations: u32,
        /// Argon2id parallelism / lane count (default 1).
        #[arg(long, default_value_t = 1)]
        argon2_parallelism: u32,
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
        /// Bind address: "127.0.0.1" (default, local-only) or "0.0.0.0" (all interfaces)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Auth token for mutating API endpoints (POST /api/config, POST /api/metrics/reset).
        /// If set, clients must send `Authorization: Bearer <token>`. If omitted, auth is disabled.
        #[arg(long)]
        auth_token: Option<String>,
    },

    /// Revoke a signing key (add to revoked-keys list)
    Revoke {
        /// Public key to revoke (hex-encoded, 32 bytes)
        #[arg(long)]
        public_key: String,
        /// Path to the revoked-keys file (default: keys/revoked.json)
        #[arg(long, short, default_value = "keys/revoked.json")]
        output: String,
    },

    /// Validate a TOML configuration file without running any pipeline
    Config {
        #[arg(default_value = "check")]
        action: String,
    },

    /// OpenTimestamps attestation: stamp or verify a file's Merkle root
    Ots {
        #[command(subcommand)]
        action: OtsAction,
    },
}

/// Subcommands for `steganographer ots`.
#[derive(Subcommand)]
enum OtsAction {
    /// Stamp a file's BLAKE3 Merkle root with the OpenTimestamps service
    Stamp {
        #[arg(long, short)]
        input: String,
        /// Directory for .ots proof files (default: from config or ./ots_proofs/)
        #[arg(long)]
        output_dir: Option<String>,
        /// Attestation method: "bitcoin" (default) or "ethereum"
        #[arg(long)]
        method: Option<String>,
        /// Re-stamp even if a proof already exists for this digest
        #[arg(long)]
        force: bool,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
    },

    /// Verify an OpenTimestamps proof for a file
    Verify {
        #[arg(long, short)]
        input: String,
        /// Path to the .ots proof file
        #[arg(long)]
        proof: String,
        /// Output format: "plain" or "json"
        #[arg(long, default_value = "plain")]
        format: String,
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
            signing_key,
        } => cmd_video::run(&cli.config, source, sink, max_frames, signing_key),

        Commands::Audio {
            source,
            sink,
            max_buffers,
            signing_key,
        } => cmd_audio::run(&cli.config, source, sink, max_buffers, signing_key),

        Commands::Encode {
            input,
            output,
            stego_type,
            bits,
            format,
            input_format,
            width,
            height,
            encrypt,
            encryption_key,
            encryption_key_file,
            embedding_key,
            embedding_key_file,
            ecc,
            ecc_parity,
            spread,
            hash_algorithm,
            signing_key,
            dir,
            payload_file,
            payload_text,
            mime_type,
            filename,
        } => {
            let opts = cmd_encode::EncodeOptions {
                encrypt,
                encryption_key,
                encryption_key_file,
                embedding_key,
                embedding_key_file,
                ecc,
                ecc_parity,
                spread,
                hash_algorithm,
                signing_key,
                input_format,
                raw_width: width,
                raw_height: height,
            };
            if payload_file.is_some() || payload_text.is_some() {
                if dir {
                    anyhow::bail!("generic packet encoding does not support --dir");
                }
                if opts.encrypt
                    || opts.ecc
                    || opts.spread > 1
                    || opts.signing_key.is_some()
                    || opts.embedding_key.is_some()
                    || opts.embedding_key_file.is_some()
                {
                    anyhow::bail!(
                        "generic packet alpha does not yet support encryption, ECC, \
                         signing, keyed placement, or multi-frame spreading"
                    );
                }
                cmd_packet::encode(
                    &input,
                    &output,
                    &stego_type,
                    bits,
                    &format,
                    &cmd_packet::GenericEncodeOptions {
                        payload_file,
                        payload_text,
                        mime_type,
                        filename,
                        input_format: opts.input_format.clone(),
                    },
                )
            } else if dir {
                cmd_encode::batch_process(
                    &cli.config,
                    &input,
                    &output,
                    &stego_type,
                    bits,
                    &format,
                    &opts,
                )
            } else {
                cmd_encode::run(
                    &cli.config,
                    &input,
                    &output,
                    &stego_type,
                    bits,
                    &format,
                    &opts,
                )
            }
        }

        Commands::Decode {
            input,
            output,
            stego_type,
            bits,
            format,
            input_format,
            force,
        } => cmd_packet::decode(
            &input,
            &output,
            &stego_type,
            &bits,
            &format,
            input_format.as_deref(),
            force,
        ),

        Commands::Verify {
            input,
            public_key,
            stego_type,
            embedding_key,
            embedding_key_file,
            bits,
            format,
            input_format,
            width,
            height,
            decrypt,
            decryption_key,
            decryption_key_file,
            ecc,
            ecc_parity,
            spread,
            hash_algorithm,
        } => {
            let opts = cmd_verify::VerifyOptions {
                bits: cmd_verify::VerifyBits::parse(&bits)?,
                decrypt,
                decryption_key,
                decryption_key_file,
                embedding_key_file,
                ecc,
                ecc_parity,
                spread,
                hash_algorithm,
                input_format,
                raw_width: width,
                raw_height: height,
            };
            cmd_verify::run_with_key(
                &cli.config,
                &input,
                public_key.as_deref(),
                &stego_type,
                &format,
                embedding_key.as_deref(),
                &opts,
            )
        }

        Commands::Keygen { output } => cmd_encode::keygen(&output),

        Commands::Info {
            input,
            stego_type,
            bits,
            format,
            width,
            height,
        } => cmd_encode::info(&input, &stego_type, bits, &format, width, height),

        Commands::Analyze {
            input,
            analysis_type,
            format,
        } => cmd_encode::analyze(&input, &analysis_type, &format),

        Commands::Derive {
            master_secret,
            master_secret_file,
            master_secret_stdin,
            password,
            password_file,
            password_stdin,
            salt,
            argon2_memory,
            argon2_iterations,
            argon2_parallelism,
            output,
        } => {
            let master_mode =
                master_secret.is_some() || master_secret_file.is_some() || master_secret_stdin;
            let password_mode = password.is_some() || password_file.is_some() || password_stdin;

            if password_mode && master_mode {
                anyhow::bail!(
                    "Provide either a master secret (--master-secret*) or a password \
                     (--password*), not both."
                );
            }

            if password_mode {
                // Resolve the password from one of three sources (raw bytes).
                let password_bytes = if password_stdin {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    buf
                } else if let Some(path) = password_file {
                    std::fs::read(&path)?
                } else if let Some(pw) = password {
                    log::warn!(
                        "Reading password from --password (visible in shell history / ps). \
                         Consider --password-file or --password-stdin for better security."
                    );
                    pw.into_bytes()
                } else {
                    anyhow::bail!(
                        "No password provided. Use --password <text>, \
                         --password-file <path>, or --password-stdin."
                    );
                };

                // Trim a single trailing newline (e.g. heredoc / `printf`), which
                // is common when piping or reading a file.
                let password_bytes = password_bytes
                    .strip_suffix(b"\n")
                    .map(<[u8]>::to_vec)
                    .unwrap_or(password_bytes);

                let params = steganographer_core::Argon2Params {
                    memory_kib: argon2_memory,
                    iterations: argon2_iterations,
                    parallelism: argon2_parallelism,
                    output_len: 32,
                };
                if !params.meets_recommendation() {
                    log::warn!(
                        "Argon2 parameters are below the OWASP recommendation \
                         ({} MiB memory, {} iterations). Increase --argon2-memory / \
                         --argon2-iterations for production secrets.",
                        steganographer_core::password::RECOMMENDED_MEMORY_KIB / 1024,
                        steganographer_core::password::RECOMMENDED_ITERATIONS
                    );
                }

                cmd_encode::derive_keys_from_password(
                    &password_bytes,
                    salt.as_deref(),
                    &params,
                    &output,
                )
            } else {
                // Resolve the master secret from one of three sources
                let secret_hex = if master_secret_stdin {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    buf.trim().to_string()
                } else if let Some(path) = master_secret_file {
                    std::fs::read_to_string(&path)?.trim().to_string()
                } else if let Some(s) = master_secret {
                    log::warn!(
                        "Reading master secret from --master-secret (visible in shell history / ps). \
                         Consider --master-secret-file or --master-secret-stdin for better security."
                    );
                    s
                } else {
                    anyhow::bail!(
                        "No master secret provided. Use --master-secret <hex>, \
                         --master-secret-file <path>, --master-secret-stdin, or the \
                         password options (--password/--password-file/--password-stdin)."
                    );
                };

                // Warn about low-entropy secrets (short hex strings are brute-forceable
                // at BLAKE3 speed — this KDF is designed for already-high-entropy key
                // material, not passphrases)
                let raw_bytes = cmd_encode::hex_decode(&secret_hex)
                    .map_err(|e| anyhow::anyhow!("Master secret is not valid hex: {}", e))?;
                if raw_bytes.len() < 32 {
                    log::warn!(
                        "Master secret is only {} bytes — BLAKE3 derive_key is NOT a slow KDF. \
                         Short or memorable passphrases can be brute-forced at hash speed. \
                         Use at least 32 bytes (64 hex chars) of high-entropy random data, \
                         or use --password for Argon2id stretching.",
                        raw_bytes.len()
                    );
                }

                cmd_encode::derive_keys(&secret_hex, &output)
            }
        }

        Commands::Config { action } => match action.as_str() {
            "check" => match steganographer_core::config::Config::from_file(&cli.config) {
                Ok(cfg) => {
                    let mut sections = vec!["global"];
                    if cfg.video.is_some() {
                        sections.push("video");
                    }
                    if cfg.audio.is_some() {
                        sections.push("audio");
                    }
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
            },
            _ => anyhow::bail!("Unknown config action: {}. Use 'check'.", action),
        },

        Commands::Revoke { public_key, output } => cmd_encode::revoke_key(&public_key, &output),

        Commands::Ots { action } => match action {
            OtsAction::Stamp {
                input,
                output_dir,
                method,
                force,
                format,
            } => cmd_ots::stamp(
                &cli.config,
                &input,
                output_dir.as_deref(),
                method.as_deref(),
                force,
                &format,
            ),
            OtsAction::Verify {
                input,
                proof,
                format,
            } => cmd_ots::verify(&cli.config, &input, &proof, &format),
        },

        Commands::Dashboard {
            port,
            backend,
            host,
            auth_token,
        } => {
            use std::sync::Arc;
            use steganographer_core::StegoMetrics;

            if host == "0.0.0.0" && auth_token.is_none() {
                log::warn!(
                    "Dashboard binding to 0.0.0.0 without --auth-token: \
                    mutating endpoints (POST /api/config, POST /api/metrics/reset) \
                    will be accessible without authentication. Consider using --auth-token."
                );
            }

            let identity_backend: Box<dyn steganographer_core::SignerBackend> =
                match backend.as_str() {
                    #[cfg(feature = "ethereum")]
                    "ethereum" => Box::new(steganographer_core::EthereumBackend::generate()),
                    _ => Box::new(steganographer_core::Ed25519Backend::generate()),
                };

            // Load OTS configuration from the config file (opt-in feature).
            let ots_config = steganographer_core::config::Config::from_file(&cli.config)
                .map(|c| c.ots_config())
                .unwrap_or_default();
            let ots_client = if ots_config.is_enabled() {
                log::info!(
                    "OTS enabled: method={}, server={}, interval={}s",
                    ots_config.method_canonical(),
                    ots_config.server_url,
                    ots_config.interval_secs
                );
                Some(std::sync::Arc::new(
                    steganographer_core::OTSClient::from_config(&ots_config),
                ))
            } else {
                None
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
                auth_token,
                ots_config,
                ots_client,
            });

            log::info!(
                "Starting dashboard on {}:{} with {} backend",
                host,
                port,
                backend
            );
            log::info!("Identity: {}", identity_backend.display_identity());

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(steganographer_dashboard::start_server(state, port, &host))?;
            Ok(())
        }
    }
}
