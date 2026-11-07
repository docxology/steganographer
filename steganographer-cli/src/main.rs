//! Steganographer CLI — user-facing binary for the steganographer toolkit.

use clap::{CommandFactory, FromArgMatches};

use std::path::PathBuf;

use cli::{Cli, Commands, OtsAction};

mod cli;
#[cfg(feature = "gst")]
mod cmd_audio;
mod cmd_encode;
mod cmd_ots;
mod cmd_packet;
mod cmd_scan;
mod cmd_verify;
#[cfg(feature = "gst")]
mod cmd_video;
mod envelope;
mod key_policy;
mod media_io;

fn main() {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().collect();
    activate_requested_machine_mode(&arguments);
    let matches = match Cli::command().try_get_matches_from(&arguments) {
        Ok(matches) => matches,
        Err(error) => {
            if !error.use_stderr() {
                let _ = error.print();
                std::process::exit(0);
            }
            usage_error(error.to_string());
        }
    };
    let explicit_config =
        matches.value_source("config") == Some(clap::parser::ValueSource::CommandLine);
    let mut cli =
        Cli::from_arg_matches(&matches).unwrap_or_else(|error| usage_error(error.to_string()));
    activate_output_mode(&cli.command);
    if cli.schema_version != "v1" {
        usage_error(format!(
            "unknown --schema-version '{}': expected 'v1'",
            cli.schema_version
        ));
    }
    if explicit_config {
        let path = std::path::Path::new(&cli.config);
        if !path.is_absolute() {
            cli.config = std::env::current_dir()
                .unwrap_or_else(|error| usage_error(format!("Cannot resolve config: {error}")))
                .join(path)
                .to_string_lossy()
                .into_owned();
        }
    }
    let effective_config = steganographer_core::config::Config::load_optional(&cli.config)
        .unwrap_or_else(|error| usage_error(format!("Configuration error: {error:#}")));
    let decode_limits = effective_config
        .limits
        .as_ref()
        .map(steganographer_core::config::LimitsConfig::to_decode_limits)
        .unwrap_or_default();

    let log_level = if cli.quiet {
        log::LevelFilter::Off
    } else {
        match cli.log_level.as_str() {
            "trace" => log::LevelFilter::Trace,
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            other => usage_error(format!(
                "unknown --log-level '{other}': expected trace, debug, info, warn, or error"
            )),
        }
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    log::info!("Steganographer v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Config: {}", cli.config);

    // Cocoa owns the process main thread, not individual library operations.
    // Enter it once for live native commands, before dispatch can create any
    // Tokio runtime. Offline/headless commands do not need NSApplication.
    #[cfg(all(feature = "gst", target_os = "macos"))]
    let needs_cocoa = matches!(
        &cli.command,
        Commands::Video { .. } | Commands::Audio { .. }
    );
    let run = move || -> anyhow::Result<()> {
        match cli.command {
            #[cfg(feature = "gst")]
            Commands::Video {
                source,
                sink,
                max_frames,
                signing_key,
            } => cmd_video::run(&cli.config, source, sink, max_frames, signing_key),

            #[cfg(feature = "gst")]
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
                compress,
                spread,
                hash_algorithm,
                signing_key,
                dir,
                payload_file,
                payload_text,
                mime_type,
                filename,
                no_verify_write,
                password,
                password_file,
            } => {
                let generic = payload_file.is_some() || payload_text.is_some();
                if !(1..=8).contains(&spread) {
                    usage_error("--spread must be 1 (disabled) or 2 through 8".to_string());
                }
                if !generic
                    && (password.is_some()
                        || password_file.is_some()
                        || compress
                        || mime_type.is_some()
                        || filename.is_some()
                        || no_verify_write)
                {
                    usage_error("passwords, compression, packet metadata and --no-verify-write require --payload-file or --payload-text".to_string());
                }
                if generic && hash_algorithm.is_some() {
                    usage_error("--hash-algorithm is unsupported for generic packets".to_string());
                }
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
                    quiet_report: false,
                };
                if payload_file.is_some() || payload_text.is_some() {
                    if dir {
                        usage_error("generic packet encoding does not support --dir".to_string());
                    }
                    if opts.spread > 1 {
                        usage_error(
                            "generic packet alpha does not yet support multi-frame spreading"
                                .to_string(),
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
                            encrypt: opts.encrypt,
                            encryption_key: opts.encryption_key.clone(),
                            encryption_key_file: opts.encryption_key_file.clone(),
                            ecc: opts.ecc,
                            ecc_parity: opts.ecc_parity,
                            compress,
                            signing_key: opts.signing_key.clone(),
                            embedding_key: opts.embedding_key.clone(),
                            embedding_key_file: opts.embedding_key_file.clone(),
                            verify_write: !no_verify_write,
                            password,
                            password_file,
                            decode_limits,
                            raw_width: width,
                            raw_height: height,
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
                decrypt,
                decryption_key,
                decryption_key_file,
                embedding_key,
                embedding_key_file,
                password,
                password_file,
                trusted_signer,
                revoked_list,
            } => {
                // Errors are classified centrally: a carrier with no embedded
                // generic packet is packet-not-found (exit 2). JSON mode
                // surfaces it as an error envelope.
                cmd_packet::decode(
                    &input,
                    &output,
                    &stego_type,
                    &bits,
                    &format,
                    input_format.as_deref(),
                    force,
                    &cmd_packet::GenericDecodeOptions {
                        decrypt,
                        decryption_key,
                        decryption_key_file,
                        embedding_key,
                        embedding_key_file,
                        password,
                        password_file,
                        trusted_signer,
                        revoked_list,
                        decode_limits,
                    },
                )
            }

            Commands::Extract {
                input,
                output,
                bits,
                force,
                password,
                password_file,
                format,
                stego_type,
                input_format,
                embedding_key,
                embedding_key_file,
                encryption_key,
                encryption_key_file,
                trusted_signer,
                revoked_list,
            } => {
                let bits = match bits.to_ascii_lowercase().as_str() {
                    "auto" => None,
                    value => match value.parse::<u8>() {
                        Ok(n @ 1..=4) => Some(n),
                        _ => usage_error(format!(
                            "--bits must be 'auto' or an integer from 1 to 4, got '{bits}'"
                        )),
                    },
                };
                // Same packet-not-found contract as decode, classified centrally.
                let stego_type = stego_type.unwrap_or_else(|| {
                    if input.to_ascii_lowercase().ends_with(".wav")
                        || input_format.as_deref() == Some("wav")
                    {
                        "lsb_audio".to_string()
                    } else {
                        "lsb_video".to_string()
                    }
                });
                cmd_packet::run_extract(
                    &PathBuf::from(input),
                    &PathBuf::from(output),
                    bits,
                    force,
                    &format,
                    cmd_packet::ExtractOptions {
                        stego_type,
                        input_format,
                        embedding_key,
                        embedding_key_file,
                        encryption_key,
                        encryption_key_file,
                        password,
                        password_file,
                        trusted_signer,
                        revoked_list,
                        decode_limits,
                    },
                )
            }

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
                revoked_list,
                frame_index,
            } => {
                // Usage validation first: unknown values are a usage error
                // (exit 1), not a silent no_signature / BLAKE3 fallback.
                if let Err(e) = cmd_verify::validate_stego_type(&stego_type) {
                    usage_error(format!("{e}"));
                }
                if let Err(e) = cmd_verify::parse_hash_algorithm_strict(
                    hash_algorithm.as_deref().unwrap_or("blake3"),
                ) {
                    usage_error(format!("{e}"));
                }
                let opts = cmd_verify::VerifyOptions {
                    bits: match cmd_verify::VerifyBits::parse(&bits) {
                        Ok(parsed) => parsed,
                        Err(e) => usage_error(format!("{e}")),
                    },
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
                    revoked_list,
                    frame_index,
                };
                match cmd_verify::run_with_key(
                    &cli.config,
                    &input,
                    public_key.as_deref(),
                    &stego_type,
                    &format,
                    embedding_key.as_deref(),
                    &opts,
                ) {
                    Ok(status) => {
                        match status.as_str() {
                            "invalid" | "valid_revoked" => std::process::exit(3),
                            "no_signature" => std::process::exit(2),
                            _ => {}
                        }
                        Ok(())
                    }
                    // Runtime failures (unreadable media, internal errors) fall
                    // through to the central error path: exit 6, or exit 1 for
                    // user-class errors, with an error envelope in JSON mode.
                    Err(e) => Err(e),
                }
            }

            Commands::Keygen { output, format } => cmd_encode::keygen(&output, &format),

            Commands::Info {
                input,
                stego_type,
                bits,
                format,
                width,
                height,
                embedding_key,
            } => cmd_encode::info(
                &input,
                &stego_type,
                bits,
                &format,
                width,
                height,
                embedding_key.as_deref(),
            ),

            Commands::Analyze {
                input,
                analysis_type,
                format,
            } => cmd_encode::analyze(&input, &analysis_type, &format),

            Commands::Scan {
                input,
                max_depth,
                max_files,
                max_bytes,
                format,
                follow_input_symlink,
                profile,
            } => {
                // Argument-shape validation is a usage error (exit 1); a
                // runtime failure inside the scan falls through to the central
                // error path (exit 6); a successful run exits with the
                // caller's policy code (0 = clean, 4 = findings meet the
                // failure threshold, 5 = truncated with no findings).
                if format == "json" || format == "jsonl" {
                    envelope::activate_json_mode("scan");
                }
                let path = std::path::Path::new(&input);
                // Symlinks are never followed by scan; rejecting the symlinked
                // input keeps the top level consistent with directory recursion
                // (usage class, exit 1).
                if let Err(message) = cmd_scan::check_input_symlink(path, follow_input_symlink) {
                    usage_error(message);
                }
                let scan_profile = match profile.as_deref() {
                    Some(name) => match resolve_scan_profile(&cli.config, name) {
                        Ok(profile) => Some(profile),
                        Err(error) => usage_error(format!("{error:#}")),
                    },
                    None => None,
                };
                let code = cmd_scan::run(
                    &input,
                    max_depth,
                    max_files,
                    max_bytes,
                    &format,
                    follow_input_symlink,
                    scan_profile.as_ref(),
                )
                .unwrap_or_else(|error| {
                    let (code, kind) = envelope::classify_exit(&format!("{error:#}"), Some(&error));
                    if let Some(command) = envelope::current_json_command() {
                        envelope::fail_json(&command, kind, &format!("{error:#}"), code);
                    }
                    eprintln!("Error: {error:#}");
                    std::process::exit(code);
                });
                std::process::exit(code)
            }

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
                format,
            } => {
                let master_mode =
                    master_secret.is_some() || master_secret_file.is_some() || master_secret_stdin;
                let password_mode = password.is_some() || password_file.is_some() || password_stdin;

                if password_mode && master_mode {
                    usage_error(
                        "Provide either a master secret (--master-secret*) or a password \
                     (--password*), not both."
                            .to_string(),
                    );
                }

                if password_mode {
                    // Resolve the password from one of three sources (raw bytes).
                    let password_bytes = if password_stdin {
                        use std::io::Read;
                        let mut buf = Vec::new();
                        std::io::stdin()
                            .read_to_end(&mut buf)
                            .unwrap_or_else(|error| terminal_error(error.into()));
                        buf
                    } else if let Some(path) = password_file {
                        std::fs::read(&path).unwrap_or_else(|error| terminal_error(error.into()))
                    } else if let Some(pw) = password {
                        log::warn!(
                            "Reading password from --password (visible in shell history / ps). \
                         Consider --password-file or --password-stdin for better security."
                        );
                        pw.into_bytes()
                    } else {
                        usage_error(
                            "No password provided. Use --password <text>, \
                         --password-file <path>, or --password-stdin."
                                .to_string(),
                        );
                    };

                    // Trim a single trailing newline (e.g. heredoc / `printf`)
                    // and a preceding carriage return (CRLF, common on Windows
                    // pipes) — both are common when piping or reading a file.
                    let mut password_bytes = password_bytes;
                    if password_bytes.ends_with(b"\n") {
                        password_bytes.pop();
                        if password_bytes.ends_with(b"\r") {
                            password_bytes.pop();
                        }
                    }

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
                        &format,
                    )
                } else {
                    // Resolve the master secret from one of three sources
                    let secret_hex = if master_secret_stdin {
                        use std::io::Read;
                        let mut buf = String::new();
                        std::io::stdin()
                            .read_to_string(&mut buf)
                            .unwrap_or_else(|error| terminal_error(error.into()));
                        buf.trim().to_string()
                    } else if let Some(path) = master_secret_file {
                        std::fs::read_to_string(&path)
                            .unwrap_or_else(|error| terminal_error(error.into()))
                            .trim()
                            .to_string()
                    } else if let Some(s) = master_secret {
                        log::warn!(
                        "Reading master secret from --master-secret (visible in shell history / ps). \
                         Consider --master-secret-file or --master-secret-stdin for better security."
                    );
                        s
                    } else {
                        usage_error(
                            "No master secret provided. Use --master-secret <hex>, \
                         --master-secret-file <path>, --master-secret-stdin, or the \
                         password options (--password/--password-file/--password-stdin)."
                                .to_string(),
                        );
                    };

                    // Warn about low-entropy secrets (short hex strings are brute-forceable
                    // at BLAKE3 speed — this KDF is designed for already-high-entropy key
                    // material, not passphrases)
                    let raw_bytes = match steganographer_core::crypto::decode_hex(&secret_hex) {
                        Ok(bytes) => bytes,
                        Err(e) => usage_error(format!("Master secret is not valid hex: {}", e)),
                    };
                    if raw_bytes.len() < 32 {
                        log::warn!(
                        "Master secret is only {} bytes — BLAKE3 derive_key is NOT a slow KDF. \
                         Short or memorable passphrases can be brute-forced at hash speed. \
                         Use at least 32 bytes (64 hex chars) of high-entropy random data, \
                         or use --password for Argon2id stretching.",
                        raw_bytes.len()
                    );
                    }

                    cmd_encode::derive_keys(&secret_hex, &output, &format)
                }
            }

            Commands::Config { action, format } => match action.as_str() {
                "check" => match steganographer_core::config::Config::from_file(&cli.config) {
                    Ok(cfg) => match cfg.validate() {
                        Ok(()) => {
                            let mut sections = vec!["global"];
                            if cfg.video.is_some() {
                                sections.push("video");
                            }
                            if cfg.audio.is_some() {
                                sections.push("audio");
                            }
                            if cfg.limits.is_some() {
                                sections.push("limits");
                            }
                            if cfg.profiles.is_some() {
                                sections.push("profiles");
                            }
                            let mut profile_names: Vec<String> = Vec::new();
                            if let Some(profiles) = &cfg.profiles {
                                profile_names.extend(profiles.keys().cloned());
                                profile_names.sort();
                            }
                            if format == "json" {
                                envelope::activate_json_mode("config check");
                                envelope::print(&envelope::success(
                                    "config check",
                                    serde_json::json!({
                                        "config_path": cli.config,
                                        "valid": true,
                                        "sections": sections,
                                        "hash_algorithm": cfg.global.hash_algorithm,
                                        "key_file": cfg.global.key_file,
                                        "profiles": profile_names,
                                    }),
                                ));
                            } else {
                                println!("✓ Configuration valid: {}", cli.config);
                                println!("  Sections: {}", sections.join(", "));
                                if let Some(algo) = &cfg.global.hash_algorithm {
                                    println!("  Hash algorithm: {}", algo);
                                }
                                if let Some(kf) = &cfg.global.key_file {
                                    println!("  Key file: {}", kf);
                                }
                                if !profile_names.is_empty() {
                                    println!("  Profiles: {}", profile_names.join(", "));
                                }
                            }
                            Ok(())
                        }
                        Err(e) => {
                            if format == "json" {
                                envelope::fail_json(
                                    "config check",
                                    envelope::USAGE_ERROR,
                                    &format!("Configuration error in {}: {e}", cli.config),
                                    1,
                                );
                            }
                            eprintln!("✗ Configuration error in {}: {}", cli.config, e);
                            std::process::exit(1)
                        }
                    },
                    Err(e) => {
                        if format == "json" {
                            envelope::fail_json(
                                "config check",
                                envelope::USAGE_ERROR,
                                &format!("Configuration error in {}: {e}", cli.config),
                                1,
                            );
                        }
                        eprintln!("✗ Configuration error in {}: {}", cli.config, e);
                        std::process::exit(1)
                    }
                },
                _ => usage_error(format!("Unknown config action: {action}. Use 'check'.")),
            },

            Commands::Revoke {
                public_key,
                output,
                format,
            } => cmd_encode::revoke_key(&public_key, &output, &format),

            Commands::Ots { action } => match action {
                OtsAction::Stamp {
                    input,
                    output_dir,
                    method,
                    force,
                    format,
                } => {
                    // Unknown --method values are a usage error (exit 1), not a
                    // silent fall-back to Bitcoin stamping.
                    if let Some(m) = method.as_deref() {
                        if let Err(e) = cmd_ots::validate_method(m) {
                            usage_error(format!("{e}"));
                        }
                    }
                    cmd_ots::stamp(
                        &cli.config,
                        &input,
                        output_dir.as_deref(),
                        method.as_deref(),
                        force,
                        &format,
                    )
                }
                OtsAction::Verify {
                    input,
                    proof,
                    format,
                } => cmd_ots::verify(&cli.config, &input, proof.as_deref(), &format),
            },

            Commands::Dashboard {
                port,
                backend,
                host,
                auth_token,
                transport,
                ice_server,
            } => {
                use std::sync::Arc;
                use steganographer_core::StegoMetrics;

                // The ICE list is consumed by the WebRTC media path; without
                // that feature the flag is parsed but has no effect. Say so
                // instead of failing the default clippy gate on an unused
                // binding.
                #[cfg(not(feature = "webrtc"))]
                if !ice_server.is_empty() || transport == "webrtc" {
                    usage_error(
                        "WebRTC transport and ICE servers require --features webrtc".to_string(),
                    );
                }

                if host == "0.0.0.0" && auth_token.is_none() {
                    log::warn!(
                        "Dashboard binding to 0.0.0.0 without --auth-token: \
                    mutating endpoints (POST /api/config, POST /api/metrics/reset) \
                    will be accessible without authentication. Consider using --auth-token."
                    );
                }

                if backend != "ed25519" {
                    usage_error(
                        "dashboard supports only the actual Ed25519 signing backend".to_string(),
                    );
                }
                if !matches!(transport.as_str(), "auto" | "websocket" | "webrtc") {
                    usage_error("unknown dashboard transport".to_string());
                }
                let signer = steganographer_core::Signer::generate();
                let identity =
                    steganographer_core::crypto::encode_hex(&signer.verifying_key().to_bytes());
                let ots_config = effective_config.ots_config();
                let ots_client = if ots_config.is_enabled() {
                    log::info!(
                        "OTS enabled: method={}, server={}, interval={}s",
                        ots_config.method_canonical(),
                        ots_config.server_url,
                        ots_config.interval_secs
                    );
                    Some(std::sync::Arc::new(
                        steganographer_core::OTSClient::from_config(&ots_config).unwrap_or_else(
                            |error| usage_error(format!("OTS configuration error: {error}")),
                        ),
                    ))
                } else {
                    None
                };

                let state = Arc::new(steganographer_dashboard::DashboardState {
                    metrics: Arc::new(StegoMetrics::new()),
                    signing_backend: "ed25519".to_string(),
                    identity: identity.clone(),
                    width: 640,
                    height: 480,
                    last_encoded_frame: std::sync::Mutex::new(None),
                    last_encoded_audio: std::sync::Mutex::new(None),
                    live_config: std::sync::Mutex::new(
                        steganographer_dashboard::LiveConfig::default(),
                    ),
                    session_start: std::time::Instant::now(),
                    auth_token,
                    transport: steganographer_dashboard::TransportPolicy::from(transport.as_str()),
                    ots_config,
                    ots_client,
                    ots_outcome: std::sync::Mutex::new(None),
                    signer,
                    audio_key: {
                        use rand::RngCore;
                        let mut k = [0u8; 32];
                        rand::rngs::OsRng.fill_bytes(&mut k);
                        k
                    },
                    #[cfg(feature = "webrtc")]
                    webrtc_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
                    #[cfg(feature = "webrtc")]
                    ice_servers: ice_server,
                    #[cfg(feature = "webrtc")]
                    media_publishers: std::sync::Mutex::new(std::collections::HashMap::new()),
                });

                log::info!(
                    "Starting dashboard on {}:{} with {} backend",
                    host,
                    port,
                    backend
                );
                log::info!("Identity: {}", identity);

                let rt = tokio::runtime::Runtime::new()
                    .unwrap_or_else(|error| terminal_error(error.into()));
                rt.block_on(steganographer_dashboard::start_server(state, port, &host))
            }
        }
    };
    #[cfg(all(feature = "gst", target_os = "macos"))]
    let run_result = if needs_cocoa {
        gstreamer::macos_main(run)
    } else {
        run()
    };
    #[cfg(not(all(feature = "gst", target_os = "macos")))]
    let run_result = run();

    // Central error path (SUR-003 exit-code contract): packet-not-found is
    // exit 2, unexpected I/O and internal failures are exit 6, and every
    // other error is a user/configuration/format error (exit 1). In JSON
    // mode the error also surfaces as an error envelope on stdout so stdout
    // stays a single machine payload.
    if let Err(error) = run_result {
        terminal_error(error);
    }
}

/// Resolve a named `[profiles.<name>]` profile from the config file.
///
/// Config-load failures, validation failures, and unknown profiles are
/// usage-class errors for the scan subcommand (exit 1 via `usage_error`).
fn resolve_scan_profile(
    config_path: &str,
    name: &str,
) -> anyhow::Result<steganographer_core::config::ProfileConfig> {
    let config = steganographer_core::config::Config::from_file(config_path)
        .map_err(|error| anyhow::anyhow!("cannot load config '{config_path}': {error:#}"))?;
    config.validate()?;
    config
        .profile(name)
        .cloned()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// Report a usage-class error and terminate with exit code 1
/// (the finalized exit-code contract's user/configuration/format class).
fn usage_error(message: String) -> ! {
    if let Some(command) = envelope::current_json_command() {
        envelope::fail_json(&command, envelope::USAGE_ERROR, &message, 1);
    }
    eprintln!("Error: {message}");
    std::process::exit(1);
}

/// Activate machine errors even when Clap rejects an argument before dispatch.
fn activate_requested_machine_mode(arguments: &[std::ffi::OsString]) {
    let text: Vec<_> = arguments
        .iter()
        .map(|value| value.to_string_lossy())
        .collect();
    let machine = text
        .windows(2)
        .any(|pair| pair[0] == "--format" && matches!(pair[1].as_ref(), "json" | "jsonl"))
        || text
            .iter()
            .any(|arg| matches!(arg.as_ref(), "--format=json" | "--format=jsonl"));
    if machine {
        let command = text
            .iter()
            .skip(1)
            .find(|arg| {
                matches!(
                    arg.as_ref(),
                    "encode"
                        | "decode"
                        | "extract"
                        | "verify"
                        | "scan"
                        | "keygen"
                        | "info"
                        | "analyze"
                        | "derive"
                        | "revoke"
                        | "config"
                        | "ots"
                )
            })
            .map(|arg| arg.as_ref())
            .unwrap_or("cli");
        envelope::activate_json_mode(command);
    }
}

fn activate_output_mode(command: &Commands) {
    let (name, format, jsonl) = match command {
        Commands::Encode { format, .. } => ("encode", format, false),
        Commands::Decode { format, .. } => ("decode", format, false),
        Commands::Extract { format, .. } => ("extract", format, false),
        Commands::Verify { format, .. } => ("verify", format, false),
        Commands::Scan { format, .. } => ("scan", format, true),
        Commands::Keygen { format, .. } => ("keygen", format, false),
        Commands::Info { format, .. } => ("info", format, false),
        Commands::Analyze { format, .. } => ("analyze", format, false),
        Commands::Derive { format, .. } => ("derive", format, false),
        Commands::Revoke { format, .. } => ("revoke", format, false),
        Commands::Config { format, .. } => ("config check", format, false),
        Commands::Ots {
            action: OtsAction::Stamp { format, .. },
        } => ("ots stamp", format, false),
        Commands::Ots {
            action: OtsAction::Verify { format, .. },
        } => ("ots verify", format, false),
        _ => return,
    };
    if format == "json" || (jsonl && format == "jsonl") {
        envelope::activate_json_mode(name);
    } else if format != "plain" {
        usage_error(format!(
            "unknown --format '{format}': expected plain, json{}",
            if jsonl { ", or jsonl" } else { "" }
        ));
    }
}

fn terminal_error(error: anyhow::Error) -> ! {
    // This marker is only returned after an inconclusive command emitted its
    // actual evidence envelope, so do not replace it with a second JSON value.
    if error
        .downcast_ref::<envelope::InconclusiveError>()
        .is_some()
    {
        std::process::exit(5);
    }
    let message = format!("{error:#}");
    let (exit_code, error_code) = envelope::classify_exit(&message, Some(&error));
    if let Some(command) = envelope::current_json_command() {
        envelope::fail_json(&command, error_code, &message, exit_code);
    }
    eprintln!("Error: {message}");
    std::process::exit(exit_code);
}
