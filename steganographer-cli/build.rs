//! Build script for steganographer-cli.
//!
//! Generates shell completions and man pages at build time.

use clap::CommandFactory;
use clap_complete::{generate_to, Shell};

// Disable for now — clap_mangen is an optional dep we add later
// include!("src/main.rs");

fn main() {
    // Only run if the completions feature is enabled or we're on a release build
    // For now, generate completions to a directory
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
    let completions_dir = std::path::Path::new(&out_dir).join("completions");
    std::fs::create_dir_all(&completions_dir).ok();

    // Generate shell completions using clap_complete
    // We define a minimal command here for completions
    let mut cmd = clap::Command::new("steganographer")
        .about("Real-time steganographic watermarking for video and audio streams")
        .version("0.2.0")
        .arg(clap::Arg::new("config").long("config").short('c').help("Path to configuration file (TOML)"))
        .arg(clap::Arg::new("log-level").long("log-level").short('l').help("Log verbosity level"))
        .arg(clap::Arg::new("quiet").long("quiet").short('q').help("Suppress all output except final result"))
        .subcommand(clap::Command::new("encode").about("Encode steganographic data into a file"))
        .subcommand(clap::Command::new("verify").about("Verify steganographic signatures in a media file"))
        .subcommand(clap::Command::new("keygen").about("Generate a new Ed25519 signing key pair"))
        .subcommand(clap::Command::new("info").about("Report steganographic capacity of a media file"))
        .subcommand(clap::Command::new("analyze").about("Analyze a file for steganographic artifacts"))
        .subcommand(clap::Command::new("derive").about("Derive keys from a master secret"))
        .subcommand(clap::Command::new("dashboard").about("Launch the web dashboard"))
        .subcommand(clap::Command::new("video").about("Run live video pipeline"))
        .subcommand(clap::Command::new("audio").about("Run live audio pipeline"))
        .subcommand(clap::Command::new("config").about("Validate a TOML configuration file"));

    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Elvish] {
        generate_to(shell, &mut cmd, "steganographer", &completions_dir).ok();
    }

    println!("cargo:rerun-if-changed=src/main.rs");
}
