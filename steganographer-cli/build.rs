//! Build script for steganographer-cli.
//!
//! Generates shell completions and man pages at build time.

use clap_complete::{generate_to, Shell};

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
    let completions_dir = std::path::Path::new(&out_dir).join("completions");
    let man_dir = std::path::Path::new(&out_dir).join("man");
    std::fs::create_dir_all(&completions_dir).ok();
    std::fs::create_dir_all(&man_dir).ok();

    // Define a minimal command for completions and man page generation
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

    // Generate shell completions
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Elvish] {
        generate_to(shell, &mut cmd, "steganographer", &completions_dir).ok();
    }

    // Generate man page
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buffer: Vec<u8> = Vec::new();
    if man.render_title(&mut buffer).is_ok() && man.render(&mut buffer).is_ok() {
        let man_path = man_dir.join("steganographer.1");
        std::fs::write(&man_path, &buffer).ok();
    }

    println!("cargo:rerun-if-changed=src/main.rs");
}
