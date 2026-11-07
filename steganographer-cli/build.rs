//! Generate completions and manuals from the binary's actual command schema.

use clap::CommandFactory;
use clap_complete::{generate_to, Shell};

#[allow(dead_code)]
#[path = "src/cli.rs"]
mod cli;

fn generate_manuals(cmd: clap::Command, out_dir: &std::path::Path) -> std::io::Result<()> {
    for subcommand in cmd.get_subcommands().filter(|s| !s.is_hide_set()).cloned() {
        generate_manuals(subcommand, out_dir)?;
    }
    let title = cmd
        .get_display_name()
        .unwrap_or_else(|| cmd.get_name())
        .to_ascii_uppercase();
    clap_mangen::Man::new(cmd)
        .title(title)
        // Omit the optional revision date rather than freezing a release date
        // into every future build. The source identifies the actual version.
        .date("")
        .source(format!("Steganographer {}", env!("CARGO_PKG_VERSION")))
        .manual("Steganographer Manual")
        .generate_to(out_dir)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or("Cargo did not provide OUT_DIR")?,
    );
    let completions_dir = out_dir.join("completions");
    let man_dir = out_dir.join("man");
    for dir in [&completions_dir, &man_dir] {
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        std::fs::create_dir_all(dir)?;
    }

    let mut cmd = cli::Cli::command();
    for shell in [
        Shell::Bash,
        Shell::Zsh,
        Shell::Fish,
        Shell::Elvish,
        Shell::PowerShell,
    ] {
        generate_to(shell, &mut cmd, "steganographer", &completions_dir)?;
    }
    let mut manual_command = cli::Cli::command().disable_help_subcommand(true);
    manual_command.build();
    generate_manuals(manual_command, &man_dir)?;

    println!("cargo:rerun-if-changed=src/cli.rs");
    Ok(())
}
