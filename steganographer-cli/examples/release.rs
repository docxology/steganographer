//! Source-bound, host-only release orchestration; see the repository README.
use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use flate2::{write::GzEncoder, Compression};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Variant {
    /// GStreamer-free CLI, supported on the current Unix host.
    Portable,
    /// All-feature CLI and native GStreamer plugin on the current Unix host.
    Native,
    /// Node.js and browser bindings from the same fresh wasm32 build.
    Wasm,
    /// All of the above; never cross-compile or claim another host was exercised.
    All,
}

#[derive(Parser)]
#[command(about = "Build source-bound local release archives (never publish)")]
struct Args {
    /// New output directory; existing entries, including empty directories, fail.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum, default_value = "all")]
    variant: Variant,
    /// Package the exact current tracked and nonignored untracked source bytes.
    /// HEAD remains a base revision, not an assertion that this is committed source.
    #[arg(long)]
    allow_dirty: bool,
}

fn text(root: &Path, program: &str, args: &[&str]) -> Result<String> {
    let result = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| format!("starting {program}"))?;
    ensure!(
        result.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}

fn run(root: &Path, program: &str, args: &[&str]) -> Result<()> {
    ensure!(
        Command::new(program)
            .args(args)
            .current_dir(root)
            .status()?
            .success(),
        "{program} {args:?} failed"
    );
    Ok(())
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}

fn safe_relative(path: &Path) -> Result<()> {
    ensure!(!path.as_os_str().is_empty(), "empty source path");
    for part in path.components() {
        let Component::Normal(name) = part else {
            bail!("unsafe source path: {}", path.display())
        };
        let name = name.to_string_lossy().to_ascii_lowercase();
        ensure!(
            !matches!(
                name.as_str(),
                ".git" | ".hg" | ".svn" | "target" | "dist" | "keys" | "output"
            ),
            "excluded source path: {}",
            path.display()
        );
        ensure!(
            !matches!(name.as_str(), "id_rsa" | "id_ed25519" | ".env")
                && !name.ends_with(".key")
                && !name.ends_with(".pem")
                && !name.ends_with(".secret")
                && !name.ends_with(".p12")
                && !name.ends_with(".pfx"),
            "private-key source path: {}",
            path.display()
        );
    }
    Ok(())
}

fn no_symlink_path(path: &Path) -> Result<()> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        ensure!(
            !matches!(part, Component::ParentDir),
            "parent traversal: {}",
            path.display()
        );
        prefix.push(part);
        match fs::symlink_metadata(&prefix) {
            Ok(meta) => ensure!(
                !meta.file_type().is_symlink(),
                "symlink path: {}",
                prefix.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn reserve_output(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    no_symlink_path(&absolute)?;
    let parent = absolute.parent().context("output has no parent")?;
    ensure!(parent.is_dir(), "create the output parent directory first");
    // create_dir, not create_dir_all: even an empty pre-existing output is unsafe.
    fs::create_dir(&absolute)
        .with_context(|| format!("refusing to overwrite {}", absolute.display()))?;
    Ok(absolute)
}

fn source_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let result = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(root)
        .output()?;
    ensure!(result.status.success(), "git source inventory failed");
    let mut paths = Vec::new();
    for name in result
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let path = PathBuf::from(std::str::from_utf8(name).context("non-UTF-8 source filename")?);
        // A tracked deletion is part of the current source, not a missing input.
        if !root.join(&path).try_exists()? {
            ensure!(
                fs::symlink_metadata(root.join(&path)).is_err(),
                "dangling source symlink"
            );
            continue;
        }
        safe_relative(&path)?;
        no_symlink_path(&root.join(&path))?;
        ensure!(
            root.join(&path).is_file(),
            "non-file source input: {}",
            path.display()
        );
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn snapshot(root: &Path, destination: &Path, paths: &[PathBuf]) -> Result<Value> {
    fs::create_dir(destination)?;
    let mut inventory = BTreeMap::new();
    for relative in paths {
        no_symlink_path(&root.join(relative))?;
        let bytes = fs::read(root.join(relative))?;
        // Filename checks are supplemented by the repository's real secret scanner.
        ensure!(!bytes.split(|byte| *byte == b'\n').any(|line|
            line.starts_with(b"-----BEGIN ") && line.ends_with(b"PRIVATE KEY-----")),
            "private key content in {}", relative.display());
        let output = destination.join(relative);
        fs::create_dir_all(output.parent().context("source parent")?)?;
        write_new(&output, &bytes)?;
        let permissions = fs::metadata(root.join(relative))?.permissions();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            permissions.mode()
        };
        #[cfg(not(unix))]
        let mode = u32::from(permissions.readonly());
        fs::set_permissions(&output, permissions)?;
        inventory.insert(
            relative.to_string_lossy().into_owned(),
            json!({"sha256": sha(&bytes), "bytes": bytes.len(), "mode": mode}),
        );
    }
    Ok(serde_json::to_value(inventory)?)
}

fn metadata(root: &Path, full: bool) -> Result<Value> {
    let mut args = vec!["metadata", "--locked", "--format-version", "1"];
    if !full {
        args.push("--no-deps");
    }
    Ok(serde_json::from_str(&text(root, "cargo", &args)?)?)
}

#[derive(Default)]
struct Build {
    executable: Option<PathBuf>,
    library: Option<PathBuf>,
    generated: Option<PathBuf>,
    features: Vec<Value>,
}

fn build(
    root: &Path,
    target: &Path,
    package: &str,
    flags: &[&str],
    commands: &mut Vec<Value>,
) -> Result<Build> {
    let meta = metadata(root, false)?;
    let package_id = meta["packages"]
        .as_array()
        .context("Cargo packages")?
        .iter()
        .find(|entry| entry["name"] == package)
        .and_then(|entry| entry["id"].as_str())
        .context("Cargo package ID")?;
    let mut args = vec![
        "build",
        "--release",
        "--locked",
        "--message-format=json-render-diagnostics",
        "-p",
        package,
    ];
    args.extend_from_slice(flags);
    commands.push(json!({"program": "cargo", "args": args}));
    let mut child = Command::new("cargo")
        .args(&args)
        .env("CARGO_TARGET_DIR", target)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut result = Build::default();
    for line in BufReader::new(child.stdout.take().context("cargo stdout")?).lines() {
        let value: Value = serde_json::from_str(&line?)?;
        let id = value["package_id"].as_str().unwrap_or_default();
        if id != package_id {
            continue;
        }
        match value["reason"].as_str() {
            Some("compiler-artifact") => {
                if let Some(path) = value["executable"].as_str() {
                    result.executable = Some(path.into());
                }
                if let Some(features) = value["features"].as_array() {
                    result.features = features.clone();
                }
                if let Some(files) = value["filenames"].as_array() {
                    for file in files.iter().filter_map(Value::as_str) {
                        if file.ends_with(".dylib")
                            || file.ends_with(".so")
                            || file.ends_with(".wasm")
                        {
                            result.library = Some(file.into());
                        }
                    }
                }
            }
            Some("build-script-executed") => {
                result.generated = value["out_dir"].as_str().map(PathBuf::from);
            }
            _ => (),
        }
    }
    ensure!(
        child.wait()?.success(),
        "fresh {package} release build failed"
    );
    Ok(result)
}

fn copy_file(input: &Path, destination: &Path) -> Result<()> {
    no_symlink_path(input)?;
    ensure!(input.is_file(), "missing artifact: {}", input.display());
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut File::open(input)?, &mut destination_file)?;
    fs::set_permissions(destination, fs::metadata(input)?.permissions())?;
    Ok(())
}

fn copy_tree(input: &Path, destination: &Path) -> Result<()> {
    no_symlink_path(input)?;
    fs::create_dir(destination)?;
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        ensure!(entry.file_type()?.is_file(), "non-file generated artifact");
        copy_file(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

fn archive(stage: &Path, name: &str, output: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join(format!("{name}.tar.gz")))?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    // BSD tar pads compressed stdout to its block size. Compress the raw tar
    // stream here so the output ends exactly at one gzip member's trailer.
    let mut child = Command::new("tar")
        .args(["-cf", "-", "-C"])
        .arg(stage)
        .arg(name)
        .env("COPYFILE_DISABLE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .context("starting tar")?;
    let mut source = child.stdout.take().expect("piped tar stdout");
    let copied = std::io::copy(&mut source, &mut encoder);
    if copied.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().context("reaping tar")?;
    copied.context("compressing tar stream")?;
    ensure!(status.success(), "tar failed");
    encoder.finish().context("finishing gzip member")?;
    Ok(())
}

fn native_variant(
    source: &Path,
    stage: &Path,
    output: &Path,
    version: &str,
    host: &str,
    native: bool,
    commands: &mut Vec<Value>,
) -> Result<Value> {
    let variant = if native { "native" } else { "portable" };
    let name = format!("steganographer-{version}-{host}-{variant}");
    let package = stage.join(&name);
    fs::create_dir(&package)?;
    let target = stage.join(format!("target-{variant}"));
    let flags = if native {
        vec!["--all-features", "--target", host]
    } else {
        vec!["--no-default-features", "--target", host]
    };
    let cli = build(source, &target, "steganographer-cli", &flags, commands)?;
    let executable = cli
        .executable
        .context("Cargo did not report the CLI executable")?;
    let reported = text(
        source,
        executable.to_str().context("executable path")?,
        &["--version"],
    )?;
    ensure!(
        reported == format!("steganographer {version}"),
        "CLI version mismatch: {reported}"
    );
    copy_file(&executable, &package.join("steganographer"))?;
    let generated = cli
        .generated
        .context("Cargo did not report CLI generated artifacts")?;
    copy_tree(&generated.join("man"), &package.join("man"))?;
    copy_tree(&generated.join("completions"), &package.join("completions"))?;
    ensure!(
        package.join("man/steganographer.1").is_file(),
        "missing root manual"
    );
    ensure!(
        fs::read_dir(package.join("completions"))?.count() == 5,
        "incomplete shell completions"
    );
    let mut plugin_features = None;
    if native {
        let plugin = build(
            source,
            &target,
            "steganographer-gst",
            &["--target", host],
            commands,
        )?;
        let library = plugin
            .library
            .context("Cargo did not report the native plugin")?;
        copy_file(
            &library,
            &package.join(library.file_name().context("plugin filename")?),
        )?;
        plugin_features = Some(plugin.features);
    }
    copy_file(
        &source.join("config/example.toml"),
        &package.join("example.toml"),
    )?;
    copy_file(
        &source.join("steganographer.toml"),
        &package.join("steganographer.toml"),
    )?;
    copy_file(&source.join("LICENSE"), &package.join("LICENSE"))?;
    let details = json!({"kind": variant, "host": host, "cli_features": cli.features, "plugin_features": plugin_features, "cli_version": reported,
        "runtime": if native { "GStreamer >= 1.22 and host platform shared libraries; not statically bundled" } else { "host platform shared libraries; not a static binary" }});
    write_json(&package.join("BUILD.json"), &details)?;
    archive(stage, &name, output)?;
    Ok(details)
}

fn wasm_variant(
    source: &Path,
    stage: &Path,
    output: &Path,
    version: &str,
    commands: &mut Vec<Value>,
) -> Result<Value> {
    let name = format!("steganographer-{version}-wasm");
    let package = stage.join(&name);
    fs::create_dir(&package)?;
    let meta = metadata(source, true)?;
    let bindings_version = meta["packages"]
        .as_array()
        .context("Cargo packages")?
        .iter()
        .find(|package| package["name"] == "wasm-bindgen")
        .and_then(|package| package["version"].as_str())
        .context("locked wasm-bindgen version")?;
    let generator = text(source, "wasm-bindgen", &["--version"])?;
    ensure!(
        generator == format!("wasm-bindgen {bindings_version}"),
        "install wasm-bindgen-cli {bindings_version}; found {generator}"
    );
    let wasm = build(
        source,
        &stage.join("target-wasm"),
        "steganographer-wasm",
        &[
            "--no-default-features",
            "--target",
            "wasm32-unknown-unknown",
        ],
        commands,
    )?;
    let library = wasm
        .library
        .context("Cargo did not report the WASM module")?;
    for (directory, target) in [("node", "nodejs"), ("web", "web")] {
        let destination = package.join(directory);
        let args = [
            "--target",
            target,
            "--out-dir",
            destination.to_str().context("WASM output path")?,
            "--out-name",
            "steganographer_wasm",
            library.to_str().context("WASM artifact path")?,
        ];
        commands.push(json!({"program": "wasm-bindgen", "args": args}));
        run(source, "wasm-bindgen", &args)?;
        write_json(
            &destination.join("package.json"),
            &json!({"name": format!("@steganographer/{directory}"), "version": version, "private": true,
            "type": if directory == "web" { "module" } else { "commonjs" }, "main": "steganographer_wasm.js", "types": "steganographer_wasm.d.ts"}),
        )?;
        ensure!(
            destination.join("steganographer_wasm_bg.wasm").is_file(),
            "missing generated WASM"
        );
    }
    copy_file(&source.join("LICENSE"), &package.join("LICENSE"))?;
    let details = json!({"kind": "wasm", "target": "wasm32-unknown-unknown", "features": wasm.features, "generator": generator, "bindings": ["nodejs", "web"]});
    write_json(&package.join("BUILD.json"), &details)?;
    archive(stage, &name, output)?;
    Ok(details)
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        cfg!(any(target_os = "macos", target_os = "linux")),
        "release archives currently support macOS/Linux hosts only; no Windows release is claimed"
    );
    let root = PathBuf::from(text(
        &std::env::current_dir()?,
        "git",
        &["rev-parse", "--show-toplevel"],
    )?);
    let head = text(&root, "git", &["rev-parse", "HEAD"])?;
    let status = text(
        &root,
        "git",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    ensure!(
        args.allow_dirty || status.is_empty(),
        "dirty source: commit first, or explicitly use --allow-dirty"
    );
    let rustc = text(&root, "rustc", &["-vV"])?;
    let host = rustc
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("rustc host")?
        .to_owned();
    let cargo = text(&root, "cargo", &["--version"])?;
    let scanner = text(&root, "gitleaks", &["version"])?;
    let paths = source_paths(&root)?;
    let temporary = tempfile::tempdir()?;
    let canonical_stage = temporary.path().canonicalize()?;
    let stage = canonical_stage.as_path();
    let source = stage.join("source");
    let inventory = snapshot(&root, &source, &paths)?;
    let meta = metadata(&source, false)?;
    let packages = meta["packages"].as_array().context("Cargo packages")?;
    let version = packages
        .iter()
        .find(|package| package["name"] == "steganographer-cli")
        .and_then(|package| package["version"].as_str())
        .context("workspace version")?
        .to_owned();
    ensure!(
        packages.iter().all(|package| package["version"] == version),
        "workspace versions differ"
    );
    // Scan the actual snapshot, not source history; never waive scanner failures.
    run(
        &source,
        "gitleaks",
        &[
            "dir",
            ".",
            "--config",
            ".gitleaks.toml",
            "--redact",
            "--no-banner",
        ],
    )?;
    let output = reserve_output(&args.output)?;
    write_json(&output.join("SOURCE.json"), &inventory)?;
    let inventory_bytes = fs::read(output.join("SOURCE.json"))?;
    let source_name = format!("steganographer-{version}-source");
    fs::rename(&source, stage.join(&source_name))?;
    let source = stage.join(&source_name);
    archive(stage, &source_name, &output)?;
    let mut commands = Vec::new();
    let mut variants = Vec::new();
    if matches!(args.variant, Variant::Portable | Variant::All) {
        variants.push(native_variant(
            &source,
            stage,
            &output,
            &version,
            &host,
            false,
            &mut commands,
        )?);
    }
    if matches!(args.variant, Variant::Native | Variant::All) {
        variants.push(native_variant(
            &source,
            stage,
            &output,
            &version,
            &host,
            true,
            &mut commands,
        )?);
    }
    if matches!(args.variant, Variant::Wasm | Variant::All) {
        variants.push(wasm_variant(
            &source,
            stage,
            &output,
            &version,
            &mut commands,
        )?);
    }
    ensure!(
        text(&root, "git", &["rev-parse", "HEAD"])? == head,
        "HEAD changed during release assembly"
    );
    write_json(
        &output.join("PROVENANCE.json"),
        &json!({"schema": "steganographer.release.v1", "version": version, "base_commit": head,
        "dirty": !status.is_empty(), "source_status": status, "source_inventory_sha256": sha(&inventory_bytes), "source_binding": "SOURCE.json records the exact bytes built, including explicitly allowed dirty/untracked source; base_commit is not a dirty snapshot identity",
        "host": host, "rustc": rustc, "cargo": cargo, "gitleaks": scanner, "variants": variants, "commands": commands,
        "validation": "fresh compilation, matching CLI version and generated-artifact presence; no claim of full tests, JavaScript runtime checks, cross-host execution or publication"}),
    )?;
    let mut checksums = BTreeMap::new();
    for entry in fs::read_dir(&output)? {
        let path = entry?.path();
        checksums.insert(
            path.file_name()
                .context("artifact filename")?
                .to_string_lossy()
                .into_owned(),
            sha_file(&path)?,
        );
    }
    let sums: String = checksums
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect();
    write_new(&output.join("SHA256SUMS"), sums.as_bytes())?;
    println!("Release artifacts: {}", output.display());
    Ok(())
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn archive_is_one_complete_gzip_member() -> Result<()> {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
        let stage = directory.path().join("stage");
        let output = directory.path().join("output");
        fs::create_dir(&stage)?;
        fs::create_dir(&output)?;
        fs::create_dir(stage.join("payload"))?;
        write_new(&stage.join("payload/data"), b"strict gzip archive")?;
        archive(&stage, "payload", &output)?;

        let mut decoder = flate2::bufread::GzDecoder::new(BufReader::new(File::open(
            output.join("payload.tar.gz"),
        )?));
        std::io::copy(&mut decoder, &mut std::io::sink())?;
        let mut trailing = [0_u8; 1];
        assert_eq!(
            decoder.into_inner().read(&mut trailing)?,
            0,
            "archive must end at the gzip trailer, without padding or another member"
        );
        Ok(())
    }

    #[test]
    fn refuses_existing_output_without_touching_it() -> Result<()> {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
        let output = directory.path().join("release");
        fs::create_dir(&output)?;
        write_new(&output.join("sentinel"), b"preserve")?;
        assert!(reserve_output(&output).is_err());
        assert_eq!(fs::read(output.join("sentinel"))?, b"preserve");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_source_and_output_parent() -> Result<()> {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        write_new(&source.join("real"), b"outside")?;
        std::os::unix::fs::symlink(source.join("real"), source.join("link"))?;
        assert!(snapshot(
            &source,
            &directory.path().join("snapshot"),
            &[PathBuf::from("link")]
        )
        .is_err());
        std::os::unix::fs::symlink(&source, directory.path().join("alias"))?;
        assert!(reserve_output(&directory.path().join("alias/release")).is_err());
        assert!(!source.join("release").exists());
        Ok(())
    }

    #[test]
    fn captures_dirty_and_untracked_bytes_not_index() -> Result<()> {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        run(&source, "git", &["init", "--quiet"])?;
        write_new(&source.join("tracked"), b"old")?;
        run(&source, "git", &["add", "tracked"])?;
        fs::write(source.join("tracked"), b"current")?;
        write_new(&source.join("new"), b"untracked")?;
        let destination = directory.path().join("snapshot");
        let inventory = snapshot(&source, &destination, &source_paths(&source)?)?;
        assert_eq!(fs::read(destination.join("tracked"))?, b"current");
        assert_eq!(fs::read(destination.join("new"))?, b"untracked");
        assert_eq!(inventory["tracked"]["sha256"], sha(b"current"));
        assert!(!destination.join(".git").exists());
        Ok(())
    }

    #[test]
    fn rejects_private_material_and_source_history() -> Result<()> {
        for path in [
            "keys/signing",
            "signer.key",
            "id_ed25519",
            "nested/.git/config",
            "../escape",
        ] {
            assert!(safe_relative(Path::new(path)).is_err(), "{path}");
        }
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
        write_new(
            &directory.path().join("innocent.txt"),
            b"-----BEGIN PRIVATE KEY-----",
        )?;
        assert!(snapshot(
            directory.path(),
            &directory.path().join("snapshot"),
            &[PathBuf::from("innocent.txt")]
        )
        .is_err());
        Ok(())
    }
}
