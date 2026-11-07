# Scripts

Thin orchestration scripts for the Steganographer workspace. Project logic
(algorithms, codecs, crypto, dashboards) lives in the Rust crates
(`steganographer-core`, `steganographer-cli`, `steganographer-gst`,
`steganographer-dashboard`); scripts only bootstrap paths, report status, and
delegate to project tooling.

## Inventory

| Script | Purpose | Delegates to | Run command |
|--------|---------|--------------|-------------|
| `status.sh` | Print workspace status: version, CLI subcommand count, docs counts, git state, test total. `--check` exits 1 when the canonical Tests line in `AGENTS.md` drifts from what cargo reports | `cargo test --workspace` (CI counting method); `Cargo.toml` version; `steganographer-cli/src/cli.rs` command schema; documentation inventory; git state; root `AGENTS.md` Tests line | `./scripts/status.sh` or `./scripts/status.sh --check` |
| `release.sh` | Build source-bound, host-only CLI/plugin and Node/web WASM archives into a new immutable directory | Rust/Clap `steganographer-cli/examples/release.rs`; Cargo JSON artifacts; Git inventory; gitleaks; wasm-bindgen; system tar | `bash scripts/release.sh --output dist/<new-directory> --variant all` |
| `check-release.py` | Verify actual checksums/source archive, execute packaged CLIs/plugin discovery, and exercise Node/browser bindings | Python 3.12+ stdlib; packaged executables; `gst-inspect-1.0`; Node.js; existing WASM consumer scenarios | `python3 scripts/check-release.py dist/<new-directory>` |

## Notes

- `status.sh` runs the full workspace test suite; it is slow on cold cargo caches.
- The canonical test count lives in the root `AGENTS.md` **Tests** line. Update
  that line first, then defer from other docs — `status.sh --check` enforces this.
- This inventory and `scripts/AGENTS.md` must be updated whenever a script is
  added, removed, or renamed.

## Local release workflow

Version selection remains workspace-wide (`release.toml`, CLI-owned single tag
and changelog replacements). Artifact generation does **not** bump versions,
commit, tag, push, create GitHub releases, or publish crates/npm packages.
Run from a checkout after selecting its actual shared version:

```bash
# Once per toolchain: select wasm-bindgen-cli matching the exact Cargo.lock entry.
rustup target add wasm32-unknown-unknown
VERSION=$(python3 -c 'import tomllib; print(next(p["version"] for p in tomllib.load(open("Cargo.lock", "rb"))["package"] if p["name"] == "wasm-bindgen"))')
cargo install wasm-bindgen-cli --version "$VERSION" --locked
# A pinned scanner installation, if gitleaks is not already on PATH:
go install github.com/zricethezav/gitleaks/v8@v8.24.3
export PATH="$(go env GOPATH)/bin:$PATH"

mkdir -p dist
# Replace this output name; it must not already exist, even as an empty directory.
bash scripts/release.sh --output dist/reviewed-release --variant all
python3 scripts/check-release.py dist/reviewed-release
```

Prerequisites are the workspace Rust toolchain, Git, system `tar`, gitleaks with
the `dir` command (8.19+), and native workspace build dependencies. Full/native
artifacts need GStreamer 1.22+ development libraries; their consumer checks need
`gst-inspect-1.0`. WASM requires the Rust target and exactly matching binding
generator above; its consumer checks need Node.js. The checker needs Python
3.12+. The orchestrator itself uses `--no-default-features`, so merely invoking
it or producing `--variant portable` does not require GStreamer.

Supported hosts are macOS and Linux. `--variant portable` builds a
GStreamer-free CLI; `--variant native` builds the all-feature CLI and real
GStreamer cdylib; `--variant wasm` produces both Node.js and browser bindings.
`--variant all` does all three. Native archives identify the actual Rust host
triple: no other architecture, OS, Windows execution, or static-library
portability is claimed. Native dependencies are **not** bundled.

Every invocation captures current tracked and nonignored untracked source
bytes, scans that snapshot with the repository's actual gitleaks policy, and
builds only from that frozen snapshot using fresh, isolated target directories.
No existing `target/` executable or historical `dist/` candidate is selected.
Clean source is required unless `--allow-dirty` is explicit; dirty artifacts
record HEAD as a **base**, not the identity of the bytes built. Deleted tracked
files remain deleted. Source history, build/output directories, private-key
filenames/material and source/output symlinks are rejected; ignored credentials
are never enumerated. A changing HEAD aborts assembly.

Each output directory contains:

- A source archive and `SOURCE.json`: exact file names, byte lengths, SHA-256
  digests and permission modes of every source input, including dirty inputs.
- Requested host-native/portable and/or WASM archives. Each carries
  `BUILD.json` with the actual Cargo artifact features and runtime requirements.
  CLI archives include generated manuals/completions, example/master config
  and license; WASM archives include Node/web JavaScript, TypeScript declarations,
  real `.wasm` modules and private local package metadata at the actual version.
- `PROVENANCE.json`: source-inventory digest, actual version/base revision and
  dirty status, host/compiler/Cargo/scanner/generator versions, build commands,
  and precisely bounded validation claims.
- `SHA256SUMS`: all archives and metadata files (not itself).

Existing outputs are never overwritten, including symlinks or empty directories.
If a build fails, the reserved output directory may contain incomplete files:
absence of final `PROVENANCE.json`/`SHA256SUMS` means it is **not** a completed
release. Inspect it, then choose a new directory; the tool never cleans old
candidates. Archives are source-bound, not a claim of byte-for-byte archive
reproducibility across operating systems/toolchains.

CLI generation continues to use the single Clap schema: the full CLI currently
has 18 manuals and five shell completions (portable has 16 manuals/five
completions). Manuals identify the actual package version and omit the optional
revision date rather than baking one historical date into later releases.
The Docker image still builds this same schema/generator from its copied CLI
sources; it does not invoke the release helper or require Git/scanner/WASM tools.

The existing packaging-metadata CI job runs this workflow and real artifact
consumer checks in addition to its metadata gate. For a reproducible local
safety regression run before assembly:

```bash
cargo test -p steganographer-cli --example release --no-default-features --locked
```

Those tests exercise no-clobber preservation, symlink boundaries, private-key/
history exclusion and dirty/untracked source capture. Full workspace/MSRV/
static checks remain separate release gates; assembly does not attest they ran.
