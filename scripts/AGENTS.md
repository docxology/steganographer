# AGENTS: `scripts/` — Thin Orchestrator Scripts

Technical specification for this directory. Read together with `scripts/README.md`.

## Contract

- `scripts/` holds thin orchestrators ONLY: argument parsing, path bootstrap
  (`cd` to the repo root via `BASH_SOURCE`), output formatting, and single
  delegated calls into project tooling (`cargo`, `git`, documented sources).
- Project business logic lives in the Rust crates under `steganographer-*`;
  never place algorithm/data/analysis logic in a script.
- Every script MUST appear in the inventory table below AND in
  `scripts/README.md`. Adding, renaming, or removing a script without updating
  both files fails the directory-documentation contract.
- Bash conventions used by existing scripts: `#!/usr/bin/env bash`,
  `set -euo pipefail`, `|| true` guards on optional `grep`/`awk` probes so a
  probe miss cannot abort the script under `set -e`.

## Inventory

| Script | Delegates to | Notes |
|--------|--------------|-------|
| `status.sh` | `cargo test --workspace --locked`; `Cargo.toml`; `steganographer-cli/src/cli.rs` (`enum Commands`); `docs/` listing; `git status -sb`; root `AGENTS.md` Tests line | Default mode prints status. `--check` exits 1 on test-count drift; CLI count drift from 15 is a nonfatal note. Failed test output is preserved. |
| `release.sh` | Rust/Clap `steganographer-cli/examples/release.rs` via Cargo with `--no-default-features` | Fresh snapshot builds; supported-host variants only; no publication/version mutation/overwrite. |
| `check-release.py` | Python 3.12+ stdlib, packaged CLI/plugin, Node.js and existing WASM binding consumer scenarios | Verifies real archives/source inventory/checksums and exercises packaged consumers; no source-text assertions. |

## Gotchas

- `status.sh` runs the FULL workspace test suite in both modes — slow on cold
  caches. Do not call it as a cheap precondition or in loops.
- `--check` compares cargo's summed `test result: ok` totals against the
  canonical Tests line in the root `AGENTS.md`. When adding or removing tests,
  update that AGENTS.md line FIRST, then other docs; otherwise `--check` exits 1.
- The subcommand probe reads the shared `steganographer-cli/src/cli.rs`
  `enum Commands` (15 top-level commands with GStreamer enabled). Restructuring
  variant opener lines requires updating that probe.
- Count the fourth field of every successful `test result:` line across test
  binaries and doc-test targets; preserve failures instead of swallowing stdout.

- Release assembly/safety logic belongs to the Rust release example, not the
  shell entrypoint. `check-release.py` only checks artifact metadata and delegates
  consumer execution; it does not implement project codecs/crypto.
- Release output directories must be new. Preserve incomplete and historical
  candidates; do not add force/reuse/stale-artifact paths.
- The source scanner is the existing repository gitleaks policy. Do not add
  scanner waivers or bypasses for packaging.
