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
| `status.sh` | `cargo test --workspace`; `Cargo.toml`; `steganographer-cli/src/main.rs` (`enum Commands`); `docs/` listing; `git status -sb`; root `AGENTS.md` Tests line | Default mode prints status. `--check` is the provenance gate: exit 1 on test-count drift; exit 0 (with a NOTE, non-fatal) if the CLI subcommand count stops being 14 |

## Gotchas

- `status.sh` runs the FULL workspace test suite in both modes — slow on cold
  caches. Do not call it as a cheap precondition or in loops.
- `--check` compares cargo's summed `test result: ok` totals against the
  canonical Tests line in the root `AGENTS.md`. When adding or removing tests,
  update that AGENTS.md line FIRST, then other docs; otherwise `--check` exits 1.
- The subcommand-count probe counts one-line variant declarations in
  `steganographer-cli/src/main.rs` `enum Commands` (expects 14). Restructuring
  that enum's formatting silently breaks the count.
- The test-count method must keep matching CI's job: sum the fourth field of
  every `test result:` line across all test binaries and doc-test targets.
