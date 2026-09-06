# Scripts

Thin orchestration scripts for the Steganographer workspace. Project logic
(algorithms, codecs, crypto, dashboards) lives in the Rust crates
(`steganographer-core`, `steganographer-cli`, `steganographer-gst`,
`steganographer-dashboard`); scripts only bootstrap paths, report status, and
delegate to project tooling.

## Inventory

| Script | Purpose | Delegates to | Run command |
|--------|---------|--------------|-------------|
| `status.sh` | Print workspace status: version, CLI subcommand count, docs counts, git state, test total. `--check` exits 1 when the canonical Tests line in `AGENTS.md` drifts from what cargo reports | `cargo test --workspace` (CI counting method); `Cargo.toml` version; `steganographer-cli/src/main.rs` `enum Commands`; `ls docs/`; `git status -sb`; root `AGENTS.md` Tests line | `./scripts/status.sh` or `./scripts/status.sh --check` |

## Notes

- `status.sh` runs the full workspace test suite; it is slow on cold cargo caches.
- The canonical test count lives in the root `AGENTS.md` **Tests** line. Update
  that line first, then defer from other docs — `status.sh --check` enforces this.
- This inventory and `scripts/AGENTS.md` must be updated whenever a script is
  added, removed, or renamed.
