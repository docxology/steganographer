# Manuscript Status — steganographer

- **Repo type:** Rust workspace tool (Cargo.toml workspace with
  `steganographer-cli`, `steganographer-core`, `steganographer-dashboard`,
  `steganographer-gst` crates), with Docker support and a dashboard.
- **Evidence checked:** repo root `README.md`, `AGENTS.md`, `Cargo.toml`,
  `docs/` (architecture, algorithms, cryptography, api-reference, cli-reference,
  configuration, security, threat-model, gstreamer, ots-integration,
  key-rotation). No `manuscript/` or `paper/` directory exists.
- **Why no publication-target manuscript applies today:** this is an applied
  software tool with its own technical documentation set; no research-analysis
  outputs or figures exist that would form a paper's evidence base.
- **What would trigger a manuscript:** an empirical evaluation of its
  steganographic techniques (capacity, detectability, robustness benchmarks)
  would justify creating `manuscript/` at repo top level following the
  `template_code_project` standard.
