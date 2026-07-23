# AGENTS.md — docs/

## Purpose

Comprehensive documentation suite for the steganographer project, covering steganographic theory, cryptographic foundations, system architecture, dashboard operations, and user guides.

## Contents (18 files)

| File                      | Topic                                                                                                |
| ------------------------- | ---------------------------------------------------------------------------------------------------- |
| `README.md`               | Documentation index with dashboard preview, features table, test summary                             |
| `steganography-theory.md` | Deep steganography theory: history, information-theoretic security, spatial/frequency domain          |
| `architecture.md`         | Four-crate layered design with dashboard, dependency graph, module map, data flow                    |
| `cryptography.md`         | BLAKE3 + Ed25519/Ethereum signing, SignerBackend trait, EIP-191, provable security, post-quantum     |
| `algorithms.md`           | LSB video/audio protocols, QR data matrix overlay, template placeholders, capacity math              |
| `getting-started.md`      | Prerequisites, build, test, dashboard quickstart, pipeline customization                             |
| `cli-reference.md`        | All 6 commands (video, audio, encode, verify, keygen, dashboard), `--format json`, exit codes        |
| `configuration.md`        | Full TOML schema, dashboard live config, template placeholders (`{timestamp}`, `{frame_index}`)      |
| `gstreamer.md`            | AppSink/AppSrc architecture, pipeline elements, config-driven construction                           |
| `platforms.md`            | macOS, Linux, Windows, Docker setup guides with config recommendations                               |
| `api-reference.md`        | Complete public API: types, traits, methods, dashboard LiveConfig, DashboardState, HTTP routes        |
| `security.md`             | Threat analysis, Cachin's framework, steganalysis resistance, key management                         |
| `contributing.md`         | Dev workflow, code style, adding new algorithms, project structure with dashboard crate               |
| `roadmap.md`              | Short/medium/long term plans — timestamp watermarks + JSON verify output now implemented             |
| `faq.md`                  | 30+ Q&As on concepts, build, usage, crypto, dashboard, MetaMask, template placeholders, JSON output  |
| `threat-model.md`         | Attacker models, LSB statistical detection, JPEG/MP3 robustness, countermeasures                     |
| `key-rotation.md`         | Key rotation record — 2026-07-22 daf.key incident report, new public key, revocation procedure      |

## Cross-references

- Dashboard docs span `algorithms.md` (QR data matrix), `configuration.md` (live config), `getting-started.md` (quickstart), and `faq.md` (dashboard Q&As)
- Template placeholders documented in `configuration.md`, `algorithms.md`, and `faq.md`
- JSON verify output documented in `cli-reference.md` and `faq.md`
- The `steganography-theory.md` references foundational papers — verify citations when expanding

## Maintenance

All documentation directly references the source code and `steganographer.toml` configuration. When modifying modules or config fields, update the corresponding doc file.
