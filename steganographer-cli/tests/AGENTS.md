# AGENTS.md — `steganographer-cli/tests/`

- `cli_integration_tests.rs` exercises real CLI commands and output/error boundaries.
- `cli_packet_tests.rs` covers generic packets, encryption and bounded inspection.
- `native_cli_tests.rs` covers actual finite native-media behavior and preflight failures.
- `revocation_tests.rs` verifies immutable compromise denial, explicit policy and
  output preservation using public-only fixtures in `../testdata/revocation/`.
- No mocks or private signing material; workspace totals live in root `AGENTS.md`.
