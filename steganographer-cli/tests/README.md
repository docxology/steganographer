# tests/

The real CLI binary is exercised by `cli_integration_tests.rs`,
`cli_packet_tests.rs`, `native_cli_tests.rs` and `revocation_tests.rs`. Coverage
includes packet boundaries, native-media preflight, immutable compromise denial
and preservation of existing outputs. Public-only pre-signed carriers live in
`../testdata/revocation/`; no private signing seed is included.

Run `cargo test -p steganographer-cli --locked` or
`cargo test --workspace --locked`.
