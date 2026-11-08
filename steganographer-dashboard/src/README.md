# src/

Dashboard source: `lib.rs` assembles Axum routes/state, `ws_handler.rs` handles
bounded signed-artifact WebSockets, optional `webrtc.rs` handles real peers and
STGO-framed JSON/base64, and `static/` owns browser lifecycle/archive UI.
Served by the `dashboard` CLI subcommand; see the crate README for trust limits.
