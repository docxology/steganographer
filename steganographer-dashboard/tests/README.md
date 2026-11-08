# tests/

Dashboard HTTP/WebSocket/RTC and browser lifecycle suites cover real delivered
artifacts, authentication, request ownership, stale verdicts, archives and
transport bounds. Root `AGENTS.md` owns observed counts. Rust entry point:
`cargo test -p steganographer-dashboard --locked`; browser/Node scenarios are
separate integration checks, not physical-camera qualification.
