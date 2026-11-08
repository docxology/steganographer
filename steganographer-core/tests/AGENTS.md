# AGENTS.md — steganographer-core/tests/

## Purpose

Integration tests that exercise cross-module interactions and end-to-end workflows.

## Coverage

Cross-module suites cover delivered carrier sign/embed/extract/verify,
packet/transforms and immutable wire compatibility, crypto and revocation,
kernel geometry/capacity, nested intent/depth/cycle limits, bounded forensics
and real standard-protocol OTS fixtures. Do not pin per-file test counts;
root `AGENTS.md` owns the observed workspace total.

Keep consumer-visible roundtrip, boundary and tamper assertions. Do not retain
wording/default/property echoes or update immutable vectors to make a changed
implementation pass. Workers do not run suites; integration verifies after
all writers stop.

## Test Dependencies

Uses only `steganographer_core` public API — no test-only utilities or mocks.
