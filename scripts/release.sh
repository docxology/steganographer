#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Only the requested native artifact build requires GStreamer. The orchestrator
# itself is always built without the CLI's default GStreamer feature.
exec cargo run --locked -p steganographer-cli --no-default-features --example release -- "$@"
