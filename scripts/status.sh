#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Steganographer — executable status (agent-ergonomics Round 2, 2026-08-31)
#
# Usage:
#   ./scripts/status.sh           Print current workspace status
#   ./scripts/status.sh --check   Run the workspace tests and fail if they fail;
#                                 counts are reported live, never pinned in prose
#
# This script derives the status claims; README/AGENTS signpost here instead of
# locking counts.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
    "") [ "$#" -eq 0 ] || { printf 'Usage: %s [--check]\n' "$0" >&2; exit 2; } ;;
    --check) [ "$#" -eq 1 ] || { printf 'Usage: %s [--check]\n' "$0" >&2; exit 2; } ;;
    *) printf 'Usage: %s [--check]\n' "$0" >&2; exit 2 ;;
esac

# Workspace version
ver=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
printf 'workspace version: %s  (source: Cargo.toml)\n' "$ver"

# CLI subcommand count (source of truth: enum Commands in the CLI binary)
subs=$(awk '/^pub[(]crate[)] enum Commands/,/^}/' steganographer-cli/src/cli.rs \
        | grep -cE '^    [A-Z][a-zA-Z]+[[:space:]]*[({]' || true)
printf 'cli subcommands: %s  (source: steganographer-cli/src/cli.rs enum Commands)\n' "$subs"

# Docs count
shopt -s nullglob
docs=(docs/*.md)
plans=(docs/plans/steganography-platform/*.md)
printf 'docs: %s files in docs/ + %s in plans/steganography-platform/  (source: shell globs)\n' "${#docs[@]}" "${#plans[@]}"

# Config inventory
configs=(steganographer.toml config/example.toml)
printf 'config files: %s  (source: explicit inventory)\n' "${configs[*]}"

# Git state
if [[ -e .git ]]; then
    up=$(git status -sb | head -1 | sed 's/^## //')
else
    up='source archive (no Git metadata)'
fi
printf 'git: %s\n' "$up"

# Test count (slow; needs cargo). The count is reported live; no prose pins it.
# Sum the "test result: ok. N passed" lines from every test binary and
# doc-test target; retain complete diagnostics if any target fails.
printf '\nrunning cargo test --workspace --locked (slow on cold caches) ...\n'
if ! test_output=$(cargo test --workspace --locked); then
    printf '%s\n' "$test_output" >&2
    exit 1
fi
tcount=$(printf '%s\n' "$test_output" | awk '/^test result:/ { sum += $4 } END { print sum+0 }')
printf 'tests (cargo test --workspace --locked, libtest totals): %s\n' "$tcount"
if [ "$tcount" = "0" ]; then
    printf 'ERROR: cargo reported no passing workspace tests.\n' >&2
    exit 1
fi

exit 0
