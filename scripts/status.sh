#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Steganographer — executable status (agent-ergonomics Round 2, 2026-08-31)
#
# Usage:
#   ./scripts/status.sh           Print current workspace status
#   ./scripts/status.sh --check   Exit 1 if the canonical test count in
#                                 AGENTS.md disagrees with what cargo reports
#
# This script is the verification path behind the status claims in
# README.md ("Project Status") and the canonical Tests line in AGENTS.md.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CHECK=0
case "${1:-}" in
    "") [ "$#" -eq 0 ] || { printf 'Usage: %s [--check]\n' "$0" >&2; exit 2; } ;;
    --check) [ "$#" -eq 1 ] || { printf 'Usage: %s [--check]\n' "$0" >&2; exit 2; }; CHECK=1 ;;
    *) printf 'Usage: %s [--check]\n' "$0" >&2; exit 2 ;;
esac

fail=0

# Workspace version
ver=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
printf 'workspace version: %s  (source: Cargo.toml)\n' "$ver"

# CLI subcommand count (source of truth: enum Commands in the CLI binary)
subs=$(awk '/^pub[(]crate[)] enum Commands/,/^}/' steganographer-cli/src/cli.rs \
        | grep -cE '^    [A-Z][a-zA-Z]+[[:space:]]*\{' || true)
printf 'cli subcommands: %s  (source: steganographer-cli/src/cli.rs enum Commands)\n' "$subs"

# Docs count
shopt -s nullglob
docs=(docs/*.md)
plans=(docs/plans/steganography-platform/*.md)
printf 'docs: %s files in docs/ + %s in plans/steganography-platform/  (source: shell globs)\n' "${#docs[@]}" "${#plans[@]}"

# Git state
if [[ -e .git ]]; then
    up=$(git status -sb | head -1 | sed 's/^## //')
else
    up='source archive (no Git metadata)'
fi
printf 'git: %s\n' "$up"

# Test count (slow; needs cargo). On --check this is the provenance gate.
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

# Canonical count home: root AGENTS.md Tests line
canon=$(grep -m1 '^\- \*\*Tests\*\*' AGENTS.md | grep -oE '= \*\*[0-9]+ passing' | grep -oE '[0-9]+' || echo 0)
printf 'canonical tests line (AGENTS.md): %s\n' "$canon"

if [ "$CHECK" = "1" ] && [ "$tcount" != "$canon" ]; then
    printf 'MISMATCH: actual %s != canonical %s — update the Tests line in AGENTS.md first, then defer elsewhere.\n' "$tcount" "$canon"
    fail=1
fi

if [ "$CHECK" = "1" ] && [ "$subs" != "15" ]; then
    printf 'NOTE: subcommand count is %s — docs that say "All 15 commands" may be stale.\n' "$subs"
fi

exit $fail
