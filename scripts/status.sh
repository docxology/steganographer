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
[ "${1:-}" = "--check" ] && CHECK=1

fail=0

# Workspace version
ver=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
printf 'workspace version: %s  (source: Cargo.toml)\n' "$ver"

# CLI subcommand count (source of truth: enum Commands in the CLI binary)
subs=$(awk '/^enum Commands/,/^}/' steganographer-cli/src/main.rs \
        | grep -cE '^    [A-Z][a-zA-Z]+\s*\{' || true)
printf 'cli subcommands: %s  (source: steganographer-cli/src/main.rs enum Commands)\n' "$subs"

# Docs count
docn=$(ls docs/*.md | wc -l | tr -d ' ')
plan=$(ls docs/plans/steganography-platform/*.md | wc -l | tr -d ' ')
printf 'docs: %s files in docs/ + %s in plans/steganography-platform/  (source: ls)\n' "$docn" "$plan"

# Git state
up=$(git status -sb | head -1 | sed 's/^## //')
printf 'git: %s\n' "$up"

# Test count (slow; needs cargo). On --check this is the provenance gate.
printf '\nrunning cargo test --workspace -- --list (slow on cold caches) ...\n'
tcount=$(cargo test --workspace -- --list 2>/dev/null | grep -c ': test' || echo 0)
printf 'tests (cargo --list): %s\n' "$tcount"

# Canonical count home: root AGENTS.md Tests line
canon=$(grep -m1 '^\- \*\*Tests\*\*' AGENTS.md | grep -oE '= \*\*[0-9]+ passing' | grep -oE '[0-9]+' || echo 0)
printf 'canonical tests line (AGENTS.md): %s\n' "$canon"

if [ "$CHECK" = "1" ] && [ "$tcount" != "0" ] && [ "$tcount" != "$canon" ]; then
    printf 'MISMATCH: actual %s != canonical %s — update the Tests line in AGENTS.md first, then defer elsewhere.\n' "$tcount" "$canon"
    fail=1
fi

if [ "$CHECK" = "1" ] && [ "$subs" != "14" ]; then
    printf 'NOTE: subcommand count is %s — docs that say "All 14 commands" may be stale.\n' "$subs"
fi

exit $fail
