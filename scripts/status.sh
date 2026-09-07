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
# Counting method matches CI's test-count job: sum the "test result: ok. N passed"
# lines from every test binary and doc-test target.
printf '\nrunning cargo test --workspace (slow on cold caches) ...\n'
# Capture every count docs may legitimately quote: the workspace total,
# every per-target count, every per-crate sum, and the integers in the
# canonical AGENTS.md Tests line (the splits docs defer to).
test_out=$(mktemp)
cargo test --workspace >"$test_out" 2>&1 || true
tcount=$(awk '/^test result:/ { sum += $4 } END { print sum+0 }' "$test_out")
allowed=" $(awk '
    function crate_of(name,   c) {
        c = ""
        if (name == "steganographer" || name ~ /cli_integration_tests/) c = "cli"
        else if (name ~ /^steganographer_core/ || name ~ /integration_tests/) c = "core"
        else if (name ~ /dashboard/) c = "dashboard"
        else if (name ~ /gst/) c = "gst"
        return c
    }
    /\/deps\// {
        n = $0
        sub(/.*\/deps\//, "", n); sub(/-[0-9a-f]+\).*/, "", n)
        pend = crate_of(n)
    }
    /^ *Doc-tests / { pend = crate_of($2) }
    /^test result:/ {
        seen[$4] = 1
        if (pend != "") { crate_sum[pend] += $4; pend = "" }
        sum += $4
    }
    END {
        printf "%d 0", sum + 0
        for (k in seen) printf " %d", k
        for (k in crate_sum) printf " %d", crate_sum[k]
    }' "$test_out") "
rm -f "$test_out"
printf 'tests (cargo test --workspace, CI method): %s\n' "$tcount"

# Canonical count home: root AGENTS.md Tests line
canon=$(grep -m1 '^\- \*\*Tests\*\*' AGENTS.md | grep -oE '= \*\*[0-9]+ passing' | grep -oE '[0-9]+' || echo 0)
printf 'canonical tests line (AGENTS.md): %s\n' "$canon"
# The canonical line's split integers (290 / 117 / 80 / 37 / ...) are
# legitimate everywhere docs defer to it.
for n in $(grep -m1 '^\- \*\*Tests\*\*' AGENTS.md | grep -oE '[0-9]+' || true); do
    allowed="$allowed $n "
done

if [ "$CHECK" = "1" ] && [ "$tcount" != "0" ] && [ "$tcount" != "$canon" ]; then
    printf 'MISMATCH: actual %s != canonical %s — update the Tests line in AGENTS.md first, then defer elsewhere.\n' "$tcount" "$canon"
    fail=1
fi

# Stale-count sweep (added 2026-09-07): every "<N> tests" / "<N> passing" /
# "tests-<N>" integer in tracked Markdown must be a cargo-reported count
# (the workspace total or one of the per-target counts). This is the gate for
# the recurring failure mode where per-doc counts drifted from the canonical
# AGENTS.md Tests line even though the total was pinned (457/288/405-era
# strings survived three "counts refreshed" passes). URL-encoded badge
# fragments ("...%20288%20unit...") are not matched; the badge total is.
if [ "$CHECK" = "1" ] && [ "$tcount" != "0" ]; then
    for f in $(git ls-files '*.md'); do
        while IFS=' ' read -r ln num; do
            [ -n "$num" ] || continue
            case "$allowed" in
                *" $num "*) ;;
                *)
                    printf 'STALE-COUNT: %s:%s — %s is not a cargo-reported test count (total %s); update from the canonical AGENTS.md Tests line.\n' "$f" "$ln" "$num" "$tcount"
                    fail=1
                    ;;
            esac
        done < <(grep -noE '[0-9]+ (inline |unit )?(tests|passing)|tests-[0-9]+' "$f" |
                 sed -E 's/^([0-9]+):([0-9]+) .*$/\1 \2/; s/^([0-9]+):tests-([0-9]+)$/\1 \2/')
    done
fi

if [ "$CHECK" = "1" ] && [ "$subs" != "14" ]; then
    printf 'NOTE: subcommand count is %s — docs that say "All 14 commands" may be stale.\n' "$subs"
fi

exit $fail
