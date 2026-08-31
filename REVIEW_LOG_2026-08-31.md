# REVIEW_LOG — 2026-08-31 (agent-ergonomics deep pass)

Agent: steganographer lane, agent-erg fleet 2026-08-31.

## Phase 0 — Preflight

- Branch `main`, remote `origin` = github.com/docxology/steganographer.
- `git fetch origin`: local main was **3 commits behind** origin/main at dispatch.
- Dirty files at dispatch: **27** (1 modified `steganographer-core/fuzz/README.md`, 26 untracked AGENTS.md/README.md pairs) — treated as pre-existing, not touched.
- Inventory: entry docs README.md (287 l) + AGENTS.md (61 l); backlog TODO.md (exists); docs/ hub (19 files incl. AGENTS/README); docs/plans/steganography-platform/ (8 files); CHANGELOG.md; run.sh.

## Phase 1 — Cold-start audit (docs only, as a cold agent)

- (a) Current status: **PASS, weakly.** Test badge carries no as-of date and no verification path; CHANGELOG "Unreleased" carries two landed slices. Status inferable but not checkable.
- (b) What to do next: **FAIL.** README never mentions TODO.md; TODO.md's "Scoped Improvements (v0.8.0 Release Target)" section is 100 percent checked boxes still framed as active work; next actions only discoverable deep in roadmap.md.
- (c) Primary verification command: **PASS** — `cargo test --workspace` stated in README Quick Start and AGENTS.md Build and Test.
- Link check: 49 markdown docs script-checked in-session, **0 broken relative links**.
- Stale/duplicated claims found:
  1. README "CLI Reference | All 13 commands"; docs/AGENTS.md cli-reference row "All 13 commands"; cli-reference.md itself covers 12 command sections and omits `revoke` and `ots`. Actual `enum Commands` in steganographer-cli/src/main.rs = **14** (README architecture diagram already says 14, AGENTS.md says 14).
  2. docs/AGENTS.md "Contents (25 files)" table omits `ots-integration.md` and miscounts; actual: 19 files in docs/ + 8 in docs/plans/steganography-platform/.
  3. docs/README.md Quick Links Test line says "457 tests" (stale vs 472 elsewhere).
  4. Test-count fact-class duplicated across README (badge + tables + commands), AGENTS.md (breakdown line + build block), docs/README.md, docs/contributing.md, docs/getting-started.md — no canonical home; AGENTS.md's own two lines disagree (288+117 vs 395 crate figure).
  5. TODO.md "Status (2026-08-19, v0.7.0)" header vs workspace Cargo.toml 0.7.0 with "Unreleased" changelog slices — minor tension, left as-is (dates are self-labeled).

## Phase 2 — Scope

See TODO.md "Agent-ergonomics pass (2026-08-31)" section appended this pass.

## Phase 3 — Implemented (this pass)

- README.md: added Project Status block (state + verification commands + next-action pointer); fixed "All 13 commands" to 14; test count lines now carry "verified by cargo test" path.
- AGENTS.md: declared canonical test-count home (one block, marked canonical); removed the self-contradicting breakdown; fixed counts with verification path.
- docs/AGENTS.md: contents table refreshed (ots-integration.md added, counts as-of dated), "All 13 commands" to 14.
- docs/README.md: 457 updated to current canonical count with verification path.
- docs/cli-reference.md: added `revoke` and `ots` command sections (source: main.rs match arms) so the doc covers all 14 subcommands.
- TODO.md: v0.8.0 completed section superseded-marked; added next-actions pointer plus scoped entries for this pass's findings.

## Phase 4 — Verify and close

Link checker re-run on touched docs: 0 broken. Commits and push recorded in the fleet report.
