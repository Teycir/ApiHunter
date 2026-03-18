# Lessons Learned

## 2026-03-18
- User preference: keep session/cookie input format singular and explicit; avoid multiple equivalent flags.
- Rule: when a user asks for one format, remove alternate CLI aliases and parser modes instead of documenting all variants.
- Rule: keep README/HOWTO/config docs synchronized immediately after CLI surface changes to prevent usage confusion.
- Rule: when external tooling (like Docker daemon) is temporarily unavailable, retry promptly once user confirms readiness and continue validation without delay.
- User correction pattern: mass-assignment signals should be explicitly confirmed, not inferred from reflection alone.
- Rule: for active-check findings that imply persisted state change, require a baseline-vs-confirm read comparison before raising high-severity confirmation checks.
- User preference: validate new scanner behavior against real public targets, not only mocks.
- Rule: after adding/changing active checks, run at least one low-impact real-target validation pass (`--no-discovery`) and log the exact command and outcomes.
- User preference: all test execution must run outside sandbox.
- Rule: always run `cargo test` (full or targeted) with escalation/outside sandbox, even if sandbox execution appears possible.
- Rule scope: this preference is global across repos; enforce it via `/home/teycir/.codex/AGENTS.md` so all projects inherit it.
