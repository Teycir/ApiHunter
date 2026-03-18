# Task: Roadmap Advancement (Phase 1)

## Plan
- [x] Roadmap Item 2: implement runtime User-Agent pool from `assets/user_agents.txt` with safe fallback.
- [x] Add focused tests for User-Agent pool behavior (format + non-empty pool).
- [x] Validate Item 2 with `cargo fmt` and targeted tests.
- [x] Roadmap Item 3: add production-ready multi-stage `Dockerfile` and `.dockerignore`.
- [x] Document Docker usage in `Readme.md` and `HOWTO.md`.
- [x] Validate Item 3 (Docker CLI check/build if available) and run full `cargo test`.

## Review
- Implemented roadmap item 2 with a runtime User-Agent pool sourced from `assets/user_agents.txt`, plus embedded fallback UAs.
- Unified default UA sourcing by switching `cli::default_user_agents()` to `WafEvasion::user_agent_pool()`.
- Added integration tests in `tests/waf_user_agents.rs` for pool integrity, random selection, and `user-agent` header presence.
- Added roadmap item 3 containerization:
  - Multi-stage `Dockerfile` with Rust builder and slim Debian runtime.
  - `.dockerignore` to keep build context lean.
  - Docker usage docs in `Readme.md` and `HOWTO.md`.
- Validation results:
  - `cargo fmt` passed.
  - `cargo test --test waf_user_agents --test cli` passed.
  - `cargo test` passed (full suite).
  - `docker --version` passed.
  - `docker build -t apihunter:local .` passed after fixing Rust version + OpenSSL build deps in builder image.
  - `docker run --rm apihunter:local --help` passed.
