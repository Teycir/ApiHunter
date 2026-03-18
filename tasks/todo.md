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

---

# Task: README Roadmap Continuation (Phase 2)

## Plan
- [x] Add a clear `Roadmap & Next Steps` section to `Readme.md`.
- [x] Mark recently completed roadmap items and list upcoming priorities.
- [x] Add immediate “what to do next” actions for users after quick start.
- [x] Verify README links and command snippets remain consistent.

## Review
- Added `Roadmap & Next Steps` in `Readme.md` with:
  - recently completed milestones (items 2 and 3),
  - upcoming roadmap priorities,
  - a practical 4-step “what to do next” flow after quick start.
- Verified all newly referenced helper scripts exist under `ScanScripts/`.
- Verification commands:
  - `ls -1 ScanScripts`
  - `rg -n "Roadmap & Next Steps|What To Do Next After Quick Start|ScanScripts/(quickscan|baselinescan|diffscan|sarifscan|authscan)\\.sh" Readme.md`

---

# Task: README Integrity Continuation (Phase 3)

## Plan
- [x] Check README local markdown links and identify missing files.
- [x] Add `CONTRIBUTING.md` referenced by README.
- [x] Re-run README link verification and document outcomes.

## Review
- README link integrity check found one missing local file: `CONTRIBUTING.md`.
- Added `CONTRIBUTING.md` with setup, style, testing, docs, PR checklist, and issue-report guidance.
- Re-ran local README link validation; all local links now resolve.
- Verification commands:
  - `rg -o "\\[[^\\]]+\\]\\([^\\)]+\\)" Readme.md | sed -E 's/^.*\\(([^)]+)\\)$/\\1/' | sort -u`
  - `rg -n "\\[CONTRIBUTING\\.md\\]\\(CONTRIBUTING\\.md\\)" Readme.md`

---

# Task: WebSocket Scanner Scaffold (Phase 4)

## Plan
- [x] Add `src/scanner/websocket.rs` with initial WebSocket upgrade/origin probe scaffold.
- [x] Register the scanner module and wire it into `runner` behind `active_checks`.
- [x] Add integration tests for positive and negative scaffold behavior in `tests/websocket_scanner.rs`.
- [x] Run formatting and targeted tests, then run full `cargo test`.
- [x] Document implementation and validation results in this review section.

## Review
- Added `WebSocketScanner` scaffold in `src/scanner/websocket.rs`:
  - probes common WS paths with handshake headers,
  - reports upgrade acceptance,
  - flags potential origin validation gaps when attacker origin is accepted.
- Wired scanner registration in `src/scanner/mod.rs` and `src/runner.rs`.
- Gated runner integration behind `config.active_checks` to avoid passive-scan noise.
- Added `tests/websocket_scanner.rs` covering:
  - upgrade detection + origin bypass detection,
  - no-op behavior when active checks are disabled,
  - non-upgrade responses not being reported.
- Updated `docs/scanners.md` with a WebSocket scanner section and refreshed metadata date/tags.
- Validation results:
  - `cargo fmt` passed.
  - `cargo test --test websocket_scanner -- --nocapture` passed (3/3).
  - `cargo test` passed (all tests green).
  - Note: tests were executed outside sandbox due local mock-server port binding restrictions.

---

# Task: Live Target Validation for WebSocket Scanner (Phase 5)

## Plan
- [x] Run WebSocket-only scan on `targets/test-targets.txt` with `--active-checks`.
- [x] Summarize findings and scanner errors from live run output.
- [x] If signal is too low, run a second low-impact pass on a focused public WebSocket target set.
- [x] Document real-target validation outcome in this review section.

## Review
- Live run #1 (`targets/test-targets.txt`, 3 real public API targets):
  - Command:
    - `./target/debug/api-scanner --urls targets/test-targets.txt --no-filter --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/ws_live_test_targets.ndjson --summary`
  - Result summary (`/tmp/ws_live_test_targets.ndjson`):
    - findings: `0`
    - errors: `0`
    - scanned: `55` (after discovery expansion)
- Live run #2 (real public WebSocket targets in `/tmp/ws_public_targets.txt`):
  - Targets:
    - `https://echo.websocket.events`
    - `https://ws.ifelse.io`
    - `https://stream.binance.com:9443/ws/btcusdt@trade`
  - Command:
    - `./target/debug/api-scanner --urls /tmp/ws_public_targets.txt --no-filter --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/ws_live_public_ws.ndjson --summary`
  - Result summary (`/tmp/ws_live_public_ws.ndjson`):
    - findings: `14` (`7 INFO` + `7 MEDIUM`)
    - errors: `122` (mostly from unresolved/unreachable `echo.websocket.events` + discovery noise)
    - scanned: `53` (after discovery expansion)
  - WebSocket findings produced by new scanner:
    - `websocket/upgrade-endpoint` on:
      - `https://stream.binance.com:9443/ws`
      - `https://stream.binance.com:9443/ws/btcusdt@trade`
      - `https://ws.ifelse.io/graphql`
      - `https://ws.ifelse.io/socket`
      - `https://ws.ifelse.io/socket.io/?EIO=4&transport=websocket`
      - `https://ws.ifelse.io/websocket`
      - `https://ws.ifelse.io/ws`
    - `websocket/origin-not-validated` on the same 7 URLs (all returned `Status: 101` for `Origin: https://evil.example`).

---

# Task: Discovery Control for Targeted WebSocket Runs (Phase 6)

## Plan
- [x] Add a CLI/config switch to skip endpoint discovery (`--no-discovery`).
- [x] Update runner to bypass discovery when the switch is enabled.
- [x] Add tests for CLI parsing and runner behavior when discovery is disabled.
- [x] Update docs (README/HOWTO/configuration) with the new flag.
- [x] Run formatting and tests, then record results.

## Review
- Added `--no-discovery` CLI flag and threaded it through config/runner:
  - `src/cli.rs` (`no_discovery` flag)
  - `src/config.rs` (`Config.no_discovery`)
  - `src/main.rs` (CLI → config mapping)
  - `src/runner.rs` (discovery bypass + explicit skip log)
- Added tests:
  - `tests/cli.rs`: parse/default coverage for `--no-discovery`
  - `tests/integration_runner.rs`: `no_discovery_skips_robots_probe`
- Updated docs:
  - `Readme.md` CLI reference includes `--no-discovery`
  - `HOWTO.md` includes targeted-checks recipe using `--no-discovery`
  - `docs/configuration.md` includes `no_discovery` field and updated date
- Validation:
  - `cargo fmt` passed
  - `cargo test --test cli` passed (`36/36`)
  - `cargo test --test integration_runner -- --nocapture` passed (`15/15`)
  - `cargo test` passed (full suite)
- Real-target confirmation with new flag:
  - Command:
    - `./target/debug/api-scanner --urls /tmp/ws_public_targets.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/ws_live_public_ws_nodiscovery.ndjson --summary`
  - Result:
    - scanned: `3` (seed-only, no discovery fan-out)
    - findings: `14` (`7 INFO`, `7 MEDIUM`)
    - errors: `5` (down from `122` in discovery-enabled run)

---

# Task: Dedicated Mass Assignment Scanner (Phase 7)

## Plan
- [x] Add `src/scanner/mass_assignment.rs` with a dedicated active-checks scanner.
- [x] Register scanner module in `scanner/mod.rs` and `runner.rs`.
- [x] Remove mass-assignment probing from `api_security` to avoid duplicate findings.
- [x] Add focused tests in `tests/mass_assignment_scanner.rs`.
- [x] Update scanner docs and roadmap status in README.
- [x] Run formatting and full tests, then document results.

## Review
- Added dedicated scanner: `src/scanner/mass_assignment.rs`
  - Active-checks gated (`config.active_checks`).
  - Probes mutation-like endpoints (`/users`, `/account`, `/profile`, etc.) with crafted sensitive fields.
  - Emits `mass_assignment/reflected-fields` when crafted fields are reflected in successful JSON-like responses.
- Registered module and runner wiring:
  - `src/scanner/mod.rs`: `pub mod mass_assignment;`
  - `src/runner.rs`: includes `MassAssignmentScanner` in active-check scanner registry.
- Removed old inline mass-assignment probe from `api_security` scanner so findings are not duplicated across scanners.
- Added tests: `tests/mass_assignment_scanner.rs`
  - reflected sensitive-field detection,
  - non-mutation path skip,
  - no-op when active checks are disabled.
- Updated docs/roadmap status:
  - `docs/scanners.md`: added `Mass Assignment` scanner section and adjusted active-check bullets.
  - `Readme.md`: moved Mass Assignment scanner to recently completed roadmap items.
- Validation:
  - `cargo fmt` passed.
  - `cargo test --test cli` passed.
  - `cargo test --test mass_assignment_scanner` passed (`3/3`).
  - `cargo test` passed (full suite green).
