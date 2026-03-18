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

---

# Task: Mass Assignment Confirmation Hardening (Phase 8)

## Plan
- [x] Require confirmation logic for elevated-state findings (baseline vs confirm read).
- [x] Add focused tests for confirmed persisted-state change path.
- [x] Update scanner documentation with both finding IDs and semantics.
- [x] Run formatting, targeted tests, and full suite validation.

## Review
- Hardened `src/scanner/mass_assignment.rs` so high-severity confirmation (`mass_assignment/persisted-state-change`) is emitted only when:
  - crafted sensitive fields are reflected in the mutation response, and
  - baseline + confirm reads both succeed, and
  - sensitive fields are newly elevated after the probe.
- Kept safe fallback to `mass_assignment/reflected-fields` when confirmation cannot be established.
- Added test coverage in `tests/mass_assignment_scanner.rs`:
  - `persisted_sensitive_fields_are_reported_as_high_severity` (stage-aware baseline/confirm flow),
  - existing reflected/skip/noop tests remain green.
- Updated `docs/scanners.md` Mass Assignment section to document both finding IDs.
- Validation:
  - `cargo fmt` passed.
  - `cargo test --test mass_assignment_scanner` passed (`4/4`).
  - `cargo test` passed (full suite green).

---

# Task: Real-Target Validation for Mass Assignment Scanner (Phase 9)

## Plan
- [x] Prepare a small set of safe public API targets with mutation-like paths.
- [x] Run a real-target active-check scan focused on mass-assignment behavior.
- [x] Capture findings/errors and confirm signal quality.
- [x] Document exact command and results in this review section.

## Review
- Target file used: `/tmp/mass_real_targets.txt`
  - `https://jsonplaceholder.typicode.com/users`
  - `https://reqres.in/api/users`
  - `https://httpbin.org/anything/users`
- Command:
  - `./target/debug/api-scanner --urls /tmp/mass_real_targets.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/mass_real.ndjson --summary`
- Notes:
  - Initial in-sandbox run showed transport send errors (network restriction), then rerun outside sandbox.
- Final live run result (`/tmp/mass_real.ndjson`):
  - scanned: `3`
  - findings: `2` (`2 MEDIUM`, both `mass_assignment/reflected-fields`)
  - errors: `0`
  - finding URLs:
    - `https://httpbin.org/anything/users`
    - `https://jsonplaceholder.typicode.com/users`
  - no finding on:
    - `https://reqres.in/api/users`

---

# Task: Expanded Real-Target Validation for Mass Assignment Scanner (Phase 10)

## Plan
- [x] Build a broader safe public target set with mutation-like paths.
- [x] Run an expanded live scan with discovery disabled for controlled request volume.
- [x] Extract per-check and per-URL results from NDJSON output.
- [x] Document findings/errors and compare against prior Phase 9 run.

## Review
- Batch A targets: `/tmp/mass_real_targets_extended.txt` (`11` URLs)
- Batch B targets: `/tmp/mass_real_targets_batch2.txt` (`10` URLs)
- Command used for each batch:
  - `./target/debug/api-scanner --urls <target-file> --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --timeout-secs 15 --retries 1 --format ndjson --output <result-file> --summary`
- Output files:
  - Batch A: `/tmp/mass_real_extended.ndjson`
  - Batch B: `/tmp/mass_real_batch2.ndjson`
- Batch A result:
  - scanned: `11`
  - findings: `5` (`5 MEDIUM`, all `mass_assignment/reflected-fields`)
  - errors: `0`
  - finding URLs:
    - `https://dummyjson.com/users/add`
    - `https://httpbin.org/anything/account`
    - `https://httpbin.org/anything/profile`
    - `https://httpbin.org/anything/users`
    - `https://jsonplaceholder.typicode.com/users`
- Batch B result:
  - scanned: `10`
  - findings: `0`
  - errors: `0`
- Combined outcome for this phase:
  - scanned: `21`
  - findings: `5`
  - errors: `0`
  - signal remained specific to reflection behavior; no confirmed persisted-state findings on public targets.

---

# Task: Third Real-Target Batch (Training + Public Mix) for Mass Assignment Scanner (Phase 11)

## Plan
- [x] Build a third target batch including training/demo user endpoints.
- [x] Run live scan outside sandbox with the same controlled flags used in prior batches.
- [x] Summarize findings and compare with prior expanded batches.

## Review
- Target file: `/tmp/mass_real_targets_batch3.txt` (`9` URLs)
  - included `demo.owasp-juice.shop` user endpoints plus prior public high-signal targets.
- Command:
  - `./target/debug/api-scanner --urls /tmp/mass_real_targets_batch3.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --timeout-secs 15 --retries 1 --format ndjson --output /tmp/mass_real_batch3.ndjson --summary`
- Result (`/tmp/mass_real_batch3.ndjson`):
  - scanned: `9`
  - findings: `4` (`4 MEDIUM`, all `mass_assignment/reflected-fields`)
  - errors: `0`
  - finding URLs:
    - `https://demo.owasp-juice.shop/api/Users`
    - `https://dummyjson.com/users/add`
    - `https://httpbin.org/anything/users`
    - `https://jsonplaceholder.typicode.com/users`
- Combined across expanded batches (Phase 10 + Phase 11):
  - total scanned: `30`
  - total findings: `9`
  - total errors: `0`
  - `mass_assignment/persisted-state-change`: `0`

---

# Task: Dedicated Vulnerable Lab Target Validation (Phase 12)

## Plan
- [x] Stand up a real local HTTP target that intentionally persists mass-assigned fields.
- [x] Run ApiHunter mass-assignment active checks against this lab target.
- [x] Verify that `mass_assignment/persisted-state-change` is emitted.
- [x] Capture command/output artifacts and document results.

## Review
- Temporary lab target server:
  - Script: `/tmp/mass_assignment_lab_server.py`
  - Bind: `127.0.0.1:18080`
  - Behavior: intentionally persists all client-controlled fields on `POST /users` and returns them in `GET /users`.
- Scan target file:
  - `/tmp/mass_lab_target.txt` with `http://127.0.0.1:18080/users`
- Scan command:
  - `./target/debug/api-scanner --urls /tmp/mass_lab_target.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/mass_lab_result.ndjson --summary`
- Result (`/tmp/mass_lab_result.ndjson`):
  - scanned: `1`
  - findings: `1`
  - errors: `0`
  - finding:
    - check: `mass_assignment/persisted-state-change`
    - severity: `HIGH`
    - evidence included newly elevated fields after confirm GET: `is_admin, permissions, role`
- Cleanup:
  - lab server process stopped after validation.

---

# Task: OAuth2/OIDC Scanner (Roadmap Priority 1, Phase 13)

## Plan
- [x] Implement a dedicated OAuth2/OIDC scanner module for active checks.
- [x] Add authorize endpoint redirect-uri/state probes.
- [x] Add OIDC metadata hardening checks (PKCE/implicit/password-grant).
- [x] Register the scanner in runner active-check registry.
- [x] Add focused tests and run full validation.
- [x] Update scanner docs and roadmap status in README.

## Review
- Added scanner module: `src/scanner/oauth_oidc.rs`
  - Active-check gated (`--active-checks` required).
  - Authorize probe:
    - `oauth/redirect-uri-not-validated`
    - `oauth/state-not-returned`
  - OIDC metadata checks:
    - `oauth/pkce-metadata-missing`
    - `oauth/pkce-s256-not-supported`
    - `oauth/pkce-plain-supported`
    - `oauth/implicit-flow-enabled`
    - `oauth/ropc-grant-enabled`
  - Uses a dedicated no-redirect probe client for authorize checks so `Location` can be analyzed safely.
- Wiring:
  - `src/scanner/mod.rs`: registered `oauth_oidc` module.
  - `src/runner.rs`: added `OAuthOidcScanner` to active-check scanner list.
- Tests:
  - Added `tests/oauth_oidc_scanner.rs` covering:
    - redirect URI acceptance detection,
    - metadata checks for PKCE/implicit/password grant,
    - no-op behavior when active checks are disabled.
- Docs:
  - `docs/scanners.md`: added OAuth2/OIDC section + active-checks subsection.
  - `Readme.md`: marked OAuth2/OIDC scanner as recently completed and removed it from next-priority backlog.
- Validation:
  - `cargo fmt` passed.
  - `cargo test --test oauth_oidc_scanner` passed (`3/3`).
  - `cargo test` passed (full suite green).
  - Live run:
    - `./target/debug/api-scanner --urls /tmp/oauth_real_targets.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/oauth_real.ndjson --summary`
    - scanned: `3`, findings: `4` (`oauth/implicit-flow-enabled`, `oauth/pkce-plain-supported`, `oauth/pkce-metadata-missing`), errors: `0`.

---

# Task: Rate Limit Scanner (Roadmap Priority 2, Phase 14)

## Plan
- [x] Add a dedicated active-check `rate_limit` scanner module.
- [x] Move rate-limit probing out of `api_security` to avoid duplicate/overlapping findings.
- [x] Register scanner in runner active-checks list.
- [x] Add focused tests for no-limit and header-bypass behavior.
- [x] Update docs/README roadmap status and run full validation.

## Review
- Added scanner module: `src/scanner/rate_limit.rs`
  - Active-check gated (`--active-checks` required).
  - Checks:
    - `rate_limit/not-detected` (no 429 + no rate-limit headers under burst)
    - `rate_limit/missing-retry-after` (429 without retry guidance)
    - `rate_limit/ip-header-bypass` (spoofed IP headers appear to evade throttling)
  - Host-level dedup to avoid repeating burst probes for every URL on the same host.
- Moved rate-limit logic out of `api_security`:
  - removed inline `check_rate_limit` implementation and call path from `src/scanner/api_security.rs`.
- Wiring:
  - `src/scanner/mod.rs`: registered `rate_limit` module.
  - `src/runner.rs`: added `RateLimitScanner` to active-check scanner list.
- Tests:
  - Added `tests/rate_limit_scanner.rs` with coverage for:
    - no-limit detection,
    - IP-header bypass detection,
    - no-op when active checks are disabled.
- Docs / roadmap:
  - `docs/scanners.md`: added Rate Limit scanner section and active-checks notes.
  - `Readme.md`: marked Rate Limit scanner as completed roadmap item.
- Validation:
  - `cargo fmt` passed.
  - `cargo test --test rate_limit_scanner` passed (`3/3`).
  - `cargo test` passed (full suite green).
  - Live run (non-mutation real targets):
    - `./target/debug/api-scanner --urls /tmp/rate_real_targets_only.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/rate_real_only.ndjson --summary --delay-ms 0`
    - scanned: `3`, findings: `1` (`rate_limit/not-detected` on `https://httpbin.org/get`), errors: `0`.

---

# Task: CVE Template Module (Roadmap Priority 3, Phase 15)

## Plan
- [x] Add a dedicated CVE template scanner module using a TOML catalog.
- [x] Translate a starter set of Nuclei-style API CVE checks into compatible templates.
- [x] Register scanner in active checks and keep probes low-impact/read-only.
- [x] Add focused tests for translated template matching and required request headers.
- [x] Update docs/README roadmap status and run full validation + live sanity pass.

## Review
- Added scanner module: `src/scanner/cve_templates.rs`
  - Active-check gated (`--active-checks` required).
  - Loads translated templates from `assets/cve_templates.toml`.
  - Executes low-impact template probes (GET only) with:
    - request headers from template definition,
    - response status/body/header matchers,
    - host+template deduplication to avoid repeated probes.
- Added translated TOML catalog: `assets/cve_templates.toml`
  - `CVE-2022-22947` Spring Cloud Gateway actuator exposure signal
  - `CVE-2021-29442` Nacos auth-bypass signal
  - `CVE-2020-13945` APISIX default admin key signal
  - Each template includes source metadata referencing original Nuclei-style template path.
- Wiring:
  - `src/scanner/mod.rs`: registered `cve_templates` module.
  - `src/runner.rs`: added `CveTemplateScanner` to active-check scanner list.
- Tests:
  - Added `tests/cve_templates_scanner.rs` with:
    - Spring actuator template detection,
    - APISIX default-key header template detection,
    - no-op behavior when active checks are disabled.
- Docs / roadmap:
  - `docs/scanners.md`: added CVE Templates scanner section and active-check notes.
  - `Readme.md`: marked CVE template module completed and updated next priorities to template expansion/tooling.
- Validation:
  - `cargo fmt` passed.
  - `cargo test --test cve_templates_scanner` passed (`3/3`).
  - `cargo test` passed (full suite green).
  - Live run:
    - `./target/debug/api-scanner --urls /tmp/cve_real_targets.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/cve_real.ndjson --summary --delay-ms 0`
    - scanned: `3`, findings: `1` (rate-limit signal), `cve/*` findings: `0`, errors: `0`.
