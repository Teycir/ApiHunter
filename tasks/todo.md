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
  - Initial version loaded translated templates from `assets/cve_templates.toml` (later migrated to template files).
  - Executes low-impact template probes (GET only) with:
    - request headers from template definition,
    - response status/body/header matchers,
    - host+template deduplication to avoid repeated probes.
- Added translated TOML starter catalog in `assets/cve_templates.toml` (later migrated to `assets/cve_templates/*.toml`).
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

---

# Task: CVE Templates-Only Loading (Phase 16)

## Plan
- [x] Remove fallback CVE catalog loading from scanner runtime.
- [x] Ensure starter CVEs are loaded from template files under `assets/cve_templates/`.
- [x] Update docs and roadmap references to the template-directory model.
- [x] Validate with formatting and CVE/full test runs.

## Review
- Runtime behavior changed to template-only loading in `src/scanner/cve_templates.rs`:
  - Removed fallback parsing path that used embedded `assets/cve_templates.toml`.
  - Scanner now warns when no templates are loaded from configured template directories.
- Migrated starter CVE catalog from single file to per-template files:
  - `assets/cve_templates/cve-2022-22947.toml`
  - `assets/cve_templates/cve-2021-29442.toml`
  - `assets/cve_templates/cve-2020-13945.toml`
- Updated references:
  - `docs/scanners.md` now points to `assets/cve_templates/*.toml`.
  - `Readme.md` roadmap "Template expansion" now points to `assets/cve_templates/*.toml`.
- Validation:
  - `cargo fmt`
  - `cargo test --test cve_templates_scanner`
  - `cargo test`

---

# Task: CVE Catalog Expansion via Exa (Phase 17)

## Plan
- [x] Use Exa to source additional API-relevant CVEs/templates beyond the initial 3 entries.
- [x] Translate additional CVEs into `assets/cve_templates/*.toml` files.
- [x] Add scanner support for baseline-vs-bypass matcher constraints needed by Nacos UA bypass signal.
- [x] Add focused tests and run full validation.
- [x] Update scanner docs with new CVE checks.

## Review
- Exa-sourced references used:
  - `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2021/CVE-2021-29441.yaml`
  - `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2021/CVE-2021-45232.yaml`
  - `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2022/CVE-2022-24112.yaml` (reviewed but not added due intrusive multi-step/oast flow)
- Added new CVE template files:
  - `assets/cve_templates/cve-2021-29441.toml`
  - `assets/cve_templates/cve-2021-45232.toml`
- Scanner enhancements in `src/scanner/cve_templates.rs`:
  - Added optional baseline matcher fields:
    - `baseline_status_any_of`
    - `baseline_body_contains_any`
    - `baseline_body_contains_all`
    - `baseline_match_headers`
  - Added baseline request/verification flow before main template probe when baseline matchers are configured.
  - Refactored response matching into shared constraint matcher utility.
- Added tests in `tests/cve_templates_scanner.rs`:
  - APISIX dashboard export exposure check (`CVE-2021-45232`).
  - Nacos User-Agent auth bypass signal with baseline-vs-bypass behavior (`CVE-2021-29441`).
- Updated docs in `docs/scanners.md` to list the two new translated checks and baseline differential capability.
- Validation:
  - `cargo fmt` passed.
  - `cargo test --test cve_templates_scanner` passed (`5/5`).
  - `cargo test` passed (full suite green).

---

# Task: Real Internet Target Validation (Phase 18)

## Plan
- [x] Use Exa to discover candidate public internet targets for CVE path validation.
- [x] Preflight candidate targets for reachability and basic endpoint status.
- [x] Run off-sandbox low-impact validation scan on real public targets.
- [x] Capture CVE/no-CVE outcomes and summarize evidence.

## Review
- Exa discovery was used to gather public candidate domains and references for Nacos/APISIX/Spring paths.
- Real internet target set used:
  - `https://docs.spring.io`
  - `https://nacos.io`
  - `https://apisix.apache.org`
  - `https://techdocs.broadcom.com`
- Preflight checks:
  - roots reachable (`200/301`), CVE-specific paths returned `404` on these domains.
- Off-sandbox validation command:
  - `./target/debug/api-scanner --urls /tmp/cve_real_public_targets.txt --no-filter --no-discovery --active-checks --no-cors --no-csp --no-graphql --no-api-security --no-jwt --no-openapi --format ndjson --output /tmp/cve_real_public_validation.ndjson --summary --delay-ms 0`
- Output summary (`/tmp/cve_real_public_validation.ndjson`):
  - scanned: `4`
  - findings: `4` (all `rate_limit/not-detected`, low)
  - errors: `0`
  - CVE findings (`scanner == cve_templates`): `0`
- Conclusion:
  - Real internet negative validation passed (no false-positive CVE matches on these public documentation/official domains).

---

# Task: Full CVE True-Positive Validation (Phase 19)

## Plan
- [x] Validate each CVE template against a controlled vulnerable target with off-sandbox runs.
- [x] Ensure baseline-vs-bypass behavior for `CVE-2021-29441` using an auth-enabled Nacos target.
- [x] Keep reproducible regression target list(s) in-repo.
- [x] Harden template matching where validation surfaced overmatching risk.
- [x] Add regression test coverage for the hardened matcher.
- [x] Re-run targeted CVE scanner tests outside sandbox.

## Review
- Off-sandbox true-positive validation completed for all translated CVEs using seeded context paths:
  - `CVE-2022-22947` -> `http://127.0.0.1:18080/actuator`
  - `CVE-2021-29442` -> `http://127.0.0.1:18848/nacos`
  - `CVE-2021-29441` -> `http://127.0.0.1:18851/nacos`
  - `CVE-2020-13945` -> `http://127.0.0.1:19080/apisix/admin`
  - `CVE-2021-45232` -> `http://127.0.0.1:19000/apisix/admin`
- Final validation artifacts:
  - `/tmp/cve_tp_runs5/CVE-2022-22947.ndjson`
  - `/tmp/cve_tp_runs5/CVE-2021-29442.ndjson`
  - `/tmp/cve_tp_runs5/CVE-2021-29441.ndjson`
  - `/tmp/cve_tp_runs5/CVE-2020-13945.ndjson`
  - `/tmp/cve_tp_runs5/CVE-2021-45232.ndjson`
- Reproducibility assets added:
  - `targets/cve-regression-vulhub-local.txt`
  - `docs/scanners.md` updated with CVE regression target lists and rerun command.
- Matcher hardening:
  - `assets/cve_templates/cve-2022-22947.toml` now requires:
    - `predicate` marker in response body
    - at least one Spring-Gateway route-shape token (`route_id` or `predicates` or `filters`)
  - This removes observed overmatch on APISIX dashboard HTML content.
- Added test coverage:
  - `translated_template_22947_does_not_match_html_routes_text` in `tests/cve_templates_scanner.rs`.

---

# Task: Real-Data CVE Test Hardening (Phase 20)

## Plan
- [x] Use Exa + Fetch to pull authoritative upstream CVE template references.
- [x] Pin upstream template snapshots into test fixtures for deterministic parity checks.
- [x] Capture real payload fixtures from live vulnerable targets for non-synthetic scanner tests.
- [x] Add new regression tests for true-match and non-match behavior using real payloads.
- [x] Run targeted and full test suites outside sandbox.

## Review
- Exa discovery + Fetch retrieval performed for upstream references (Nuclei CVE YAML sources).
- Added pinned upstream fixtures:
  - `tests/fixtures/upstream_nuclei/CVE-2022-22947.yaml`
  - `tests/fixtures/upstream_nuclei/CVE-2021-29441.yaml`
  - `tests/fixtures/upstream_nuclei/CVE-2021-29442.yaml`
  - `tests/fixtures/upstream_nuclei/CVE-2020-13945.yaml`
  - `tests/fixtures/upstream_nuclei/CVE-2021-45232.yaml`
  - `tests/fixtures/upstream_nuclei/README.md`
- Added real captured payload fixtures:
  - `tests/fixtures/real_cve_payloads/cve-2022-22947-body.json`
  - `tests/fixtures/real_cve_payloads/cve-2021-29442-body.json`
  - `tests/fixtures/real_cve_payloads/cve-2021-29441-baseline-body.json`
  - `tests/fixtures/real_cve_payloads/cve-2021-29441-bypass-body.json`
  - `tests/fixtures/real_cve_payloads/cve-2020-13945-body.json`
  - `tests/fixtures/real_cve_payloads/cve-2021-45232-body.json`
  - `tests/fixtures/real_cve_payloads/nonmatch-apisix-dashboard-actuator-routes.html`
  - `tests/fixtures/real_cve_payloads/README.md`
- Added new tests:
  - `tests/cve_templates_real_data.rs`
    - 5 true-positive tests using real payload fixtures.
    - 1 real non-match control test (APISIX dashboard HTML should not trip `CVE-2022-22947`).
  - `tests/cve_templates_upstream_parity.rs`
    - CVE/source linkage check against pinned upstream snapshots.
    - body-match indicator alignment check against captured real payload fixtures.
- Validation:
  - `cargo test --test cve_templates_real_data --test cve_templates_upstream_parity`
  - `cargo test` (full suite)

---

# Task: Exa-Sourced Real-World CVE Test Hardening Continuation (Phase 21)

## Plan
- [x] Add Exa-sourced translated CVE template for Apache Airflow `CVE-2022-24288` using low-impact GET probe semantics.
- [x] Pin upstream Nuclei snapshot and real-world fixture snapshots (vulnerable + patched) for deterministic test coverage.
- [x] Extend CVE scanner and real-data/parity tests with true-positive and false-positive regression checks.
- [x] Run targeted and full test suites outside sandbox and record results.

## Review
- Added translated CVE template:
  - `assets/cve_templates/cve-2022-24288.toml`
  - check: `cve/cve-2022-24288/airflow-example-dag-params-rce-signal`
  - low-impact GET probe path: `/admin/airflow/code?root=&dag_id=example_passing_params_via_test_command`
- Added Exa-sourced pinned fixtures:
  - Upstream Nuclei snapshot:
    - `tests/fixtures/upstream_nuclei/CVE-2022-24288.yaml`
  - Real-world body snapshots from upstream Airflow source:
    - `tests/fixtures/real_cve_payloads/cve-2022-24288-body.py` (2.2.3 vulnerable signal)
    - `tests/fixtures/real_cve_payloads/nonmatch-cve-2022-24288-airflow-2.2.4-body.py` (2.2.4 patched control)
- Extended tests:
  - `tests/cve_templates_real_data.rs`
    - `cve_2022_24288_matches_real_airflow_223_source_fixture`
    - `cve_2022_24288_does_not_match_real_airflow_224_patched_fixture`
  - `tests/cve_templates_upstream_parity.rs`
    - included `CVE-2022-24288` in upstream parity table
    - included `CVE-2022-24288` in body-indicator alignment matrix
- Updated fixture metadata docs:
  - `tests/fixtures/upstream_nuclei/README.md`
  - `tests/fixtures/real_cve_payloads/README.md`
- Updated scanner docs:
  - `docs/scanners.md` current translated checks now includes `CVE-2022-24288`.
- Validation (outside sandbox for tests):
  - `cargo fmt`
  - `cargo test --test cve_templates_real_data --test cve_templates_upstream_parity --test cve_templates_scanner`
  - `cargo test`

---

# Task: Initial Template Tooling CLI (Phase 22)

## Plan
- [x] Add a dedicated CLI utility to import a Nuclei YAML template into ApiHunter CVE TOML format.
- [x] Support currently scanner-compatible fields (GET method, path, headers, status matcher, body word matchers).
- [x] Add integration tests for successful conversion and unsupported-method rejection.
- [x] Document usage and run targeted/full tests outside sandbox.

## Review
- Added new tooling binary:
  - `src/bin/template-tool.rs`
  - subcommand: `import-nuclei`
  - imports scanner-compatible Nuclei YAML fields into ApiHunter template TOML:
    - request method (`GET` only; explicit rejection for non-GET)
    - primary path (`path[0]` or first `raw` request line)
    - request headers
    - status matchers
    - body `word` matchers (`and` -> `body_contains_all`, default/or -> `body_contains_any`)
    - contextual hints (derived or user-provided)
- Added integration tests:
  - `tests/template_tooling.rs`
    - `import_nuclei_converts_get_template_into_apihunter_toml`
    - `import_nuclei_extracts_status_matcher_when_present`
    - `import_nuclei_rejects_non_get_methods`
- Added initial template-tooling documentation:
  - `HOWTO.md` section: "Import a Nuclei CVE template into ApiHunter TOML"
  - `Readme.md` roadmap updated:
    - marked initial template tooling completed
    - shifted remaining work to tooling coverage expansion
- Continued template expansion using the new tool with Exa-sourced upstream template:
  - added upstream fixture:
    - `tests/fixtures/upstream_nuclei/CVE-2020-3452.yaml`
  - generated template:
    - `assets/cve_templates/cve-2020-3452.toml`
    - check: `cve/cve-2020-3452/cisco-asa-ftd-path-traversal-signal`
  - scanner/parity coverage updates:
    - `tests/cve_templates_scanner.rs` added `translated_template_detects_cisco_asa_portal_lfi_signal`
    - `tests/cve_templates_upstream_parity.rs` includes `CVE-2020-3452` source-linkage parity check
    - `docs/scanners.md` current translated checks list includes `CVE-2020-3452`
    - `tests/fixtures/upstream_nuclei/README.md` updated with new pinned source URL
- Validation (tests run outside sandbox):
  - `cargo fmt`
  - `cargo test --test template_tooling --test cve_templates_scanner --test cve_templates_upstream_parity --test cve_templates_real_data`
  - `cargo test`

---

# Task: README Missing Items Patch (Phase 16)

## Plan
- [x] Patch stale Nuclei positioning language to reflect ApiHunter CVE template support.
- [x] Add explicit `template-tool` usage section with importer scope.
- [x] Add CVE hardening test strategy notes (`real_data`, `upstream_parity`, tooling tests).
- [x] Add missing docs link to `docs/auth-flow.md`.
- [x] Update active-check and CVE coverage wording for consistency with current scanners.

## Review
- Updated `Readme.md` comparison and FAQ text to clarify tool complementarity and current CVE coverage posture.
- Added a dedicated `Template Tooling (Nuclei -> ApiHunter TOML)` section with runnable command and importer scope.
- Added a `CVE Hardening Test Strategy` section documenting real payload replay tests and upstream parity checks.
- Added `Auth Flow` to the documentation index list in README.
- Updated CVE template module bullet to include current translated checks (including CVE-2020-3452).
- Verification commands:
  - `rg -n "Template Tooling|CVE Hardening Test Strategy|Auth Flow|community-maintained CVE templates|active checks" Readme.md`

---

# Task: Roadmap Extraction from STEALTH_IMPROVEMENTS (Phase 17)

## Plan
- [x] Read `STEALTH_IMPROVEMENTS.md` and extract only items with no depth/speed quality regressions.
- [x] Exclude proposals that explicitly trade off coverage or performance (sampling, decoy traffic, traffic shaping, heavy delays).
- [x] Add accepted items to `Readme.md` roadmap as a dedicated stealth-hardening lane.

## Review
- Added a new roadmap bullet in `Readme.md` under `Next Priorities`:
  - `Stealth hardening (no depth/speed regressions)`
- Included only low-risk, no-regression items from `STEALTH_IMPROVEMENTS.md`:
  - remove explicit scanner markers (`__ah_probe`, `X-AH-*`) while preserving semantics
  - replace obvious CORS probe literals with realistic values while keeping bypass coverage
  - randomize scanner and probe-path ordering
  - make WAF-evasion headers context-aware/randomized without reducing checks
- Explicitly excluded trade-off ideas from this extraction:
  - probe sampling / max-probes-per-check
  - decoy traffic injection
  - traffic shaping modes that slow scans
  - heavy inter-probe delays that reduce throughput

---

# Task: No-Brainer Stealth Improvements (Phase 18)

## Plan
- [x] Remove obvious mass-assignment scanner fingerprints (`__ah_probe`, `X-AH-*`).
- [x] Randomize deterministic scanner/probe ordering without reducing probe count.
- [x] Improve WAF evasion header realism with lightweight randomization.
- [x] Update tests for stealth behavior changes.
- [x] Run targeted and full tests outside sandbox.

## Review
- Removed obvious mass-assignment markers while preserving baseline/confirm logic:
  - `src/scanner/mass_assignment.rs` no longer sends `__ah_probe`.
  - baseline/confirm reads now use standard GET requests without `X-AH-MA-Stage`.
  - reflected-field detection still keys on `is_admin`, `role`, and `permissions`.
- Reduced deterministic fingerprinting without reducing probe count:
  - `src/runner.rs`: scanner registry order is shuffled per run.
  - `src/scanner/graphql.rs`: GraphQL path probe order is shuffled per run.
  - `src/discovery/common_paths.rs`: common-path probe list is shuffled after dedup.
  - `src/scanner/cors.rs`: probe origin list is deduped and shuffled.
- Improved low-cost header realism in `src/waf.rs`:
  - randomized `Accept-Language`.
  - optional `DNT`.
  - context-leaning `sec-fetch-*` values.
  - retained low overhead and existing UA rotation behavior.
- Updated tests for marker/header removal:
  - `tests/mass_assignment_scanner.rs` payload fixtures no longer include `__ah_probe`.
  - replaced stage-header-based baseline/confirm mocks with ordered GET responses via atomic call counting.
- Validation (outside sandbox for tests):
  - `cargo fmt`
  - `cargo test --test mass_assignment_scanner --test cors_scanner --test integration_runner --test waf_user_agents`
  - `cargo test`

---

# Task: Stealth Hardening Pass 2 (Phase 19)

## Plan
- [x] Randomize/remove fixed probe literals in OAuth and WebSocket active checks.
- [x] Replace remaining obvious CORS bypass literals with neutral equivalents.
- [x] Randomize fixed-order endpoint/path/template iteration in API-security and CVE template scanner.
- [x] Rotate rate-limit spoofed header values using reserved test ranges.
- [x] Update impacted tests and run targeted + full tests outside sandbox.

## Review
- OAuth/OIDC stealth hardening (`src/scanner/oauth_oidc.rs`):
  - replaced fixed `state`/`client_id` with per-run random tokens.
  - replaced fixed redirect probe with randomized realistic callback domains.
- WebSocket stealth hardening (`src/scanner/websocket.rs`):
  - replaced fixed cross-origin probe with randomized realistic origin set.
  - randomized `Sec-WebSocket-Key` per probe request.
  - shuffled websocket candidate path order per run.
- CORS literal cleanup (`src/scanner/cors.rs`):
  - replaced remaining obvious bypass literals (`evil`, `attacker`) with neutral equivalents while preserving bypass-shape coverage.
- API Security + CVE ordering randomization:
  - `src/scanner/api_security.rs`: shuffled debug endpoint and directory listing probe order.
  - `src/scanner/cve_templates.rs`: shuffled template execution order per host scan.
- Rate-limit spoof variation (`src/scanner/rate_limit.rs`):
  - spoofed IP now rotates across reserved documentation networks (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`).
- Test updates:
  - `tests/oauth_oidc_scanner.rs`: authorize mock now echoes dynamic `redirect_uri` and `state`.
  - `tests/websocket_scanner.rs`: removed fixed attacker-origin matcher dependency.
  - `tests/rate_limit_scanner.rs`: bypass detection now keys on spoof-header presence rather than a single fixed IP literal.
- Validation (outside sandbox):
  - `cargo fmt`
  - `cargo test --test oauth_oidc_scanner --test websocket_scanner --test rate_limit_scanner --test cors_scanner --test cve_templates_scanner --test integration_runner`
  - `cargo test`

---

# Task: Mass Assignment Test Audit & Hardening (Phase 20)

## Plan
- [x] Validate each reported remark against current scanner logic and test behavior.
- [x] Fix true issues in tests (precision/assertions/coverage) and implementation where warranted.
- [x] Run targeted and full test suites outside sandbox.

## Review
- Validated user remarks and hardened tests for true gaps.
- Scanner implementation improvement:
  - `src/scanner/mass_assignment.rs`: reflected-field matching now case-insensitive by lowercasing response body before key checks.
- Test precision fixes in `tests/mass_assignment_scanner.rs`:
  - added explicit POST path matcher for the reflected test (`/users`).
  - added request-level payload assertions for probe body (`is_admin`, `role`, `permissions`).
  - added call-order assertion (`GET -> POST -> GET`) for persisted-state confirmation path.
- New coverage added in `tests/mass_assignment_scanner.rs`:
  - partial reflection still reports finding.
  - non-JSON POST response path.
  - POST 5xx early-return path.
  - confirmation GET failure still keeps reflected finding and records error.
  - mixed-case reflected keys detection.
  - empty 200 POST body path.
  - nested elevated fields confirmation path.
- Notes on remark validity:
  - "GET before POST" is intentional baseline-vs-confirm design, not a bug.
  - other precision/coverage remarks were largely valid and addressed.
- Validation (outside sandbox):
  - `cargo fmt`
  - `cargo test --test mass_assignment_scanner`
  - `cargo test`

---

# Task: Mass Assignment Recall-First Logic Hardening (Phase 21)

## Plan
- [x] Replace string-fragile reflected-field detection with JSON key traversal and canonical key normalization.
- [x] Support key-name variants (`is_admin`, `isAdmin`, `IsAdmin`, `permissions`, `roles`) in reflected and elevated detection consistently.
- [x] Add missing edge-case tests: camelCase reflection, baseline GET failure path, reflected-only (no persisted change), empty-object JSON response, and single-finding behavior.
- [x] Tighten assertions for error specificity and request headers where relevant.
- [x] Run formatting + targeted/full tests outside sandbox and document outcomes.

## Review
- Scanner logic hardening in `src/scanner/mass_assignment.rs`:
  - replaced string-based reflected matching with parsed-JSON canonical detection by reusing elevated-field extraction.
  - added canonical key normalization for snake/camel/pascal variants and related aliases:
    - `is_admin`, `isAdmin`, `IsAdmin`, `is-administrator` style keys
    - `role`/`roles`
    - `permissions`/`scope(s)`
  - aligned reflected-field detection and elevated-field detection to the same JSON traversal + value semantics.
- Test hardening in `tests/mass_assignment_scanner.rs`:
  - added POST `Content-Type` assertion (`application/json`) in request-payload helper.
  - strengthened high-severity test to assert exactly one finding (`persisted-state-change`) and baseline with no sensitive fields.
  - tightened confirm/baseline failure tests to assert captured transport-error shape (`context = http::send`).
  - expanded coverage:
    - mixed + camel-case reflected key detection,
    - empty JSON object response ignored,
    - reflected-only signal when confirm GET shows no persisted change,
    - baseline GET failure still yielding reflected finding.
- Validation (outside sandbox for tests):
  - `cargo fmt`
  - `cargo test --test mass_assignment_scanner`
  - `cargo test`

---

# Task: Mass Assignment Recall-Safe Performance Pass (Phase 22)

## Plan
- [x] Implement parse-once JSON handling in mass-assignment scan path and GET confirmation path.
- [x] Reduce hot-path allocations in key canonicalization and field collection.
- [x] Add early traversal exit when all tracked sensitive fields are already found.
- [x] Keep recall guardrails: avoid heuristic skips that may drop findings.
- [x] Run formatting, targeted tests, and full suite outside sandbox; document outcomes.

## Review
- `src/scanner/mass_assignment.rs` performance updates (recall-safe):
  - parse-once JSON flow added via `parse_json_body(...)` and reused in:
    - POST response reflection handling in `scan(...)`,
    - GET baseline/confirm handling in `fetch_elevated_fields(...)`.
  - removed redundant JSON parse round trips in hot path.
  - reduced key-canonicalization allocations:
    - replaced per-key `String` normalization with allocation-free `key_matches_normalized(...)`.
  - reduced token normalization allocations:
    - switched truthy/role/permission checks from `to_ascii_lowercase()` allocation to `eq_ignore_ascii_case(...)` comparisons.
  - added `HashSet::with_capacity(3)` for sensitive-field collection.
  - added early exit in recursive traversal once all 3 tracked fields are found.
- Regression coverage additions:
  - `tests/mass_assignment_scanner.rs`:
    - `json_body_with_non_json_content_type_is_still_processed`
  - this explicitly protects recall by ensuring valid JSON bodies are still processed even with incorrect `Content-Type`.
- Explicitly not applied (to preserve recall):
  - heuristic pre-skip of baseline GET for “write-only-looking” paths (`/create`, `/add`, `/submit`).
  - skipping scan when baseline GET is non-JSON.
  - rationale: both can suppress true positives on real APIs with inconsistent semantics.
- Validation (outside sandbox for tests):
  - `cargo fmt`
  - `cargo test --test mass_assignment_scanner`
  - `cargo test`

---

# Task: Mass Assignment Reusable Refactor Pass (Phase 23)

## Plan
- [x] Extract shared response/body parsing helper usage to reduce branching duplication in scanner flow.
- [x] Extract reusable finding-construction helper for reflected vs persisted findings.
- [x] Extract reusable confirmation-diff helper for newly elevated fields.
- [x] Refactor `scan()` guard/flow for readability while preserving detection behavior.
- [x] Run formatting and targeted/full tests outside sandbox; document outcomes.

## Review
- Refactored `src/scanner/mass_assignment.rs` into reusable helpers without changing behavior:
  - guard helpers:
    - `should_skip_scan(...)`
    - `should_skip_response_status(...)`
  - response parsing helper:
    - `parse_json_http_response(...)` (shared by `scan` and `fetch_elevated_fields`)
  - confirmation diff helper:
    - `compute_newly_elevated_fields(...)`
  - finding builder helper:
    - `create_mass_assignment_finding(...)`
- `scan(...)` now reads as a high-level workflow (guard -> baseline -> probe -> parse -> confirm -> emit finding), with less duplicated branching/building code.
- Kept recall-safe behavior intact:
  - no heuristic URL/path-based skips were introduced.
  - JSON parsing still accepts valid JSON bodies even with non-JSON `Content-Type`.
- Validation (outside sandbox for tests):
  - `cargo fmt`
  - `cargo test --test mass_assignment_scanner`
  - `cargo test`

---

# Task: Mass Assignment Quick-Win Maintainability Pass (Phase 24)

## Plan
- [x] Extract shared JSON HTTP helpers to a scanner-common module and reuse in mass-assignment scanner.
- [x] Add step-aware error annotations for baseline/probe/confirm paths.
- [x] Add `--dry-run` / `Config.dry_run` and mass-assignment dry-run behavior (no POST sent).
- [x] Add reusable test helpers under `tests/helpers/` and use them in mass-assignment tests.
- [x] Add rustdoc API documentation for mass-assignment scanner behavior/findings.
- [x] Run formatting, targeted tests, and full suite outside sandbox; document outcomes.

## Review
- Added shared scanner HTTP JSON utilities in `src/scanner/http_utils.rs`:
  - `parse_json_response(...)`
  - `parse_json_body(...)`
  - `is_json_content_type(...)`
- Reused the shared helper in `src/scanner/mass_assignment.rs` and removed duplicate local response-parsing utilities.
- Added step-aware error annotation in `mass_assignment` path:
  - baseline GET: `baseline_get: ...`
  - probe POST: `probe_post: ...`
  - confirm GET: `confirm_get: ...`
  - implemented via `annotate_error(...)`.
- Added dry-run support:
  - CLI: `--dry-run` (`src/cli.rs`)
  - config: `Config.dry_run` (`src/config.rs`, wired in `src/main.rs`)
  - scanner behavior: `mass_assignment/dry-run` info finding and no network probe requests in dry-run mode.
- Added reusable test helpers:
  - `tests/helpers/mod.rs` with `mock_json_response(...)` and `assert_finding_exists(...)`
  - adopted in `tests/mass_assignment_scanner.rs`.
- Added scanner rustdoc on `MassAssignmentScanner` documenting workflow and finding IDs.
- Updated docs for the new flag/behavior:
  - `Readme.md` CLI table (`--dry-run`)
  - `HOWTO.md` dry-run recipe
  - `docs/configuration.md` (`dry_run` field)
  - `docs/scanners.md` mass-assignment dry-run note
- Validation (outside sandbox for tests):
  - `cargo fmt`
  - `cargo test --test cli --test mass_assignment_scanner`
  - `cargo test`

---

# Task: Cross-Scanner Common Utilities Refactor (Phase 25)

## Plan
- [x] Add `src/scanner/common/` modules for shared HTTP, finding-builder, string, probe, and error-collection utilities.
- [x] Rewire existing scanner HTTP helper exports to the new common module without breaking existing imports.
- [x] Adopt common utilities in selected scanners (`mass_assignment`, `oauth_oidc`, `api_security`, `rate_limit`) for immediate reuse.
- [x] Preserve scanner behavior and finding semantics while reducing duplicated helper logic.
- [x] Run formatting, targeted tests, and full suite outside sandbox; document outcomes.

## Review
- Added shared utility modules:
  - `src/scanner/common/http_utils.rs`
  - `src/scanner/common/finding_builder.rs`
  - `src/scanner/common/string_utils.rs`
  - `src/scanner/common/probe.rs`
  - `src/scanner/common/errors.rs`
- Added common module exports via `src/scanner/common/mod.rs` and `pub mod common;` in `src/scanner/mod.rs`.
- Kept compatibility for legacy imports by turning `src/scanner/http_utils.rs` into a re-export of `common::http_utils`.
- Adopted utilities across scanners:
  - `mass_assignment`: JSON parsing helper + fluent finding builder.
  - `oauth_oidc`: shared JSON response detection.
  - `jwt`: shared JSON content-type detection.
  - `api_security`: shared HTML/content-type and string redaction/snippet/slug helpers.
  - `rate_limit`: shared burst probe execution + shared error collection for probe results.
- Validation (tests run outside sandbox):
  - `cargo fmt`
  - `cargo test --test rate_limit_scanner --test mass_assignment_scanner --test cli`
  - `cargo test`

---

# Task: Scanner Error-Handling Hardening (Phase 26)

## Plan
- [x] Remove silent error swallowing in critical scanner probe paths (`cors`, `jwt`, `api_security` SPA canary).
- [x] Fix ambiguous error-state handling in `api_security` ID-range walk and keep error context explicit.
- [x] Improve scanner reporting when checks partially fail (`rate_limit` full-burst failure info finding, `mass_assignment` confirm-failure evidence note).
- [x] Preserve parse/probe context on OAuth metadata parse failures.
- [x] Add/adjust regression tests under `tests/` for each changed behavior and run fmt + targeted/full test suites outside sandbox.

## Review
- Scanner hardening changes:
  - `src/scanner/cors.rs`: bypass probe request failures now append to scanner `errors` instead of being silently ignored.
  - `src/scanner/jwt.rs`:
    - malformed JWT segment decode failures now emit `jwt/decode` errors with URL context.
    - algorithm-confusion active probe request failures now propagate into `errors` (`alg_confusion_probe: ...`) instead of silent `.ok()?`.
  - `src/scanner/api_security.rs`:
    - SPA canary request errors are now surfaced (annotated with `spa_canary_probe`).
    - ID-range probe results now store status as `Option<u16>` and only count explicit `200..399` successes.
    - Generic-secret validation skips now emit debug logs with redacted match context.
  - `src/scanner/rate_limit.rs`: when all burst probes fail, scanner now emits `rate_limit/check-failed` info finding and returns captured errors.
  - `src/scanner/mass_assignment.rs`: reflected-only finding evidence now notes failed confirmation GET when confirm step errors.
  - `src/scanner/oauth_oidc.rs`: metadata JSON parse errors now include the failing metadata URL in `CapturedError`.
  - `src/runner.rs`: duplicate `CapturedError` entries are now deduplicated before final reporting.
- Regression tests added/updated:
  - `tests/cors_scanner.rs`: `regex_bypass_probe_failures_are_collected`
  - `tests/jwt_scanner.rs`: `malformed_jwt_decode_errors_are_reported`, `alg_confusion_probe_failure_is_reported`
  - `tests/rate_limit_scanner.rs`: `all_burst_requests_fail_reports_check_failed`
  - `tests/mass_assignment_scanner.rs`: confirmation-failure evidence note assertion
  - `tests/oauth_oidc_scanner.rs`: metadata parse URL-context assertion (cache-seeded invalid metadata)
  - `tests/integration_runner.rs`: `api_security_spa_canary_probe_errors_are_reported`, `api_security_id_range_request_errors_are_not_counted_as_success`
- Validation (tests run outside sandbox):
  - `cargo fmt`
  - `cargo test --test cors_scanner --test jwt_scanner --test rate_limit_scanner --test mass_assignment_scanner --test oauth_oidc_scanner --test integration_runner`
  - `cargo test`

---

# Task: Panic-Safety Hardening (Phase 27)

## Plan
- [x] Remove panic in adaptive semaphore acquisition path in `http_client`.
- [x] Remove panic in startup URL-filter client builder in `main`.
- [x] Keep behavior stable while adding clarity improvements for cookie and host parsing in `http_client`.
- [x] Run formatting and full suite outside sandbox.

## Review
- `src/http_client.rs`:
  - `AdaptiveLimiter::acquire()` now returns `Result<OwnedSemaphorePermit, &'static str>` instead of panicking with `expect`.
  - Request path now tolerates adaptive limiter acquire failure and continues with a debug log (`adaptive limiter acquire failed`).
  - Added `parse_host_or_unknown(...)` helper with debug context for malformed URLs / missing host.
  - Added `parse_set_cookie_pair(...)` helper and switched session cookie update loop to explicit parsing instead of chained `splitn + unwrap_or`.
- `src/main.rs`:
  - `filter_accessible_urls(...)` now handles reqwest client build failure gracefully:
    - emits warnings via `eprintln!`
    - skips accessibility filtering by returning `(urls.to_vec(), Vec::new())`
    - avoids process panic.
- Validation (tests run outside sandbox):
  - `cargo fmt`
  - `cargo test`

---

# Task: Valid+Partial Gap Closure (Phase 28)

## Plan
- [x] Add explicit startup config validation + security warnings (timeouts, concurrency, auth token/header hygiene).
- [x] Improve observability with structured scan lifecycle logs and adaptive concurrency change logs.
- [x] Add runtime metrics snapshots (HTTP request/retry counts and per-scanner finding/error counters) and expose them in run/report metadata.
- [x] Add individual active-scanner CLI toggles (mass-assignment, oauth/oidc, rate-limit, websocket, CVE templates).
- [x] Add/adjust tests/docs for new toggles and metadata fields, then run full validation outside sandbox.

## Review
- Added explicit startup validation and hygiene warnings in `src/main.rs`:
  - hard validation for invalid runtime knobs (`--timeout-secs`, `--filter-timeout`, `--concurrency` zero cases),
  - strict auth input checks (`--auth-bearer` whitespace/empty, `--auth-basic` `USER:PASS` format),
  - warning signals for high-risk runtime settings and sensitive CLI-injected headers/cookies.
- Added active-check scanner toggles end-to-end:
  - CLI flags in `src/cli.rs`:
    - `--no-mass-assignment`
    - `--no-oauth-oidc`
    - `--no-rate-limit`
    - `--no-cve-templates`
    - `--no-websocket`
  - Config wiring in `src/config.rs` and `src/main.rs` (`ScannerToggles` + CLI mapping).
  - Runner gating in `src/runner.rs` so each active scanner is independently switchable.
- Improved observability:
  - structured lifecycle logs added in `src/runner.rs` for scan setup, scanner registry readiness, and completion.
  - adaptive concurrency increase/decrease transitions now emit structured logs in `src/http_client.rs`.
- Added runtime metrics snapshots and report metadata exposure:
  - HTTP transport counters in `src/http_client.rs`:
    - `requests_sent`
    - `retries_performed`
  - per-scanner runtime counters in `src/runner.rs`:
    - findings by scanner
    - errors by scanner
  - report metadata extension in `src/reports.rs`:
    - `meta.runtime_metrics` now includes HTTP + per-scanner counters.
  - auto report markdown/log enrichment in `src/auto_report.rs` with runtime counter sections.
- Tests updated for new fields/behavior:
  - `tests/cli.rs`: new active-toggle parsing coverage and expanded `ScannerToggles` mapping assertions.
  - `tests/integration_runner.rs`: `RuntimeMetrics` fixture updates and runtime counter assertion in CORS integration run.
  - `tests/reports.rs`: metadata assertions for `meta.runtime_metrics`.
  - all `ScannerToggles` test configs updated across scanner test files to include newly added toggle fields.
- Docs updated:
  - `Readme.md` CLI reference + FAQ for new active scanner flags, plus runtime-metrics feature callout.
  - `HOWTO.md` targeted active-check command now includes new active scanner disable flags.
  - `docs/configuration.md` includes new active scanner toggle fields.
- Validation:
  - `cargo fmt`
  - `cargo check`
  - `cargo test --test cli --test reports --test integration_runner` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Template Tooling Expansion (Phase 29)

## Plan
- [x] Expand importer request selection to support multi-request Nuclei templates by choosing the first compatible GET request mapping.
- [x] Parse request headers from Nuclei `raw` blocks when structured `headers` mappings are absent.
- [x] Translate header-based `word` matchers into ApiHunter `match_headers` constraints when header/value pairs are explicit.
- [x] Add/adjust template-tool integration tests for multi-request selection, raw-header extraction, and header-matcher translation.
- [x] Update README/HOWTO importer capability notes, then run formatting + targeted/full tests outside sandbox.

## Review
- Expanded importer request selection in `src/bin/template-tool.rs`:
  - added `select_importable_request(...)` to walk `http` request entries and pick the first compatible `GET` request with an extractable path.
  - preserved explicit failure behavior for non-GET-only templates with the existing error signature.
- Improved raw request parsing support:
  - `extract_method(...)` and `extract_path(...)` now iterate raw request blocks instead of only inspecting the first raw item.
  - `extract_headers(...)` now falls back to parsing headers from `raw` blocks when structured `headers` are missing.
  - raw-header import skips `Host` and `Content-Length` to avoid brittle target-specific request artifacts.
- Added matcher translation coverage:
  - `extract_matchers(...)` now returns `match_headers` and maps `word` matchers with `part: header` / `all_headers` into `NameValue` pairs when tokens are in explicit `Header: Value` form.
  - wired translated header matchers into output TOML templates (`match_headers` field).
- Added template-tool integration tests in `tests/template_tooling.rs`:
  - `import_nuclei_selects_first_compatible_get_request_from_multi_request_template`
  - `import_nuclei_extracts_headers_from_raw_request_block`
  - `import_nuclei_translates_header_word_matchers_into_match_headers`
  - existing conversion/status/non-GET rejection tests remain green.
- Updated importer capability docs:
  - `Readme.md` importer scope section now reflects multi-request GET selection, raw-header extraction, and header-word matcher mapping.
  - `HOWTO.md` importer scope section updated with matching capability notes.
  - `Readme.md` roadmap wording for template-tooling priority now calls out remaining matcher/request-chain gaps (regex/dsl + multi-step chains) rather than already-delivered raw/header coverage.
- Validation:
  - `cargo fmt`
  - `cargo check`
  - `cargo test --test template_tooling` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)
