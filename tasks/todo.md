# Task: Clarify Testing Strategy in Docs (Phase 10)

## Plan
- [x] Add a dedicated testing strategy document describing what each test class covers.
- [x] Link the testing strategy from `Readme.md` and `docs/INDEX.md` so it is discoverable.
- [x] Verify updated doc links and summarize outcomes in a review section.

## Review
- Added `docs/testing.md` with a clear testing matrix covering scanner suites, runner integration, CLI/startup, HTTP/auth, fixture regression, and helper-level tests.
- Explicitly documented that default `cargo test` coverage is local/deterministic (wiremock + fixtures) and does not require live internet targets.
- Updated `Readme.md` testing section with explicit manual-only live target note and a direct link to the new testing guide.
- Updated `docs/INDEX.md` navigation, development references, deep-dive list, metadata date, and document count to include the new testing guide.
- Verification:
  - `test -f docs/testing.md`
  - `rg -n "\\[Testing Guide\\]\\(docs/testing\\.md\\)|\\[Testing Guide\\]\\(\\./testing\\.md\\)" Readme.md docs/INDEX.md`

---

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

---

# Task: Template Tooling Expansion 2 (Phase 30)

## Plan
- [x] Add importer translation support for Nuclei `regex` and `dsl` matcher families into scanner-compatible TOML fields.
- [x] Extend CVE template runtime schema/matching to evaluate translated regex constraints.
- [x] Add controlled multi-step request-chain support with low-impact preflight steps (safe methods only, no mutation/body payloads).
- [x] Add tests for regex/dsl translation, chain import shape, and chain execution behavior.
- [x] Update README/HOWTO/docs and run fmt + targeted/full tests outside sandbox.

## Review
- Expanded template importer in `src/bin/template-tool.rs`:
  - matcher translation now supports:
    - `regex` matchers for body/header parts,
    - supported `dsl` subset:
      - `status_code == ...`
      - `contains(...)` for body/headers
      - `regex(...)` for body/headers
  - added TOML output fields for regex constraints:
    - `body_regex_any`, `body_regex_all`
    - `header_regex_any`, `header_regex_all`
  - added controlled request-chain extraction:
    - emits `preflight_requests` before the main probe request,
    - preflights are restricted to low-impact methods (`GET`/`HEAD`/`OPTIONS`),
    - capped by `MAX_PREFLIGHT_STEPS`.
  - improved main request selection for multi-request templates:
    - prefers first `GET` request with importable matchers,
    - falls back to first importable `GET` if no matcher-bearing request exists.
- Extended CVE template runtime in `src/scanner/cve_templates.rs`:
  - added schema support for importer-emitted fields:
    - `preflight_requests`
    - body/header regex matcher arrays
  - preflight chain execution added before main probe:
    - each preflight executes with safe-method validation,
    - optional `expect_status_any_of` gating controls chain continuation.
  - response matching now evaluates:
    - body regex constraints,
    - header regex constraints (against flattened response headers),
    - existing status/body/header contains logic remains intact.
- Added/updated tests:
  - `tests/template_tooling.rs`:
    - `import_nuclei_translates_regex_and_dsl_matchers`
    - `import_nuclei_emits_safe_preflight_chain_steps`
    - existing importer tests remain green.
  - new runtime integration tests in `tests/cve_templates_runtime_ext.rs`:
    - `preflight_chain_executes_before_probe`
    - `regex_constraints_match_for_body_and_headers`
  - existing `tests/cve_templates_scanner.rs` suite remains green.
- Documentation updates:
  - `Readme.md` Template Tooling section now documents regex/dsl translation and safe preflight chain extraction.
  - `HOWTO.md` importer scope updated with the same capabilities.
  - `docs/scanners.md` CVE template scanner section updated to include regex constraints and safe preflight behavior.
- Validation:
  - `cargo fmt`
  - `cargo check`
  - `cargo test --test template_tooling --test cve_templates_runtime_ext --test cve_templates_scanner` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Issues & Weaknesses Remediation (Phase 31)

## Plan
- [x] Standardize naming surface to reduce `ApiHunter` vs `api-scanner` confusion without breaking existing CLI usage.
- [x] Make `--quiet` affect tracing initialization as intended.
- [x] Relax seed URL accessibility filtering so auth-gated targets (for example `403`) are not dropped.
- [x] Add an explicit CLI control to disable automatic local report persistence.
- [x] Validate/disambiguate discovery politeness behavior; apply code changes only if a true gap exists.
- [x] Improve IDOR range-walk severity scaling by observed breadth of successful object access.
- [x] Remove local/editor and risky target artifacts from version control (`.history/`, gambling target lists) while preserving local files.
- [x] Resolve changelog naming inconsistency if present in current tree.
- [x] Run fmt + targeted/full tests outside sandbox and document final review notes.

## Review
- Naming clarity:
  - Added an explicit naming section in `Readme.md` (project vs package vs lib vs binary) to remove ambiguity.
  - No legacy project name references were found in the current repo state.
- Logging + quiet mode:
  - `init_tracing(quiet)` now uses default `error` in quiet mode and `info` otherwise (while still honoring `RUST_LOG` overrides).
- URL prefilter behavior:
  - `filter_accessible_urls(...)` now treats all non-5xx HTTP responses (`200..500`) as reachable so auth-gated endpoints such as `403`/`451` are not dropped.
  - Added per-host delay enforcement to the prefilter phase using `--delay-ms` to avoid bursty pre-scan traffic.
- Auto-report control:
  - Added new CLI flag `--no-auto-report` in `src/cli.rs`.
  - `src/main.rs` now skips `auto_report::save_auto_report(...)` when this flag is present.
  - Updated `Readme.md` CLI table and `HOWTO.md` examples.
- Discovery politeness validation:
  - Confirmed discovery requests already route through `HttpClient` (`self.client.get/head`), which already enforces per-host delay.
  - Applied additional politeness only to prefilter stage, where raw `reqwest` client requests were previously bursty.
- IDOR severity scaling:
  - `api_security/idor-id-enumerable` severity now scales with adjacent-ID success breadth:
    - 2 successes -> `MEDIUM`
    - 3 successes -> `HIGH`
    - 4+ successes -> `CRITICAL`
  - Finding detail now includes observed adjacent success count.
  - Added integration test:
    - `api_security_id_range_severity_scales_with_success_breadth` (`tests/integration_runner.rs`)
- Repo hygiene:
  - Untracked `.history/` from git while keeping local files.
  - Untracked `targets/gambling-sites.txt` from git while keeping local file.
  - Reinforced ignore rules in `.gitignore` for `.history/` and `targets/gambling*.txt`.
- Changelog typo check:
  - No root-level `Changelog.md` exists in current tree; canonical file is `Changelog.md`.
  - The typo-like names were historical editor snapshots inside `.history/`, now untracked.
- Validation:
  - `cargo fmt`
  - `cargo test --test cli --test integration_runner` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Scanner Correctness & Concurrency Fixes (Phase 32)

## Plan
- [x] Fix JWT alg-confusion key material extraction (`x5c`/`jwk`) so probes use RSA key material, not raw cert/JWK JSON blobs.
- [x] Remove per-URL scan dead clones and dual return/send path in runner scanner fan-in.
- [x] Make finding dedup severity-aware in runner by using the report-level dedup behavior.
- [x] Reduce scanner-order test flakiness by disabling random scanner shuffling in test builds.
- [x] Improve CORS probe request strategy to prefer preflight (`OPTIONS`) and only fallback to `GET` when needed.
- [x] Parallelize per-site discovery strategy execution (`robots`, `sitemap`, `swagger`, `js`, `headers`, `common_paths`) with `tokio::join!`.
- [x] Clean minor hygiene issues (`substitute_env_vars` replace-all correctness, remove dead comment stub, runner `eprintln!` -> tracing).
- [x] Add/adjust tests for the new behavior and run fmt + targeted/full tests outside sandbox.

## Review
- JWT alg-confusion probe correctness:
  - `src/scanner/jwt.rs` no longer uses raw `x5c` DER blobs or serialized JWK JSON as HMAC secret material.
  - Added key derivation helpers:
    - RSA modulus extraction from `jwk.n` (base64url decode),
    - best-effort RSA modulus extraction from `x5c` certificate DER (SPKI BIT STRING parse).
  - If key hints exist but extraction fails, scanner now records a `CapturedError` (`jwt/alg_confusion`) instead of silently running with invalid key bytes.
  - Updated JWT test fixture to use RSA JWK in token header for active-probe path coverage.
- Runner correctness and hygiene:
  - `scan_url_with_results(...)` now returns lightweight per-URL summary counters and scanner stats only; removed dead clone-heavy `all_findings/all_errors` accumulation.
  - Worker progress summary now uses returned severity counters rather than cloned finding vectors.
  - Final finding dedup in runner now calls `reports::dedup_findings(...)` (severity-aware); removed runner-local first-seen dedup implementation.
  - Runner lifecycle status output moved from `eprintln!` to `tracing` (`info!/warn!`).
  - Scanner registry shuffling remains enabled in normal builds but is skipped under `cfg(test)` to prevent order-related test flakiness.
- Discovery and CORS behavior:
  - Per-site discovery strategies now run concurrently via `tokio::join!` in `run_discovery_per_site(...)` instead of sequential blocking.
  - CORS scanner now prefers `OPTIONS` preflight probing via `probe_cors_response(...)` and only falls back to `GET` if preflight response lacks CORS headers.
  - Added regression test `options_probe_is_preferred_over_get_when_cors_headers_present`.
- Minor fixes:
  - `auth.rs` env substitution now uses a single `replace_all` pass (no repeated global string replacement loop).
  - Removed dead comment stub from `HttpClient::new`.
- Validation:
  - `cargo fmt`
  - `cargo test --test jwt_scanner --test cors_scanner --test integration_runner --test reports` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Scanner Identity + Auth Refresh Lifecycle (Phase 33)

## Plan
- [x] Promote scanner identity to the `Scanner` trait (`fn name()`) so registry metadata can’t drift.
- [x] Update all scanner implementations to provide stable scanner names.
- [x] Refactor runner scanner registry to consume trait-provided names instead of a parallel hardcoded name field.
- [x] Add cancellation support to auth refresh background tasks and stop them cleanly before process exit.
- [x] Add regression tests for scanner names and refresh task cancellation.
- [x] Run fmt + targeted/full tests outside sandbox.

## Review
- Scanner trait and implementations:
  - Added `fn name(&self) -> &'static str` to `src/scanner/mod.rs`.
  - Updated all scanner modules (`cors`, `csp`, `graphql`, `api_security`, `jwt`, `openapi`, `mass_assignment`, `oauth_oidc`, `rate_limit`, `cve_templates`, `websocket`) to implement `name()`.
- Runner registry simplification:
  - `RegisteredScanner` no longer carries a duplicated `name` field.
  - Runner now reads scanner names directly from `scanner.name()` for lifecycle logging and stats aggregation.
- Auth refresh lifecycle:
  - Added `RefreshTaskHandle` in `src/auth.rs` with cooperative cancellation via `tokio_util::sync::CancellationToken`.
  - `spawn_refresh_task(...)` now returns this handle.
  - `src/main.rs` now stores refresh task handles for both auth flows and calls `shutdown().await` before exit, preventing orphaned background tasks.
- Stability tests:
  - Added `tests/scanner_names.rs` to assert stable scanner trait names.
  - Added `tests/auth_refresh.rs` to verify immediate refresh-task cancellation.
- Validation:
  - `cargo fmt`
  - `cargo test --test auth_refresh --test scanner_names --test integration_runner --test jwt_scanner` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Naming + Auth Credential Storage Continuation (Phase 34)

## Plan
- [x] Complete the `LiveCredential` storage migration to lock-free reads using `ArcSwap<String>`.
- [x] Remove obsolete async awaits from credential read/apply paths after the storage migration.
- [x] Update affected tests to the new credential storage type.
- [x] Finalize package naming surface (`apihunter`) while preserving `api-scanner` CLI compatibility.
- [x] Sync README/changelog notes with the above behavior.
- [x] Run formatting and targeted/full tests outside sandbox.

## Review
- Completed auth credential storage refactor in `src/auth.rs`:
  - `LiveCredential.value` now uses `Arc<ArcSwap<String>>`.
  - `LiveCredential::current()` and `LiveCredential::apply_to()` are now synchronous.
  - Refresh task now stores new token values with `cred.value.store(...)` and no lock acquisition on request path.
- Updated `src/http_client.rs` to use synchronous credential application (`cred.apply_to(...)`).
- Updated `tests/auth_refresh.rs` to construct `LiveCredential` with `ArcSwap::from_pointee(...)`.
- Finalized naming surface:
  - `Cargo.toml` package name is `apihunter`.
  - Added `default-run = "api-scanner"` to preserve existing `cargo run` behavior.
  - Kept both CLI binaries (`api-scanner` and `apihunter`) mapped to `src/main.rs` for compatibility.
- Documentation/changelog sync:
  - `Readme.md` naming section now reflects `apihunter` package and dual binary names.
  - `Changelog.md` includes package rename and lock-free auth credential storage notes.
- Validation:
  - `cargo fmt`
  - `cargo test --test auth_refresh --test cli --test integration_runner` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Zero-Warning Binary Target Cleanup (Phase 35)

## Plan
- [x] Remove Cargo duplicate-target warnings by ensuring `apihunter` and `api-scanner` binaries do not share the same target path.
- [x] Preserve CLI compatibility for both binary names (`apihunter` and `api-scanner`) and keep default run behavior unchanged.
- [x] Run formatter and full test suite outside sandbox and verify warning removal.

## Review
- Updated binary target layout in `Cargo.toml`:
  - kept `apihunter` binary on `src/main.rs`,
  - moved `api-scanner` binary target to `src/bin/api-scanner.rs`.
- Added compatibility wrapper `src/bin/api-scanner.rs` that reuses the main entrypoint via `include!("../main.rs");`.
- Behavior verification:
  - `cargo run -- --help` runs `api-scanner` (default-run) with no duplicate-target warning.
  - `cargo run --bin apihunter -- --help` works.
  - `cargo run --bin api-scanner -- --help` works.
- Validation:
  - `cargo fmt`
  - `cargo test` (outside sandbox, full suite)

---

# Task: Targeted Correctness Follow-up (Phase 36)

## Plan
- [x] Audit reported findings against current code and patch only reproducible gaps.
- [x] Harden JWT alg-confusion key derivation to probe with RSA public key material from `jwk` (`n` + `e`) and `x5c` SPKI forms, with explicit errors when unusable.
- [x] Reduce JWT weak-secret matching overhead by removing full wordlist clone per token.
- [x] Improve URL canonicalization by normalizing query parameter ordering.
- [x] Align SARIF driver/tool name with package metadata (`env!("CARGO_PKG_NAME")`).
- [x] Apply low-risk CORS scanner cleanup (`same-origin` comparison clarity, avoid duplicate regex bypass loops).
- [x] Add/adjust tests for JWT alg-confusion positive path and query-order canonicalization dedup.
- [x] Run `cargo fmt` and full `cargo test` outside sandbox, then document review + non-reproducible items.

## Review
- Reproducibility audit outcomes:
  - Already fixed in current tree: discovery per-site parallelization (`tokio::join!` in `run_discovery_per_site`), auth env substitution (`replace_all` form), auth refresh task cancellation handle, runner dedup path using `reports::dedup_findings`, and runner lifecycle logging via `tracing` (no runner `eprintln!`).
  - Reproducible/valid gaps addressed in this phase: JWT alg-confusion key material realism, weak-secret clone overhead, query-order canonicalization, SARIF tool-name hardcode, and minor CORS hygiene.
- JWT alg-confusion hardening (`src/scanner/jwt.rs`):
  - Reworked probe key derivation to generate realistic public-key material candidates:
    - from `jwk`: build RSA SPKI DER from decoded `n` + `e`, plus PEM form.
    - from `x5c`: use certificate DER/PEM and extracted SPKI DER/PEM candidates.
  - Probe now iterates candidate key-material encodings and records source-specific probe transport errors (`alg_confusion_probe[<source>]`).
  - Added DER construction helpers (`INTEGER`, TLV lengths, SPKI builder) and certificate SPKI extraction helper.
- JWT weak-secret performance:
  - Removed full `WEAK_SECRET_LIST` clone per token; now iterates static list by reference and chains small host-derived candidates.
- URL canonicalization:
  - Added query-parameter normalization in `runner::canonicalise` by sorting parsed `(key, value)` pairs before serialization, so equivalent query order variants dedup.
- SARIF consistency:
  - Replaced hardcoded SARIF tool name with `env!("CARGO_PKG_NAME")`.
- CORS cleanup:
  - Made same-origin comparison explicit with `as_str()` on both sides.
  - Added `regex_bypass_checked` guard so regex-bypass expansion runs at most once per URL even if multiple origins reflect, reducing redundant active probe volume without disabling the check.
- Added/updated tests:
  - `tests/jwt_scanner.rs`: `alg_confusion_detected_when_forged_hs256_matches_jwk_spki`.
  - `tests/integration_runner.rs`: `canonicalise_dedups_query_parameter_order_variants`.
  - `tests/reports.rs`: SARIF driver name assertion against `env!("CARGO_PKG_NAME")`.
- Validation:
  - `cargo fmt`
  - `cargo check`
  - `cargo test --test jwt_scanner --test integration_runner --test reports --test cors_scanner` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Post-Review Hardening Sweep (Phase 37)

## Plan
- [x] Re-verify reported “remaining” items against current source and classify fixed vs still-open.
- [x] Add per-step discovery timeout wrapping to prevent one hanging discovery strategy from blocking site discovery forever.
- [x] Improve auth JSON extraction to accept scalar values beyond strings/integers (notably float `expires_in`).
- [x] Allow empty cookie values when parsing `Set-Cookie` pairs for session persistence.
- [x] Optimize JWT leading-zero normalization to avoid repeated `Vec::remove(0)` shifts.
- [x] Add regression tests for discovery changes, float `expires_in`, and empty cookie value persistence.
- [x] Run fmt/check and full tests outside sandbox; document outcomes.

## Review
- Verification pass outcomes:
  - Already fixed in current tree before this phase: SARIF driver name uses `env!("CARGO_PKG_NAME")`, query-order canonicalization is active, refresh task handle lifecycle is retained + shutdown in `main.rs`, discovery already runs strategies concurrently, and package/binary naming has already moved to `apihunter` + `api-scanner` alias.
- Discovery hardening (`src/runner.rs`):
  - Added `run_discovery_with_timeout(...)` wrapper.
  - Each per-site discovery step (`robots`, `sitemap`, `swagger`, `js`, `headers`, `common-paths`) now runs under timeout = `max(1, timeout_secs * 2)`.
  - Timeout emits explicit captured error context `discovery/<step>` instead of stalling site discovery.
  - Added integration coverage in `tests/integration_runner.rs`:
    - `discovery_results_are_merged_when_step_completes_in_time` verifies discovery output still feeds scan targets.
  - Moved discovery timeout tests out of production source to comply with test-placement policy (`tests/` only).
- Auth JSON extraction (`src/auth.rs`):
  - Added `json_scalar_to_string(...)` to normalize string/int/uint/float/bool JSON scalar values.
  - `extract_jsonpath(...)` now uses this helper for both JSON Pointer and JSONPath results.
  - Float values like `3600.0` are normalized to integer string form when integral.
  - Added `tests/auth_flow.rs`:
    - `execute_flow_accepts_float_expires_in` verifies float `expires_in` drives refresh interval correctly.
- Cookie parsing (`src/http_client.rs`):
  - `parse_set_cookie_pair` now accepts empty cookie values (`name=`) while still rejecting empty names.
  - Added `tests/session_file_formats.rs`:
    - `session_file_preserves_empty_cookie_values` verifies empty-value cookies are persisted in session store output.
- JWT normalization performance (`src/scanner/jwt.rs`):
  - Replaced iterative leading-byte removal with a single drain based on first non-zero position.
  - Preserves at least one zero byte for all-zero inputs.
- Validation:
  - `cargo fmt`
  - `cargo check`
  - `cargo test --test auth_flow --test session_file_formats --test jwt_scanner --test integration_runner --test reports` (outside sandbox)
  - `cargo test --test cve_templates_runtime_ext --test integration_runner` (outside sandbox)
  - `cargo test` (outside sandbox, full suite)

---

# Task: Main.rs CI/Runtime Hardening Follow-up (Phase 38)

## Plan
- [x] Re-verify each reported issue against live source and classify stale vs reproducible.
- [x] Replace non-essential `eprintln!` status/warning output in `main.rs` and URL filter path with `tracing` logs so `--quiet` and `RUST_LOG` are respected.
- [x] Relax CLI cookie parsing to allow empty cookie values while still rejecting empty names.
- [x] Improve URL accessibility pre-filter heuristic to treat any HTTP response as reachable and only classify connect/timeout failures as inaccessible.
- [x] Add startup validation for `--auth-flow` and `--auth-flow-b` path existence/type/readability.
- [x] Update lessons/changelog/todo review and run CI checks (`fmt`, `clippy -D warnings`) plus full tests outside sandbox.

## Review
- Verification outcomes:
  - Already fixed/stale claims in the report: `spawn_refresh_task` handles are already stored and shut down in `main.rs`, `extract_jsonpath` already supports float scalars, JWT `trim_leading_zeros` is already single-pass, and `init_tracing` already defaults to `info` when not quiet.
- `main.rs` logging cleanup:
  - Replaced non-essential status/warning `eprintln!` calls with `tracing::info!`/`tracing::warn!` in the run lifecycle and URL filtering path.
  - Kept intentional banner printing behavior unchanged.
- Cookie parsing:
  - `parse_cookies(...)` now rejects only empty cookie names and accepts empty values (`name=`), aligning CLI parsing with valid cookie semantics.
- Accessibility filter heuristic:
  - URL pre-filter now treats any HTTP response as reachable.
  - Only network-level connect/timeout failures are classified as inaccessible; other request errors are treated as reachable to avoid false pruning.
- Startup validation:
  - Added early validation for `--auth-flow` and `--auth-flow-b` paths (exists, file type, readable) with precise error messages.
- Validation:
  - `cargo fmt --all --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test` (outside sandbox, full suite)

---

# Task: Canonical CLI Binary Name (`apihunter`) (Phase 39)

## Plan
- [x] Remove the legacy `api-scanner` binary target and keep only `apihunter` in Cargo metadata.
- [x] Update release workflow packaging to publish only `apihunter` artifacts.
- [x] Update user-facing docs/examples to use `apihunter` command paths.
- [x] Run `fmt`, strict `clippy`, and full tests outside sandbox to confirm CI health.
- [x] Document outcomes in changelog and lessons.

## Review
- Cargo/runtime naming:
  - Updated `Cargo.toml` to `default-run = "apihunter"`.
  - Removed legacy `[[bin]]` target for `api-scanner`.
  - Deleted compatibility wrapper binary `src/bin/api-scanner.rs`.
- Release workflow:
  - Updated `.github/workflows/release.yml` to publish `apihunter` binary/artifact names.
- Docs/examples:
  - Updated command examples in `Readme.md`, `HOWTO.md`, `docs/findings.md`, and `docs/scanners.md` from `api-scanner` to `apihunter`.
- Validation:
  - `cargo fmt --all --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test` (outside sandbox, full suite)

---

# Task: Startup Input Regression Lock (Phase 40)

## Plan
- [x] Re-verify reported `main.rs` startup issues against current source before patching.
- [x] Add startup regression tests under `tests/` for empty cookie-value acceptance and missing auth-flow fast-fail.
- [x] Run targeted tests outside sandbox and record results.

## Review
- Verification outcomes:
  - `src/main.rs::parse_cookies(...)` already rejects only empty cookie names and accepts empty values.
  - `src/main.rs::validate_startup_inputs(...)` already validates `--auth-flow` and `--auth-flow-b` via `validate_auth_flow_path(...)` (exists/file/readable).
- Added `tests/startup_inputs.rs`:
  - `empty_cookie_values_are_accepted`: proves `--cookies session=` does not fail startup parsing.
  - `auth_flow_path_is_validated_before_runtime`: proves missing `--auth-flow` path fails fast with `file not found`.
- Validation:
  - `cargo test --test startup_inputs` (outside sandbox): `2 passed; 0 failed`.

---

# Task: Pre-Filter/Retry/Stream Dedup Correctness Sweep (Phase 41)

## Plan
- [x] Reproduce and patch URL pre-filter transport mismatch so accessibility checks honor config transport settings (proxy, TLS override, default headers, cookies).
- [x] Remove dead elapsed assignment in `main.rs` and surface elapsed runtime via structured logging.
- [x] Restrict HTTP retry-status policy to transient-safe codes (`429`, `500`, `502`, `503`, `504`).
- [x] Prevent duplicate NDJSON stream lines by deduplicating findings before `flush_finding` during streaming.
- [x] Add regression tests in `tests/` for proxy-aware pre-filter path, retry-status policy, and stream dedup behavior.
- [x] Run targeted tests outside sandbox and document results.

## Review
- `main.rs` pre-filter transport parity:
  - Built scan `Config` before pre-filtering and passed config into `filter_accessible_urls(...)`.
  - Added `build_filter_client(...)` to apply config transport settings to pre-filter requests:
    - proxy (`--proxy`),
    - TLS override (`--danger-accept-invalid-certs`),
    - default headers,
    - cookie header merge from configured cookies.
- `main.rs` elapsed cleanup:
  - Replaced dead `_elapsed` assignment with structured completion log:
    - `info!(elapsed_ms = ..., "Run lifecycle: completed")`.
- Retry policy tightening (`src/http_client.rs`):
  - `should_retry_status(...)` now retries only `429`, `500`, `502`, `503`, `504`.
- Streaming dedup fix (`src/runner.rs`):
  - Added run-wide stream dedup guard keyed by `(url, check)` behind `Arc<Mutex<HashSet<...>>>`.
  - `flush_finding` now emits only first-seen keys during stream mode, preventing duplicate NDJSON lines before end-of-run dedup.
- Added regression coverage in `tests/`:
  - `tests/startup_inputs.rs`:
    - `accessibility_filter_uses_configured_proxy` validates pre-filter uses configured proxy path.
  - `tests/http_client_retry_policy.rs`:
    - `retries_503_responses`,
    - `does_not_retry_501_responses`.
  - `tests/integration_runner.rs`:
    - `stream_mode_flushes_unique_findings_only` ensures stream output does not emit duplicate `check` entries for same URL.
- Validation:
  - `cargo fmt`
  - `cargo test --test startup_inputs --test http_client_retry_policy --test integration_runner` (outside sandbox): all passed (`26 passed; 0 failed`).
  - `cargo test` (outside sandbox, full suite): all passed.

---

# Task: Burst/JWT/OAuth/Auth Placeholder Correctness Sweep (Phase 42)

## Plan
- [x] Fix `BurstProbe` to issue burst requests concurrently (not sequential await loop) so rate-limit probes reflect true burst semantics.
- [x] Require unauthenticated baseline comparison for JWT alg-confusion confirmation to avoid false positives on publicly accessible endpoints.
- [x] Make OAuth authorize no-redirect probe honor configured auth material (default headers + cookies) and transport settings.
- [x] Expand auth flow env placeholder regex to support lowercase variable names in `{{...}}` substitutions.
- [x] Add regression tests in `tests/` for burst concurrency behavior, JWT baseline gating, OAuth auth-header propagation, and lowercase env substitution.
- [x] Run `cargo fmt`, strict clippy, and full tests outside sandbox; document outcomes.

## Review
- Burst probe correctness:
  - `src/scanner/common/probe.rs` now executes burst requests concurrently via `buffer_unordered(...)` instead of sequential per-request await.
  - Added dedicated burst transport helpers in `src/http_client.rs` (`get_burst`, `get_with_headers_burst`) so burst probes bypass host-delay/retry orchestration and preserve near-simultaneous request semantics.
- JWT alg-confusion baseline gating:
  - `src/scanner/jwt.rs::attempt_alg_confusion(...)` now captures an unauthenticated baseline using `get_without_auth`.
  - A `jwt/alg-confusion` finding is emitted only when forged-token status is successful and unauthenticated baseline is not successful (`>= 400`), preventing public-endpoint false positives.
  - Baseline fetch failures are captured as `jwt/alg_confusion_baseline` errors (check becomes inconclusive rather than silently passing/failing).
- OAuth authorize probe auth propagation:
  - `src/scanner/oauth_oidc.rs::authorize_probe_without_redirects(...)` now applies configured request auth material:
    - `default_headers`,
    - fallback `auth_bearer`/`auth_basic` auth header injection when absent,
    - merged cookie header from configured cookies.
  - Existing proxy/TLS timeout behavior remains preserved.
- Auth env placeholder expansion:
  - `src/auth.rs` placeholder regex now accepts lowercase names: `{{api_key}}` and mixed-case variables work.
- Added regression tests:
  - `tests/burst_probe.rs`: `burst_probe_executes_requests_concurrently`.
  - `tests/jwt_scanner.rs`: `alg_confusion_not_reported_when_unauthenticated_access_is_already_successful`.
  - `tests/oauth_oidc_scanner.rs`: `authorize_probe_uses_configured_auth_headers_and_cookies`.
  - `tests/auth_flow.rs`: `execute_flow_substitutes_lowercase_env_placeholders`.
- Validation:
  - `cargo fmt`
  - `cargo test --test burst_probe --test jwt_scanner --test oauth_oidc_scanner --test auth_flow` (outside sandbox): all passed.
  - `cargo clippy --all-targets --all-features -- -D warnings` (outside sandbox): passed.
  - `cargo test` (outside sandbox, full suite): all passed.

---

# Task: Design/Logic Follow-up Sweep (Phase 43)

## Plan
- [x] Improve report dedup granularity to avoid dropping distinct multi-evidence findings with identical `(url, check)`.
- [x] Route OAuth authorize no-redirect probes through `HttpClient` so request metrics, host delay, retries, and WAF evasion behavior are consistent.
- [x] Decouple OAuth state round-trip check from redirect-uri acceptance outcome.
- [x] Refine mass-assignment probe strategy: adaptive payload keying from observed schema hints and remove silent elevated-field cap.
- [x] Offload JWT weak-secret brute-force work from async hot path using blocking-task isolation.
- [x] Skip GraphQL base-URL introspection probe when seed path is clearly non-GraphQL.
- [x] Replace rate-limit bypass spoof IP generator with plausible public IPv4 generation (non-TEST-NET ranges).
- [x] Improve WebSocket origin validation check to avoid auth-context false negatives.
- [x] Add/update regression tests and run `cargo fmt`, strict clippy, and full tests outside sandbox.

## Review
- Reporting/dedup:
  - `src/reports.rs::dedup_findings(...)` now dedups by `(url, check, evidence)` and keeps highest severity per exact evidence key.
  - Stream-mode behavior remains `(url, check)` to preserve existing NDJSON contract/test expectations.
- OAuth/OIDC probe consistency:
  - `src/http_client.rs` added no-redirect transport path: `get_with_headers_no_redirect(...)` with retries, metrics, host delay, WAF jitter, cookies, and live credentials.
  - `src/scanner/oauth_oidc.rs` now uses the above path for authorize probes.
  - State finding is independent of redirect-uri acceptance: missing/altered `state` emits `oauth/state-not-returned` even when redirect URI is not attacker-controlled.
- Mass-assignment logic:
  - Completed adaptive payload generation in `src/scanner/mass_assignment.rs`:
    - baseline schema-sensitive key harvesting,
    - per-key probe values based on key semantics (boolean/role/permission-like),
    - canonical fields always included.
  - Removed broken recursive payload function and completed missing helper implementations (`normalize_key`, sensitive-key classification/candidate extraction).
  - No silent elevated-field cap remains.
- JWT hot-path CPU isolation:
  - `src/scanner/jwt.rs` weak-secret matching now runs under `tokio::task::spawn_blocking`.
- GraphQL probe optimization:
  - `src/scanner/graphql.rs` skips direct seed-path probe when path is obviously REST-like; continues probing known GraphQL paths.
- Rate-limit bypass realism:
  - `src/scanner/rate_limit.rs` now generates plausible public-ish spoof IPs instead of TEST-NET ranges.
- WebSocket origin check ordering:
  - `src/scanner/websocket.rs` evaluates cross-origin upgrade independently of same-origin probe success to reduce auth-context false negatives.
- Regression tests added/updated:
  - `tests/reports.rs`: multi-evidence dedup retention.
  - `tests/oauth_oidc_scanner.rs`: authorize probe request accounting + independent state-not-returned check.
  - `tests/graphql_scanner.rs`: REST-like seed skips base probe; GraphQL-like seed retains base probe.
  - `tests/mass_assignment_scanner.rs`: adaptive payload fields + >3 elevated-field confirmation coverage; payload assertion helper now validates required canonical fields while allowing adaptive extras.
- Validation:
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features -- -D warnings` (outside sandbox): passed.
  - `cargo test` (outside sandbox, full suite): passed.

---

# Task: JWT Alg-Confusion Baseline Guard (2026-03-19)

## Plan
- [x] Add baseline validation in `src/scanner/jwt.rs` so alg-confusion probing is skipped when authenticated baseline status is 4xx/5xx.
- [x] Add a regression test in `tests/jwt_scanner.rs` proving alg-confusion is not attempted when baseline auth fails.
- [x] Run JWT-targeted and full test suites outside sandbox, then document outcomes.

## Review
- Added an early return in `src/scanner/jwt.rs` (`attempt_alg_confusion`) when `baseline_status >= 400`, preventing alg-confusion probing when the authenticated baseline request is already unsuccessful.
- Added regression test `alg_confusion_skipped_when_authenticated_baseline_fails` in `tests/jwt_scanner.rs`:
  - baseline call returns `401` with RS256 token containing JWK,
  - asserts no `jwt/alg-confusion` finding,
  - asserts no follow-up confusion probe request is sent (call count remains `1`).
- Validation:
  - `cargo fmt`
  - `cargo test --test jwt_scanner` (outside sandbox): passed (`7/7`)
  - `cargo test` (outside sandbox, full suite): passed

---

# Task: Bug Report Validation and Fixes (2026-03-19)

## Plan
- [x] Fix `HttpClient` no-redirect path to reuse a cached no-redirect client instead of rebuilding per request.
- [x] Harden adaptive concurrency backoff so `AdaptiveLimiter::decrease()` still takes effect under saturated load.
- [x] Add retry handling to `get_without_auth()` for transient statuses to align with other request paths.
- [x] Include discovery per-site cap drops in `RunResult.skipped` accounting.
- [x] Add canonicalization fallback debug logging when URL normalization fails in dedup flow.
- [x] Add/adjust regression tests for the above behavior and run formatting plus full test validation outside sandbox.

## Review
- Reproduced and fixed core transport/orchestration issues:
  - `src/http_client.rs`
    - Added cached `no_redirect_inner` client built once in `HttpClient::new()` and reused in `send_once_no_redirect`.
    - Adaptive limiter hardening: when saturated and `try_acquire_owned()` fails, `decrease()` now schedules a single background permit hold to apply effective backoff once capacity frees.
    - `get_without_auth()` now uses retry/backoff flow (including adaptive signals, host delay, and WAF jitter) instead of single-shot execution.
  - `src/runner.rs`
    - `run_discovery_per_site()` now returns dropped-by-cap count.
    - `run()` now includes per-site cap drops in `RunResult.skipped`.
    - Added debug logging when URL canonicalization fails and raw URL fallback is used.
- Added regression coverage:
  - `tests/http_client_unauth.rs`: `unauthenticated_probe_retries_transient_statuses` validates transient-status retry behavior for unauth probes.
  - `tests/integration_runner.rs`: `discovery_per_site_cap_contributes_to_skipped_count` validates capped discovery URLs are counted in `skipped`.
- Validation:
  - `cargo fmt`
  - `cargo test --test http_client_unauth --test integration_runner` (outside sandbox): passed.
  - `cargo test` (outside sandbox, full suite): passed.
- Verification outcome for reported items:
  - Fixed: 1, 2, 3, 4, 7.
  - Not reproducible as stated: 5 (logging paths are mutually exclusive due early return).
  - Already fixed in current tree: 6 (`--urls` documented/implemented as file-path input).

---

# Task: Bug 5/6 Follow-up Correction (2026-03-19)

## Plan
- [x] Remove duplicate inaccessible-URL logging paths in `src/main.rs` by keeping one canonical log site.
- [x] Re-verify `Readme.md` examples for `--urls` semantics and correct any raw-URL usage.
- [x] Run formatting and targeted/full tests outside sandbox, then document outcomes.

## Review
- `src/main.rs` now logs filtered inaccessible URLs in a single canonical block immediately after URL accessibility filtering.
  - Removed the extra lifecycle-end logging block that re-iterated `inaccessible_urls`.
  - Removed the alternate per-URL message in the early-return branch so all runs use one consistent log format.
- `Readme.md` was re-verified for bug 6:
  - Quick start uses file-path input (`--urls ./targets/targets.txt`).
  - No raw-URL `--urls https://...` examples were found in `Readme.md`, `HOWTO.md`, or `docs/`.
- Validation:
  - `cargo fmt`
  - `cargo test` (outside sandbox, full suite): passed.

---

# Task: OAuth/Mass-Assignment/Auth Follow-up Fix Pass (2026-03-19)

## Plan
- [x] Verify bug report claims against current source and classify as reproducible vs already fixed.
- [x] Harden `BurstProbe::execute` to use owned captures (`HttpClient` clone + owned URL) so closure lifetimes are robust to future spawn refactors.
- [x] Tighten mass-assignment mutation target matching so probes only run on collection-like endpoints, not arbitrary nested resource paths.
- [x] Complete auth-flow transport wiring by passing `Config` through all `execute_flow`/refresh call sites and aligning tests with the current API.
- [x] Add/refresh regression tests for OAuth host-level metadata dedup and redirect comparison robustness.
- [x] Run `cargo fmt` and full `cargo test` outside sandbox, then document review outcomes.

## Review
- Verification outcome for this report:
  - Already fixed in current tree: Bug 1 (OAuth metadata per-host dedup), Bug 2 (case-folded redirect comparison), Bug 5 (auth flow transport settings in `auth.rs`).
  - Reproducible and fixed in this pass: Bug 3 (BurstProbe closure-capture fragility hardening), Bug 4 (mass-assignment overbroad mutation target matching).
  - Confirmed non-bug: Bug 6 (`print_summary_table` behavior remains correctly gated by `print_summary`; comment intent remains informational).
- Code changes:
  - `src/main.rs`: completed auth flow wiring by passing `config` into `auth::execute_flow(...)` and `auth::spawn_refresh_task(...)`.
  - `src/auth.rs`: added explicit `use crate::config::Config;` import for the existing config-aware auth flow API.
  - `src/scanner/common/probe.rs`: `BurstProbe::execute` now captures owned `HttpClient` clone and owned URL string in async closures.
  - `src/scanner/mass_assignment.rs`: mutation target detection now matches final path segment hints only (URL-parsed), avoiding nested resource over-probing.
- Regression tests:
  - `tests/oauth_oidc_scanner.rs`:
    - `oidc_metadata_is_analyzed_once_per_host`
    - `oauth_redirect_uri_probe_is_case_insensitive_for_location`
  - `tests/mass_assignment_scanner.rs`:
    - `nested_users_resource_paths_are_skipped`
  - `tests/auth_flow.rs` and `tests/auth_refresh.rs` aligned with current config-aware auth-flow API.
- Validation:
  - `cargo fmt`
  - `cargo test --test oauth_oidc_scanner --test mass_assignment_scanner --test auth_flow --test auth_refresh --test burst_probe` (outside sandbox): passed.
  - `cargo test` (outside sandbox, full suite): passed.

---

# Task: Scanner/Auth Bugfix Batch (2026-03-19)

## Plan
- [x] Add per-host dedup in `ApiSecurityScanner` so `check_security_txt` runs once per host per scan run.
- [x] Replace `eprintln!` warnings in `CveTemplateScanner::load_templates()` with `tracing::warn!`.
- [x] Apply `config.politeness.timeout_secs` to auth flow HTTP client timeout in `auth::execute_flow`.
- [x] Add/adjust tests in `tests/` for security.txt host dedup and auth timeout behavior.
- [x] Verify with formatting and targeted tests, then document outcomes in Review.

## Review
- Verification outcome for reported items:
  - Reproducible and fixed: Bug 1 (`ApiSecurityScanner` security.txt host dedup), Bug 2 (`CveTemplateScanner` warnings now use tracing), Bug 4 (`auth::execute_flow` timeout now config-driven).
  - Confirmed non-bug: Bug 3 (`mass_assignment::is_likely_mutation_target` behavior is correct under URL parsing and current segment matching semantics).
- Code changes:
  - `src/scanner/api_security.rs`:
    - Added `checked_hosts: Arc<DashSet<String>>` to `ApiSecurityScanner`.
    - Added host-level guard around `check_security_txt` so it executes once per host per run.
  - `src/scanner/cve_templates.rs`:
    - Replaced all `eprintln!` warning paths in `load_templates()` with `tracing::warn!` (including empty-template warning).
  - `src/auth.rs`:
    - Updated auth client timeout from hardcoded `30s` to `config.politeness.timeout_secs`.
- Regression tests:
  - Added `tests/api_security_scanner.rs`:
    - `security_txt_probe_runs_once_per_host`
  - Updated `tests/auth_flow.rs`:
    - `execute_flow_uses_configured_timeout`
- Validation:
  - `cargo fmt`
  - `cargo test --test api_security_scanner --test auth_flow` (outside sandbox): passed.
  - `cargo test --test cve_templates_scanner` (outside sandbox): passed.

---

# Task: README Accuracy and Completeness Pass (2026-03-19)

## Plan
- [x] Verify README claims against current CLI surface (`cargo run -- --help`) and scanner registry.
- [x] Fix scanner taxonomy/count mismatches and clarify IDOR/BOLA ownership.
- [x] Correct CLI/exit-code documentation drift and stale command paths.
- [x] Align script coverage notes with current `ScanScripts/` contents.
- [x] Re-validate referenced local command paths and summarize outcomes.

## Review
- Updated `Readme.md` to reflect the current implementation:
  - Scanner modules corrected to `11` and scanner table clarified (`API Security` now explicitly covers secret exposure + active IDOR/BOLA checks).
  - Added explicit note that there is no standalone `--no-idor` flag (`--no-api-security` disables those checks).
  - Added missing `inaccessiblescan.sh` profile and corrected script behavior note (`split-by-host.sh` is the exception for `--stdin`).
  - Corrected CLI reference drift (`--unauth-strip-headers` default is `none`).
  - Corrected exit-code semantics (`1` means findings at/above `--fail-on`, not any finding).
  - Replaced stale/non-existent example target paths with existing repo targets.
  - Updated FAQ command examples to use the actual built binary path.
- Verification commands:
  - `cargo run --quiet -- --help`
  - `cargo run --quiet --bin template-tool -- --help`
  - `test -f targets/cve-regression-real-public.txt && ls ScanScripts | rg "inaccessiblescan.sh|split-by-host.sh|quickscan.sh"`

---

# Task: CVE Catalog Expansion from User Reference Doc (2026-03-19)

## Plan
- [x] Extract candidate CVE IDs from `/home/teycir/Téléchargements/apihunter_cve_catalog.docx`.
- [x] Import additional upstream Nuclei CVE templates with `template-tool` into `assets/cve_templates/*.toml`.
- [x] Keep only scanner-compatible templates (GET-based, parser-safe) and avoid duplicates with existing local templates.
- [x] Update docs to reflect expanded CVE coverage and template count.
- [x] Run CVE-focused tests outside sandbox and record validation outcomes.

## Review
- Source extraction:
  - Parsed `/home/teycir/Téléchargements/apihunter_cve_catalog.docx` via `word/document.xml` text extraction.
  - Candidate IDs processed: `266` (catalog text mentions).
- Import pipeline:
  - Bulk fetched upstream templates from `projectdiscovery/nuclei-templates` (`http/cves/<year>/CVE-...yaml`).
  - Imported successfully: `161` additional templates into `assets/cve_templates/`.
  - Existing preserved templates: `7`.
  - Current local CVE template catalog size: `168`.
  - Fetch failures: `1` (`CVE-2022-22955`, no upstream file at canonical CVE path).
  - Import failures: `102` (primarily non-GET templates, rejected by `template-tool` policy).
- Documentation updates:
  - `Readme.md`: CVE scanner/module wording now reflects template-catalog coverage (`168` templates).
  - `docs/scanners.md`: quick-reference and CVE section updated to reflect current catalog size.
- Validation (outside sandbox):
  - `cargo test --test cve_templates_scanner --test cve_templates_runtime_ext --test cve_templates_upstream_parity --test cve_templates_real_data`
  - Result: passed (`19/19` tests across the four suites).

---

# Task: Vulhub Lab Setup Documentation (2026-03-19)

## Plan
- [x] Add a dedicated `docs/lab-setup.md` covering reproducible CVE template validation labs.
- [x] Include a concrete “top 10 next” Vulhub-ready scenarios for template/fixture work.
- [x] Migrate Nacos guidance from custom local references to explicit `vulhub/nacos/CVE-2021-29441` and `vulhub/nacos/CVE-2021-29442` compose flows.
- [x] Link lab setup docs from scanner docs/README and target-list comments.
- [x] Record upstream path-availability caveats for catalog candidate paths that are not currently present in upstream Vulhub.

## Review
- Added `docs/lab-setup.md` with:
  - Vulhub prerequisites and start/stop workflow.
  - 10 upstream-verified Vulhub-ready scenarios for near-term CVE template validation.
  - Explicit Nacos one-at-a-time migration guidance using:
    - `vulhub/nacos/CVE-2021-29441/docker-compose.yml`
    - `vulhub/nacos/CVE-2021-29442/docker-compose.yml`
    - shared target URL `http://127.0.0.1:8848/nacos`.
  - Upstream availability notes (as checked on `2026-03-19`) for paths returning `404`:
    - `minio/CVE-2021-41266`
    - `forgerock/CVE-2021-35464`
    - `sonarqube/CVE-2020-27986`
    - `gitlab/CVE-2021-22214`
- Updated references:
  - `Readme.md` now links to `docs/lab-setup.md`.
  - `docs/scanners.md` now references `docs/lab-setup.md` and includes Vulhub-native Nacos mapping.
  - `targets/cve-regression-vulhub-local.txt` comment now points to `docs/lab-setup.md`.
- Verification commands:
  - `rg -n "lab-setup|vulhub/nacos/CVE-2021-29441|vulhub/nacos/CVE-2021-29442" Readme.md docs/scanners.md docs/lab-setup.md targets/cve-regression-vulhub-local.txt`

---

# Task: CVE Runtime Hardening Toward Production Grade (2026-03-19)

## Plan
- [x] Add CVE template loader quality gates for unresolved request-surface placeholders and invalid request metadata.
- [x] Tighten context-path matching from substring matching to segment-aware matching.
- [x] Reduce over-broad template triggering by preferring specific context hints over generic hints.
- [x] Add regression tests in `tests/` for placeholder rejection and context segment matching behavior.
- [x] Validate with CVE-focused test suites (outside sandbox) and compare seeded real-target run metrics before/after.

## Review
- Runtime hardening in `src/scanner/cve_templates.rs`:
  - Added loader quality gates to reject unsafe templates at load-time:
    - unresolved request-surface placeholders in main/preflight request metadata
    - unsupported methods for main/preflight requests
    - non-root-relative request paths
  - Added context hint normalization + derived fallback hints.
  - Replaced context substring matching with segment-aware matching.
  - Added hint prioritization: specific context hints are preferred over generic hints.
  - Added loader summary warning with loaded/skipped counts.
- Regression tests (`tests/` only):
  - `tests/cve_templates_runtime_ext.rs`
    - `generic_api_hint_is_ignored_when_specific_hint_exists`
    - `request_surface_placeholders_are_rejected_at_load`
  - Existing CVE suites remain green.
- Validation (outside sandbox):
  - `cargo test --test cve_templates_scanner --test cve_templates_runtime_ext --test cve_templates_upstream_parity --test cve_templates_real_data`
  - Result: passed (`21/21` tests across these suites after additions).
  - Follow-up: `cargo test --test cve_templates_scanner --test cve_templates_runtime_ext` passed (`11/11`).
- Seeded real-target comparison (`/tmp/cve_real_public_seeded_targets.txt`):
  - Before hardening: `http_requests=470`, `errors=198`, `elapsed≈48.7s`, findings `0`.
  - After hardening: `http_requests=48`, `errors=12`, `elapsed≈5.3s`, findings `0`.
- Net effect: significant noise and probe fan-out reduction while preserving no-false-positive outcome.

---

# Task: CVE Template Data-Quality Guardrails (Follow-up) (2026-03-19)

## Plan
- [x] Re-verify reported CVE template quality issues against current loader/runtime behavior.
- [x] Harden loader gates to reject status-only and matcherless templates, while preserving valid high-signal templates.
- [x] Improve skipped-template operator visibility with actionable template IDs, including `--quiet` mode.
- [x] Resolve root-path context mismatch behavior for base-path CVE templates.
- [x] Add focused regression tests in `tests/cve_templates_runtime_ext.rs` for new gate behavior.
- [x] Run formatting and CVE-focused/full test suites outside sandbox and document outcomes.

## Review
- Re-verified current behavior against report:
  - unresolved request placeholders were skipped silently (summary-only warning),
  - status-only and matcherless templates were accepted and could overfire,
  - root-path templates with context hints could be path-gated inconsistently.
- Loader hardening (`src/scanner/cve_templates.rs`):
  - Rejected matcherless templates (`status_any_of=[]` and no body/header evidence).
  - Rejected status-only templates (`status_any_of` without body/header evidence).
  - Preserved valid templates that include body/header evidence matchers.
  - For root-path probes (`path="/"`), ignored `context_path_contains_any` so host-root checks are not seed-path gated.
  - Added actionable skip diagnostics listing template IDs/paths:
    - non-quiet mode: `info!` details for invalid/unsafe IDs,
    - `--quiet` mode: escalated detail logs to `error!` so they remain visible.
- Regression tests added in `tests/cve_templates_runtime_ext.rs`:
  - `status_only_templates_are_rejected_at_load`
  - `templates_without_any_response_matchers_are_rejected_at_load`
  - `root_path_templates_ignore_context_hints`
- Validation (outside sandbox):
  - `cargo fmt --all` passed.
  - `cargo test --test cve_templates_runtime_ext` passed (`7/7`).
  - `cargo test` passed (full suite green).

---

# Task: Documentation Consistency & Security Posture Polish (2026-03-19)

## Plan
- [x] Reconcile naming/docs surface and remove any stale legacy project name/placeholder install references.
- [x] Expand README scanner documentation with concrete finding format examples and module-level guidance pointers.
- [x] Add explicit testing-strategy documentation (unit vs integration vs fixture coverage).
- [x] Add explicit security posture notes for proxy+TLS behavior, `--danger-accept-invalid-certs`, and WAF-evasion legal/ethical usage.
- [x] Rename changelog to `CHANGELOG.md` and align formatting with Keep a Changelog.
- [x] Update internal docs links/references impacted by README/CHANGELOG adjustments.
- [x] Verify with link/reference checks and any needed targeted tests; record results.

## Review
- Reconciled naming/install surface:
  - Confirmed no legacy project name references and no placeholder install URL (`github.com/you/...`) remain.
  - Installation section uses `git clone https://github.com/Teycir/ApiHunter`.
- README enhancements (`Readme.md`):
  - Added GitHub metadata recommendations (description/website/topics) for discoverability.
  - Added module output + signal-quality guidance table with false-positive/false-negative expectations.
  - Added concrete NDJSON finding example.
  - Added explicit testing strategy section (unit/integration/fixture/mock-server tests).
  - Added release artifact section linking GitHub Releases (Linux/macOS/Windows prebuilt binaries).
  - Added security/legal guardrails for proxy+TLS behavior, `--danger-accept-invalid-certs`, and WAF-evasion authorization expectations.
- Scanner module docs (`docs/scanners.md`):
  - Added standardized finding structure section.
  - Added per-scanner signal quality guidance table (confidence + FP/FN drivers).
- Changelog + docs index:
  - Renamed root changelog to `CHANGELOG.md`.
  - Updated changelog content to Keep a Changelog-style sections and added release compare/tag links.
  - Updated `docs/INDEX.md` changelog link to `../CHANGELOG.md` and refreshed scanner/document stats.
- Runtime warning hardening:
  - `src/main.rs` now emits explicit SECURITY WARNING logs for `--danger-accept-invalid-certs`.
  - Added warning clarifying that `--proxy` does not re-enable TLS validation when danger mode is enabled.
- Verification:
  - `cargo fmt --all` passed.
  - `cargo test --test cli --test startup_inputs` passed (`43/43`).
  - `rg -n "github\\.com/you/" Readme.md docs HOWTO.md src tests` returned no hits.

---

# Task: Scanner Module Documentation Depth (2026-03-19)

## Plan
- [x] Add a dedicated per-module check catalog in `docs/scanners.md` with concrete check ID examples.
- [x] Add explicit false-positive expectation guidance (tendency bands + common causes) for each scanner module.
- [x] Document how operators can measure environment-specific FP rate from NDJSON output.
- [x] Add a README pointer to the expanded scanner module documentation section.
- [x] Verify docs consistency with scanner check IDs in source and record validation commands.

## Review
- Expanded scanner-module documentation in `docs/scanners.md`:
  - Added `False-Positive Expectation Model` section with explicit tendency-band semantics.
  - Added a full `Module Check Catalog` table mapping each scanner to:
    - exact checks performed,
    - concrete finding ID examples/patterns (source-aligned),
    - FP tendency,
    - common FP drivers.
  - Added `Measuring False-Positive Rate In Your Environment` with NDJSON triage workflow and formula.
- Updated `Readme.md` scanner section with direct pointers to:
  - `docs/scanners.md#module-check-catalog`
  - `docs/scanners.md#false-positive-expectation-model`
- Validation commands:
  - `rg -n "False-Positive Expectation Model|Module Check Catalog|Measuring False-Positive Rate" docs/scanners.md Readme.md`
  - check-ID spot verification against scanner source:
    - `cors/wildcard-no-credentials`
    - `csp/missing`
    - `graphql/introspection-enabled`
    - `api_security/idor-cross-user`
    - `jwt/alg-none`
    - `openapi/no-security-schemes`
    - `mass_assignment/persisted-state-change`
    - `oauth/redirect-uri-not-validated`
    - `rate_limit/not-detected`
    - `websocket/upgrade-endpoint`

---

# Task: Produce Release Artifact (2026-03-19)

## Plan
- [x] Build release binary for current host target.
- [x] Package binary + essential docs into a distributable archive under `dist/`.
- [x] Generate SHA256 checksum for integrity verification.
- [x] Smoke-test artifact binary (`--help`) and record outputs.

## Review
- Built release binary:
  - `cargo build --release --bin apihunter`
  - produced `target/release/apihunter` (`apihunter 0.1.0`)
- Produced Linux host artifact bundle:
  - `dist/apihunter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
  - checksum file: `dist/apihunter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256`
- Archive contents:
  - `apihunter`
  - `README.md`
  - `CHANGELOG.md`
  - `LICENSE`
- Integrity + smoke verification:
  - `sha256sum` generated: `0c53b2d3b567073d3b64afd32a4bfd5b88a4cc9af8114d09b9d0db22e878aa4d`
  - packaged binary smoke test passed: `dist/apihunter-v0.1.0-x86_64-unknown-linux-gnu/apihunter --help`

---

# Task: Add `make release` Target (2026-03-19)

## Plan
- [x] Create a root `Makefile` with a `release` target.
- [x] Ensure target builds `apihunter`, creates `dist/` archive, and writes `.sha256`.
- [x] Run `make release` and record produced artifact paths.

## Review
- Added root `Makefile` with `release` target that:
  - builds `apihunter` in release mode,
  - computes `VERSION` and host `TARGET`,
  - stages `apihunter`, `README.md`, `CHANGELOG.md`, and `LICENSE`,
  - creates `dist/apihunter-v<version>-<target>.tar.gz`,
  - writes `dist/apihunter-v<version>-<target>.tar.gz.sha256`.
- Environment compatibility hardening:
  - adjusted make shell flags to avoid `nounset` (`PS1`) startup noise in this shell environment.
- Validation:
  - `make release` passed.
  - Output artifact: `dist/apihunter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
  - Output checksum: `dist/apihunter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256`
