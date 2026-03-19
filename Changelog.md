# Changelog

All notable changes to this project will be documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Runtime User-Agent pool from `assets/user_agents.txt` with embedded fallback UAs
- Multi-stage `Dockerfile` with Rust builder and slim Debian runtime
- `.dockerignore` for lean Docker build context
- Docker usage documentation in `Readme.md` and `HOWTO.md`
- `--no-discovery` CLI flag to skip endpoint discovery and scan only seed URLs
- `--stdin` flag for reading newline-delimited URLs from stdin
- `--har` flag for importing endpoints from HAR files
- `--session-file` flag for loading Excalibur session cookies JSON format
- `--quiet` flag to suppress verbose output
- `--summary` flag to print summary even in quiet mode
- `--stream` flag for real-time NDJSON output
- `--baseline` flag for diff-only findings against baseline NDJSON
- `--no-filter` flag to skip URL accessibility pre-filtering
- `--filter-timeout` for pre-check timeout configuration
- `--cookies` flag for comma-separated cookie injection
- `--auth-bearer` and `--auth-basic` convenience flags for authentication
- `--adaptive-concurrency` flag for AIMD-based concurrency adjustment
- `--per-host-clients` flag for per-host HTTP client pools
- `--unauth-strip-headers` for configuring headers to strip in unauth probes
- Automatic report saving to `~/Documents/ApiHunterReports/<timestamp>/`
  - `findings.json` with full structured findings
  - `summary.md` with markdown-formatted report
  - `scan.log` with detailed scan execution log
- Progress tracker with real-time scan progress display
- URL accessibility pre-filtering before full scan
- SPA (Single Page Application) detection to reduce false positives
  - Canary path probing (`/__canary_*`, `/_canary_*`, `/xyzabc*`)
  - Response fingerprinting to skip catch-all routes
- Separate unauthenticated HTTP client for IDOR/BOLA checks
- WebSocket scanner module (`scanner::websocket`) for active-checks probing
  - Detects WebSocket upgrade acceptance on common WS paths
  - Flags potential missing origin validation
- Mass Assignment scanner module (`scanner::mass_assignment`) for active-checks
  - `mass_assignment/reflected-fields` when crafted sensitive fields are reflected
  - `mass_assignment/persisted-state-change` with baseline/confirm read verification
- OAuth2/OIDC scanner module (`scanner::oauth_oidc`) for active-checks
  - `oauth/redirect-uri-not-validated` for authorization endpoint probes
  - `oauth/state-not-returned` for state round-trip validation
  - OIDC metadata hardening checks (PKCE, implicit flow, password grant)
- Rate Limit scanner module (`scanner::rate_limit`) for active-checks
  - `rate_limit/not-detected` when burst probes don't trigger 429
  - `rate_limit/missing-retry-after` when 429 lacks retry guidance
  - `rate_limit/ip-header-bypass` for spoofed client IP header tests
- CVE Templates scanner module (`scanner::cve_templates`) for active-checks
  - TOML-based template catalog in `assets/cve_templates/*.toml`
  - Translated checks: CVE-2022-22947, CVE-2021-29442, CVE-2021-29441, CVE-2020-13945, CVE-2021-45232, CVE-2022-24288
  - Baseline-vs-bypass matcher support for differential CVE checks
  - Host+template deduplication to avoid repeated probes
- Template tooling: `template-tool import-nuclei` binary for Nuclei YAML → ApiHunter TOML conversion
- JWT scanner improvements:
  - JWT detection in both headers and cookies
  - Weak HS256 secret detection with curated wordlist
  - `alg=none` token detection
  - Long-lived token detection (missing/excessive `exp` claim)
- OpenAPI/Swagger scanner with spec caching
- SARIF 2.1.0 output format for GitHub Code Scanning integration
- NDJSON streaming output with `--stream` flag
- Baseline diff mode with `--baseline` flag
- Exit code bitmask (0x01 for findings, 0x02 for errors)
- CVE regression target lists: `targets/cve-regression-vulhub-local.txt`, `targets/cve-regression-real-public.txt`
- Pinned upstream Nuclei template snapshots in `tests/fixtures/upstream_nuclei/`
- Real CVE payload fixtures in `tests/fixtures/real_cve_payloads/` for deterministic testing
- Helper scan scripts in `ScanScripts/`:
  - `defaultscan.sh` - run with CLI defaults
  - `quickscan.sh` - fast, low-impact baseline
  - `deepscan.sh` - deeper scan profile with active checks
  - `baselinescan.sh` - generate baseline.ndjson for diffing
  - `diffscan.sh` - run against baseline and output only new findings
  - `inaccessiblescan.sh` - re-scan inaccessible URLs with slower settings
  - `authscan.sh` - scan using --auth-flow
  - `sarifscan.sh` - produce SARIF output
  - `scan-and-report.sh` - run scan and print latest auto-saved report
  - `split-by-host.sh` - split URL list per host with optional parallel scans
  - `_scan_common.sh` - shared utilities for scan scripts
- Test coverage:
  - `tests/websocket_scanner.rs` for WebSocket upgrade/origin detection
  - `tests/mass_assignment_scanner.rs` for reflected/persisted field injection
  - `tests/oauth_oidc_scanner.rs` for OAuth redirect/metadata checks
  - `tests/rate_limit_scanner.rs` for throttling/bypass detection
  - `tests/cve_templates_scanner.rs` for CVE template matching
  - `tests/cve_templates_real_data.rs` for real payload regression
  - `tests/cve_templates_upstream_parity.rs` for upstream linkage validation
  - `tests/template_tooling.rs` for Nuclei import conversion
  - `tests/waf_user_agents.rs` for UA pool integrity
  - `tests/session_file_formats.rs` for Excalibur session format
  - `tests/http_client_unauth.rs` for unauthenticated client behavior
- `RunResult::dummy` test helper under `#[cfg(test)]`
- Integration tests via `wiremock`: CORS, CSP, GraphQL, API-security, endpoint cap, deduplication, panicking-scanner recovery, aggregation
- CLI integration tests: exit-code bitmask, `--quiet`, `--summary`, `--output-path` vs stdout, `--min-severity` filtering
- NDJSON reporter: concurrent writes, idempotent `finalize`, atomic lines
- CORS: Dynamic origin generation based on target URL domain
- CORS: Regex bypass testing (suffix/prefix attacks) when origins are reflected
- `CONTRIBUTING.md` with setup, style, testing, docs, PR checklist, and issue-report guidance
- Roadmap & Next Steps section in `Readme.md`
- FAQ section in `Readme.md` with 40+ common questions
- Comparison table with Nuclei, ZAP, Burp Suite, and ffuf in `Readme.md`
- `docs/findings.md` with detailed finding descriptions and remediation guidance
- `docs/auth-flow.md` for authentication flow configuration
- Advanced HOWTO examples for CI/CD integration, jq parsing, baseline diffing

### Security
- Verified no exposed API keys or secrets in repository
- Confirmed CVE template credentials are intentional test fixtures only
- All sensitive patterns are known public defaults for vulnerability detection
- Enhanced secret detection with context-aware validation to reduce false positives
  - Frontend vs backend context detection
  - Error response array detection
  - Generic secret validation guards

### Changed
- **Code Quality & Reliability**:
  - Replaced panic-prone `expect()` calls with proper error handling in HTTP client and main initialization
  - Improved semaphore acquisition error handling to prevent scanner crashes
  - Enhanced cookie parsing clarity using `split_once()` instead of iterator unwraps
  - Added comprehensive panic safety review across all unwrap/expect usage
- Unified default UA sourcing: `cli::default_user_agents()` now uses `WafEvasion::user_agent_pool()`
- Removed inline mass-assignment probe from `api_security` scanner (now dedicated module)
- Removed inline rate-limit probe from `api_security` scanner (now dedicated module)
- CVE template scanner now loads only from `assets/cve_templates/*.toml` (removed fallback catalog)
- CVE-2022-22947 template hardened to require `predicate` + Spring Gateway route-shape tokens
- Runner now deduplicates and canonicalizes endpoints before dispatch
- Scanner errors captured as `CapturedError`; panics recovered via `JoinSet`
- CORS: Removed hardcoded `PROBE_ORIGINS` array in favor of dynamic generation
- CORS: Skip `Access-Control-Allow-Origin: *` with credentials (browsers block it)
- CORS: Downgrade `Access-Control-Allow-Origin: *` without credentials to Low severity
- CORS: Only flag High severity when regex bypass succeeds with credentials enabled
- Discovery bypass: runner skips robots/sitemap/swagger probes when `--no-discovery` is enabled
- Replaced tracing logs with eprintln for user-facing output
- Default `--min-severity` changed from High to Info
- Endpoint cap now applies per-site instead of globally
- CSP missing header severity downgraded from Medium to Low
- WAF evasion now enforces delay per-host instead of globally
- Improved code idioms and flexibility across multiple modules (clippy fixes)
- Simplified session file format to only support Excalibur cookies JSON
- HAR import now filters for likely API/business endpoints (excludes static/CDN)

### Fixed
- **Critical Error Handling**:
  - Fixed silent failures in CORS bypass probes that could hide security issues
  - Fixed IDOR range walk incorrectly counting network errors (status=0) as successes
  - Fixed JWT algorithm confusion errors being silently swallowed via `.ok()?`
  - Fixed rate limit checks failing silently when all requests error
  - Fixed SPA detection errors not being logged for debugging
- Docker build: added OpenSSL build dependencies in builder image
- CVE-2022-22947 overmatch on APISIX dashboard HTML content (now requires Spring-specific tokens)
- SPA detection logic for catch-all routing false positives
- CSP bypass regex patterns
- Host delay logic for concurrent requests (replaced DashMap with Mutex<HashMap>)
- Cross-compilation issues with swagger spec caching
- Secret detection false positives with additional validation
- Error array response detection to reduce false positives
- Severity serde expectation in tests

### Performance
- **Mass Assignment Scanner Optimizations**:
  - Skip baseline GET request for write-only endpoints (POST/PUT/PATCH)
  - Avoid double JSON parsing by reusing parsed baseline response
  - Use static strings instead of format!() allocations for common patterns
  - Early exit when all injected fields are found in response
  - Optimize string operations with capacity pre-allocation
  - Skip confirmation GET when baseline fails (no state to verify)
  - Use Arc cloning instead of full string clones for shared data
  - Batch field checks to reduce iteration overhead

### Documentation
- **Code Analysis & Technical Debt**:
  - Documented 12 critical test coverage gaps in mass assignment scanner tests
  - Identified 8 performance optimization opportunities with no recall impact
  - Catalogued 12 major refactoring opportunities for code reusability across scanners
  - Comprehensive error handling audit across all scanner modules
  - Complete panic safety analysis of all unwrap/expect calls
  - Identified additional improvement areas: logging, config validation, resource cleanup, false positive reduction, security hardening, UX, output formats, and testing gaps

---

## [0.1.0] - 2026-03-14

### Added
- Initial async scanner framework
- `HttpClient` with politeness delay, retries, UA rotation, proxy, TLS config
- Scanner modules: `cors`, `csp`, `graphql`, `api_security`
- Discovery: URL normalization, same-host filtering
- `Runner`: semaphore-bounded concurrency, `JoinSet`, sorted/deduped results
- NDJSON reporter with `Arc<Mutex<BufWriter<File>>>`
- CLI via `clap` with `--min-severity`, `--concurrency`, `--output-path`
- WAF evasion headers and random UA pool

