# Changelog

All notable changes to this project will be documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- New passive scanner: `api_versioning`:
  - version header disclosure checks (`api_versioning/version-header-disclosed`)
  - deprecation/sunset header signals (`api_versioning/deprecation-signaled`)
  - sibling version reachability checks (`api_versioning/multiple-active-versions`, `api_versioning/legacy-version-still-accessible`)
  - initial response-diff checks for benign query/version variants (`response_diff/*`)
- API Security active blind SSRF callback probes (when `--active-checks` + `APIHUNTER_OAST_BASE`):
  - `api_security/blind-ssrf-probe-dispatched`
  - `api_security/blind-ssrf-token-reflected`
  - `api_security/blind-ssrf-probe-dry-run`
- API Security gateway checks:
  - passive gateway fingerprint signal `api_security/gateway-detected`
  - active gateway bypass probes `api_security/gateway-bypass-suspected` and dry-run mode `api_security/gateway-bypass-dry-run`
- API versioning deep response-diff mode (`--response-diff-deep`):
  - `response_diff/deep-variant-server-error`
  - `response_diff/deep-variant-drift`
- New scanner module: `grpc_protobuf`:
  - `grpc_protobuf/grpc-transport-detected`
  - `grpc_protobuf/protobuf-signal-detected`
  - `grpc_protobuf/grpc-reflection-or-health-surface`
- GraphQL active mutation fuzzing checks:
  - `graphql/mutation-fuzzing-accepted`
  - `graphql/mutation-fuzzing-server-errors`
  - `graphql/mutation-fuzzing-dry-run`
- New input source: `--collection <file>` for Postman/Insomnia export JSON URL import.
- Added targeted regression coverage:
  - `tests/api_versioning_scanner.rs`
  - blind SSRF callback probe tests in `tests/api_security_scanner.rs`
  - gateway detection/bypass tests in `tests/api_security_scanner.rs`
  - deep response-diff mode tests in `tests/api_versioning_scanner.rs`
  - `tests/grpc_protobuf_scanner.rs`
  - GraphQL mutation fuzzing tests in `tests/graphql_scanner.rs`
  - Collection import tests in `tests/cli.rs`

### Changed
- CLI input group now supports exactly one of `--urls`, `--stdin`, `--har`, or `--collection`.
- Added scanner toggle flag `--no-api-versioning`.
- Added scanner toggle flag `--no-grpc-protobuf` and runtime flag `--response-diff-deep`.
- Desktop full-scan profile now includes `response_diff_deep` toggle and forwards it to scanner config.
- Documentation updates for scanner inventory, CLI flags, and API versioning coverage.

### Fixed
- Restored full test-suite compatibility after introducing `response_diff_deep` by adding the missing field to `tests/mass_assignment_scanner.rs` test config initialization.
- Stabilized startup scanner-disabled integration assertions in `tests/startup_inputs.rs` by explicitly disabling newly added scanners (`--no-api-versioning`, `--no-grpc-protobuf`) in those command invocations.

## [0.3.0] - 2026-04-03

### Added
- README now includes:
  - GitHub metadata recommendations (description, website, topics)
  - module output/signal notes with false-positive and false-negative guidance
  - sample NDJSON finding payload
  - testing strategy summary and commands
  - release artifact section for prebuilt binaries
  - security/legal guardrails for proxy, TLS, and WAF-evasion usage
- `docs/scanners.md` now includes standardized finding structure and per-module signal quality guidance.
- Desktop app (`apps/desktop`) now supports multi-target scan workflows (up to 100 targets) with:
  - manual target entry and CSV import/merge
  - per-target live progress cards for parallel scans
  - export size visibility and one-click `Save All Reports`
- Desktop launcher tooling on Linux:
  - `npm run desktop:install-icon` for app-menu/Desktop shortcut install
  - launcher scripts under `apps/desktop/scripts/` for stable binary startup
- Desktop scan form now includes advanced runtime controls:
  - scope/filtering (`max endpoints per site`, `no filter`, `filter timeout`)
  - transport/auth (`proxy`, headers, cookies, bearer/basic auth, invalid TLS toggle, unauth strip headers)
  - performance (`per-host clients`, `adaptive concurrency`, WAF evasion + custom user-agent pool)
- Desktop UI now includes inline help labels clarifying `active checks`, `dry run`, `no discovery`, and URL separator/CSV input behavior.

### Changed
- Renamed changelog file from `Changelog.md` to `CHANGELOG.md`.
- Updated `docs/INDEX.md` changelog reference and scanner/document stats.
- Desktop Tauri integration now maps advanced scan-profile settings directly into scanner `Config` instead of using desktop-side hardcoded defaults for proxy/auth/transport/performance fields.
- Desktop full-scan flow now optionally pre-filters inaccessible targets before scan start when filtering is enabled.
- Desktop dev startup now serves built frontend assets directly via Tauri config, removing reliance on a separate `localhost:1420` Vite dev server.

### Fixed
- Startup security warning for `--danger-accept-invalid-certs` is now louder and explicitly documents proxy/TLS interaction.
- CVE template runtime hardening for production-readiness:
  - loader now skips unsafe templates with unresolved request-surface placeholders
  - loader now enforces request metadata sanity (supported methods, root-relative paths)
  - context matching changed from raw substring checks to segment-aware matching
  - matching now prefers specific context hints over generic hints to reduce over-broad probe fan-out
  - added runtime regression tests for placeholder rejection and context-hint specificity
- Fixed duplicate desktop progress event streams caused by async event-listener setup race under React StrictMode cleanup.
- Fixed desktop export actions on Linux Tauri/WebKit by using backend file-save command and surfacing saved file paths in UI.
- Fixed Tauri launch reliability in Snap-based environments via sanitized runtime environment wrapper script.

## [0.2.0] - 2026-03-19

### Added
- CVE template catalog expanded to 168 templates in `assets/cve_templates/*.toml`
- Additional CVE templates covering various vulnerabilities from 2014-2024

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

[Unreleased]: https://github.com/Teycir/ApiHunter/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.3.0
[0.2.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.2.0
[0.1.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.1.0
