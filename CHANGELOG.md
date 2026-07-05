# Changelog

All notable changes to this project will be documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).


## [Unreleased]

## [1.0.0] - 2026-07-05

### Added
- **Concurrent Pre-Flight Reachability Filtering**: Optimized target reachability checks in the desktop app to run in parallel using a bounded `tokio::task::JoinSet` (up to 100 concurrent requests at a time).
- **Real-Time Filtering Progress**: Added `filtering_progress` scan event reporting from the Tauri backend, displaying live checked/total count and an amber pulse progress animation in the UI instead of the static "Waiting for scan start" state.
- **Tauri Commands**: Added missing `read_text_file` command for loading NDJSON findings in Enrich Mode, and `cancel_scan` for stopping active scans.
- **Consolidated Target Rankings Dashboard**: Combined separate Target Ranking, Most Highs, and Most Criticals cards into a single high-fidelity, tabbed widget (supporting Discoveries, Criticals, and Highs tabs).
- **Improved Progress Bar**: Redesigned the progress bar to show distinct visual states and status messaging for checking reachability (amber pulse animation) and scanning (blue accent).

### Changed
- **Deprecate and Remove Mass Sweep Preset**: Completely removed the unstable "Mass Sweep" preset from the CLI, Tauri configurations, desktop app preset selection, and all user documentation guides.
- **Calibrated Scan Capacity Limits**: Configured target limit to support up to `3,000` max targets (calibrated from previous limits) and reduced maximum imported CSV file size to `300 KiB` to prevent browser hangs and crashes on large files.
- **Performance Optimization for Large Runs**: Replaced detailed UI cards with lists of text logs in the live progress component to support large-scale runs without rendering lag.
- **Bumped Version to 1.0.0**: Upgraded all manifests, configuration files, and package specifications to v1.0.0.

### Fixed
- **Instant Resource Cleanup & Cancellation**: Implemented a global thread-safe scan cancellation flag and registered window event hook to perform instant process termination (`std::process::exit(0)`) on window close, preventing memory leaks, socket hangs, and crash-on-reopen behavior.
- **UI Performance Lag**: Optimized frontend URL parser functions to check protocol prefixes before calling the expensive `new URL()` constructor, eliminating input character lag when copy-pasting targets.

## [0.7.0] - 2026-04-29

### Added
- **Scan Persistence (Last-Scan Store)**: Desktop app now persists scan results across sessions
  - Automatic save to Tauri app-data directory (`~/.local/share/com.apihunter.desktop/last-scan.json` on Linux)
  - Persists summary, NDJSON, SARIF, Insomnia collection, runner data, target summaries, and discovery ranking
  - Results panel auto-hydrates on launch with restored session badge showing timestamp
  - New Tauri commands: `persist_last_scan` and `load_persisted_scan`
  - Badge clears immediately when new scan starts
- **Scan Results Analytics Dashboard**: Comprehensive analytics layer for deeper insights
  - Severity heatmaps with visual breakdown by check type
  - "Worst target" identification based on weighted severity scoring
  - Scan efficiency and error rate calculations
  - Scanner coverage analysis and top vulnerable path detection
  - Severity breakdown tables with chip-based visualization
  - Meta-data cards for high-level security metrics
- **Glass Morphism Design System**: Premium "Glass UI" design language
  - Dark-themed, high-fidelity aesthetic with semi-transparent backgrounds
  - Custom typography: Syne and JetBrains Mono via Google Fonts
  - Deep blue and electric cyan color palette
  - Sophisticated border/glow effects and radial gradient backgrounds
  - Updated design tokens for shadows, radii, and severity-based color scales

### Changed
- Removed "Balanced" preset label from desktop UI

### Fixed
- Removed stale component stubs (`LiveProgress.tsx`, `LoadedScan.tsx`) that caused TypeScript build failures with broken imports

## [0.6.0] - 2026-04-28

### Added
- **Scan persistence (last-scan store)**: Closing and reopening the desktop app no longer wipes results. After every successful scan the summary and all export artefacts (NDJSON, SARIF, Insomnia collection, runner data, target summaries, discovery ranking) are written to the Tauri app-data directory (`~/.local/share/com.apihunter.desktop/last-scan.json` on Linux). On the next launch the Results panel is automatically hydrated with the previous scan — the panel title shows `Results · ⟳ restored from last session (<timestamp>)` so it is always clear the data is historical. Starting a new scan clears the badge instantly. Two new Tauri backend commands: `persist_last_scan` and `load_persisted_scan`.

### Fixed
- Removed two stale component stub files (`src/components/LiveProgress.tsx`, `src/components/LoadedScan.tsx`) that were committed with broken imports (`../utils`, `../hooks/useScanResults`) and caused TypeScript build failures. Their content is still rendered inline in `App.tsx` and will be extracted properly as part of the App.tsx split (Task 9).


## [0.6.0] - 2026-04-28

### Added
- **Enrich → Deep-Scan Promote Flow**:
  - CLI: `apihunter enrich` gains `--promote-to <FILE>` — writes one canonical origin URL per qualifying unique host (score ≥ `--promote-min-score`) ready for `apihunter --urls <FILE> --preset deep --active-checks`.
  - CLI: `apihunter enrich` gains `--promote-min-score <SCORE>` (default 0) to filter which hosts are promoted.
  - Desktop backend: `EnrichHostResult` now carries `representativeUrl` (scheme+host+port) built from the first finding URL per host — enables clean URL-based promotion without scheme guessing.
  - Desktop: new **Enrich Mode** collapsible panel (between Triage and Full Scan) with findings NDJSON input, **Load from Last Scan** button, per-host result cards (score, severity, ports, CVEs, signals), per-host **→ Deep Scan** promote button, bulk **Promote hosts scoring ≥ N → Deep Scan** control, and **Save Enriched NDJSON** button. Promotion merges hosts into the Full Scan textarea and applies the Deep Active preset.
- **Enrich test suite** (`tests/enrich.rs`): 25 deterministic unit and integration tests covering NDJSON parsing, empty/single/multi-finding inputs, host deduplication (same host, different ports, default-port normalisation), field pass-through, `EnrichConfig` defaults, JSON serialisation round-trip, and `EnrichResult` shape invariants.
- **`docs/enrich.md`** updated with dedicated Enrich CLI Usage section, complete `apihunter enrich` flag table, and full three-step mass-sweep → enrich → deep-scan pipeline example.

## [0.5.0] - 2026-04-27

### Added
- **Discovery Configuration**: Fine-grained control over endpoint discovery phase
  - New `DiscoveryConfig` to manage `max_sitemaps`, `max_scripts`, and per-step `timeout_secs`
  - CLI arguments for discovery controls
  - Desktop UI integration with preset-based scan configurations
  - Prevents scanner stalls on large or complex targets
- **Enrich Workflow**: Multi-stage pipeline for threat intelligence enrichment
  - `apihunter enrich` CLI subcommand for processing NDJSON findings
  - Desktop Enrich Mode panel with per-host result cards
  - Scan presets: `quick`, `mass`, `balanced`, `deep`
  - Comprehensive test suite in `tests/enrich.rs`
  - Documentation for mass-sweep → enrich → deep-scan pipeline

### Changed
- Refactored `triage` module to `threat_intel` for improved domain clarity
- Desktop UI now uses design tokens for improved maintainability
- Removed deprecated triage subcommand and UI components

### Fixed
- CORS bypass URL formatting (missing period in prefix construction)
- Triage engine now reports true total hit count before top-N truncation

## [0.4.0] - 2026-04-26

### Added
- **Triage Mode**: Large-scale target scanning with risk scoring
  - Lightweight probes using InternetDB and ipinfo.io
  - CLI subcommand with `--min-score`, `--top`, `--concurrency`, `--timeout-secs` flags
  - `--promote-to` flag writes top-N targets to file for piping into full scan
  - Pretty table, JSON, and NDJSON output formats
  - Desktop UI integration with per-row and bulk promotion to Full Scan
  - Severity badges, VULN chip, CVE highlighting
- **CLI Enhancements**:
  - `--fail-on` severity threshold for CI/CD integration
  - Automated build failures based on vulnerability levels
- **Desktop Features**:
  - Triage functionality via Tauri commands
  - Per-target promotion buttons
  - Bulk "Promote Top N" action
  - Save Triage JSON export
  - Removed target count limitations to support large lists

### Changed
- Improved scanner accuracy and reduced false positives
- Enhanced security probe coverage in api_security scanner
- Secrets detection now includes response headers

### Fixed
- Desktop Tauri invoke parameter mapping for triage requests
- Test suite async function annotations

## [0.3.2] - 2026-04-23

### Added
- **Scan Loading Feature**: Load and analyze past scan results from export directories
  - New `--load-scan <DIR>` CLI flag to load previous scan exports
  - Core `scan_loader` module with auto-detection of `.ndjson` and `findings.json` formats
  - Desktop "Load Past Scan" panel with native directory picker (Browse button)
  - Support for severity filtering and baseline diffing on loaded scans
  - All output formats (pretty, ndjson, sarif) work with loaded scans
- Desktop scan loading UI enhancements:
  - Native directory picker using `@tauri-apps/plugin-dialog`
  - Detailed findings display focused on Critical & High severity
  - Color-coded severity indicators (red for critical, orange for high)
  - Collapsible evidence sections with formatted output
  - Findings grouped by scanner module
  - Top 10 checks ranked by frequency
  - Manual path input as fallback option

### Changed
- `ReportMeta.scanner_ver` changed from `&'static str` to `String` for deserialization compatibility
- `CapturedErrorRecord`, `ReportMeta`, and `ReportSummary` now implement `Deserialize` and `Clone`
- Desktop capabilities updated to include `dialog:allow-open` permission
- Scan loader architecture: core logic in `scan_loader.rs`, minimal wrappers in CLI and desktop

### Fixed
- Desktop browse button now uses proper Tauri dialog plugin instead of broken HTML5 directory picker
- Added debug logging to browse function for troubleshooting

## [0.3.1] - 2026-04-17

### Added
- Additive transport/stealth modularization:
  - new reusable proxy module with optional `--proxy-file` pool support (single `--proxy` still takes precedence)
  - new reusable TLS profile module with optional `--tls-profile` (`system`, `modern`, `tls13-only`)
  - new reusable retry policy module for transient transport status/backoff logic
  - optional host-sticky browser persona mode via `--waf-sticky-persona`
  - new transport adapter abstraction (`transport_adapter`) with optional `--transport-backend` (default `reqwest`)
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
- API Security IDOR/BOLA comparison hardening:
  - tiered IDOR/authz comparison now uses body fingerprints plus selected stable response headers (`etag`, `content-type`, `last-modified`, and related identity/resource headers) to reduce drift-induced misses.
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
- Transport builder wiring now uses shared adapter/options paths for both runtime scanner clients and startup URL accessibility filter client, preserving additive defaults and loose coupling.
- Desktop full-scan profile now includes `response_diff_deep` toggle and forwards it to scanner config.
- Documentation updates for scanner inventory, CLI flags, and API versioning coverage.
- Authorization-matrix similarity checks now use the same body+header comparison basis as IDOR checks.
- Desktop scan UX now provides guided presets (`Quick Passive`, `Balanced`, `Deep Active`) and clearer sectioned setup flow with richer explanatory labels.
- Desktop scanner toggles now expose full parity for `API Versioning` and `gRPC/Protobuf` modules.
- Desktop advanced controls now include `OAST callback base` for blind SSRF correlation, wired to runtime `APIHUNTER_OAST_BASE` as a scoped per-scan override.
- Desktop export flow now writes reports into timestamped export folders and generates per-target JSON reports with bundled discovery summary + discovery-count ranking files.
- Desktop exports now include an Insomnia-importable collection file (Postman v2.1 JSON) grouped per target with discovery context.
- Desktop UI panels are now collapsible for faster navigation: top-level sections plus large Full Scan subsections (`Safety`, `Runtime Limits`, and `Scanner toggles`).
- Desktop full-scan subsections (`Safety and Scan Behavior`, `Runtime Limits`, `Scanner toggles`) now default to collapsed for faster first-load navigation.
- Desktop full-scan section labels were simplified by removing numbered prefixes from subsection headers.
- Desktop advanced settings panel now uses the same right-aligned collapse caret treatment and full-width layout behavior as adjacent scan sections.
- Desktop exports now include an Insomnia Runner-data JSON file (array of key-value objects) for Runner preview/upload flows when collection import UI is unavailable.
- Desktop `Overview` now shows a persistent `release: vX.Y.Z` chip, and desktop runtime auto-fetches backend health so release version is visible without a manual health-check click.

### Fixed
- Restored full test-suite compatibility after introducing `response_diff_deep` by adding the missing field to `tests/mass_assignment_scanner.rs` test config initialization.
- Stabilized startup scanner-disabled integration assertions in `tests/startup_inputs.rs` by explicitly disabling newly added scanners (`--no-api-versioning`, `--no-grpc-protobuf`) in those command invocations.
- Added IDOR regression coverage for header-based equivalence when response bodies differ (`tests/api_security_scanner.rs`).
- Fixed desktop results card overflow by forcing long finding keys and target URLs to wrap within panel boundaries.

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

[Unreleased]: https://github.com/Teycir/ApiHunter/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Teycir/ApiHunter/releases/tag/v1.0.0
[0.7.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.7.0
[0.6.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.6.0
[0.5.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.5.0
[0.4.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.4.0
[0.3.2]: https://github.com/Teycir/ApiHunter/releases/tag/v0.3.2
[0.3.1]: https://github.com/Teycir/ApiHunter/releases/tag/v0.3.1
[0.3.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.3.0
[0.2.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.2.0
[0.1.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.1.0
