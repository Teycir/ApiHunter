# Changelog

All notable changes to this project will be documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- README now includes:
  - GitHub metadata recommendations (description, website, topics)
  - module output/signal notes with false-positive and false-negative guidance
  - sample NDJSON finding payload
  - testing strategy summary and commands
  - release artifact section for prebuilt binaries
  - security/legal guardrails for proxy, TLS, and WAF-evasion usage
- `docs/scanners.md` now includes standardized finding structure and per-module signal quality guidance.

### Changed
- Renamed changelog file from `Changelog.md` to `CHANGELOG.md`.
- Updated `docs/INDEX.md` changelog reference and scanner/document stats.

### Fixed
- Startup security warning for `--danger-accept-invalid-certs` is now louder and explicitly documents proxy/TLS interaction.
- CVE template runtime hardening for production-readiness:
  - loader now skips unsafe templates with unresolved request-surface placeholders
  - loader now enforces request metadata sanity (supported methods, root-relative paths)
  - context matching changed from raw substring checks to segment-aware matching
  - matching now prefers specific context hints over generic hints to reduce over-broad probe fan-out
  - added runtime regression tests for placeholder rejection and context-hint specificity

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

[Unreleased]: https://github.com/Teycir/ApiHunter/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.2.0
[0.1.0]: https://github.com/Teycir/ApiHunter/releases/tag/v0.1.0
