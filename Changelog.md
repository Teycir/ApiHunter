# Changelog

All notable changes to this project will be documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Fixed
- Mermaid flowchart syntax in README.md (replaced HTML `<br/>` tags with proper multi-line text formatting)
- CVE template runtime hardening for production-readiness:
  - loader now skips unsafe templates with unresolved request-surface placeholders
  - loader now enforces request metadata sanity (supported methods, root-relative paths)
  - context matching changed from raw substring checks to segment-aware matching
  - matching now prefers specific context hints over generic hints to reduce over-broad probe fan-out
  - added runtime regression tests for placeholder rejection and context-hint specificity

---

## [0.2.0] - 2026-03-19

### Added
- CVE template catalog expanded to 168 templates in `assets/cve_templates/*.toml`
- Additional CVE templates covering various vulnerabilities from 2014-2024

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
