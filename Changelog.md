# Changelog

All notable changes to this project will be documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- `RunResult::dummy` test helper under `#[cfg(test)]`
- Integration tests via `wiremock`: CORS, CSP, GraphQL, API-security,
  endpoint cap, deduplication, panicking-scanner recovery, aggregation
- CLI integration tests: exit-code bitmask, `--quiet`, `--summary`,
  `--output-path` vs stdout, `--min-severity` filtering
- NDJSON reporter: concurrent writes, idempotent `finalize`, atomic lines
- CORS: Dynamic origin generation based on target URL domain
- CORS: Regex bypass testing (suffix/prefix attacks) when origins are reflected

### Changed
- Runner now deduplicates and canonicalizes endpoints before dispatch
- Scanner errors captured as `CapturedError`; panics recovered via `JoinSet`
- CORS: Removed hardcoded `PROBE_ORIGINS` array in favor of dynamic generation
- CORS: Skip `Access-Control-Allow-Origin: *` with credentials (browsers block it)
- CORS: Downgrade `Access-Control-Allow-Origin: *` without credentials to Low severity
- CORS: Only flag High severity when regex bypass succeeds with credentials enabled

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

