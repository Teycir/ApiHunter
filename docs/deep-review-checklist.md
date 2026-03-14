# Deep Review Checklist

Status: implemented (not yet re-tested).

## Fix First (Correctness/Reliability)

- [x] Implement retry loop in `src/http_client.rs` using `PolitenessConfig::retries`.
- [x] Rework GraphQL status guard in `src/scanner/graphql.rs` to avoid skipping 403 endpoints and keep 400 responses for schema hints.
- [x] Add SPA catch-all guard to HTTP method prober in `src/scanner/api_security.rs`.

## Fix Second (Output Quality)

- [x] Fix `CapturedError::new` type reporting in `src/error.rs` (avoid constant `dyn std::error::Error`).
- [x] Remove duplicated summary counting between `src/main.rs` and `src/reports.rs` (expose or reuse a shared summary builder).
- [x] Prevent duplicate null-origin CORS findings in `src/scanner/cors.rs`.

## Fix Third (Minor / Cleanup)

- [x] Remove dead WAF `default_headers()` call in `src/http_client.rs` if per-request headers always override.
- [x] Anchor `BYPASS_HOSTS` regexes in `src/scanner/csp.rs` to avoid substring matches.
- [x] Prune non-evasive UA strings (e.g., `curl`, `python-httpx`) from the pool in `src/waf.rs`.
- [x] Harden channel drain ordering in `src/runner.rs` to ensure no message loss.

## Notes

- [x] Validate that each checklist item still applies to current code before editing.
