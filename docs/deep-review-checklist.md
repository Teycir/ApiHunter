# Deep Review Checklist

Status: unverified (items captured from the review text; validate against current code before changes).

## Fix First (Correctness/Reliability)

- [ ] Implement retry loop in `src/http_client.rs` using `PolitenessConfig::retries`.
- [ ] Rework GraphQL status guard in `src/scanner/graphql.rs` to avoid skipping 403 endpoints and keep 400 responses for schema hints.
- [ ] Add SPA catch-all guard to HTTP method prober in `src/scanner/api_security.rs`.

## Fix Second (Output Quality)

- [ ] Fix `CapturedError::new` type reporting in `src/error.rs` (avoid constant `dyn std::error::Error`).
- [ ] Remove duplicated summary counting between `src/main.rs` and `src/reports.rs` (expose or reuse a shared summary builder).
- [ ] Prevent duplicate null-origin CORS findings in `src/scanner/cors.rs`.

## Fix Third (Minor / Cleanup)

- [ ] Remove dead WAF `default_headers()` call in `src/http_client.rs` if per-request headers always override.
- [ ] Anchor `BYPASS_HOSTS` regexes in `src/scanner/csp.rs` to avoid substring matches.
- [ ] Prune non-evasive UA strings (e.g., `curl`, `python-httpx`) from the pool in `src/waf.rs`.
- [ ] Harden channel drain ordering in `src/runner.rs` to ensure no message loss.

## Notes

- [ ] Validate that each checklist item still applies to current code before editing.
