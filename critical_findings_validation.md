# ApiHunter Recommendations (Validated Against Repo State)

Date: 2026-03-14

This document revises the earlier suggestion list to reflect the actual repo
state in the current workspace. Items below are organized by impact and clearly
separate what already exists from what would be additive.

## Already Implemented (Do Not Re-Suggest)

- Discovery is not just URL normalization. It already includes:
  - `robots.txt` and sitemap parsing.
  - JS endpoint extraction from `<script src>` and inline scripts.
  - Common path probing (e.g., `/api`, `/v1`, `/graphql`).
  - Swagger/OpenAPI spec discovery and path enumeration.
- GraphQL scanner already checks introspection, batching, and alias/depth
  amplification signals.
- Politeness: per-host delay, retries, and concurrency caps are implemented.

## High-Impact Additions

1. SARIF output format
- Add `--format sarif` to generate SARIF 2.1.0.
- This unlocks GitHub Code Scanning and enterprise SAST ingestion.

2. OpenAPI security analysis (new scanner or enhancement)
- Swagger discovery already enumerates paths; add analysis for:
  - missing `securitySchemes` or unsecured operations.
  - file-upload endpoints.
  - deprecated endpoints still served.
- This is analysis of specs, not just discovery.

3. Baseline diff mode
- `--baseline <ndjson>` to suppress findings that already existed.
- Useful for CI to only report new regressions.

## Security-Depth Improvements (Opt-In)

These should be gated behind an explicit active-testing flag to avoid
unexpected side effects.

1. CORS
- Preflight method exposure check using `OPTIONS` and unsafe verbs.
- Missing `Vary: Origin` when reflecting Origin (cache poisoning risk).

2. JWT
- Expand weak HS256 secret list using `include_str!()`-based wordlist.
- Optional RS256->HS256 confusion test (active).
- Optional `kid` header injection probes (active).

3. API security
- BOLA/IDOR path probing (ID swap) for numeric IDs.
- Verb tampering: attempt `TRACE`, `PATCH`, `HEAD`.
- Mass-assignment reflection checks for JSON payloads.
- Rate-limit detection (burst probe for 429).

## Performance and UX

- Streaming NDJSON mode: emit findings as they arrive (useful for long scans).
- Adaptive concurrency (AIMD) to back off on 429/timeouts.
- Optional per-host client pools if slow hosts starve global concurrency.

## Auth and Session Handling

- `--auth-bearer`, `--auth-basic`, `--session-file` (cookie jar support).
- Optional `--auth-refresh-url` to reissue tokens mid-scan.

## CI and Release Infrastructure

- Add CI workflow: `cargo test`, `cargo clippy -D warnings`, `cargo audit`.
- Add release workflow to build binaries on tag `v*`.
- Consider `cargo-dist` for cross-platform release artifacts.

## Notes

- These recommendations assume the default mode remains passive.
- Active checks should require explicit user opt-in to avoid unintended impact.
