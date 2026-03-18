# Task: HAR API Filtering + Discovery Dedup

## Plan
- [x] Add HAR API-focused filtering option to exclude static/CDN URLs.
- [x] Implement host-level dedup in discovery so each site is discovered once.
- [x] Add tests for HAR filtering behavior and discovery grouping logic.
- [x] Update docs for new HAR filtering controls and usage.
- [x] Run `cargo test` and verify behavior with your HAR sample.

## Review
- Added `--har-api-only` filtering for HAR imports (API/business-focused, static/CDN suppression).
- Discovery now groups seeds by site base and runs per-site discovery once.
- Added CLI tests for HAR filtering controls and an integration test asserting one `/robots.txt` hit for multiple seeds on the same site.
- Updated docs (`Readme.md`, `HOWTO.md`, `docs/configuration.md`) for `--har-api-only`.
- Validation:
- `cargo test` passed (full suite green).
- HAR sample comparison (`--no-filter --max-endpoints 1`, timed 8s): baseline `Targets: 239` vs `--har-api-only` `Targets: 48`.
