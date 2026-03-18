# Task: Single Session Format

## Plan
- [x] Remove `--cookies-json` and `--session-file-format` CLI options.
- [x] Enforce a single session schema: native `{\"hosts\": {...}}` via `--session-file`.
- [x] Update tests (CLI + session file behavior) to match the one-format policy.
- [x] Update docs to document only one session input format and one flag.
- [x] Run `cargo fmt && cargo test`.

## Review
- Removed multi-format session parsing and CLI aliases; session input is now `--session-file` only.
- Standardized docs around one accepted JSON schema: `{\"hosts\": {\"<host>\": {\"cookie\": \"value\"}}}`.
- Updated test suite for the new policy:
  - CLI tests now assert legacy flags are rejected.
  - Session format tests now validate accepted `hosts` schema and reject legacy `cookies` schema.
- Verification:
  - `cargo fmt` passed.
  - `cargo test` passed (all unit/integration/doc tests green).
