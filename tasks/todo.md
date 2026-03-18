# Task: Add `--cookies-json` CLI Shorthand

## Plan
- [x] Add `--cookies-json <FILE>` to CLI args with safe conflict behavior.
- [x] Map alias to `session_file` + `SessionFileFormat::Excalibur` in config hydration.
- [x] Add CLI tests for alias parsing and conflict handling.
- [x] Update user docs (`Readme.md`, `HOWTO.md`, `docs/configuration.md`).
- [x] Run `cargo test` and capture results.

## Review
- Added `--cookies-json <FILE>` as an explicit shorthand for Excalibur cookie imports.
- Enforced conflict safety in CLI parsing against `--session-file` and `--session-file-format`.
- Verified with new CLI tests (`cookies_json_alias_parses`, conflict tests) and full suite pass.
- Validation: `cargo test` passed (all tests green).
