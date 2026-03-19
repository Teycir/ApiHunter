---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-19
tags: [testing, strategy, unit-tests, integration-tests, wiremock, fixtures]
category: Testing Guide
---

# Testing Strategy

ApiHunter uses a layered test strategy that prioritizes deterministic, local runs.

`cargo test` is designed to run without internet access by default:
- scanner/runtime tests use local `wiremock` servers,
- fixture regression tests replay pinned payload snapshots,
- CLI tests execute local binaries with `assert_cmd`.

## What Is Tested

| Test Class | Scope | Representative Files | Live Target Required |
|------------|-------|----------------------|----------------------|
| Scanner behavior suites | Individual scanner logic and edge cases | `tests/cors_scanner.rs`, `tests/graphql_scanner.rs`, `tests/jwt_scanner.rs`, `tests/websocket_scanner.rs`, `tests/mass_assignment_scanner.rs`, `tests/oauth_oidc_scanner.rs`, `tests/rate_limit_scanner.rs`, `tests/cve_templates_scanner.rs` | No |
| Runner integration | End-to-end orchestration via `runner::run` with real config/client wiring | `tests/integration_runner.rs` | No (local `wiremock`) |
| CLI and startup behavior | Arg parsing, startup validation, process-level behavior | `tests/cli.rs`, `tests/startup_inputs.rs` | No |
| HTTP client and auth flows | Retry/timeout semantics, unauth probing, auth flow execution and refresh behavior | `tests/http_client_retry_policy.rs`, `tests/http_client_unauth.rs`, `tests/auth_flow.rs`, `tests/auth_refresh.rs` | No |
| Template/fixture regression | CVE template parity and replay against pinned upstream and real payload fixtures | `tests/cve_templates_upstream_parity.rs`, `tests/cve_templates_real_data.rs`, `tests/cve_templates_runtime_ext.rs`, `tests/template_tooling.rs` | No |
| Core library helpers | Reporting, scanner naming stability, probe helpers, parsing formats | `tests/reports.rs`, `tests/scanner_names.rs`, `tests/burst_probe.rs`, `tests/session_file_formats.rs` | No |

## Mocking and Real Data

- Mocking: network interactions are emulated with `wiremock` to keep tests stable and fast.
- Real payload coverage: `tests/fixtures/real_cve_payloads/` contains captured real-world response bodies that are replayed locally.
- Upstream parity: `tests/fixtures/upstream_nuclei/` pins reference templates used for importer/parity checks.

## What Is Not In `cargo test`

- Live internet target scanning is not part of the default automated suite.
- Optional real-target validation can be run manually with `ScanScripts/*.sh` and explicit target lists under `targets/`.

## Running Tests

```bash
# Focused scanner suite
cargo test --test cors_scanner

# Orchestration suite
cargo test --test integration_runner

# Full local suite
cargo test
```

