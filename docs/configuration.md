---
author: teycir ben soltane
email: teycir@pxdmail.net
website: teycirbensoltane.tn
last_updated: 2026-03-14
tags: [configuration, cli, settings, parameters]
category: Configuration Guide
---

# Configuration Reference

All fields live in `Config` (populated by `clap`).  
Durations are in milliseconds unless noted.

| Field | Type | Default | Description |
|---|---|---|---|
| `urls` | `Vec<String>` | required* | Target URLs (newline-delimited file or stdin) |
| `concurrency` | `usize` | `20` | Max parallel tasks |
| `max_endpoints` | `usize` | `0` | Hard cap on discovered endpoints (0 = unlimited) |
| `min_severity` | `Severity` | `Info` | Drop findings below this |
| `fail_on` | `Severity` | `Medium` | Exit non-zero at or above this level |
| `output_path` | `Option<PathBuf>` | `None` (stdout) | Report output file |
| `format` | `pretty` | Output format (`pretty`, `ndjson`) |
| `quiet` | `bool` | `false` | Suppress non-error output |
| `summary` | `bool` | `false` | One-line summary after scan |
| `timeout_secs` | `u64` | `30` | Per-request HTTP timeout |
| `retries` | `u32` | `3` | Retry budget per request |
| `politeness.delay_ms` | `u64` | `100` | Per-host delay between requests |
| `headers` | `Vec<String>` | `[]` | Default request headers (NAME:VALUE) |
| `cookies` | `Vec<String>` | `[]` | Default cookies (NAME=VALUE) |
| `proxy` | `Option<String>` | `None` | Proxy URL |
| `danger_accept_invalid_certs` | `bool` | `false` | Skip TLS verification |
| `no_jwt` | `bool` | `false` | Disable JWT scanner |

*You must provide exactly one of `--urls` or `--stdin`.
